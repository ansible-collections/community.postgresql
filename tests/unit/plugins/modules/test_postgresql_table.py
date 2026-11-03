# -*- coding: utf-8 -*-

# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest

from ansible_collections.community.postgresql.plugins.modules import postgresql_table
from ansible_collections.community.postgresql.plugins.modules.postgresql_table import Table


def make_table(mocker, relpersistence=None):
    """Return a Table object whose existence check is mocked.

    If relpersistence is None, the table does not exist.
    """
    rows = []
    if relpersistence is not None:
        rows = [{
            'tableowner': 'alice',
            'tablespace': None,
            'reloptions': None,
            'relpersistence': relpersistence,
        }]
    exec_sql = mocker.patch.object(postgresql_table, 'exec_sql', return_value=rows)
    table = Table('test_table', mocker.MagicMock(), mocker.MagicMock())
    exec_sql.reset_mock()
    exec_sql.return_value = True
    return table, exec_sql


@pytest.mark.parametrize('relpersistence, expected', [('u', True), ('p', False)])
def test_info_unlogged(mocker, relpersistence, expected):
    table, dummy = make_table(mocker, relpersistence)
    assert table.exists is True
    assert table.info['unlogged'] is expected


@pytest.mark.parametrize('unlogged, expected', [
    (True, 'ALTER TABLE "test_table" SET UNLOGGED'),
    (False, 'ALTER TABLE "test_table" SET LOGGED'),
])
def test_set_unlogged(mocker, unlogged, expected):
    table, exec_sql = make_table(mocker, 'p')
    assert table.set_unlogged(unlogged) is True
    exec_sql.assert_called_once_with(table, expected, return_bool=True)


@pytest.mark.parametrize('relpersistence, unlogged, expected', [
    ('p', True, 'ALTER TABLE "test_table" SET UNLOGGED'),
    ('u', False, 'ALTER TABLE "test_table" SET LOGGED'),
])
def test_create_existing_table_changes_persistence(mocker, relpersistence, unlogged, expected):
    table, exec_sql = make_table(mocker, relpersistence)
    assert table.create(unlogged=unlogged) is True
    exec_sql.assert_called_once_with(table, expected, return_bool=True)


@pytest.mark.parametrize('relpersistence, unlogged', [
    ('p', False),
    ('u', True),
    ('p', None),
    ('u', None),
])
def test_create_existing_table_keeps_persistence(mocker, relpersistence, unlogged):
    table, exec_sql = make_table(mocker, relpersistence)
    assert table.create(unlogged=unlogged) is False
    exec_sql.assert_not_called()


@pytest.mark.parametrize('unlogged, expected', [
    (True, 'CREATE UNLOGGED TABLE "test_table" ()'),
    (False, 'CREATE TABLE "test_table" ()'),
    (None, 'CREATE TABLE "test_table" ()'),
])
def test_create_new_table(mocker, unlogged, expected):
    table, exec_sql = make_table(mocker)
    assert table.exists is False
    assert table.create(unlogged=unlogged) is True
    exec_sql.assert_called_once_with(table, expected, return_bool=True)


class FailJson(Exception):
    pass


def run_main_with_params(mocker, **params):
    module_params = {
        'table': 'test_table',
        'state': 'present',
        'tablespace': None,
        'owner': None,
        'unlogged': None,
        'like': None,
        'including': None,
        'storage_params': None,
        'truncate': False,
        'columns': None,
        'cascade': False,
        'session_role': None,
        'trust_input': True,
    }
    module_params.update(params)
    module = mocker.MagicMock()
    module.params = module_params
    module.fail_json.side_effect = FailJson
    mocker.patch.object(postgresql_table, 'AnsibleModule', return_value=module)
    connect = mocker.patch.object(postgresql_table, 'ensure_required_libs', side_effect=AssertionError('must fail before connecting'))
    with pytest.raises(FailJson):
        postgresql_table.main()
    connect.assert_not_called()
    return module.fail_json.call_args[1]['msg']


@pytest.mark.parametrize('unlogged', [True, False])
def test_absent_is_mutually_exclusive_with_unlogged(mocker, unlogged):
    msg = run_main_with_params(mocker, state='absent', unlogged=unlogged)
    assert 'state=absent is mutually exclusive with' in msg


@pytest.mark.parametrize('unlogged', [True, False])
def test_truncate_is_mutually_exclusive_with_unlogged(mocker, unlogged):
    msg = run_main_with_params(mocker, truncate=True, unlogged=unlogged)
    assert 'truncate is mutually exclusive with' in msg
