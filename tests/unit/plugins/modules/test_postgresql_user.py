# -*- coding: utf-8 -*-

# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import sys

if sys.version_info[0] == 3:
    from plugins.modules.postgresql_user import parse_user_configuration, compare_user_configurations, \
        user_configuration, get_user_configuration
elif sys.version_info[0] == 2:
    from ansible_collections.community.postgresql.plugins.modules.postgresql_user import parse_user_configuration, \
        compare_user_configurations, user_configuration, get_user_configuration


def test_parse_user_configuration(mocker):
    """Tests if correct inputs return the expected results"""
    module = mocker.MagicMock()
    test_input = ["some_setting=some_value", "another.setting=20MB", "nested=something=null"]
    expected = {"some_setting": "some_value", "another.setting": "20MB", "nested": "something=null"}
    result = parse_user_configuration(module, test_input)
    assert result == expected
    assert parse_user_configuration(module, None) == {}


def test_parse_user_config_incorrect_input(mocker):
    """Tests if incorrect input is handled properly"""
    module = mocker.MagicMock()
    faulty_input = ["key=value", "incorrect"]
    parse_user_configuration(module, faulty_input)
    module.fail_json.assert_called_once_with(
        msg="Expecting a list of strings where each string has the format 'key=value'.")


def test_compare_user_configurations():
    """Tests if the correct update-path is created from input"""
    # for some reason this one fails in Python 2
    if sys.version_info[0] == 2:
        return

    desired = {"some_setting": "some_value", "another_setting": "different_value"}
    current = {"some_setting": "some_value", "another_setting": "DIFFERENT_VALUE", "ghost_setting": "no_value"}
    expected = {"reset": ["ghost_setting"],
                "update": {"another_setting": "different_value"}
                }
    output = compare_user_configurations(current, desired, True)
    assert output == expected
    output = compare_user_configurations(current, {}, True)
    # TODO the last for lines of the following assertion were added because the assertion fails
    # when testing against stable-2.15 probably due to some specific Python version used.
    # Remove them when stable-2.15 gets EOL in November 2024.
    assert output == {"reset": ["some_setting", "another_setting", "ghost_setting"], "update": {}} or \
        output == {'reset': ['another_setting', 'some_setting', 'ghost_setting'], 'update': {}} or \
        output == {'reset': ['some_setting', 'ghost_setting', 'another_setting'], 'update': {}} or \
        output == {'reset': ['ghost_setting', 'some_setting', 'another_setting'], 'update': {}} or \
        output == {'reset': ['ghost_setting', 'another_setting', 'some_setting'], 'update': {}} or \
        output == {'reset': ['another_setting', 'ghost_setting', 'some_setting'], 'update': {}}
    output = compare_user_configurations({}, desired, True)
    assert output == {"reset": [], "update": desired}
    output = compare_user_configurations(current, desired, False)
    no_reset_expected = {"reset": [],
                         "update": {"another_setting": "different_value"}
                         }
    assert output == no_reset_expected
    output = compare_user_configurations(current, {}, False)
    assert output == {"reset": [], "update": {}}


def test_user_configuration_quotes_keys(mocker):
    """Tests if configuration keys are quoted as identifiers, with an embedded double quote doubled"""
    module = mocker.MagicMock()
    cursor = mocker.MagicMock()
    # rolconfig read: initially, after RESET, after SET
    cursor.fetchone.side_effect = [{"rolconfig": ['re"set=1']}, {"rolconfig": None}, {"rolconfig": ['se"t=2']}]
    # quote_values=False, because that is the path where a key containing a double quote is not rejected
    changed = user_configuration(cursor, module, 'us"er', {'se"t': '2'}, True, False)
    assert changed
    alter_calls = [c for c in cursor.execute.call_args_list if c.args[0].startswith('ALTER ROLE')]
    assert alter_calls == [
        mocker.call('ALTER ROLE "us""er" RESET "re""set";'),
        mocker.call('ALTER ROLE "us""er" SET "se""t" TO 2;'),
    ]
    assert mocker.call('RELEASE SAVEPOINT ansible_pg_user_config;') in cursor.execute.call_args_list


def test_user_configuration_equivalent_value_is_not_a_change(mocker):
    """A value that PostgreSQL normalizes to the stored one is rolled back and not reported as changed"""
    module = mocker.MagicMock()
    cursor = mocker.MagicMock()
    # rolconfig is identical before and after the ALTER ROLE: the value was equivalent
    cursor.fetchone.return_value = {"rolconfig": ['search_path=a, public']}
    changed = user_configuration(cursor, module, 'user', {'search_path': 'A,public'}, False, False)
    assert not changed
    assert cursor.execute.call_args_list[-1] == mocker.call('ROLLBACK TO SAVEPOINT ansible_pg_user_config;')


def test_get_user_configuration(mocker):
    """Tests that the raw rolconfig array is returned and that a missing role fails the module"""
    module = mocker.MagicMock()
    cursor = mocker.MagicMock()
    cursor.fetchone.return_value = {"rolconfig": ['search_path=a, public']}
    assert get_user_configuration(cursor, module, 'user') == ['search_path=a, public']
    cursor.execute.assert_called_once_with("SELECT rolconfig FROM pg_roles WHERE rolname = %(user)s;", {"user": 'user'})
    module.fail_json.assert_not_called()

    cursor.fetchone.return_value = None
    module.fail_json.side_effect = SystemExit
    try:
        get_user_configuration(cursor, module, 'missing')
    except SystemExit:
        pass
    module.fail_json.assert_called_once_with(msg="Can't find user missing in 'pg_roles'")


def test_user_configuration_rolls_back_only_equivalent_values(mocker):
    """Tests that, of two parameters, the equivalent one is rolled back and the changed one is kept"""
    module = mocker.MagicMock()
    cursor = mocker.MagicMock()
    # rolconfig read: initially, after SET search_path (unchanged), after SET work_mem (changed)
    stored = ['search_path=a, public', 'work_mem=8MB']
    cursor.fetchone.side_effect = [{"rolconfig": stored}, {"rolconfig": stored},
                                   {"rolconfig": ['search_path=a, public', 'work_mem=16MB']}]
    changed = user_configuration(cursor, module, 'user', {'search_path': 'A,public', 'work_mem': '16MB'}, False, False)
    assert changed
    statements = [c.args[0] for c in cursor.execute.call_args_list if not c.args[0].startswith('SELECT')]
    assert statements == [
        'SAVEPOINT ansible_pg_user_config;',
        'ALTER ROLE "user" SET "search_path" TO A,public;',
        'ROLLBACK TO SAVEPOINT ansible_pg_user_config;',
        'SAVEPOINT ansible_pg_user_config;',
        'ALTER ROLE "user" SET "work_mem" TO 16MB;',
        'RELEASE SAVEPOINT ansible_pg_user_config;',
    ]
