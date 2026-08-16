# -*- coding: utf-8 -*-

# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import sys

if sys.version_info[0] == 3:
    from plugins.module_utils.database import check_input, pg_quote_name
elif sys.version_info[0] == 2:
    from ansible_collections.community.postgresql.plugins.module_utils.database import (
        check_input, pg_quote_name,
    )


def test_check_input(mocker):
    module = mocker.MagicMock()
    check_input(module, "teststring", 3, True, ["teststring", ["teststring"]], {"test": "string"})
    module.fail_json.assert_not_called()
    dangerous_elements = (";DROP DATABASE;--",)
    check_input(module, *dangerous_elements)
    module.fail_json.assert_called_once_with(msg="Passed input '%s' is potentially dangerous"
                                                 % ', '.join(dangerous_elements))


def test_pg_quote_name():
    # An ordinary name is simply wrapped.
    assert pg_quote_name('alice') == '"alice"'

    # A dot belongs to the role name rather than qualifying it, so it stays inside the
    # quotes. pg_quote_identifier splits on dots and rejects this name outright.
    assert pg_quote_name('group.with.dots') == '"group.with.dots"'

    # An embedded quote is doubled instead of terminating the identifier early.
    assert pg_quote_name('we"ird') == '"we""ird"'

    # The name is taken literally: a value that already looks quoted is a role whose
    # name contains quotes, not a pre-quoted identifier to pass through.
    assert pg_quote_name('"prequoted"') == '"""prequoted"""'

    # A per cent sign is left alone for a statement psycopg gets no parameters for.
    assert pg_quote_name('per%cent') == '"per%cent"'


def test_pg_quote_name_for_params():
    # Doubled so that psycopg's substitution over the whole statement leaves one behind
    # rather than reading the name as a placeholder.
    assert pg_quote_name('per%cent', for_params=True) == '"per%%cent"'
    assert pg_quote_name('a%sb', for_params=True) == '"a%%sb"'
    assert pg_quote_name('x%(password)sy', for_params=True) == '"x%%(password)sy"'

    # Names without a per cent sign are unaffected by the flag.
    assert pg_quote_name('alice', for_params=True) == '"alice"'
    assert pg_quote_name('we"ird', for_params=True) == '"we""ird"'

    # psycopg substitutes over the whole statement, which reduces the doubling back to
    # one, so what reaches the server is the name as written.
    doubled = pg_quote_name('per%cent', for_params=True)
    assert doubled % {} == '"per%cent"'


def test_check_input_nested_inputs(mocker):
    module = mocker.MagicMock()
    dangerous_elements = ([[";DROP DATABASE;--"]], {"somekey": {"somesubkey": ";ALTER ROLE"}})
    check_input(module, *dangerous_elements)
    module.fail_json.assert_called_once_with(
        msg="Passed input ';DROP DATABASE;--, ;ALTER ROLE' is potentially dangerous")
