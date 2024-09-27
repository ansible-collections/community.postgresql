# -*- coding: utf-8 -*-

# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import sys

import pytest

if sys.version_info[0] == 3:
    from plugins.modules.postgresql_user import parse_user_configuration, compare_user_configurations, _pg_quote_user
elif sys.version_info[0] == 2:
    from ansible_collections.community.postgresql.plugins.modules.postgresql_user import parse_user_configuration, \
        compare_user_configurations, _pg_quote_user


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


def test__pg_quote_user(mocker):
    """Tests if quoting users works correctly"""
    module = mocker.MagicMock()
    output = _pg_quote_user('someuser', module)
    assert output == '"someuser"'
    output = _pg_quote_user('"someuser"', module)
    assert output == '"someuser"'
    output = _pg_quote_user('some.user.with.dots', module)
    assert output == '"some.user.with.dots"'
    output = _pg_quote_user('some.user.with\"\"quotes', module)
    assert output == '"some.user.with\"\"quotes"'
    _pg_quote_user('someuser"', module)
    module.fail_json.assert_called_once_with("The value of the user-field can't contain a double-quote in the end "
                                             "if it doesn't start with one and vice-versa.")
    module = mocker.MagicMock()
    _pg_quote_user('"someuser', module)
    module.fail_json.assert_called_once_with("The value of the user-field can't contain a double-quote in the end "
                                             "if it doesn't start with one and vice-versa.")
    module = mocker.MagicMock()
    with pytest.raises(Exception, match='User escaped identifiers must escape extra quotes'):
        _pg_quote_user('some.user.with\"illegal.quotes', module)
