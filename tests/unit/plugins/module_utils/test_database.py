# -*- coding: utf-8 -*-

# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import sys

if sys.version_info[0] == 3:
    from plugins.module_utils.database import check_input
elif sys.version_info[0] == 2:
    from ansible_collections.community.postgresql.plugins.module_utils.database import check_input


def test_check_input(mocker):
    module = mocker.MagicMock()
    check_input(module, "teststring", 3, True, ["teststring", ["teststring"]], {"test": "string"})
    module.fail_json.assert_not_called()
    dangerous_elements = (";DROP DATABASE;--",)
    check_input(module, *dangerous_elements)
    module.fail_json.assert_called_once_with(msg="Passed input '%s' is potentially dangerous"
                                                 % ', '.join(dangerous_elements))


def test_check_input_nested_inputs(mocker):
    module = mocker.MagicMock()
    dangerous_elements = ([[";DROP DATABASE;--"]], {"somekey": {"somesubkey": ";ALTER ROLE"}})
    check_input(module, *dangerous_elements)
    module.fail_json.assert_called_once_with(
        msg="Passed input ';DROP DATABASE;--, ;ALTER ROLE' is potentially dangerous")
