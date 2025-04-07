# Copyright: (c) 2025, Andrew Klychkov (@Andersson007) <andrew.a.klychkov@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest

from ansible_collections.community.postgresql.plugins.modules.postgresql_alter_system import (
    check_pg_version,
    check_problematic_params,
    convert_ret_vals,
    str_contains_float,
    to_int,
)


@pytest.fixture(scope='function')
def m_ansible_module():
    """Return an object of dummy AnsibleModule class
    that emulates some of its methods we need.
    """
    class DummyAnsibleModule():
        def __init__(self):
            self.err_msg = None
            self.warn_msg = None

        def fail_json(self, msg):
            self.err_msg = msg

        def warn(self, msg):
            self.warn_msg = msg

    return DummyAnsibleModule()


@pytest.mark.parametrize('_input,expected', [
    ('1', 1),
    ('01', 1),
]
)
def test_to_int(m_ansible_module, _input, expected):
    assert to_int(m_ansible_module, _input) == expected


@pytest.mark.parametrize('_input,err_msg', [
    ('1.0', 'Value 1.0 cannot be converted to int'),
    ('blah', 'Value blah cannot be converted to int'),
]
)
def test_to_int_fail(m_ansible_module, _input, err_msg):
    to_int(m_ansible_module, _input)
    assert m_ansible_module.err_msg == err_msg


@pytest.mark.parametrize('_input,expected', [
    ('1', False),
    ('100', False),
    ('blah', False),
    ('0.1', True),
    ('1.1', True),
    ('0.0000001', True),
]
)
def test_str_contains_float(_input, expected):
    assert str_contains_float(_input) == expected


@pytest.mark.parametrize('_input,expected', [
    (
        {
            "boot_val": "try",
            "setting": "try",
            "context": "sighup",
            "enumvals": [
                "off",
                "on",
                "try"
            ],
            "max_val": None,
            "min_val": None,
            "unit": None,
            "vartype": "enum"
        },
        {
            "boot_val": "try",
            "setting": "try",
            "context": "sighup",
            "enumvals": [
                "off",
                "on",
                "try"
            ],
            "max_val": None,
            "min_val": None,
            "unit": None,
            "vartype": "enum"
        },
    ),
    (
        {
            "boot_val": "test",
            "setting": "test",
            "context": "sighup",
            "enumvals": None,
            "max_val": None,
            "min_val": None,
            "unit": None,
            "vartype": "string"
        },
        {
            "boot_val": "test",
            "setting": "test",
            "context": "sighup",
            "enumvals": None,
            "max_val": None,
            "min_val": None,
            "unit": None,
            "vartype": "string"
        },
    ),
    (
        {
            "boot_val": "0",
            "setting": "1",
            "context": "sighup",
            "enumvals": None,
            "max_val": "100",
            "min_val": "0",
            "unit": None,
            "vartype": "integer"
        },
        {
            "boot_val": 0,
            "setting": 1,
            "context": "sighup",
            "enumvals": None,
            "max_val": 100,
            "min_val": 0,
            "unit": None,
            "vartype": "integer"
        },
    ),
    (
        {
            "boot_val": "0.1",
            "setting": "0.1",
            "context": "sighup",
            "enumvals": None,
            "max_val": "1",
            "min_val": "0",
            "unit": None,
            "vartype": "real"
        },
        {
            "boot_val": 0.1,
            "setting": 0.1,
            "context": "sighup",
            "enumvals": None,
            "max_val": 1,
            "min_val": 0,
            "unit": None,
            "vartype": "real"
        },
    ),
]
)
def test_convert_ret_vals(_input, expected):
    assert convert_ret_vals(_input) == expected


@pytest.mark.parametrize('_input,warn_msg', [
    (130000, 'PostgreSQL version 140000 is supported, but 130000 is used. '
             'Before filing a bug report, please run your task on a supported version of PostgreSQL.'),
    (140000, None),
    (150000, None),
]
)
def test_check_pg_version(m_ansible_module, _input, warn_msg):
    check_pg_version(m_ansible_module, _input)
    assert m_ansible_module.warn_msg == warn_msg


@pytest.mark.parametrize('param_input,value_input,err_msg', [
    ('work_mem', '1024', None),
    ('shared_preload_libraries', 'pg_stat_statements', None),
    ('shared_preload_libraries', '', 'Due to a PostgreSQL bug in resetting shared_preload_libraries '
                                     'with ALTER SYSTEM SET, setting it as an empty string '
                                     'is not supported by the module to avoid crashes. '
                                     'Use `value: _RESET` instead. '
                                     'If you think the bug has been fixed, please let us know.'),
]
)
def test_check_problematic_params(m_ansible_module, param_input, value_input, err_msg):
    check_problematic_params(m_ansible_module, param_input, value_input)
    assert m_ansible_module.err_msg == err_msg
