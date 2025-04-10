# Copyright: (c) 2025, Andrew Klychkov (@Andersson007) <andrew.a.klychkov@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest

from ansible_collections.community.postgresql.plugins.modules.postgresql_alter_system import (
    build_value_class,
    check_pg_version,
    check_problematic_params,
    convert_ret_vals,
    normalize_bool_val,
    str_contains_float,
    to_int,
    ValueBool,
    ValueEnum,
    ValueInt,
    ValueMem,
    ValueReal,
    ValueString,
    ValueTime,
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


@pytest.mark.parametrize('_input,expected', [
    ('blah', 'blah'),
    ('True', 'on'),
    ('False', 'off'),
]
)
def test_normalize_bool_val(_input, expected):
    assert normalize_bool_val(_input) == expected


@pytest.mark.parametrize('param_name,value,unit,vartype,pg_ver,expected_class_type', [
    ('negative_param', '-1', None, 'real', None, ValueInt),
    ('negative_param', '-1', None, 'integer', None, ValueInt),
    ('time_param', '1', 'min', 'integer', None, ValueTime),
    ('time_param', '1', 's', 'real', None, ValueTime),
    ('time_param', '1', 'ms', 'whatever', None, ValueTime),
    ('int_param', '1', 'B', 'integer', None, ValueMem),
    ('int_param', '1', 'kB', 'integer', None, ValueMem),
    ('int_param', '1', '8kB', 'integer', None, ValueMem),
    ('int_param', '1', 'MB', 'integer', None, ValueMem),
    ('int_param', '1', None, 'integer', None, ValueInt),
    ('bool_param', 'on', None, 'bool', None, ValueBool),
    ('real_param', '1', None, 'real', None, ValueReal),
    ('string_param', 'value', None, 'string', 140000, ValueString),
    ('enum_param', 'value', None, 'enum', None, ValueEnum),
]
)
def test_build_value_class(m_ansible_module, param_name, value, unit, vartype, pg_ver, expected_class_type):
    obj = build_value_class(m_ansible_module, param_name, value, unit, vartype, pg_ver)
    assert isinstance(obj, expected_class_type)


@pytest.mark.parametrize('value,expected_normalized', [
    ('on', 'on'),
    ('off', 'off'),
    ('True', 'on'),
    ('False', 'off'),
]
)
def test_value_bool(m_ansible_module, value, expected_normalized):
    obj = ValueBool(m_ansible_module, "param", value, None)
    assert obj.normalized == expected_normalized


@pytest.mark.parametrize('value,expected_normalized', [
    ('1', 1),
    ('-1', -1),
]
)
def test_value_int(m_ansible_module, value, expected_normalized):
    obj = ValueInt(m_ansible_module, 'param', value, None)
    assert obj.normalized == expected_normalized


@pytest.mark.parametrize('value,expected_normalized', [
    ('-1', -1),
    ('2ms', 2),
    ('20ms', 20),
    ('0.025', 0.025),
    ('1', 1),
]
)
def test_value_real(m_ansible_module, value, expected_normalized):
    obj = ValueReal(m_ansible_module, 'param', value, None)
    assert obj.normalized == expected_normalized


# Whatever you pass, the class always returns a normalized value in bytes
@pytest.mark.parametrize('value,default_unit,expected_normalized', [
    ('1024', 'B', 1024),
    ('1024B', 'B', 1024),
    ('1kB', 'B', 1024),
    ('1', 'kB', 1024),
    ('1', '8kB', 8192),
    ('1', 'MB', 1048576),
    ('1MB', 'MB', 1048576),
    ('1024MB', 'MB', 1073741824),
    ('1MB', 'B', 1048576),
    ('1MB', 'kB', 1048576),
    ('1MB', '8kB', 1048576),
    ('1GB', 'B', 1073741824),
    ('1TB', 'MB', 1099511627776),
]
)
def test_value_mem(m_ansible_module, value, default_unit, expected_normalized):
    obj = ValueMem(m_ansible_module, 'param', value, default_unit, None)
    assert obj.normalized == expected_normalized


# Whatever you pass, the class always returns a normalized value in microseconds
@pytest.mark.parametrize('value,default_unit,expected_normalized', [
    ('1', 'us', 1),
    ('1us', 'us', 1),
    ('1', 'ms', 1000),
    ('1ms', 'ms', 1000),
    ('1s', 'ms', 1000000),
    ('1min', 'ms', 60000000),
    ('1h', 'ms', 3600000000),
    ('1d', 'ms', 86400000000),
    ('1', 's', 1000000),
    ('1ms', 's', 1000),
    ('1s', 's', 1000000),
    ('1min', 's', 60000000),
    ('1h', 's', 3600000000),
    ('1d', 's', 86400000000),
    ('1', 'min', 60000000),
    ('1min', 'min', 60000000),
    ('1ms', 'min', 1000),
    ('1s', 'min', 1000000),
    ('1h', 'min', 3600000000),
    ('1d', 'min', 86400000000),
]
)
def test_value_time(m_ansible_module, value, default_unit, expected_normalized):
    obj = ValueTime(m_ansible_module, 'param', value, default_unit, None)
    assert obj.normalized == expected_normalized


@pytest.mark.parametrize('value', [
    ('B'),
    ('1PB'),
    ('blah'),
]
)
def test_value_mem_fail(m_ansible_module, value):
    obj = None
    try:
        obj = ValueMem(m_ansible_module, 'param', value, 'does not matter', None)
    except Exception:
        if obj:  # To use it somehow to avoid tox errors in CI
            pass
        pass

    assert 'invalid value for parameter' in m_ansible_module.err_msg


@pytest.mark.parametrize('value', [
    ('B'),
    ('1PB'),
    ('blah'),
]
)
def test_value_time_fail(m_ansible_module, value):
    obj = None
    try:
        obj = ValueTime(m_ansible_module, 'param', value, 'does not matter', None)
    except Exception:
        if obj:  # To use it somehow to avoid tox error in CI
            pass
        pass

    assert 'invalid value for parameter' in m_ansible_module.err_msg


@pytest.mark.parametrize('param_name,value,expected_normalized', [
    ('local_preload_libraries', 'value1', 'value1'),
    ('local_preload_libraries', 'value1,value2,value3', 'value1, value2, value3'),
    ('local_preload_libraries', '"value1", "value2", "value3"', 'value1, value2, value3'),
    ('search_path', 'value1', 'value1'),
    ('search_path', 'value1,value2,value3', 'value1, value2, value3'),
    ('search_path', '"value1", "value2", "value3"', 'value1, value2, value3'),
    ('session_preload_libraries', 'value1', 'value1'),
    ('session_preload_libraries', 'value1,value2,value3', 'value1, value2, value3'),
    ('session_preload_libraries', '"value1", "value2", "value3"', 'value1, value2, value3'),
    ('shared_preload_libraries', 'value1', 'value1'),
    ('shared_preload_libraries', 'value1,value2,value3', 'value1, value2, value3'),
    ('shared_preload_libraries', '"value1", "value2", "value3"', 'value1, value2, value3'),
    ('temp_tablespaces', 'value1', 'value1'),
    ('temp_tablespaces', 'value1,value2,value3', 'value1, value2, value3'),
    ('temp_tablespaces', '"value1", "value2", "value3"', 'value1, value2, value3'),
    ('unix_socket_directories', 'value1', 'value1'),
    ('unix_socket_directories', 'value1,value2,value3', 'value1, value2, value3'),
    ('unix_socket_directories', '"value1", "value2", "value3"', 'value1, value2, value3'),
    ('param', 'value', 'value'),
]
)
def test_value_string(m_ansible_module, param_name, value, expected_normalized):
    obj = ValueString(m_ansible_module, param_name, value, None, 140000)
    assert obj.normalized == expected_normalized
