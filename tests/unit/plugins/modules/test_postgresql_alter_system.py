# Copyright: (c) 2025, Andrew Klychkov (@Andersson007) <andrew.a.klychkov@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest

from ansible_collections.community.postgresql.plugins.modules.postgresql_alter_system import (
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
def test_is_str_float(_input, expected):
    assert str_contains_float(_input) == expected
