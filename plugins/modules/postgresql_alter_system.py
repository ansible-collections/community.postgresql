#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Andrew Klychkov (@Andersson007) <andrew.a.klychkov@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: postgresql_alter_system
short_description: Change a PostgreSQL server configuration parameter
description:
  - Allows to change a PostgreSQL server configuration parameter.
  - The module uses ALTER SYSTEM command and applies changes by reload server configuration.

options:
  param:
    description:
    - Name of PostgreSQL server parameter.
    type: str
    required: true

  value:
    description:
    - Parameter value to set.
    - Specify the value in appropriate units!
      Check out the C(unit) and C(vartype) columns of the C(pg_settings) table
      for your setting. For example, for C(work_mem) pass C(1024), NOT C(1M),
      because the vartype is integer and unit is kB.
    - Use C(defalut) to remove a parameter string from postgresql.auto.conf
      by running C(ALTER SYSTEM SET param = DEFAULT); always returns changed=true.
    - Use C(reset) to restore the parameter to its initial state (boot_val)
      by running C(ALTER SYSTEM RESET param); always returns changed=true.
    type: str
    required: true

  pg_reload_conf:
    description:
    - Whether to run C(SELECT pg_reload_conf()) after altering the system.
    type: bool
    default: true

  session_role:
    description:
    - Switch to session_role after connecting. The specified session_role must
      be a role that the current login_user is a member of.
    - Permissions checking for SQL commands is carried out as though
      the session_role were the one that had logged in originally.
    type: str

  login_db:
    description:
    - Name of database to connect.
    type: str

  trust_input:
    description:
    - If C(false), check whether values of parameters are potentially dangerous.
    - It makes sense to use C(false) only when SQL injections are possible.
    type: bool
    default: true

notes:
- For some parameters restart of PostgreSQL server is required.
  See official documentation U(https://www.postgresql.org/docs/current/view-pg-settings.html).

attributes:
  check_mode:
    support: full

seealso:
- module: community.postgresql.postgresql_info
- name: PostgreSQL server configuration
  description: General information about PostgreSQL server configuration.
  link: https://www.postgresql.org/docs/current/runtime-config.html
- name: PostgreSQL view pg_settings reference
  description: Complete reference of the pg_settings view documentation.
  link: https://www.postgresql.org/docs/current/view-pg-settings.html
- name: PostgreSQL ALTER SYSTEM command reference
  description: Complete reference of the ALTER SYSTEM command documentation.
  link: https://www.postgresql.org/docs/current/sql-altersystem.html

author:
- Andrew Klychkov (@Andersson007)

extends_documentation_fragment:
- community.postgresql.postgres
'''

EXAMPLES = r'''
- name: Set work_mem
  community.postgresql.postgresql_alter_system:
    param: work_mem
    value: 1024

- name: Reset work_mem
  community.postgresql.postgresql_alter_system:
    param: work_mem
    value: reset
    pg_reload_conf: true

- name: Set work_mem as DEFAULT
  community.postgresql.postgresql_alter_system:
    param: work_mem
    value: default

- name: Set TimeZone parameter (careful, case sensitive)
  community.postgresql.postgresql_alter_system:
    param: TimeZone
    value: 'Europe/Paris'
'''

RETURN = r'''
pg_settings_entry:
  description: Key-value pairs representing some columns and values for the parameter.
  returned: success
  type: dict
  sample: {
    'name': 'work_mem',
    'setting': 4096,
    'unit': 'kB',
    'context': 'user',
    'vartype': 'integer',
    'min_val': 64,
    'max_val': 2147483647,
    'boot_val': 4096,
    'reset_val': 4096,
    'pending_restart': false
  }
executed_queries:
  description:
  - List of executed DML queries.
  returned: success
  type: list
  elements: str
  sample: ["ALTER SYSTEM SET shared_preload_libraries = ''"]
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.community.postgresql.plugins.module_utils.database import \
    check_input
from ansible_collections.community.postgresql.plugins.module_utils.postgres import (
    connect_to_db,
    ensure_required_libs,
    get_conn_params,
    pg_cursor_args,
    postgres_common_argument_spec,
)

executed_queries = []

# class Value():
#     def __init__(self, attrs):
#         self.vartype = attrs["vartype"]
#         self.setting = attrs["setting"]
#         self.unit = attrs["unit"]
#         self.context = attrs["context"]
#         self.boot_val = attrs["boot_val"]
#         self.enumvals = attrs["enumvals"]
#         self.reset_val = attrs["reset_val"]
#         self.pending_restart = attrs["pending_restart"]


class ValueInt():
    # If you pass anything else for int,
    # Postgres will show that only the following
    # units are acceptable
    VALID_UNITS = {"B", "kB", "MB", "GB", "TB"}

    # Bytes = MB << 20, etc.
    # This looks a bit better and maybe
    # even works more efficiently than
    # Bytes = MB * 1024 * 1024
    UNIT_TO_BYTES_BITWISE_SHIFT = {
        "kB": 10,
        "MB": 20,
        "GB": 30,
        "TB": 40,
    }

    def __init__(self, module, param_name, value, unit):
        self.module = module
        self.unit = unit
        self.value, self.unit = self.__set(param_name, value)
        self.value_in_bytes = self.value << ValueInt.UNIT_TO_BYTES_BITWISE_SHIFT[unit]

    def __set(self, param_name, value):
        return self.__validate(param_name, value)
        # TODO: convert it to the default units here too

    def __validate(self, param_name, value):
        int_part = None
        unit_part = None

        # When the value is like 1024MB
        if len(value) > 2 and value[-2:].isalpha():
            int_part = int(value[:-2])
            unit_part = value[-2:]

        # When the value is like 1024B
        elif len(value) > 1 and value[-1].isalpha():
            int_part = self.__to_int(value[:-2])
            unit_part = value[-1]

        # When it doesn't contain a unit part
        # we set it as the unit defined for this
        # parameter in pg_settings
        else:
            int_part = self.__to_int(value)
            unit_part = self.unit

        if unit_part not in ValueInt.VALID_UNITS:
            val_err_msg = ('invalid value for parameter "%s": "%s", '
                           'Valid units for this parameter '
                           'are %s' % (param_name, value, ', '.join(ValueInt.VALID_UNITS)))
            self.module.fail_json(msg=val_err_msg)

        return (int_part, unit_part)

    def __to_int(self, value):
        try:
            return int(value)
        except Exception:
            val_err_msg = "Value %s cannot be converted to int" % value
            self.module.fail_json(msg=val_err_msg)


# This dict maps vartypes to appropriate classes.
# TODO: Add support for all vartypes (enum, string, bool, integer, real)
# To get a list of supported vartypes for settings in PostgreSQL
# run "SELECT DISTINCT vartype FROM pg_settings;"
VARTYPE_CLASS_MAP = {
    "integer": ValueInt,
}


def build_value_class(module, param_name, value, unit, vartype):
    # This function is a wrapper around
    # the VARTYPE_CLASS_MAP dict for readability.
    # The dict maps vartypes to appropriate classes.
    return VARTYPE_CLASS_MAP[vartype](module, param_name, value, unit)


class PgParam():

    def __init__(self, module, cursor, name):
        self.module = module
        self.cursor = cursor
        self.name = name
        # self.init_value = Value(self.__get_attrs())
        self.init_attrs = self.__get_attrs()[0]
        self.init_value = build_value_class(self.module, self.name,
                                            self.init_attrs["setting"],
                                            self.init_attrs["unit"],
                                            self.init_attrs["vartype"])

    def __get_attrs(self):
        query = ("SELECT setting, unit, context, vartype, enumvals, "
                 "boot_val, reset_val, pending_restart "
                 "FROM pg_settings where name = %s")
        res = self.__exec_sql(query, (self.name,))
        # DEBUG
        return res

    def __exec_sql(self, query, params=()):
        try:
            self.cursor.execute(query, params)
            res = self.cursor.fetchall()
            if res:
                return res
        except Exception as e:
            msg = "Cannot execute SQL '%s': %s" % (query, to_native(e))
            self.module.fail_json(msg=msg)
            self.cursor.close()
        return None


# ===========================================
# Module execution.
#


def main():
    argument_spec = postgres_common_argument_spec()
    argument_spec.update(
        param=dict(type='str', required=True),
        login_db=dict(type='str'),
        value=dict(type='str', required=True),
        pg_reload_conf=dict(type='bool', default=True),
        session_role=dict(type='str'),
        trust_input=dict(type='bool', default=True),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    param = module.params['param']
    value = module.params['value']
    pg_reload_conf = module.params['pg_reload_conf']
    session_role = module.params['session_role']
    trust_input = module.params['trust_input']

    if not trust_input:
        # Check input for potentially dangerous elements:
        check_input(module, param, value, session_role)

    # Ensure psycopg libraries are available before connecting to DB:
    ensure_required_libs(module)
    conn_params = get_conn_params(module, module.params, warn_db_default=False)
    db_connection, dummy = connect_to_db(module, conn_params, autocommit=True)
    cursor = db_connection.cursor(**pg_cursor_args)

    # TODO consider using DIFF to return before-after

    changed = False

    pg_param = PgParam(module, cursor, param)

    # Disconnect
    cursor.close()
    db_connection.close()

    module.exit_json(
        changed=changed,
        # DEBUG below
        attrs=pg_param.init_attrs,
        value_class_value=pg_param.init_value.value,
        value_class_unit=pg_param.init_value.unit,
        value_class_value_in_bytes=pg_param.init_value.value_in_bytes,
    )


if __name__ == '__main__':
    main()
