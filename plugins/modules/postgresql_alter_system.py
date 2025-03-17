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
    - For memory-related parameters of type integer, it is C(kB), C(MB), C(GB), and C(TB).
    - Use C(_DEFAULT) to remove a parameter string from postgresql.auto.conf
      by running C(ALTER SYSTEM SET param = DEFAULT); always returns I(changed=true).
    - Use C(_RESET) to restore the parameter to its initial state (boot_val)
      by running C(ALTER SYSTEM RESET param); always returns I(changed=true).
    - For boolean parameters, pass the C("on") or C("off") string.
    type: str
    required: true

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
    value: _RESET

- name: Set work_mem as DEFAULT
  community.postgresql.postgresql_alter_system:
    param: work_mem
    value: _DEFAULT

- name: Set TimeZone parameter (careful, case sensitive)
  community.postgresql.postgresql_alter_system:
    param: TimeZone
    value: 'Europe/Paris'
'''

RETURN = r'''
diff:
  description:
  - A dictionary the C(before) and C(after) keys.
  - Each key contains a dictionary of key-value pairs
    representing some columns and values for the parameter
    obtained from the pg_settings relation.
  returned: success
  type: dict
  sample: {
    'before': {
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
    },
    'after': {
        'name': 'work_mem',
        'setting': 8192,
        'unit': 'kB',
        'context': 'user',
        'vartype': 'integer',
        'min_val': 64,
        'max_val': 2147483647,
        'boot_val': 4096,
        'reset_val': 4096,
        'pending_restart': false,
    }
  }

executed_queries:
  description:
  - List of executed queries except SELECTs.
  returned: success
  type: list
  elements: str
  sample: ["ALTER SYSTEM SET shared_preload_libraries = ''"]

restart_required:
  description:
  - Indicates if restart of PostgreSQL is required or not.
  - Can be also determined from
    the diff["after"]["pending_restart"] return value.
  returned: success
  type: bool
  sample: true
'''

from abc import ABC, abstractmethod

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


class Value(ABC):
    # TODO write comprehensive dos
    # TODO Write an algorithms of how to add new value type support
    # This anstract class is a blueprint for "real" classes
    # that represent values of certain types.
    # This makes practical sense as we want the classes
    # have same set of parameters to instanciate them
    # in the same manner.

    @abstractmethod
    def __init__(self, module, param_name, value, default_unit):
        pass


class ValueBool(Value):
    VALID_UNITS = {'on', 'off'}

    def __init__(self, module, param_name, value, default_unit):
        self.module = module
        self.default_unit = None  # TODO Evaluate later if you need it
        self.__validate(param_name, value)
        self.normalized = value

    def __validate(self, param_name, value):
        if value not in ValueBool.VALID_UNITS:
            val_err_msg = ('invalid value for parameter "%s": "%s", '
                           'Valid units for this parameter '
                           'are %s' % (param_name, value, ', '.join(ValueBool.VALID_UNITS)))
            self.module.fail_json(msg=val_err_msg)


class ValueMem(Value):
    # If you pass anything else for memory-related param,
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

    def __init__(self, module, param_name, value, default_unit):
        self.module = module
        self.default_unit = default_unit  # TODO evaluate later if you need it
        self.num_value, self.passed_unit = self.__set(param_name, value)
        self.normalized = self.num_value << ValueMem.UNIT_TO_BYTES_BITWISE_SHIFT[self.passed_unit]

    def __set(self, param_name, value):
        return self.__validate(param_name, value)

    def __validate(self, param_name, value):
        int_part = None
        unit_part = None

        # When the value is like 1024MB
        if len(value) > 2 and value[-2:].isalpha():
            int_part = int(value[:-2])
            unit_part = value[-2:]

        # When the value is like 1024B
        elif len(value) > 1 and value[-1].isalpha():
            int_part = self.__to_int(value[:-1])
            unit_part = value[-1]

        # When it doesn't contain a unit part
        # we set it as the unit defined for this
        # parameter in pg_settings
        else:
            int_part = self.__to_int(value)
            unit_part = self.default_unit

        if unit_part not in ValueMem.VALID_UNITS:
            val_err_msg = ('invalid value for parameter "%s": "%s", '
                           'Valid units for this parameter '
                           'are %s' % (param_name, value, ', '.join(ValueMem.VALID_UNITS)))
            self.module.fail_json(msg=val_err_msg)

        return (int_part, unit_part)

    def __to_int(self, value):
        try:
            return int(value)
        except Exception:
            val_err_msg = "Value %s cannot be converted to int" % value
            self.module.fail_json(msg=val_err_msg)


# Run "SELECT DISTINCT unit FROM pg_settings;"
# and extract memory-related ones
# TODO handle that 8kB-pages case later
MEM_PARAM_UNITS = {"B", "kB", "MB"}


def build_value_class(module, param_name, value, unit, vartype):
    tmp = vartype  # Will probably get handy later
    if vartype == 'integer':
        if unit in MEM_PARAM_UNITS:
            return ValueMem(module, param_name, value, unit)
        else:
            # TODO change it to a specific case
            return ValueMem(module, param_name, value, unit)
    elif vartype == 'bool':
        return ValueBool(module, param_name, value, unit)


class PgParam():

    def __init__(self, module, cursor, name):
        self.module = module
        self.cursor = cursor
        self.name = name

        self.attrs = self.get_attrs()
        # For some type of context it's impossible
        # to change settings with ALTER SYSTEM and
        # for some service restart is required
        self.__check_param_context(self.attrs["context"])

        self.init_value = build_value_class(self.module, self.name,
                                            self.attrs["setting"],
                                            self.attrs["unit"],
                                            self.attrs["vartype"])
        self.desired_value = None  # TODO remove this after debugging

    def set(self, value):
        # TODO handle _RESET here
        # TODO remove "self" from desired_value after debugging
        self.desired_value = build_value_class(self.module, self.name,
                                               value,
                                               self.attrs["unit"],
                                               self.attrs["vartype"])

        if self.desired_value.normalized != self.init_value.normalized:
            if not self.module.check_mode:
                # TODO: Do the work here
                # TODO: the following query works on PG Ver >= 14
                query = "ALTER SYSTEM SET %s = '%s'" % (self.name, value)
                self.__exec_set_sql(query)

            return True

        return False

    def set_to_default(self):
        # Because the result of running "ALTER SYSTEM SET param = DEFAULT;"
        # is alway removal of the line from postgresql.auto.conf
        # this will always run the command to ensure the removal
        # and report changed=true
        # TODO finish this after completing setting up a regular value.
        query = "ALTER SYSTEM SET %s = DEFAULT" % self.name
        self.__exec_set_sql(query)
        return True

    def get_attrs(self):
        query = ("SELECT setting, unit, context, vartype, enumvals, "
                 "boot_val, reset_val, pending_restart "
                 "FROM pg_settings where name = %s")
        executed_queries.append(query % self.name)
        res = self.__exec_sql(query, (self.name,))
        executed_queries.append(res[0])  # TODO remove this DEBUG
        return res[0]

    def __check_param_context(self, context):
        if context == "internal":
            msg = ("%s cannot be changed (internal context). "
                   "See https://www.postgresql.org/docs/current/"
                   "runtime-config-preset.html" % self.name)
            self.module.fail_json(msg=msg)

        elif context == "postmaster":
            self.module.warn("Restart of PostgreSQL is required for setting %s" % self.name)

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

    def __exec_set_sql(self, query):
        try:
            executed_queries.append(query)
            self.cursor.execute(query)
        except Exception as e:
            self.module.fail_json(msg="Cannot set %s: %s" % (self.name, to_native(e)))

        try:
            query = "SELECT pg_reload_conf()"
            executed_queries.append(query)
            self.cursor.execute(query)
        except Exception as e:
            self.module.fail_json(msg="Cannot run 'SELECT pg_reload_conf()': %s" % to_native(e))


# ===========================================
# Module execution.
#

def main():
    argument_spec = postgres_common_argument_spec()
    argument_spec.update(
        param=dict(type='str', required=True),
        login_db=dict(type='str'),
        value=dict(type='str', required=True),
        session_role=dict(type='str'),
        trust_input=dict(type='bool', default=True),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    param = module.params['param']
    value = module.params['value']
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

    # We assume nothing has changed by default
    changed = False

    # Instanciate the object
    pg_param = PgParam(module, cursor, param)

    # When we need to remove the corresponding line
    # from postgresql.auto.conf by running
    # "ALTER SYSTEM SET param = DEFAULT;"
    # we run it and always report changed=true
    # TODO Implement it after finishing
    # setting up a regular value first
    if value == "_DEFAULT":
        changed = pg_param.set_to_default()

    # Whe we need to reset the value by running
    # "ALTER SYSTEM RESET param;".
    # TODO Read more about it
    # TODO Implement it after finishing
    # setting up a regular value first
    elif value == "_RESET":
        # TODO implement
        pass

    # This is the default case when we need to run
    # "ALTER SYSTEM SET param = 'value';",
    # i.e., it's not the above cases
    else:
        changed = pg_param.set(value)

    # Fetch info again to get diff.
    # It doesn't see the changes w/o reconnect
    cursor.close()
    db_connection.close()
    db_connection, dummy = connect_to_db(module, conn_params, autocommit=True)
    cursor = db_connection.cursor(**pg_cursor_args)
    # Instantiate another object to get the latest attrs
    pg_param_after = PgParam(module, cursor, param)

    # Make sure if there any difference between
    # the attrs in the diff, report changed
    changed = pg_param.attrs != pg_param_after.attrs or changed

    # Disconnect
    cursor.close()
    db_connection.close()

    # Populate diff
    diff = {
        "before": pg_param.attrs,
        "after": pg_param_after.attrs,
    }

    module.exit_json(
        changed=changed,
        executed_queries=executed_queries,
        diff=diff,
        restart_required=pg_param_after.attrs["pending_restart"],
        # DEBUG below
        value_class_value=pg_param.init_value.num_value,
        value_class_unit=pg_param.init_value.passed_unit,
        value_class_normalized=pg_param.init_value.normalized,
        desir_class_value=pg_param.desired_value.num_value,
        desir_class_unit=pg_param.desired_value.passed_unit,
        desir_class_normalized=pg_param.desired_value.normalized,
    )


if __name__ == '__main__':
    main()
