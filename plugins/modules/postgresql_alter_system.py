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

version_added: '3.13.0'

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
    - Use V(_RESET) to run the C(ALTER SYSTEM RESET param) which will remove
      a corresponding entry from C(postgresql.auto.conf). Always returns C(changed=True).
    - For boolean parameters, pass the V("on") or V("off") string.
    type: str
    required: true

  session_role:
    description:
    - Switch to session_role after connecting. The specified session_role must
      be a role that the current login_user is a member of.
    - Permissions checking for SQL commands is carried out as though
      the O(session_role) were the one that had logged in originally.
    type: str

  login_db:
    description:
    - Name of database to connect.
    type: str

  trust_input:
    description:
    - If V(false), check whether values of parameters are potentially dangerous.
    - It makes sense to use V(false) only when SQL injections are possible.
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
    get_server_version,
    pg_cursor_args,
    postgres_common_argument_spec,
)

executed_queries = []

# As of today, PostgreSQL 13 is the oldest
# officially supported version. Let's start from here
PG_SUPPORTED_VER = 130000

# GUC_LIST_QUOTE parameters list for each version where they changed (from PG_REQ_VER).
# It is a tuple of tuples as we need to iterate it in order.
# TODO it was copied here from postgresql_set. After merge, it should be
# moved to a lib and shared between the modules
PARAMETERS_GUC_LIST_QUOTE = (
    (140000, (
        'local_preload_libraries',
        'search_path',
        'session_preload_libraries',
        'shared_preload_libraries',
        'temp_tablespaces',
        'unix_socket_directories'
    )),
    (90400, (
        'local_preload_libraries',
        'search_path',
        'session_preload_libraries',
        'shared_preload_libraries',
        'temp_tablespaces'
    )),
)


# TODO it was copied here from postgresql_set. After merge, it should be
# moved to a lib and shared between the modules
def param_is_guc_list_quote(server_version, name):
    for guc_list_quote_ver, guc_list_quote_params in PARAMETERS_GUC_LIST_QUOTE:
        if server_version >= guc_list_quote_ver:
            return name in guc_list_quote_params
    return False


# TODO it was copied here from postgresql_set. After merge, it should be
# moved to a lib and shared between the modules
def param_guc_list_unquote(value):
    # Unquote GUC_LIST_QUOTE parameter (each element can be quoted or not)
    # Assume the parameter is GUC_LIST_QUOTE (check in param_is_guc_list_quote function)
    return ', '.join([v.strip('" ') for v in value.split(',')])


def check_pg_version(module, pg_ver):
    if pg_ver < PG_SUPPORTED_VER:
        msg = ("PostgreSQL version %s is supported, but %s is used. "
               "Before filing a bug report, please run your task "
               "on a supported version of PostgreSQL.")
        module.warn(msg)


def check_problematic_params(module, param, value):
    # Due to a bug in PostgreSQL
    if param == 'shared_preload_libraries' and value == '':
        msg = ("Due to a PostgreSQL bug in resetting shared_preload_libraries "
               "with ALTER SYSTEM SET, setting it as an empty string "
               "is not supported by the module to avoid crashes. "
               "Use `value: _RESET` instead. "
               "If you think the bug has been fixed, please let us know.")
        module.fail_json(msg=msg)


class Value(ABC):
    # This anstract class is a blueprint for "real" classes
    # that represent values of certain types.
    # This makes practical sense as we want the classes
    # have same set of parameters to instanciate them
    # in the same manner.
    # If you need to handle parameters of a new type
    # or if you need to handle some combination of vartype
    # and unit differently (like we do it with ValueMem or ValueTime),
    # create another class using this class as parent.

    # To understand why we use this,
    # take a look how the child classes are instanciated
    # in the build_value_class function.
    @abstractmethod
    def __init__(self, module, param_name, value, default_unit, pg_ver):
        pass


class ValueBool(Value):
    """Represents a parameter of type bool."""

    # SELECT * FROM pg_settings WHERE vartype = 'bool'

    def __init__(self, module, param_name, value, default_unit, pg_ver=None):
        # We do not use all the parameters in every class
        # like default_unit, etc., but we need them to instanciate
        # classes in a standard manner
        self.module = module
        self.normalized = self.__normalize(value)

    def __normalize(self, value):
        return normalize_bool_val(value)


class ValueInt(Value):
    """Represents a parameter of type integer.
    Memory- and time-related parameters are handled by dedicated classes.
    """

    # To handle values of the "integer" type with no unit
    # SELECT * FROM pg_settings WHERE vartype = 'integer' and unit IS NULL

    def __init__(self, module, param_name, value, default_unit, pg_ver=None):
        # We do not use all the parameters in every class
        # like default_unit, etc., but we need them to instanciate
        # classes in a standard manner
        self.module = module
        self.normalized = value


class ValueString(Value):
    """Represents a parameter of type string."""

    # SELECT * FROM pg_settings WHERE vartype = 'string'

    def __init__(self, module, param_name, value, default_unit, pg_ver):
        # We do not use all the parameters in every class
        # like default_unit, etc., but we need them to instanciate
        # classes in a standard manner
        self.module = module
        # It typically doesn't need normalization,
        # so accept it as is
        self.normalized = self.__normalize(pg_ver, param_name, value)

    def __normalize(self, pg_ver, param_name, value):
        # Check parameter is GUC_LIST_QUOTE (done once as depend only on server version).
        # These functions were copied here from the postgresql_set module
        is_guc_list_quote = param_is_guc_list_quote(pg_ver, param_name)
        if is_guc_list_quote:
            return param_guc_list_unquote(value)

        return value


class ValueEnum(Value):
    """Represents a parameter of type enum."""

    # SELECT * FROM pg_settings WHERE vartype = 'enum'

    def __init__(self, module, param_name, value, default_unit, pg_ver=None):
        # We do not use all the parameters in every class
        # like default_unit, etc., but we need them to instanciate
        # classes in a standard manner
        self.module = module
        # It typically doesn't need normalization,
        # so accept it as is
        self.normalized = self.__normalize(value)

    def __normalize(self, value):
        return normalize_bool_val(value)


def normalize_bool_val(value):
    # No idea why Ansible converts on/off passed as string
    # to "True" and "False". However, there are represented
    # as "on" and "off" in pg_settings.
    if value == "True":
        return "on"
    elif value == "False":
        return "off"
    else:
        return value


class ValueReal(Value):
    """Represents a parameter of type real."""

    # To handle values of the "real" vartype:
    # SELECT * FROM pg_settings WHERE vartype = 'real'

    def __init__(self, module, param_name, value, default_unit, pg_ver=None):
        # We do not use all the parameters in every class
        # like default_unit, etc., but we need them to instanciate
        # classes in a standard manner
        self.module = module
        self.normalized = self.__normalize(value)

    def __normalize(self, value):
        # Drop the unit part as there's only "ms" or nothing
        if len(value) > 2 and value[-2:].isalpha():
            return value[:-2]

        return value


class ValueTime(Value):
    """Represents a time-related parameter."""

    VALID_UNITS = {"us", "ms", "s", "min", "h", "d"}

    def __init__(self, module, param_name, value, default_unit, pg_ver=None):
        # We do not use all the parameters in every class
        # like default_unit, etc., but we need them to instanciate
        # classes in a standard manner
        self.module = module
        self.default_unit = default_unit
        self.num_value, self.passed_unit = self.__set(param_name, value)
        self.normalized = self.__normalize(self.num_value, self.passed_unit)

    def __normalize(self, num_value, passed_unit):
        value_in_microsecs = None
        # Let's convert num_value to the smallest unit,
        # i.e. to "us" which means microseconds
        if num_value == -1:
            # When disabled, some params have -1 as value
            value_in_microsecs = num_value
        elif passed_unit == "us":
            value_in_microsecs = num_value
        elif passed_unit == "ms":
            value_in_microsecs = num_value * 1000
        elif passed_unit == "s":
            value_in_microsecs = num_value * 1_000_000
        elif passed_unit == "min":
            value_in_microsecs = num_value * 60 * 1_000_000
        elif passed_unit == "h":
            value_in_microsecs = num_value * 60 * 60 * 1_000_000
        elif passed_unit == "d":
            value_in_microsecs = num_value * 24 * 60 * 60 * 1_000_000

        return value_in_microsecs

    def __set(self, param_name, value):
        return self.__validate(param_name, value)

    def __validate(self, param_name, value):
        int_part = None
        unit_part = None

        # When the value is like 1min
        if len(value) > 3 and value[-3:].isalpha():
            int_part = to_int(self.module, value[:-3])
            unit_part = value[-3:]

        # When the value is like 1ms
        elif len(value) > 2 and value[-2:].isalpha():
            int_part = to_int(self.module, value[:-2])
            unit_part = value[-2:]

        # When the value is like 1s
        elif len(value) > 1 and value[-1].isalpha():
            int_part = to_int(self.module, value[:-1])
            unit_part = value[-1]

        # When it doesn't contain a unit part
        # we set it as the unit defined for this
        # parameter in pg_settings
        else:
            int_part = to_int(self.module, value)
            unit_part = self.default_unit

        if unit_part not in ValueTime.VALID_UNITS:
            val_err_msg = ('invalid value for parameter "%s": "%s", '
                           'Valid units for this parameter '
                           'are %s' % (param_name, value, ', '.join(ValueTime.VALID_UNITS)))
            self.module.fail_json(msg=val_err_msg)

        return (int_part, unit_part)


class ValueMem(Value):
    """Represents a memory-related parameter."""
    # If you pass anything else for memory-related param,
    # Postgres will show that only the following
    # units are acceptable
    VALID_UNITS = {"B", "kB", "MB", "GB", "TB"}

    # Bytes = MB << 20, etc.
    # This looks a bit better and maybe
    # even works more efficiently than
    # say Bytes = MB * 1024 * 1024
    UNIT_TO_BYTES_BITWISE_SHIFT = {
        "kB": 10,
        "MB": 20,
        "GB": 30,
        "TB": 40,
    }

    def __init__(self, module, param_name, value, default_unit, pg_ver=None):
        self.module = module
        self.default_unit = default_unit
        self.num_value, self.passed_unit = self.__set(param_name, value)
        if self.passed_unit == "8kB":
            # This is a special case when the unit in pg_settings is "8kB".
            # Users can still pass such values as "10MB", etc.
            # The only issue seems to appear when users don't specify values
            # of 8kB default value explicitly, i.e., when they pass just "100".
            # In this case the self.__validate method will assign its default unit of 8kB
            self.normalized = (self.num_value << ValueMem.UNIT_TO_BYTES_BITWISE_SHIFT["kB"]) * 8
        else:
            self.normalized = self.num_value << ValueMem.UNIT_TO_BYTES_BITWISE_SHIFT[self.passed_unit]

    def __set(self, param_name, value):
        return self.__validate(param_name, value)

    def __validate(self, param_name, value):
        int_part = None
        unit_part = None

        # When the value is like 1024MB
        if len(value) > 2 and value[-2:].isalpha():
            int_part = to_int(self.module, value[:-2])
            unit_part = value[-2:]

        # When the value is like 1024B
        elif len(value) > 1 and value[-1].isalpha():
            int_part = to_int(self.module, value[:-1])
            unit_part = value[-1]

        # When it doesn't contain a unit part
        # we set it as the unit defined for this
        # parameter in pg_settings
        else:
            int_part = to_int(self.module, value)
            unit_part = self.default_unit

        if unit_part not in ValueMem.VALID_UNITS and unit_part != "8kB":
            val_err_msg = ('invalid value for parameter "%s": "%s", '
                           'Valid units for this parameter '
                           'are %s' % (param_name, value, ', '.join(ValueMem.VALID_UNITS)))
            self.module.fail_json(msg=val_err_msg)

        return (int_part, unit_part)


def to_int(module, value):
    """Tries to convert the value to int and
    fail gracefully when unseccess.
    """
    try:
        return int(value)
    except Exception:
        val_err_msg = "Value %s cannot be converted to int" % value
        module.fail_json(msg=val_err_msg)


# Run "SELECT DISTINCT unit FROM pg_settings;"
# and extract memory-related ones
MEM_PARAM_UNITS = {"B", "kB", "8kB", "MB"}


# Run "SELECT DISTINCT unit FROM pg_settings;"
# and extract time-related ones
TIME_PARAM_UNITS = {"min", "s", "ms"}


def build_value_class(module, param_name, value, unit, vartype, pg_ver):
    # Choose a proper Value class based on vartype and/or unit,
    # instanciate it and return the object
    if unit in TIME_PARAM_UNITS:
        return ValueTime(module, param_name, value, unit)

    elif vartype == "integer":
        if unit in MEM_PARAM_UNITS:
            return ValueMem(module, param_name, value, unit)
        else:
            return ValueInt(module, param_name, value, unit)

    elif vartype == "bool":
        return ValueBool(module, param_name, value, unit)

    elif vartype == "real":
        return ValueReal(module, param_name, value, unit)

    elif vartype == "string":
        return ValueString(module, param_name, value, unit, pg_ver)

    elif vartype == "enum":
        return ValueEnum(module, param_name, value, unit)


class PgParam():
    """Represents a postgresql parameter.

    Provides attributes and method for operating
    on a corresponding parameter in the database
    like setting or resetting its value.

    If you're interested in adding other operations,
    add them in this class as methods.

    To represent values of particular types we use
    corresponding classes. For example for booleans
    we use ValueBool and for strings ValueString.
    The build_value_class function returns a proper
    class object based on the vartype column value
    for a particular parameter.
    To get types, run in your PG client
    SELECT DISTINCT vartype FROM pg_settings;

    We can't predict what our users pass, so we need
    some kind of normalization of the values that we
    do in the value classes (not for every kind of parameter).
    """
    def __init__(self, module, cursor, name, pg_ver):
        self.module = module
        self.cursor = cursor
        self.name = name
        self.pg_ver = pg_ver

        self.attrs = self.get_attrs()
        # For some type of context it's impossible
        # to change settings with ALTER SYSTEM and
        # for some service restart is required
        self.__check_param_context(self.attrs["context"])

        # Return a proper value class based on vartype and unit
        # from a pg_settings entry for a specific parameter
        self.init_value = build_value_class(self.module, self.name,
                                            self.attrs["setting"],
                                            self.attrs["unit"],
                                            self.attrs["vartype"],
                                            self.pg_ver)
        # Same object will be instanciated to compare
        # the desired and the current values
        self.desired_value = None

    def set(self, value):
        self.desired_value = build_value_class(self.module, self.name,
                                               value,
                                               self.attrs["unit"],
                                               self.attrs["vartype"],
                                               self.pg_ver)

        # Compare normalized values of the desired and the current
        # values to decide whether we need to do any real job
        if self.desired_value.normalized != self.init_value.normalized:
            if not self.module.check_mode:
                query = self.__construct_alter_system_query(value)
                self.__exec_set_sql(query)
            return True

        return False

    def reset(self):
        # As the value is "_RESET", i.e. a string, and
        # the module always return changed=true, we just instanciate
        # the desired value as if it would be a value of string type
        self.desired_value = ValueString(self.module, self.name,
                                         "_RESET",
                                         self.attrs["unit"],
                                         self.pg_ver)
        # Because the result of running "ALTER SYSTEM RESET param;"
        # is alway a removal of the line from postgresql.auto.conf
        # this will always run the command to ensure the removal
        # and report changed=true
        query = "ALTER SYSTEM RESET %s" % self.name
        self.__exec_set_sql(query)
        return True

    def get_attrs(self):
        query = ("SELECT setting, unit, context, vartype, enumvals, "
                 "boot_val, reset_val, pending_restart "
                 "FROM pg_settings where name = %s")
        executed_queries.append(query % self.name)
        res = self.__exec_sql(query, (self.name,))
        # You can uncomment the line below while debugging
        # to see what DB actually returns for the parameter
        # executed_queries.append(res[0])
        return res[0]

    def __construct_alter_system_query(self, value):
        if isinstance(value, str) and ',' in value and \
                not self.name.endswith(('_command', '_prefix')) and \
                not (self.pg_ver < 140000 and self.name == 'unix_socket_directories'):
            # Issue https://github.com/ansible-collections/community.postgresql/issues/78
            # Change value from 'one, two, three' -> "'one','two','three'"
            # PR https://github.com/ansible-collections/community.postgresql/pull/400
            # Parameter names ends with '_command' or '_prefix'
            # can contains commas but they are not lists
            # PR https://github.com/ansible-collections/community.postgresql/pull/521
            # unix_socket_directories up to PostgreSQL 13 lacks GUC_LIST_INPUT and
            # GUC_LIST_QUOTE options so it is a single value parameter
            tmp = []
            for elem in value.split(','):
                if elem.strip()[0] == '"':
                    # In case like search_path value "$user"
                    # just append it w/o any modufications
                    tmp.append(elem.strip())
                else:
                    tmp.append("'" + elem.strip() + "'")

            query = "ALTER SYSTEM SET %s = %s" % (self.name, ','.join(tmp))

        elif self.pg_ver >= 140000:
            query = "ALTER SYSTEM SET %s = '%s'" % (self.name, value)

        else:
            query = "ALTER SYSTEM SET %s = %s" % (self.name, value)

        return query

    def __check_param_context(self, context):
        if context == "internal":
            msg = ("%s cannot be changed (internal context). "
                   "See https://www.postgresql.org/docs/current/"
                   "runtime-config-preset.html" % self.name)
            self.module.fail_json(msg=msg)

        elif context == "postmaster":
            self.module.warn("Restart of PostgreSQL is required for setting %s" % self.name)

    def __exec_sql(self, query, params=()):
        """Execute a query that is supposed to return something."""
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
        """Execute ALTER SYSTEM kind of queries."""
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

    # There's at least one param that doesn't
    # work well with ALTER SYSTEM SET.
    # Add more to this function if you see any
    check_problematic_params(module, param, value)

    if not trust_input:
        # Check input for potentially dangerous elements
        check_input(module, param, value, session_role)

    # Ensure psycopg libraries are available before connecting to DB
    ensure_required_libs(module)
    conn_params = get_conn_params(module, module.params, warn_db_default=False)
    db_connection, dummy = connect_to_db(module, conn_params, autocommit=True)
    cursor = db_connection.cursor(**pg_cursor_args)

    # Get and check server version
    pg_ver = get_server_version(db_connection)
    check_pg_version(module, pg_ver)

    # We assume nothing has changed by default
    changed = False

    # Instanciate the object
    pg_param = PgParam(module, cursor, param, pg_ver)

    # Whe we need to reset the value by running
    # "ALTER SYSTEM RESET param;".
    # setting up a regular value first
    if value == "_RESET":
        changed = pg_param.reset()

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
    pg_param_after = PgParam(module, cursor, param, pg_ver)

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
        # DEBUG below. Uncomment it while debugging if needed
        # value_class_value=pg_param.init_value.num_value,
        # value_class_unit=pg_param.init_value.passed_unit,
        value_class_normalized=pg_param.init_value.normalized,
        # desir_class_value=pg_param.desired_value.num_value,
        # desir_class_unit=pg_param.desired_value.passed_unit,
        desir_class_normalized=pg_param.desired_value.normalized,
    )


if __name__ == '__main__':
    main()
