#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Andrew Klychkov (@Andersson007) <andrew.a.klychkov@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: postgresql_user_obj_stat_info
short_description: Gather statistics about PostgreSQL user objects
description:
- Gathers statistics about PostgreSQL user objects.
version_added: '0.2.0'
options:
  filter:
    description:
    - Limit the collected information by comma separated string or YAML list.
    - Allowable values are C(functions), C(indexes), C(tables).
    - By default, collects all subsets.
    - Unsupported values are ignored.
    type: list
    elements: str
  schema:
    description:
    - Restrict the output by certain schema.
    type: str
  login_db:
    description:
    - Name of database to connect.
    type: str
    aliases:
    - db
  session_role:
    description:
    - Switch to session_role after connecting. The specified session_role must
      be a role that the current login_user is a member of.
    - Permissions checking for SQL commands is carried out as though
      the session_role were the one that had logged in originally.
    type: str
  trust_input:
    description:
    - If C(false), check the value of I(session_role) is potentially dangerous.
    - It makes sense to use C(false) only when SQL injections via I(session_role) are possible.
    type: bool
    default: true
    version_added: '0.2.0'

notes:
- C(size) and C(total_size) returned values are presented in bytes.
- For tracking function statistics the PostgreSQL C(track_functions) parameter must be enabled.
  See U(https://www.postgresql.org/docs/current/runtime-config-statistics.html) for more information.

attributes:
  check_mode:
    support: full

seealso:
- module: community.postgresql.postgresql_info
- module: community.postgresql.postgresql_ping
- name: PostgreSQL statistics collector reference
  description: Complete reference of the PostgreSQL statistics collector documentation.
  link: https://www.postgresql.org/docs/current/monitoring-stats.html
author:
- Andrew Klychkov (@Andersson007)
- Thomas O'Donnell (@andytom)
extends_documentation_fragment:
- community.postgresql.postgres
'''

EXAMPLES = r'''
- name: Collect information about all supported user objects of the acme database
  community.postgresql.postgresql_user_obj_stat_info:
    login_db: acme

- name: Collect information about all supported user objects in the custom schema of the acme database
  community.postgresql.postgresql_user_obj_stat_info:
    login_db: acme
    schema: custom

- name: Collect information about user tables and indexes in the acme database
  community.postgresql.postgresql_user_obj_stat_info:
    login_db: acme
    filter: tables, indexes
'''

RETURN = r'''
indexes:
  description: User index statistics.
  returned: success
  type: dict
  sample: {"public": {"test_id_idx": {"idx_scan": 0, "idx_tup_fetch": 0, "idx_tup_read": 0, "relname": "test", "size": 8192, ...}}}
tables:
  description: User table statistics.
  returned: success
  type: dict
  sample: {"public": {"test": {"analyze_count": 3, "n_dead_tup": 0, "n_live_tup": 0, "seq_scan": 2, "size": 0, "total_size": 8192, ...}}}
functions:
  description: User function statistics.
  returned: success
  type: dict
  sample: {"public": {"inc": {"calls": 1, "funcid": 26722, "self_time": 0.23, "total_time": 0.23}}}
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six import iteritems
from ansible_collections.community.postgresql.plugins.module_utils.database import \
    check_input
from ansible_collections.community.postgresql.plugins.module_utils.postgres import (
    connect_to_db,
    ensure_required_libs,
    exec_sql,
    get_conn_params,
    pg_cursor_args,
    postgres_common_argument_spec,
)

# ===========================================
# PostgreSQL module specific support methods.
#


class PgUserObjStatInfo():
    """Class to collect information about PostgreSQL user objects.

    Args:
        module (AnsibleModule): Object of AnsibleModule class.
        cursor (cursor): Cursor object of psycopg library to work with PostgreSQL.

    Attributes:
        module (AnsibleModule): Object of AnsibleModule class.
        cursor (cursor): Cursor object of psycopg library to work with PostgreSQL.
        executed_queries (list): List of executed queries.
        info (dict): Statistics dictionary.
        obj_func_mapping (dict): Mapping of object types to corresponding functions.
        schema (str): Name of a schema to restrict stat collecting.
    """

    def __init__(self, module, cursor):
        self.module = module
        self.cursor = cursor
        self.info = {
            'functions': {},
            'indexes': {},
            'tables': {},
        }
        self.obj_func_mapping = {
            'functions': self.get_func_stat,
            'indexes': self.get_idx_stat,
            'tables': self.get_tbl_stat,
        }
        self.schema = None

    def collect(self, filter_=None, schema=None):
        """Collect statistics information of user objects.

        Kwargs:
            filter_ (list): List of subsets which need to be collected.
            schema (str): Restrict stat collecting by certain schema.

        Returns:
            ``self.info``.
        """
        if schema:
            self.set_schema(schema)

        if filter_:
            for obj_type in filter_:
                obj_type = obj_type.strip()
                obj_func = self.obj_func_mapping.get(obj_type)

                if obj_func is not None:
                    obj_func()
                else:
                    self.module.warn("Unknown filter option '%s'" % obj_type)

        else:
            for obj_func in self.obj_func_mapping.values():
                obj_func()

        return self.info

    def get_func_stat(self):
        """Get function statistics and fill out self.info dictionary."""
        query = "SELECT * FROM pg_stat_user_functions"
        qp = None
        if self.schema:
            query = "SELECT * FROM pg_stat_user_functions WHERE schemaname = %s"
            qp = (self.schema,)

        result = exec_sql(self, query, query_params=qp, add_to_executed=False)

        if not result:
            return

        self.__fill_out_info(result,
                             info_key='functions',
                             schema_key='schemaname',
                             name_key='funcname')

    def get_idx_stat(self):
        """Get index statistics and fill out self.info dictionary."""
        query = "SELECT * FROM pg_stat_user_indexes"
        qp = None
        if self.schema:
            query = "SELECT * FROM pg_stat_user_indexes WHERE schemaname = %s"
            qp = (self.schema,)

        result = exec_sql(self, query, query_params=qp, add_to_executed=False)

        if not result:
            return

        self.__fill_out_info(result,
                             info_key='indexes',
                             schema_key='schemaname',
                             name_key='indexrelname')

    def get_tbl_stat(self):
        """Get table statistics and fill out self.info dictionary."""
        query = "SELECT * FROM pg_stat_user_tables"
        qp = None
        if self.schema:
            query = "SELECT * FROM pg_stat_user_tables WHERE schemaname = %s"
            qp = (self.schema,)

        result = exec_sql(self, query, query_params=qp, add_to_executed=False)

        if not result:
            return

        self.__fill_out_info(result,
                             info_key='tables',
                             schema_key='schemaname',
                             name_key='relname')

    def __fill_out_info(self, result, info_key=None, schema_key=None, name_key=None):
        # Convert result to list of dicts to handle it easier:
        result = [dict(row) for row in result]

        for elem in result:
            # Add schema name as a key if not presented:
            if not self.info[info_key].get(elem[schema_key]):
                self.info[info_key][elem[schema_key]] = {}

            # Add object name key as a subkey
            # (they must be uniq over a schema, so no need additional checks):
            self.info[info_key][elem[schema_key]][elem[name_key]] = {}

            # Add other other attributes to a certain index:
            for key, val in iteritems(elem):
                if key not in (schema_key, name_key):
                    self.info[info_key][elem[schema_key]][elem[name_key]][key] = val

            if info_key in ('tables', 'indexes'):
                schemaname = elem[schema_key]
                if self.schema:
                    schemaname = self.schema

                relname = '%s.%s' % (schemaname, elem[name_key])

                result = exec_sql(self, "SELECT pg_relation_size (%s)",
                                  query_params=(relname,),
                                  add_to_executed=False)

                self.info[info_key][elem[schema_key]][elem[name_key]]['size'] = result[0]["pg_relation_size"]

                if info_key == 'tables':
                    result = exec_sql(self, "SELECT pg_total_relation_size (%s)",
                                      query_params=(relname,),
                                      add_to_executed=False)

                    self.info[info_key][elem[schema_key]][elem[name_key]]['total_size'] = result[0]["pg_total_relation_size"]

    def set_schema(self, schema):
        """If schema exists, sets self.schema, otherwise fails."""
        query = ("SELECT 1 as schema_exists FROM information_schema.schemata "
                 "WHERE schema_name = %s")
        result = exec_sql(self, query, query_params=(schema,),
                          add_to_executed=False)

        if result and result[0]["schema_exists"]:
            self.schema = schema
        else:
            self.module.fail_json(msg="Schema '%s' does not exist" % (schema))


# ===========================================
# Module execution.
#

def main():
    argument_spec = postgres_common_argument_spec()
    argument_spec.update(
        login_db=dict(type='str', aliases=['db'], deprecated_aliases=[
            {
                'name': 'db',
                'version': '5.0.0',
                'collection_name': 'community.postgresql',
            }],
        ),
        filter=dict(type='list', elements='str'),
        session_role=dict(type='str'),
        schema=dict(type='str'),
        trust_input=dict(type="bool", default=True),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    filter_ = module.params["filter"]
    schema = module.params["schema"]

    if not module.params["trust_input"]:
        check_input(module, module.params['session_role'])

    # Ensure psycopg libraries are available before connecting to DB:
    ensure_required_libs(module)
    # Connect to DB and make cursor object:
    pg_conn_params = get_conn_params(module, module.params)
    # We don't need to commit anything, so, set it to False:
    db_connection, dummy = connect_to_db(module, pg_conn_params, autocommit=False)
    cursor = db_connection.cursor(**pg_cursor_args)

    ############################
    # Create object and do work:
    pg_obj_info = PgUserObjStatInfo(module, cursor)

    info_dict = pg_obj_info.collect(filter_, schema)

    # Clean up:
    cursor.close()
    db_connection.close()

    # Return information:
    module.exit_json(**info_dict)


if __name__ == '__main__':
    main()
