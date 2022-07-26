#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018-2020 Andrew Klychkov (@Andersson007) <aaklychkov@mail.ru>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: postgresql_ping
short_description: Check remote PostgreSQL server availability
description:
- Simple module to check remote PostgreSQL server availability.
options:
  db:
    description:
    - Name of a database to connect to.
    type: str
    aliases:
    - login_db
  session_role:
    description:
    - Switch to session_role after connecting. The specified session_role must
      be a role that the current login_user is a member of.
    - Permissions checking for SQL commands is carried out as though
      the session_role were the one that had logged in originally.
    type: str
    version_added: '0.2.0'
  trust_input:
    description:
    - If C(no), check whether a value of I(session_role) is potentially dangerous.
    - It makes sense to use C(no) only when SQL injections via I(session_role) are possible.
    type: bool
    default: yes
    version_added: '0.2.0'
seealso:
- module: community.postgresql.postgresql_info
author:
- Andrew Klychkov (@Andersson007)
extends_documentation_fragment:
- community.postgresql.postgres
notes:
- Supports C(check_mode).
'''

EXAMPLES = r'''
# PostgreSQL ping dbsrv server from the shell:
# ansible dbsrv -m postgresql_ping

# In the example below you need to generate certificates previously.
# See https://www.postgresql.org/docs/current/libpq-ssl.html for more information.
- name: >
    Ping PostgreSQL server using non-default credentials and SSL
    registering the return values into the result variable for future use
  community.postgresql.postgresql_ping:
    db: protected_db
    login_host: dbsrv
    login_user: secret
    login_password: secret_pass
    ca_cert: /root/root.crt
    ssl_mode: verify-full
  register: result
  # If you need to fail when the server is not available,
  # uncomment the following line:
  #failed_when: not result.is_available

# You can use the registered result with another task
- name: This task should be executed only if the server is available
  # ...
  when: result.is_available == yes
'''

RETURN = r'''
is_available:
  description: PostgreSQL server availability.
  returned: always
  type: bool
  sample: true
server_version:
  description: PostgreSQL server version.
  returned: always
  type: dict
  sample: { major: 13, minor: 2, full: '13.2', raw: 'PostgreSQL 13.2 on x86_64-pc-linux-gnu' }
conn_err_msg:
  description: Connection error message.
  returned: always
  type: str
  sample: ''
  version_added: 1.7.0
'''

import re

try:
    from psycopg2.extras import DictCursor
except ImportError:
    # psycopg2 is checked by connect_to_db()
    # from ansible.module_utils.postgres
    pass

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.postgresql.plugins.module_utils.database import (
    check_input,
)
from ansible_collections.community.postgresql.plugins.module_utils.postgres import (
    connect_to_db,
    exec_sql,
    ensure_required_libs,
    get_conn_params,
    postgres_common_argument_spec,
)


# ===========================================
# PostgreSQL module specific support methods.
#


class PgPing(object):
    def __init__(self, module, cursor):
        self.module = module
        self.cursor = cursor
        self.is_available = False
        self.version = {}

    def do(self):
        self.get_pg_version()
        return (self.is_available, self.version)

    def get_pg_version(self):
        query = "SELECT version()"
        raw = exec_sql(self, query, add_to_executed=False)[0][0]

        if not raw:
            return

        self.is_available = True

        full = raw.split()[1]
        m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", full)

        major = int(m.group(1))
        minor = int(m.group(2))
        patch = None
        if m.group(3) is not None:
            patch = int(m.group(3))

        self.version = dict(
            major=major,
            minor=minor,
            full=full,
            raw=raw,
        )

        if patch is not None:
            self.version['patch'] = patch


# ===========================================
# Module execution.
#


def main():
    argument_spec = postgres_common_argument_spec()
    argument_spec.update(
        db=dict(type='str', aliases=['login_db']),
        session_role=dict(type='str'),
        trust_input=dict(type='bool', default=True),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    if not module.params['trust_input']:
        # Check input for potentially dangerous elements:
        check_input(module, module.params['session_role'])

    # Set some default values:
    cursor = False
    db_connection = False
    result = dict(
        changed=False,
        is_available=False,
        server_version=dict(),
        conn_err_msg='',
    )

    # Ensure psycopg2 libraries are available before connecting to DB:
    ensure_required_libs(module)
    conn_params = get_conn_params(module, module.params, warn_db_default=False)
    db_connection, err = connect_to_db(module, conn_params, fail_on_conn=False)
    if err:
        result['conn_err_msg'] = err

    if db_connection is not None:
        cursor = db_connection.cursor(cursor_factory=DictCursor)

    # Do job:
    pg_ping = PgPing(module, cursor)
    if cursor:
        # If connection established:
        result["is_available"], result["server_version"] = pg_ping.do()
        db_connection.rollback()

    module.exit_json(**result)


if __name__ == '__main__':
    main()
