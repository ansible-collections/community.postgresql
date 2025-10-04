#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Aly Ghobashy (@gebz97) <gebz97@proton.me>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
name: postgresql_lookup
short_description: Retrieve data from PostgreSQL database
author: Aly Ghobashy (@gebz97)
description:
  - This lookup returns data from a PostgreSQL database.
options:
  host:
    description: Host running the database.
    type: string
    default: localhost
  port:
    description: Database port to connect to.
    type: integer
    default: 5432
  db:
    description: Name of database to connect to.
    type: string
    required: true
  user:
    description: The username to authenticate with.
    type: string
    default: postgres
  password:
    description: The password to authenticate with.
    type: string
    required: true
  ssl_mode:
    description: SSL mode for the connection.
    type: string
    default: disable
    choices: ['allow', 'disable', 'prefer', 'require', 'verify-ca', 'verify-full']
"""


from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display
from ansible_collections.community.postgresql.plugins.module_utils.version import (
    LooseVersion,
)

psycopg = None  # This line is needed for unit tests
psycopg2 = None  # This line is needed for unit tests
pg_cursor_args = None  # This line is needed for unit tests
PSYCOPG_VERSION = LooseVersion("0.0")  # This line is needed for unit tests

try:
    import psycopg

    # We need Psycopg 3 to be at least 3.1.0 because we need Client-side-binding cursors
    # When a Linux distribution provides both Psycopg2 and Psycopg 3.0 we will use Psycopg2
    PSYCOPG_VERSION = LooseVersion(psycopg.__version__)
    if PSYCOPG_VERSION < LooseVersion("3.1"):
        raise ImportError
    HAS_PSYCOPG = True
    pg_cursor_args = {"row_factory": psycopg.rows.dict_row}
except ImportError:
    try:
        import psycopg2

        psycopg = psycopg2
        from psycopg2.extras import DictCursor

        PSYCOPG_VERSION = LooseVersion(psycopg2.__version__)
        HAS_PSYCOPG = True
        pg_cursor_args = {"cursor_factory": DictCursor}
    except ImportError:
        HAS_PSYCOPG = False


display = Display()


class LookupModule(LookupBase):
    NAME = "community.postgresql.postgresql_lookup"

    def run(self, terms, variables=None, **kwargs):
        # Set and retrieve configuration options
        self.set_options(var_options=variables, direct=kwargs)

        ret = []

        try:
            # Establish database connection using options
            db_conn = psycopg.connect(
                host=self.get_option("host"),
                port=self.get_option("port", 5432),
                dbname=self.get_option("db"),
                user=self.get_option("user"),
                password=self.get_option("password"),
            )

            cursor = db_conn.cursor()

            # Execute each query provided in 'terms'
            for query in terms:
                display.vvvv(f"PostgreSQL lookup executing query: {query}")
                cursor.execute(query)

                # Handle query results
                if cursor.description is not None:  # Returns data
                    results = cursor.fetchall()
                    # Single column? Return simple list. Multiple columns? Return list of dictionaries.
                    if len(cursor.description) == 1:
                        ret.extend([row[0] for row in results])
                    else:
                        columns = [desc[0] for desc in cursor.description]
                        ret.extend([dict(zip(columns, row)) for row in results])
                else:  # No data returned (e.g., INSERT/UPDATE)
                    ret.append({"rows_affected": cursor.rowcount})

            cursor.close()
            db_conn.close()

        except Exception as e:
            raise AnsibleError(f"PostgreSQL lookup error: {str(e)}")

        return ret
