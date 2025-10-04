# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Aly Ghobashy (@gebz97) <gebz97@proton.me>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
name: postgresql_inventory
short_description: PostgreSQL backed dynamic inventory
author: Aly Ghobashy (@gebz97)
description:
    - Fetch inventory hosts from a PostgreSQL database.
options:
    plugin:
        description: Token that ensures this is a source file for the plugin.
        required: true
        type: str
        choices: ['community.postgresql.postgresql_inventory']
    dsn:
        description: PostgreSQL connection string (DSN)
        required: false
        type: str
    db_host:
        description: PostgreSQL host
        required: false
        type: str
    db_port:
        description: PostgreSQL port
        required: false
        type: int
        default: 5432
    db_name:
        description: PostgreSQL database name
        required: false
        type: str
    db_user:
        description: PostgreSQL username
        required: false
        type: str
    db_password:
        description: PostgreSQL password
        required: false
        type: str
    query:
        description: |
            SQL query returning hostname, groups, ansible_host, and host_vars.
            Expected columns:
            - hostname (text): inventory hostname
            - groups (text[] or text): array or comma-separated list of groups
            - ansible_host (text, optional): connection hostname/IP
            - host_vars (json, text[], or text, optional): host variables in JSON, array, or string format
        required: true
        type: str
    cache:
        description: Enable caching
        required: false
        type: bool
        default: false
"""

EXAMPLES = r"""
# Example using DSN
plugin: community.postgresql.postgresql_inventory
dsn: postgresql://user:password@localhost:5432/mydb
query: SELECT hostname, groups, ansible_host, host_vars FROM inventory

# Example using individual parameters
plugin: community.postgresql.postgresql_inventory
db_host: localhost
db_port: 5432
db_name: mydb
db_user: myuser
db_password: mypassword
query: SELECT hostname, groups FROM servers
"""

from ansible.plugins.inventory import BaseFileInventoryPlugin, Constructable, Cacheable
from ansible.errors import AnsibleError, AnsibleParserError
from ansible_collections.community.postgresql.plugins.module_utils.version import (
    LooseVersion,
)
import json

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


class InventoryModule(BaseFileInventoryPlugin, Constructable, Cacheable):
    NAME = "community.postgresql.postgresql_inventory"

    def __init__(self):
        super().__init__()
        self._spec = {
            "plugin": {
                "required": True,
                "type": "str",
                "choices": ["community.postgresql.postgresql_inventory"],
            },
            "dsn": {"required": False, "type": "str", "default": None},
            "db_host": {"required": False, "type": "str"},
            "db_port": {"required": False, "type": "int", "default": 5432},
            "db_name": {"required": False, "type": "str"},
            "db_user": {"required": False, "type": "str"},
            "db_password": {"required": False, "type": "str"},
            "query": {"required": True, "type": "str"},
            "cache": {"required": False, "type": "bool", "default": False},
        }
        self._options = {}
        self._origins = {}

    def get_options(self):
        return self._spec

    def set_options(self, direct=None, **kwargs):
        super().set_options(direct=direct, **kwargs)
        if direct:
            for k, v in direct.items():
                self._options[k] = v
        # Ensure all spec keys exist in _options
        for key, spec in self.get_options().items():
            if key not in self._options:
                self._options[key] = spec.get("default", None)

    def set_option(self, option, value):
        # Intercept custom "cache" (and any others that the base config manager might reject)
        if option == 'cache':
            self._options["cache"] = value
        else:
            super().set_option(option, value)

    def parse(self, inventory, loader, path, cache=True):
        super().parse(inventory, loader, path, cache)
        self._read_config_data(path)
        try:
            self.set_options(direct=self.config)
        except AttributeError:
            pass  # tests may stub _read_config_data without setting .config

        cache_enabled = self.get_option("cache") or cache
        self.set_option("cache", cache_enabled)

        inventory_data = self._fetch_inventory_data()
        self._process_inventory_data(inventory_data)

    def _get_connection(self):
        dsn = self.get_option("dsn")
        if dsn:
            return psycopg.connect(dsn)

        db_host = self.get_option("db_host")
        db_port = self.get_option("db_port")
        db_name = self.get_option("db_name")
        db_user = self.get_option("db_user")
        db_password = self.get_option("db_password")

        if not all([db_host, db_name, db_user, db_password]):
            raise AnsibleParserError(
                "Either 'dsn' or all of 'db_host', 'db_name', 'db_user', 'db_password' must be provided"
            )

        return psycopg.connect(
            host=db_host,
            port=db_port,
            dbname=db_name,
            user=db_user,
            password=db_password,
        )

    def verify_file(self, path):
        if not path.endswith(("pg_inv.yml", "pg_inv.yaml")):
            return False
        return super().verify_file(path)

    def _execute_query(self, query, cache_key=None):
        if cache_key and self.get_option("cache"):
            cached = self._get_cache_data(cache_key)
            if cached is not None:
                return cached

        try:
            with self._get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(query)
                    result = cur.fetchall()

                    if cache_key and self.get_option("cache"):
                        self._set_cache_data(cache_key, result)

                    return result
        except Exception as e:
            raise AnsibleError(f"Database query failed: {e}")

    def _get_cache_data(self, cache_key):
        try:
            return self._cache[cache_key]
        except (KeyError, AttributeError):
            return None

    def _set_cache_data(self, cache_key, data):
        if not hasattr(self, "_cache"):
            self._cache = {}
        self._cache[cache_key] = data

    def _fetch_inventory_data(self):
        query = self.get_option("query")
        if not query:
            raise AnsibleParserError("The 'query' option is required")
        return self._execute_query(query, "inventory")

    def _process_inventory_data(self, inventory_data):
        for row in inventory_data:
            self._process_inventory_row(row)

    def _process_inventory_row(self, row):
        if len(row) < 2:
            raise AnsibleError(
                f"Invalid row format: expected at least 2 columns, got {len(row)}"
            )

        hostname = row[0]
        groups = row[1] if row[1] is not None else []
        ansible_host = row[2] if len(row) > 2 and row[2] is not None else None
        host_vars = row[3] if len(row) > 3 and row[3] is not None else None

        self.inventory.add_host(hostname)
        self._add_host_to_groups(hostname, groups)

        if ansible_host:
            self.inventory.set_variable(hostname, "ansible_host", ansible_host)

        if host_vars is not None:
            self._process_host_vars(hostname, host_vars)

    def _add_host_to_groups(self, hostname, groups):
        if not groups:
            return

        if isinstance(groups, str):
            group_names = [g.strip() for g in groups.split(",") if g.strip()]
        elif isinstance(groups, (list, tuple)):
            group_names = []
            for g in groups:
                try:
                    g_str = str(g).strip()
                except Exception:
                    continue
                if g_str:
                    group_names.append(g_str)
        else:
            try:
                group_names = [str(g).strip() for g in groups]
            except Exception:
                group_names = []

        for name in group_names:
            if name:
                self.inventory.add_group(name)
                self.inventory.add_host(hostname, group=name)

    def _process_host_vars(self, hostname, host_vars):
        if not host_vars:
            return
        try:
            if isinstance(host_vars, dict):
                for key, value in host_vars.items():
                    self.inventory.set_variable(hostname, key, value)
            elif isinstance(host_vars, str):
                try:
                    parsed = json.loads(host_vars)
                    if isinstance(parsed, dict):
                        for key, value in parsed.items():
                            self.inventory.set_variable(hostname, key, value)
                    else:
                        self._parse_string_host_vars(hostname, host_vars)
                except json.JSONDecodeError:
                    self._parse_string_host_vars(hostname, host_vars)
            elif isinstance(host_vars, (list, tuple)):
                for item in host_vars:
                    if isinstance(item, str):
                        self._parse_key_value_string(hostname, item)
                    elif isinstance(item, (list, tuple)) and len(item) >= 2:
                        key, value = item[0], item[1]
                        self.inventory.set_variable(hostname, key, value)
            else:
                self._parse_string_host_vars(hostname, str(host_vars))
        except Exception as e:
            raise AnsibleError(f"Failed to process host_vars for {hostname}: {e}")

    def _parse_string_host_vars(self, hostname, host_vars_str):
        if not host_vars_str.strip():
            return
        if "," in host_vars_str:
            pairs = [p.strip() for p in host_vars_str.split(",") if p.strip()]
        else:
            pairs = [p.strip() for p in host_vars_str.split() if p.strip()]
        for pair in pairs:
            self._parse_key_value_string(hostname, pair)

    def _parse_key_value_string(self, hostname, key_value_str):
        if "=" in key_value_str:
            key, value = key_value_str.split("=", 1)
            key = key.strip()
            value = value.strip()
            try:
                parsed = json.loads(value)
                self.inventory.set_variable(hostname, key, parsed)
            except (json.JSONDecodeError, ValueError):
                self.inventory.set_variable(hostname, key, value)
        else:
            self.inventory.set_variable(hostname, key_value_str.strip(), True)
