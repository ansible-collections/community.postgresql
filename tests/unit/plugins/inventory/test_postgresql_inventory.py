# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Aly Ghobashy (@gebz97) <gebz97@proton.me>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

import pytest
import json
from unittest.mock import patch, MagicMock

from ansible.parsing.dataloader import DataLoader
from ansible.inventory.data import InventoryData
from ansible.errors import AnsibleError, AnsibleParserError

from plugins.inventory.postgresql_inventory import HAS_PSYCOPG, InventoryModule

# Skip all tests if psycopg is not available
pytestmark = pytest.mark.skipif(
    not HAS_PSYCOPG,
    reason="psycopg not installed"
)

# Or mock the module at the module level

import sys
# Create a mock psycopg module
mock_psycopg = MagicMock()
mock_psycopg.__version__ = "3.1.0"
mock_psycopg.connect = MagicMock()
mock_psycopg.rows.dict_row = MagicMock()
sys.modules['psycopg'] = mock_psycopg
sys.modules['psycopg.rows'] = MagicMock()
sys.modules['psycopg.rows'].dict_row = MagicMock()


class TestPostgreSQLInventoryPlugin:
    """Test suite for PostgreSQL inventory plugin."""

    @pytest.fixture
    def inventory_plugin(self):
        """Return a clean inventory plugin instance."""
        plugin = InventoryModule()
        plugin.inventory = InventoryData()
        plugin.loader = DataLoader()
        return plugin

    @pytest.fixture
    def mock_connection(self):
        """Mock PostgreSQL connection."""
        with patch("psycopg.connect") as mock_conn:
            mock_cursor = MagicMock()
            mock_conn.return_value.__enter__.return_value.cursor.return_value.__enter__.return_value = (
                mock_cursor
            )
            yield mock_conn, mock_cursor

    def test_verify_file_valid(self, inventory_plugin):
        """Test that verify_file accepts valid file extensions."""
        assert (
            inventory_plugin.verify_file(
                "tests/unit/plugins/inventory/inventory.pg_inv.yml"
            )
            is True
        )
        assert (
            inventory_plugin.verify_file(
                "tests/unit/plugins/inventory/inventory.pg_inv.yaml"
            )
            is True
        )

    def test_verify_file_invalid(self, inventory_plugin):
        """Test that verify_file rejects invalid file extensions."""
        assert (
            inventory_plugin.verify_file("tests/unit/plugins/inventory/inventory.ini")
            is False
        )
        assert (
            inventory_plugin.verify_file("tests/unit/plugins/inventory/inventory.yml")
            is False
        )

    def test_get_connection_with_dsn(self, inventory_plugin):
        """Test connection establishment with DSN."""
        with patch("psycopg.connect") as mock_conn:
            inventory_plugin.set_options(
                direct={
                    "plugin": "community.postgresql.postgresql_inventory",
                    "dsn": "postgresql://user:pass@host:5432/db",
                }
            )

            print("OPTIONS:", inventory_plugin._options)
            print("ORIGINS:", getattr(inventory_plugin, "_origins", None))
            inventory_plugin._get_connection()
            mock_conn.assert_called_once_with("postgresql://user:pass@host:5432/db")

    def test_get_connection_with_individual_params(self, inventory_plugin):
        """Test connection establishment with individual parameters."""
        with patch("psycopg.connect") as mock_conn:
            inventory_plugin.set_options(
                direct={
                    "plugin": "community.postgresql.postgresql_inventory",
                    "db_host": "localhost",
                    "db_port": 5432,
                    "db_name": "testdb",
                    "db_user": "testuser",
                    "db_password": "testpass",
                }
            )

            inventory_plugin._get_connection()
            mock_conn.assert_called_once_with(
                host="localhost",
                port=5432,
                dbname="testdb",
                user="testuser",
                password="testpass",
            )

    def test_get_connection_missing_params(self, inventory_plugin):
        """Test connection fails when required parameters are missing."""
        inventory_plugin.set_options(
            direct={
                "plugin": "community.postgresql.postgresql_inventory",
                "db_host": "localhost",
                # Missing db_name, db_user, db_password
            }
        )

        with pytest.raises(AnsibleParserError):
            inventory_plugin._get_connection()

    def test_execute_query_with_cache(self, inventory_plugin, mock_connection):
        """Test query execution with caching enabled."""
        mock_conn, mock_cursor = mock_connection
        mock_cursor.fetchall.return_value = [("host1", ["group1"])]

        inventory_plugin.set_options(
            direct={
                "plugin": "community.postgresql.postgresql_inventory",
                "cache": True,
                "db_host": "pg.example.com",
                "db_port": 5432,
                "db_name": "ansible",
                "db_user": "ansible",
                "db_password": "ansible",
            }
        )

        # First call - should execute query
        result = inventory_plugin._execute_query("SELECT * FROM hosts", "test_key")

        # Second call - should return cached result
        cached_result = inventory_plugin._execute_query(
            "SELECT * FROM hosts", "test_key"
        )

        assert result == cached_result
        mock_cursor.execute.assert_called_once()  # Query executed only once

    def test_execute_query_without_cache(self, inventory_plugin, mock_connection):
        """Test query execution without caching."""
        mock_conn, mock_cursor = mock_connection
        mock_cursor.fetchall.return_value = [("host1", ["group1"])]

        inventory_plugin.set_options(
            direct={
                "plugin": "community.postgresql.postgresql_inventory",
                "cache": False,
                "db_host": "pg.example.com",
                "db_port": 5432,
                "db_name": "ansible",
                "db_user": "ansible",
                "db_password": "ansible",
            }
        )

        result = inventory_plugin._execute_query("SELECT * FROM hosts")

        mock_cursor.execute.assert_called_once_with("SELECT * FROM hosts")
        assert result == [("host1", ["group1"])]

    def test_execute_query_database_error(self, inventory_plugin, mock_connection):
        """Test query execution with database error."""
        mock_conn, mock_cursor = mock_connection
        mock_cursor.execute.side_effect = Exception("Database connection failed")

        with pytest.raises(AnsibleError, match="Database query failed"):
            inventory_plugin._execute_query("SELECT * FROM hosts")

    def test_process_inventory_row_minimal(self, inventory_plugin):
        """Test processing a row with minimal required fields."""
        row = ("web-server-1", ["web_servers"])

        inventory_plugin._process_inventory_row(row)
        # Debug output (optional)
        print("###DEBUGPRINT")
        print(
            type(inventory_plugin.inventory.groups["web_servers"].hosts),
            inventory_plugin.inventory.groups["web_servers"].hosts,
            [type(h) for h in inventory_plugin.inventory.groups["web_servers"].hosts],
        )

        assert "web-server-1" in inventory_plugin.inventory.hosts
        assert "web_servers" in inventory_plugin.inventory.groups

        # New assertion: check .name of each Host object
        hosts = inventory_plugin.inventory.groups["web_servers"].hosts
        assert any(h.name == "web-server-1" for h in hosts)

    def test_process_inventory_row_with_ansible_host(self, inventory_plugin):
        """Test processing a row with ansible_host."""
        row = ("web-server-1", ["web_servers"], "192.168.1.10")

        inventory_plugin._process_inventory_row(row)

        host_vars = inventory_plugin.inventory.hosts["web-server-1"].get_vars()
        assert host_vars["ansible_host"] == "192.168.1.10"

    def test_process_inventory_row_with_host_vars_json(self, inventory_plugin):
        """Test processing a row with JSON host_vars."""
        host_vars = {"ansible_user": "ubuntu", "ansible_port": 22}
        row = ("web-server-1", ["web_servers"], None, json.dumps(host_vars))

        inventory_plugin._process_inventory_row(row)

        host_vars_result = inventory_plugin.inventory.hosts["web-server-1"].get_vars()
        assert host_vars_result["ansible_user"] == "ubuntu"
        assert host_vars_result["ansible_port"] == 22

    def test_process_inventory_row_with_host_vars_dict(self, inventory_plugin):
        """Test processing a row with direct dict host_vars (from PostgreSQL JSON)."""
        host_vars = {"ansible_user": "centos", "environment": "production"}
        row = ("db-server-1", ["db_servers"], None, host_vars)

        inventory_plugin._process_inventory_row(row)

        host_vars_result = inventory_plugin.inventory.hosts["db-server-1"].get_vars()
        assert host_vars_result["ansible_user"] == "centos"
        assert host_vars_result["environment"] == "production"

    def test_process_inventory_row_with_host_vars_string_array(self, inventory_plugin):
        """Test processing a row with string array host_vars."""
        host_vars = ["ansible_user=admin", "role=database"]
        row = ("db-server-1", ["db_servers"], None, host_vars)

        inventory_plugin._process_inventory_row(row)

        host_vars_result = inventory_plugin.inventory.hosts["db-server-1"].get_vars()
        assert host_vars_result["ansible_user"] == "admin"
        assert host_vars_result["role"] == "database"

    def test_process_inventory_row_with_host_vars_comma_string(self, inventory_plugin):
        """Test processing a row with comma-separated string host_vars."""
        row = (
            "app-server-1",
            ["app_servers"],
            None,
            "ansible_user=deploy,environment=staging",
        )

        inventory_plugin._process_inventory_row(row)

        host_vars_result = inventory_plugin.inventory.hosts["app-server-1"].get_vars()
        assert host_vars_result["ansible_user"] == "deploy"
        assert host_vars_result["environment"] == "staging"

    def test_process_inventory_row_invalid_format(self, inventory_plugin):
        """Test processing a row with invalid format."""
        row = ("host1",)  # Only one column

        with pytest.raises(AnsibleError, match="Invalid row format"):
            inventory_plugin._process_inventory_row(row)

    def test_add_host_to_groups_string_comma_separated(self, inventory_plugin):
        """Test adding host to groups from comma-separated string."""
        inventory_plugin._add_host_to_groups("host1", "web,app,db")

        assert "web" in inventory_plugin.inventory.groups
        assert "app" in inventory_plugin.inventory.groups
        assert "db" in inventory_plugin.inventory.groups

        for grp in ("web", "app", "db"):
            hosts = inventory_plugin.inventory.groups[grp].hosts
            assert any(h.name == "host1" for h in hosts)

    def test_add_host_to_groups_list(self, inventory_plugin):
        """Test adding host to groups from list."""
        inventory_plugin._add_host_to_groups("host1", ["load_balancer", "web_frontend"])

        assert "load_balancer" in inventory_plugin.inventory.groups
        assert "web_frontend" in inventory_plugin.inventory.groups

    def test_add_host_to_groups_empty(self, inventory_plugin):
        """Test adding host to empty groups."""
        inventory_plugin._add_host_to_groups("host1", [])
        # Should not raise any errors

    def test_parse_key_value_string_simple(self, inventory_plugin):
        """Test parsing simple key=value string."""
        inventory_plugin.inventory.add_host("test-host")
        inventory_plugin._parse_key_value_string("test-host", "key=value")

        host_vars = inventory_plugin.inventory.hosts["test-host"].get_vars()
        assert host_vars["key"] == "value"

    def test_parse_key_value_string_json_value(self, inventory_plugin):
        """Test parsing key=value with JSON value."""
        inventory_plugin.inventory.add_host("test-host")
        inventory_plugin._parse_key_value_string("test-host", 'tags=["web", "prod"]')

        host_vars = inventory_plugin.inventory.hosts["test-host"].get_vars()
        assert host_vars["tags"] == ["web", "prod"]

    def test_parse_key_value_string_boolean_flag(self, inventory_plugin):
        """Test parsing key without value (boolean true)."""
        inventory_plugin.inventory.add_host("test-host")
        inventory_plugin._parse_key_value_string("test-host", "monitored")

        host_vars = inventory_plugin.inventory.hosts["test-host"].get_vars()
        assert host_vars["monitored"] is True

    def test_full_parse_integration(self, inventory_plugin, mock_connection):
        """Test full parse method integration."""
        mock_conn, mock_cursor = mock_connection
        mock_cursor.fetchall.return_value = [
            (
                "web1",
                ["web_servers"],
                "10.0.0.1",
                '{"ansible_user": "ubuntu", "zone": "us-east-1"}',
            ),
            (
                "web2",
                ["web_servers", "staging"],
                "10.0.0.2",
                "ansible_user=centos,environment=staging",
            ),
            ("db1", ["db_servers"], "10.0.1.1", ["role=primary", "replication=true"]),
            ("lb1", ["load_balancers"], None, None),
        ]

        # Mock config reading
        with patch.object(inventory_plugin, "_read_config_data"):
            inventory_plugin.set_options(
                direct={
                    "plugin": "community.postgresql.postgresql_inventory",
                    "db_host": "pg.example.com",
                    "db_name": "ansible",
                    "db_user": "ansible",
                    "db_password": "ansible",
                    "query": "SELECT name, groups, ansible_host, host_vars FROM inventory",
                }
            )

            inventory_plugin.parse(
                inventory_plugin.inventory, DataLoader(), "/fake/path.yml"
            )

        # Verify hosts exist
        assert "web1" in inventory_plugin.inventory.hosts
        assert "web2" in inventory_plugin.inventory.hosts
        assert "db1" in inventory_plugin.inventory.hosts
        assert "lb1" in inventory_plugin.inventory.hosts

        # Verify groups
        assert "web_servers" in inventory_plugin.inventory.groups
        assert "db_servers" in inventory_plugin.inventory.groups
        assert "load_balancers" in inventory_plugin.inventory.groups
        assert "staging" in inventory_plugin.inventory.groups

        # Verify host variables
        web1_vars = inventory_plugin.inventory.hosts["web1"].get_vars()
        assert web1_vars["ansible_host"] == "10.0.0.1"
        assert web1_vars["ansible_user"] == "ubuntu"
        assert web1_vars["zone"] == "us-east-1"

        web2_vars = inventory_plugin.inventory.hosts["web2"].get_vars()
        assert web2_vars["ansible_user"] == "centos"
        assert web2_vars["environment"] == "staging"

        db1_vars = inventory_plugin.inventory.hosts["db1"].get_vars()
        assert db1_vars["role"] == "primary"
        # Expect boolean True rather than string "true"
        assert db1_vars["replication"] is True

    def test_parse_missing_query(self, inventory_plugin):
        """Test parse method with missing query option."""
        with patch.object(inventory_plugin, "_read_config_data"):
            inventory_plugin.set_options(
                direct={
                    "plugin": "community.postgresql.postgresql_inventory"
                    # Missing required 'query'
                }
            )

            with pytest.raises(
                AnsibleParserError, match="The 'query' option is required"
            ):
                inventory_plugin.parse(
                    inventory_plugin.inventory, DataLoader(), "/fake/path.yml"
                )

    def test_cache_data_management(self, inventory_plugin):
        """Test cache data getter and setter methods."""
        # Test setting cache data
        inventory_plugin._set_cache_data("test_key", "test_value")

        # Test getting cache data
        cached_value = inventory_plugin._get_cache_data("test_key")
        assert cached_value == "test_value"

        # Test getting non-existent cache data
        non_existent = inventory_plugin._get_cache_data("non_existent")
        assert non_existent is None

    def test_host_vars_complex_json(self, inventory_plugin):
        """Test processing complex JSON host_vars."""
        complex_vars = {
            "nested": {"level1": {"level2": "value"}},
            "array": [1, 2, 3],
            "boolean": True,
            "number": 42,
        }
        row = ("complex-host", ["special"], None, json.dumps(complex_vars))

        inventory_plugin._process_inventory_row(row)

        host_vars = inventory_plugin.inventory.hosts["complex-host"].get_vars()
        assert host_vars["nested"]["level1"]["level2"] == "value"
        assert host_vars["array"] == [1, 2, 3]
        assert host_vars["boolean"] is True
        assert host_vars["number"] == 42

    def test_groups_with_whitespace(self, inventory_plugin):
        """Test groups with leading/trailing whitespace."""
        row = ("host1", ["  web_servers  ", "  db_servers  "], None, None)

        inventory_plugin._process_inventory_row(row)

        # Groups should be trimmed
        assert "web_servers" in inventory_plugin.inventory.groups
        assert "db_servers" in inventory_plugin.inventory.groups
        assert "  web_servers  " not in inventory_plugin.inventory.groups


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
