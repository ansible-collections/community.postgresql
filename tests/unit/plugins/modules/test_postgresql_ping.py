# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest

from ansible_collections.community.postgresql.plugins.modules import postgresql_ping


@pytest.mark.parametrize(
    "raw, major, minor, full, expected_patch",
    [
        (
            "PostgreSQL 18.6 (Debian 18.6-1.pgdg13+2) on x86_64-pc-linux-gnu, "
            "compiled by gcc, 64-bit",
            18,
            6,
            "18.6",
            None,
        ),
        (
            "PostgreSQL 9.6.24 on x86_64-pc-linux-gnu, compiled by gcc, 64-bit",
            9,
            6,
            "9.6.24",
            24,
        ),
    ],
)
def test_get_pg_version_keeps_release_output(monkeypatch, raw, major, minor, full, expected_patch):
    queries = []

    def mock_exec_sql(_obj, query, add_to_executed=False):
        queries.append(query)
        assert query == "SELECT pg_catalog.version()"
        return [{"version": raw}]

    monkeypatch.setattr(postgresql_ping, "exec_sql", mock_exec_sql)

    ping = postgresql_ping.PgPing(None, None)
    ping.get_pg_version()

    expected = {
        "major": major,
        "minor": minor,
        "full": full,
        "raw": raw,
    }
    if expected_patch is not None:
        expected["patch"] = expected_patch

    assert ping.is_available is True
    assert ping.version == expected
    assert queries == ["SELECT pg_catalog.version()"]


@pytest.mark.parametrize(
    "version_string, server_version_num",
    [
        ("19beta1", "190000"),
        ("19rc1", "190000"),
    ],
)
def test_get_pg_version_uses_server_version_num_for_prereleases(
    monkeypatch, version_string, server_version_num
):
    raw = "PostgreSQL %s (Debian build) on x86_64-pc-linux-gnu" % version_string
    queries = []

    def mock_exec_sql(_obj, query, add_to_executed=False):
        queries.append(query)
        if query == "SELECT pg_catalog.version()":
            return [{"version": raw}]
        if query == "SELECT pg_catalog.current_setting('server_version_num')":
            return [{"current_setting": server_version_num}]
        raise AssertionError("Unexpected query: %s" % query)

    monkeypatch.setattr(postgresql_ping, "exec_sql", mock_exec_sql)

    ping = postgresql_ping.PgPing(None, None)
    ping.get_pg_version()

    assert ping.is_available is True
    assert ping.version == {
        "major": 19,
        "minor": 0,
        "full": version_string,
        "raw": raw,
    }
    assert queries == [
        "SELECT pg_catalog.version()",
        "SELECT pg_catalog.current_setting('server_version_num')",
    ]
