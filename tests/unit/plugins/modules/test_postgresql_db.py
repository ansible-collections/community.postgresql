# -*- coding: utf-8 -*-

# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import sys

if sys.version_info[0] == 3:
    from plugins.modules import postgresql_db
elif sys.version_info[0] == 2:
    from ansible_collections.community.postgresql.plugins.modules import postgresql_db


def _run_compressed_restore(mocker, monkeypatch, password):
    monkeypatch.setenv("PGSSLMODE", "verify-full")
    module = mocker.MagicMock()
    module.get_bin_path.side_effect = lambda name, required=False: "/usr/bin/" + name

    proc = mocker.MagicMock()
    proc.communicate.return_value = (b"", b"")
    proc.returncode = 0
    popen = mocker.patch.object(postgresql_db.subprocess, "Popen", return_value=proc)

    rc = postgresql_db.db_restore(module, "/tmp/dump.sql.gz", db="test",
                                  user="postgres", password=password)[0]
    assert rc == 0

    # The second Popen call runs psql/pg_restore and receives the env.
    return popen.call_args_list[1][1]["env"]


def test_db_restore_compressed_keeps_environment_with_password(mocker, monkeypatch):
    env = _run_compressed_restore(mocker, monkeypatch, password="secret")
    assert env["PGPASSWORD"] == "secret"
    assert env["PGSSLMODE"] == "verify-full"


def test_db_restore_compressed_keeps_environment_without_password(mocker, monkeypatch):
    env = _run_compressed_restore(mocker, monkeypatch, password=None)
    assert "PGPASSWORD" not in env
    assert env["PGSSLMODE"] == "verify-full"
