# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.community.postgresql.plugins.modules import postgresql_privs


def test_absent_default_privileges_revoke_only_requested_privileges_and_objects():
    query = (
        postgresql_privs.QueryBuilder('absent')
        .for_objtype('default_privs')
        .for_whom('"developers"')
        .as_who('"writers"')
        .for_schema('"public"')
        .set_what('TRUNCATE,TRIGGER')
        .for_objs(['TABLES'])
        .build()
    )

    assert query == (
        'ALTER DEFAULT PRIVILEGES FOR ROLE "writers" IN SCHEMA "public" '
        'REVOKE TRUNCATE,TRIGGER ON TABLES FROM "developers";'
    )


def test_absent_default_privileges_without_target_role_or_schema():
    query = (
        postgresql_privs.QueryBuilder('absent')
        .for_objtype('default_privs')
        .for_whom('"reader"')
        .as_who(None)
        .for_schema(None)
        .set_what('SELECT')
        .for_objs(['TABLES', 'SEQUENCES'])
        .build()
    )

    assert set(query.splitlines()) == {
        'ALTER DEFAULT PRIVILEGES REVOKE SELECT ON TABLES FROM "reader";',
        'ALTER DEFAULT PRIVILEGES REVOKE SELECT ON SEQUENCES FROM "reader";',
    }


def test_present_default_privileges_keep_existing_revoke_all_then_grant_behavior():
    query = (
        postgresql_privs.QueryBuilder('present')
        .for_objtype('default_privs')
        .for_whom('"developers"')
        .as_who('"writers"')
        .for_schema('"public"')
        .set_what('SELECT')
        .for_objs(['TABLES'])
        .build()
    )

    assert query.splitlines() == [
        'ALTER DEFAULT PRIVILEGES FOR ROLE "writers" IN SCHEMA "public" '
        'REVOKE ALL ON TABLES FROM "developers";',
        'ALTER DEFAULT PRIVILEGES FOR ROLE "writers" IN SCHEMA "public" '
        'GRANT SELECT ON TABLES TO "developers";',
    ]
