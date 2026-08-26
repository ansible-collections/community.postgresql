#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Andrew Klychkov (@Andersson007) <andrew.a.klychkov@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: postgresql_membership
short_description: Add or remove PostgreSQL roles from groups
description:
- Adds or removes PostgreSQL roles from groups (other roles).
- Users are roles with login privilege.
- Groups are PostgreSQL roles usually without LOGIN privilege.
- "Common use case:"
- 1) add a new group (groups) by M(community.postgresql.postgresql_user) module with I(role_attr_flags=NOLOGIN)
- 2) grant them desired privileges by M(community.postgresql.postgresql_privs) module
- 3) add desired PostgreSQL users to the new group (groups) by this module
options:
  groups:
    description:
    - The list of groups (roles) that need to be granted to or revoked from I(target_roles).
    required: true
    type: list
    elements: str
    aliases:
    - group
    - source_role
    - source_roles
  target_roles:
    description:
    - The list of target roles (groups will be granted to them).
    required: true
    type: list
    elements: str
    aliases:
    - target_role
    - users
    - user
  fail_on_role:
    description:
      - If C(true), fail when group or target_role doesn't exist. If C(false), just warn and continue.
    default: true
    type: bool
  admin_option:
    description:
      - Controls the membership option C(ADMIN). When unset, the PostgreSQL default applies
        to a new grant and an existing grant keeps the setting it has.
      - Requires PostgreSQL 16 or later. Ignored when I(state=absent); with any other
        state, setting it against an older server makes the module fail.
    type: bool
    version_added: '5.0.0'
  inherit_option:
    description:
      - Controls the membership option C(INHERIT). When unset, the PostgreSQL default applies
        to a new grant and an existing grant keeps the setting it has.
      - Requires PostgreSQL 16 or later. Ignored when I(state=absent); with any other
        state, setting it against an older server makes the module fail.
    type: bool
    version_added: '5.0.0'
  set_option:
    description:
      - Controls the membership option C(SET). When unset, the PostgreSQL default applies
        to a new grant and an existing grant keeps the setting it has.
      - Requires PostgreSQL 16 or later. Ignored when I(state=absent); with any other
        state, setting it against an older server makes the module fail.
    type: bool
    version_added: '5.0.0'
  granted_by:
    description:
      - Role to record as the granting role of the membership this module manages.
      - When unset, the module names the bootstrap superuser if the connecting role is
        a superuser, and the connecting role otherwise. PostgreSQL itself would pick
        differently, naming a role that holds C(ADMIN OPTION) on the group, which is
        not always the connecting one.
      - The named role must already exist, must hold C(ADMIN OPTION) on the groups, and
        the connecting role must hold its privileges. Set it when the connecting role
        holds C(ADMIN OPTION) only indirectly, through another role, since PostgreSQL
        then refuses a grant naming the connecting role. Also set it to manage a grant
        made by a different role.
      - The role must exist even with I(fail_on_role=false), which covers only I(groups)
        and I(target_roles). A missing granting role has no safe fallback, since the
        module would otherwise record the grant under a different role.
      - One role is named for the whole task. Groups whose C(ADMIN OPTION) is held by
        different roles therefore have to be split into a task each.
      - Requires PostgreSQL 16 or later, where the granting role is part of the
        membership identity. Setting it against an older server makes the module fail.
    type: str
    version_added: '5.0.0'
  state:
    description:
    - Membership state.
    - I(state=present) implies the I(groups)must be granted to I(target_roles).
    - I(state=absent) implies the I(groups) must be revoked from I(target_roles).
    - I(state=exact) implies that I(target_roles) will be members of only the I(groups)
      (available since community.postgresql 2.2.0).
      Any other groups will be revoked from I(target_roles).
    type: str
    default: present
    choices: [ absent, exact, present ]
  login_db:
    description:
    - Name of database to connect to.
    - The V(db) alias is deprecated and will be removed in version 5.0.0.
    type: str
    aliases:
    - db
  session_role:
    description:
    - Switch to session_role after connecting.
      The specified session_role must be a role that the current login_user is a member of.
    - Permissions checking for SQL commands is carried out as though
      the session_role were the one that had logged in originally.
    type: str
  trust_input:
    description:
    - If C(false), check whether values of parameters I(groups),
      I(target_roles), I(session_role), I(granted_by) are potentially dangerous.
    - It makes sense to use C(false) only when SQL injections via the parameters are possible.
    type: bool
    default: true
    version_added: '0.2.0'
notes:
- On PostgreSQL 16 and later, the same membership can be granted independently by
  several roles, each grant carrying its own options. A membership is therefore
  identified by the group, the target role B(and) the granting role, and this module
  manages one of those grants.
- PostgreSQL chooses the granting role itself when a statement does not name one, and
  the role it chooses is not necessarily the connecting role. It is the bootstrap
  superuser when the connecting role is a superuser, and otherwise the nearest role
  the connecting role inherits that holds C(ADMIN OPTION) on the group. This module
  therefore names the granting role explicitly, so that the grant it manages is
  identified exactly. Use I(granted_by) to choose that role.
- When the connecting role is not a superuser the module names that role itself. If it
  holds C(ADMIN OPTION) on a group only indirectly, through another role, PostgreSQL
  refuses a grant naming it, and I(granted_by) must name the role that holds the option.
- Before granting anything, the module checks that the granting role holds
  C(ADMIN OPTION) on every group it is about to grant, and fails naming the roles that
  do hold it. Left to the server, the refusal arrives partway through the transaction
  and takes the grants already made with it. Only the groups a C(GRANT) is actually
  emitted for are checked, so a task that has nothing left to do keeps succeeding even
  after the granting role lost the option.
- This module manages only its own grant. A membership granted by another role is not
  removed by I(state=absent) or I(state=exact), and does not stop the module making its
  own grant; the module warns instead.
- Set I(granted_by) to that role to manage its grant instead. The connecting role must
  hold that role's privileges, which a superuser always does.
- A grant whose granting role has since been dropped cannot be named, so it can only be
  warned about.
- PostgreSQL applies membership options as the union of all grants of a pair, so a
  target role keeps an option as long as any grant carries it. Setting for example
  I(admin_option=false) only clears it on the grant this module manages. The
  C(effective_options) return value reports what the target role actually holds.
- Before PostgreSQL 16 a pair can be granted only once, so the granting role is ignored.
seealso:
- module: community.postgresql.postgresql_user
- module: community.postgresql.postgresql_privs
- module: community.postgresql.postgresql_owner
- name: PostgreSQL role membership reference
  description: Complete reference of the PostgreSQL role membership documentation.
  link: https://www.postgresql.org/docs/current/role-membership.html
- name: PostgreSQL role attributes reference
  description: Complete reference of the PostgreSQL role attributes documentation.
  link: https://www.postgresql.org/docs/current/role-attributes.html

attributes:
  check_mode:
    support: full
  idempotent:
    support: full

author:
- Andrew Klychkov (@Andersson007)

extends_documentation_fragment:
- community.postgresql.postgres
'''

EXAMPLES = r'''
- name: Grant role read_only to alice and bob
  community.postgresql.postgresql_membership:
    group: read_only
    target_roles:
    - alice
    - bob
    state: present

# you can also use target_roles: alice,bob,etc to pass the role list

- name: Revoke role read_only and exec_func from bob. Ignore if roles don't exist
  community.postgresql.postgresql_membership:
    groups:
    - read_only
    - exec_func
    target_role: bob
    fail_on_role: false
    state: absent

- name: >
    Make sure alice and bob are members only of marketing and sales.
    If they are members of other groups, they will be removed from those groups
  community.postgresql.postgresql_membership:
    group:
    - marketing
    - sales
    target_roles:
    - alice
    - bob
    state: exact

- name: Make sure alice and bob do not belong to any groups
  community.postgresql.postgresql_membership:
    group: []
    target_roles:
    - alice
    - bob
    state: exact

- name: Grant read_write to alice with SET and INHERIT but without ADMIN (PostgreSQL 16+)
  community.postgresql.postgresql_membership:
    group: read_write
    target_role: alice
    admin_option: false
    inherit_option: true
    set_option: true
    state: present

# Needed when the connecting role holds ADMIN OPTION on read_write only through
# dba_team rather than directly.
- name: Grant read_write to alice as dba_team (PostgreSQL 16+)
  community.postgresql.postgresql_membership:
    group: read_write
    target_role: alice
    granted_by: dba_team
    state: present

- name: Remove the read_write membership dba_team granted, leaving other grants alone (PostgreSQL 16+)
  community.postgresql.postgresql_membership:
    group: read_write
    target_role: alice
    granted_by: dba_team
    state: absent
'''

RETURN = r'''
queries:
    description:
      - List of executed queries.
      - On PostgreSQL 16 and later each statement names the granting role, as in the sample.
        Before 16 there is no C(GRANTED BY) clause.
    returned: success
    type: list
    elements: str
    sample: [ "GRANT \"user_ro\" TO \"alice\" GRANTED BY \"postgres\"" ]
granted:
    description:
      - Dict of granted groups and roles.
      - Contains an entry for every requested group, empty when nothing was granted for it.
    returned: if I(state=present) or I(state=exact)
    type: dict
    sample: { "ro_group": [ "alice", "bob" ] }
revoked:
    description:
      - Dict of revoked groups and roles.
      - With I(state=absent) it contains an entry for every requested group, empty when
        nothing was revoked for it. With I(state=exact) only the groups actually revoked
        appear, because those are discovered on the server rather than requested.
    returned: if I(state=absent) or I(state=exact)
    type: dict
    sample: { "ro_group": [ "alice", "bob" ] }
state:
    description: Membership state that tried to be set.
    returned: success
    type: str
    sample: "present"
grants:
    description:
      - Every grant of the requested groups to the requested target roles, keyed by
        group and then by target role, with one entry per granting role.
      - Includes the grants made by roles other than the connecting one, which this
        module does not manage.
      - The C(inherit_option) and C(set_option) keys are only present on PostgreSQL 16 and later.
      - C(grantor) is C(null) for a grant whose granting role has since been dropped,
        which PostgreSQL only allows before version 16.
      - In check mode this describes the state the run would produce, because it is read
        before the transaction is rolled back.
    returned: success
    type: dict
    sample:
      ro_group:
        alice:
        - grantor: postgres
          admin_option: false
          inherit_option: true
          set_option: true
    version_added: '5.0.0'
effective_options:
    description:
      - Membership options the target role effectively holds for a group, keyed by
        group and then by target role.
      - PostgreSQL applies membership options as the union of every grant of the pair,
        so an option is C(true) when any grant carries it, including a grant this
        module does not manage.
      - Only pairs where the target role is a member are reported.
      - The C(inherit_option) and C(set_option) keys are only present on PostgreSQL 16 and later.
      - In check mode this describes the state the run would produce, because it is read
        before the transaction is rolled back.
    returned: success
    type: dict
    sample: { "ro_group": { "alice": { "admin_option": false, "inherit_option": true, "set_option": true } } }
    version_added: '5.0.0'
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.postgresql.plugins.module_utils.database import \
    check_input
from ansible_collections.community.postgresql.plugins.module_utils.membership import (
    MEMBERSHIP_OPTIONS,
    PgMembership,
    membership_option_name,
)
from ansible_collections.community.postgresql.plugins.module_utils.postgres import (
    connect_to_db,
    ensure_required_libs,
    get_conn_params,
    pg_cursor_args,
    postgres_common_argument_spec,
    get_server_version,
)

# Parameters carrying a membership option, in the order PostgreSQL names them.
OPTION_PARAMS = tuple(membership_option_name(option) for option in MEMBERSHIP_OPTIONS)

# ===========================================
# Module execution.
#


def main():
    argument_spec = postgres_common_argument_spec()
    argument_spec.update(
        groups=dict(type='list', elements='str', required=True, aliases=['group', 'source_role', 'source_roles']),
        target_roles=dict(type='list', elements='str', required=True, aliases=['target_role', 'user', 'users']),
        admin_option=dict(type='bool', default=None),
        inherit_option=dict(type='bool', default=None),
        set_option=dict(type='bool', default=None),
        granted_by=dict(type='str'),
        fail_on_role=dict(type='bool', default=True),
        state=dict(type='str', default='present', choices=['absent', 'exact', 'present']),
        login_db=dict(type='str', aliases=['db'], deprecated_aliases=[
            {
                'name': 'db',
                'version': '5.0.0',
                'collection_name': 'community.postgresql',
            }],
        ),
        session_role=dict(type='str'),
        trust_input=dict(type='bool', default=True),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    groups = module.params['groups']
    target_roles = module.params['target_roles']
    fail_on_role = module.params['fail_on_role']
    # Keyed by the PostgreSQL membership option keyword, which is what the GRANT
    # statement and pg_auth_members use.
    membership_options = dict(
        (option, module.params[membership_option_name(option)])
        for option in MEMBERSHIP_OPTIONS)
    granted_by = module.params['granted_by']
    state = module.params['state']
    session_role = module.params['session_role']
    trust_input = module.params['trust_input']
    if not trust_input:
        # Check input for potentially dangerous elements:
        check_input(module, groups, target_roles, session_role, granted_by)

    # Ensure psycopg libraries are available before connecting to DB:
    ensure_required_libs(module)
    conn_params = get_conn_params(module, module.params, warn_db_default=False)
    db_connection, dummy = connect_to_db(module, conn_params, autocommit=False)
    cursor = db_connection.cursor(**pg_cursor_args)

    # The options describe a grant, so a revoke cannot apply them.
    if state == 'absent':
        ignored = [name for name in OPTION_PARAMS if module.params[name] is not None]
        if ignored:
            module.warn("The %s parameter(s) have no effect with state=absent "
                        "and are ignored" % ", ".join(ignored))

    # Both the membership options and the granting role are PostgreSQL 16 features, and
    # this is the only place they are rejected, so fail here rather than let the server
    # reject a statement it cannot parse. See the notes section for the model itself.
    server_version = get_server_version(db_connection)
    if server_version < 160000:
        unsupported = []
        if state != 'absent':
            unsupported = [name for name in OPTION_PARAMS if module.params[name] is not None]
        # Truthiness, not "is not None", so an empty granted_by means "not set"
        # here exactly as it does when the grantor is resolved.
        if granted_by:
            unsupported.append('granted_by')

        if unsupported:
            module.fail_json(msg="The %s parameter(s) require PostgreSQL 16 or later"
                                 % ", ".join(unsupported))

    ##############
    # Create the object and do main job:
    pg_membership = PgMembership(module, cursor, groups, target_roles, fail_on_role,
                                 membership_options, server_version, granted_by)

    if state == 'present':
        pg_membership.grant()

    elif state == 'exact':
        pg_membership.match()

    elif state == 'absent':
        pg_membership.revoke()

    grants, effective_options = pg_membership.report()

    # Rollback if it's possible and check_mode:
    if module.check_mode:
        db_connection.rollback()
    else:
        db_connection.commit()

    cursor.close()
    db_connection.close()

    # Make return values:
    return_dict = dict(
        changed=pg_membership.changed,
        state=state,
        groups=pg_membership.groups,
        target_roles=pg_membership.target_roles,
        queries=pg_membership.executed_queries,
        grants=grants,
        effective_options=effective_options,
    )

    if state == 'present':
        return_dict['granted'] = pg_membership.granted
    elif state == 'absent':
        return_dict['revoked'] = pg_membership.revoked
    elif state == 'exact':
        return_dict['granted'] = pg_membership.granted
        return_dict['revoked'] = pg_membership.revoked

    module.exit_json(**return_dict)


if __name__ == '__main__':
    main()
