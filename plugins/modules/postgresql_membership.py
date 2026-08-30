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
    - DEPRECATED. This option will be removed in version 6.0.0. Use the C(groups)
      key of I(memberships) instead.
    - The list of groups (roles) that need to be granted to or revoked from I(target_roles).
    - Mutually exclusive with I(memberships), and one of the two is required.
    - On PostgreSQL 16 and later it treats the (group, target role) pair as the
      membership, whoever granted it; see the notes.
    type: list
    elements: str
    aliases:
    - group
    - source_role
    - source_roles
  target_roles:
    description:
    - The list of target roles (groups will be granted to them).
    - Required with I(groups). With I(memberships) it is optional, and acts as the
      fallback for the rows that do not name their own. A row naming its own
      replaces this value rather than adding to it.
    type: list
    elements: str
    aliases:
    - target_role
    - users
    - user
  memberships:
    description:
    - A list of objects, each describing one membership. Use this to manage
      memberships that need a different granting role or different options from one
      another, which the top-level parameters cannot express because they name one
      value for the whole task.
    - On PostgreSQL 16 and later a row manages the one grant recorded under its
      granting role; see the notes.
    - Mutually exclusive with I(groups). The top-level I(target_roles) may still be
      given, as the default for rows that do not name their own.
    - I(state), I(fail_on_role) and the connection parameters describe the task and
      stay at the top level.
    - The whole task is one transaction, so a failure part-way leaves none of the
      memberships applied. This is the difference from looping this module over a
      list, which gives one transaction per item.
    - Two rows may not describe the same grant, meaning the same group, target role
      and granting role, the derived one included, since the second would only
      overwrite the options of the first.
    - An option key left out leaves that option as it is, so a new grant gets
      PostgreSQL's default for it and an existing grant keeps its value. The option
      keys are ignored with I(state=absent).
    - An empty list with I(state=exact) leaves the target roles a member of no group,
      as an empty I(groups) list does. It needs the top-level I(target_roles). With
      the other states it does nothing.
    type: list
    elements: dict
    version_added: '5.0.0'
    suboptions:
      groups:
        description:
        - The list of groups (roles) granted to or revoked from the target roles of
          this membership.
        type: list
        elements: str
        required: true
      target_roles:
        description:
        - The list of target roles of this membership.
        - Replaces the top-level I(target_roles) for this membership rather than
          adding to it. Falls back to it when not named.
        type: list
        elements: str
      granted_by:
        description:
        - Role to record as the granting role of this membership.
        - When not set, the granting role is the bootstrap superuser if the connecting
          role is a superuser, and the connecting role itself otherwise.
        - The connecting role must hold the privileges of the role named, which a
          superuser always does.
        - The role must exist, whatever I(fail_on_role) says.
        - With I(state=absent) it selects which grant of the pair is revoked.
        - Requires PostgreSQL 16 or later.
        type: str
      admin_option:
        description:
        - Controls the membership option C(ADMIN) for this membership.
        - Requires PostgreSQL 16 or later.
        type: bool
      inherit_option:
        description:
        - Controls the membership option C(INHERIT) for this membership.
        - Requires PostgreSQL 16 or later.
        type: bool
      set_option:
        description:
        - Controls the membership option C(SET) for this membership.
        - Requires PostgreSQL 16 or later.
        type: bool
  fail_on_role:
    description:
      - If C(true), fail when group or target_role doesn't exist. If C(false), just warn and continue.
      - A I(granted_by) role that does not exist always fails.
    default: true
    type: bool
  state:
    description:
    - Membership state.
    - I(state=present) implies the I(groups)must be granted to I(target_roles).
    - I(state=absent) implies the I(groups) must be revoked from I(target_roles).
    - I(state=exact) leaves the target roles members of the named groups and of no
      other group, revoking every other membership they hold. Roles not named in
      I(target_roles) are never touched (available since community.postgresql 2.2.0).
    - On PostgreSQL 16 and later a membership can be held through several grants, one
      per granting role, and a task can only revoke the grant recorded under its own
      granting role (see I(granted_by)). With I(memberships), I(state=absent) and
      I(state=exact) therefore remove a membership only when this task's granting
      role made it. A grant made by another role stays, the target role stays a
      member, and the module warns. To remove such a grant, name its granting role
      in I(granted_by) in a I(state=absent) task, connected as a role that holds
      that role's privileges.
    - With I(memberships) and I(state=exact), a target role keeps every group any
      row names for it; the groups no row names are revoked under the granting role
      derived from the connection, since no row names one for them.
    - The deprecated I(groups) revokes every grant of a membership, whoever made it,
      so with it I(state=absent) and I(state=exact) always remove the membership.
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
  several roles, each grant carrying its own options. I(memberships) therefore
  identifies a membership by the group, the target role B(and) the granting role, and
  manages one of those grants. The deprecated I(groups) names neither a granting role
  nor an option, so it identifies a membership by the group and the target role alone.
  It is present when any role has granted it, its C(GRANT) leaves the choice of
  granting role to PostgreSQL, and I(state=absent) and I(state=exact) revoke every
  grant of the pair, one C(REVOKE) per granting role. The connecting role must hold
  the privileges of each of those granting roles; the module checks that before
  revoking anything and fails naming the role it lacks.
- The connecting role is I(session_role) when set, and I(login_user) otherwise.
- PostgreSQL chooses the granting role itself when a statement does not name one. It
  is the bootstrap superuser when the connecting role is a superuser, otherwise the
  connecting role itself when it holds C(ADMIN OPTION) on the group, or else the
  nearest role it inherits that does. I(memberships) always names one; see
  I(granted_by).
- When the connecting role is not a superuser, a I(memberships) row names that role
  itself. If it holds C(ADMIN OPTION) on a group only indirectly, through another
  role, PostgreSQL refuses a grant naming it, and I(granted_by) must name the role
  that holds the option. The deprecated I(groups) needs nothing in that case, because
  PostgreSQL picks the role that holds it.
- Under I(memberships) the module checks, before emitting a C(GRANT), that the
  granting role holds C(ADMIN OPTION) on the group, and fails naming the roles that
  do. Only the groups a C(GRANT) is emitted for are checked, so a task with nothing
  left to do keeps succeeding even after the granting role lost the option. The
  deprecated I(groups) leaves the check to the server.
- A membership granted by another role does not count as the module's own.
  I(state=present) makes its own grant beside it. I(state=absent) and I(state=exact)
  leave it in place and warn. Set I(granted_by) to that role to manage its grant; the
  connecting role must hold that role's privileges, which a superuser always does.
- Before PostgreSQL 16 a grant whose granting role has since been dropped is revoked
  like any other grant. PostgreSQL 16 and later refuse to drop a role that a grant
  records as its granting role, so the case does not arise there.
- PostgreSQL applies membership options as the union of all grants of a pair, so a
  target role keeps an option as long as any grant carries it. Setting for example
  I(admin_option=false) only clears it on the grant this module manages. The
  C(effective_options) return value reports what the target role actually holds.
- Before PostgreSQL 16 a pair can be granted only once and carries no per-grant
  options, so the two forms behave the same. I(granted_by) and the option keys are
  refused there.
- Names are stripped of surrounding whitespace, and a name repeated in a list counts
  once.
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
    target_roles:
    - alice
    - bob
    memberships:
    - groups: read_only
    state: present

# you can also use target_roles: alice,bob,etc to pass the role list

- name: Revoke role read_only and exec_func from bob. Ignore if roles don't exist
  community.postgresql.postgresql_membership:
    target_role: bob
    memberships:
    - groups:
      - read_only
      - exec_func
    fail_on_role: false
    state: absent

- name: >
    Make sure alice and bob are members only of marketing and sales.
    They are removed from any other group this task's granting role granted them;
    a grant made by another role is warned about instead (see the notes)
  community.postgresql.postgresql_membership:
    target_roles:
    - alice
    - bob
    memberships:
    - groups:
      - marketing
      - sales
    state: exact

- name: Make sure alice and bob do not belong to any groups
  community.postgresql.postgresql_membership:
    target_roles:
    - alice
    - bob
    memberships: []
    state: exact

- name: Grant read_write to alice with SET and INHERIT but without ADMIN (PostgreSQL 16+)
  community.postgresql.postgresql_membership:
    target_role: alice
    memberships:
    - groups: read_write
      admin_option: false
      inherit_option: true
      set_option: true
    state: present

# Needed when the connecting role holds ADMIN OPTION on read_write only through
# dba_team rather than directly.
- name: Grant read_write to alice as dba_team (PostgreSQL 16+)
  community.postgresql.postgresql_membership:
    target_role: alice
    memberships:
    - groups: read_write
      granted_by: dba_team
    state: present

- name: Remove the read_write membership dba_team granted, leaving other grants alone (PostgreSQL 16+)
  community.postgresql.postgresql_membership:
    target_role: alice
    memberships:
    - groups: read_write
      granted_by: dba_team
    state: absent

# One task, one transaction. The granting role and the options differ per group,
# which one set of top-level parameters could not express.
- name: Grant two groups whose ADMIN OPTION is held by different roles (PostgreSQL 16+)
  community.postgresql.postgresql_membership:
    target_roles:
    - alice
    - bob
    memberships:
    - groups: read_only
      granted_by: app_team
      admin_option: false
    - groups: read_write
      granted_by: dba_team
      admin_option: false
      set_option: false
    state: present

# alice is left a member of reporting and read_only, even though no single row
# names both. Any other membership granted by the connecting role is revoked;
# one granted by another role survives with a warning.
- name: Make alice a member of exactly these groups (PostgreSQL 16+)
  community.postgresql.postgresql_membership:
    target_roles: alice
    memberships:
    - groups: reporting
      granted_by: app_team
    - groups: read_only
      granted_by: dba_team
    state: exact
'''

RETURN = r'''
queries:
    description:
      - List of executed queries.
      - With I(memberships) on PostgreSQL 16 and later, each statement names the granting
        role, as in the sample. With the deprecated I(groups), C(GRANT) names none and
        C(REVOKE) names the granting role of each grant it removes. Before 16 there is
        no C(GRANTED BY) clause.
    returned: success
    type: list
    elements: str
    sample: [ "GRANT \"user_ro\" TO \"alice\" GRANTED BY \"postgres\"" ]
granted:
    description:
      - Dict of granted groups and roles.
      - Contains an entry for every requested group that exists, empty when nothing
        was granted for it.
    returned: if I(state=present) or I(state=exact)
    type: dict
    sample: { "ro_group": [ "alice", "bob" ] }
revoked:
    description:
      - Dict of revoked groups and roles.
      - With I(state=absent) it contains an entry for every requested group that
        exists, empty when nothing was revoked for it. With I(state=exact) only the
        groups actually revoked appear, because those are discovered on the server
        rather than requested.
    returned: if I(state=absent) or I(state=exact)
    type: dict
    sample: { "ro_group": [ "alice", "bob" ] }
state:
    description: Membership state that tried to be set.
    returned: success
    type: str
    sample: "present"
groups:
    description:
      - Groups the task named, in order of first appearance, without those found not
        to exist. With I(memberships) it spans every row.
    returned: success
    type: list
    elements: str
    sample: [ "ro_group" ]
target_roles:
    description:
      - Target roles the task named, in order of first appearance, without those found
        not to exist. With I(memberships) it spans every row.
    returned: success
    type: list
    elements: str
    sample: [ "alice", "bob" ]
grants:
    description:
      - Every grant of the requested groups to the requested target roles, keyed by
        group and then by target role, with one entry per granting role.
      - Includes the grants made by roles other than the connecting one, which this
        module does not manage.
      - Only pairs where the target role is a member are reported.
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
    PgMembershipByGrantor,
    PgMembershipByPair,
    membership_option_name,
    unique,
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

# The argument spec of one memberships row, and so the keys a row carries. state,
# fail_on_role and the connection parameters are deliberately absent: they describe
# the task rather than one membership.
MEMBERSHIP_ROW_SPEC = dict(
    groups=dict(type='list', elements='str', required=True),
    target_roles=dict(type='list', elements='str'),
    granted_by=dict(type='str'),
    admin_option=dict(type='bool'),
    inherit_option=dict(type='bool'),
    set_option=dict(type='bool'),
)


def normalise_names(names):
    """Return the names stripped, in order, without repeats.

    Args:
        names (list) -- role names as given.

    Returns the names to use (list of str).
    """
    return unique(name.strip() for name in names)


def parse_memberships(module):
    """Return the rows of the memberships parameter, completed.

    One dict per row, carrying every key of MEMBERSHIP_ROW_SPEC. The keys are validated
    and coerced by the argument spec, which also fills in the ones a row leaves out,
    so only what the spec cannot express is done here.

    Args:
        module (AnsibleModule) -- object of ansible.module_utils.basic.AnsibleModule,
            with the memberships parameter set.

    Returns the memberships (list of dict).
    """
    rows = module.params['memberships']

    # groups: [] with state=exact means "a member of no group at all"; an empty
    # memberships list is turned into the row that produces.
    if not rows:
        if module.params['target_roles'] is None:
            module.fail_json(msg="An empty memberships list needs target_roles at the top "
                                 "level, naming the roles it applies to")

        membership = dict.fromkeys(MEMBERSHIP_ROW_SPEC)
        membership.update(groups=[], target_roles=normalise_names(module.params['target_roles']))
        return [membership]

    memberships = []
    for index, row in enumerate(rows):
        # The one key a row may take from the top level, which the argument spec has
        # no way of expressing. Resolved here so everything downstream sees a
        # complete membership.
        target_roles = row['target_roles']
        if target_roles is None:
            target_roles = module.params['target_roles']

        # None, not falsy: an empty list is a task with no target role to grant to,
        # which the deprecated form treats as a no-op, so this one does too.
        if target_roles is None:
            module.fail_json(msg="memberships[%d] has no target_roles, and none is set "
                                 "at the top level to fall back to" % index)

        membership = dict(row)
        # Stripped and deduplicated here rather than in PgMembershipByGrantor, so that
        # a name repeated inside one row is one grant rather than a clash with itself,
        # and its duplicate check compares the names the statements will use.
        membership['groups'] = normalise_names(row['groups'])
        membership['target_roles'] = normalise_names(target_roles)
        # None rather than empty when not set, so that a value carrying whitespace
        # from a lookup is not reported as a role that does not exist, and an empty
        # string means "not set" everywhere.
        membership['granted_by'] = (row['granted_by'] or '').strip() or None
        memberships.append(membership)

    return memberships


def main():
    argument_spec = postgres_common_argument_spec()
    argument_spec.update(
        groups=dict(type='list', elements='str', aliases=['group', 'source_role', 'source_roles'],
                    removed_in_version='6.0.0', removed_from_collection='community.postgresql'),
        target_roles=dict(type='list', elements='str', aliases=['target_role', 'user', 'users']),
        memberships=dict(type='list', elements='dict', options=MEMBERSHIP_ROW_SPEC),
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
        # Either form of naming the memberships, never both, so there is never a
        # question of which one a grant came from. target_roles is not excluded,
        # since memberships may take it as the default for its rows.
        required_one_of=[['groups', 'memberships']],
        mutually_exclusive=[['groups', 'memberships']],
        # Naming groups without saying who they are for describes no membership.
        required_by=dict(groups=('target_roles',)),
    )

    fail_on_role = module.params['fail_on_role']
    state = module.params['state']
    session_role = module.params['session_role']

    # required_one_of counts a parameter as given when its key is present, so a null
    # value passes it. Refused here, so that neither form goes on to iterate None.
    if module.params['groups'] is None and module.params['memberships'] is None:
        module.fail_json(msg="one of the following is required: groups, memberships")

    # Each form gets the class of its model; see the class docstrings in
    # module_utils/membership.py.
    if module.params['memberships'] is None:
        groups = normalise_names(module.params['groups'])
        target_roles = normalise_names(module.params['target_roles'])
        memberships = None
        options_given = []

        if not module.params['trust_input']:
            check_input(module, groups, target_roles, session_role)
    else:
        memberships = parse_memberships(module)

        if not module.params['trust_input']:
            for membership in memberships:
                check_input(module, membership['groups'], membership['target_roles'],
                            session_role, membership['granted_by'])

        # The option parameters any row sets. They describe a grant, so a revoke
        # cannot apply them, and they need PostgreSQL 16, which is checked below.
        options_given = sorted(set(name for membership in memberships
                                   for name in OPTION_PARAMS
                                   if membership[name] is not None))
        if state == 'absent' and options_given:
            module.warn("The %s parameter(s) have no effect with state=absent "
                        "and are ignored" % ", ".join(options_given))

    # Ensure psycopg libraries are available before connecting to DB:
    ensure_required_libs(module)
    conn_params = get_conn_params(module, module.params, warn_db_default=False)
    db_connection, dummy = connect_to_db(module, conn_params, autocommit=False)
    cursor = db_connection.cursor(**pg_cursor_args)

    # Both the membership options and the granting role are PostgreSQL 16 features, and
    # this is the only place they are rejected, so fail here rather than let the server
    # reject a statement it cannot parse.
    server_version = get_server_version(db_connection)
    if memberships is not None and server_version < 160000:
        unsupported = set(options_given) if state != 'absent' else set()
        if any(membership['granted_by'] for membership in memberships):
            unsupported.add('granted_by')

        if unsupported:
            module.fail_json(msg="The %s parameter(s) require PostgreSQL 16 or later"
                                 % ", ".join(sorted(unsupported)))

    ##############
    # Create the object and do main job:
    #
    # One object for the whole task, so that a task naming several memberships reads
    # the server once, is one transaction, and a failure part-way leaves nothing behind.
    if memberships is None:
        handler = PgMembershipByPair(module, cursor, groups, target_roles,
                                     server_version, fail_on_role)
    else:
        handler = PgMembershipByGrantor(module, cursor, memberships, server_version,
                                        fail_on_role)

    if state == 'present':
        handler.grant()
    elif state == 'absent':
        handler.revoke()
    elif state == 'exact':
        handler.match()

    grants, effective_options = handler.report()

    # Rollback if it's possible and check_mode:
    if module.check_mode:
        db_connection.rollback()
    else:
        db_connection.commit()

    cursor.close()
    db_connection.close()

    # Make return values:
    return_dict = dict(
        changed=handler.changed,
        state=state,
        groups=handler.groups,
        target_roles=handler.target_roles,
        queries=handler.executed_queries,
        grants=grants,
        effective_options=effective_options,
    )

    if state == 'present':
        return_dict['granted'] = handler.granted
    elif state == 'absent':
        return_dict['revoked'] = handler.revoked
    elif state == 'exact':
        return_dict['granted'] = handler.granted
        return_dict['revoked'] = handler.revoked

    module.exit_json(**return_dict)


if __name__ == '__main__':
    main()
