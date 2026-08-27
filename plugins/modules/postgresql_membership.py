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
    - DEPRECATED as a top-level option. It will be removed in version 6.0.0.
      Use the C(groups) key of I(memberships) instead, which is not deprecated.
    - The list of groups (roles) that need to be granted to or revoked from I(target_roles).
    - Mutually exclusive with I(memberships), and one of the two is required.
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
    - Mutually exclusive with I(groups), I(granted_by), I(admin_option),
      I(inherit_option) and I(set_option). Those describe a single membership, so
      naming them next to I(memberships) would leave it open which rows they apply
      to. I(target_roles) is the exception, since the granting role and the options
      belong to the group rather than to the member.
    - A row that names C(target_roles) replaces the top-level I(target_roles) for
      that row rather than adding to it. A row that names neither is an error.
    - I(state), I(fail_on_role) and the connection parameters describe the task and
      stay at the top level.
    - The whole task is one transaction, so a failure part-way leaves none of the
      memberships applied. This is the difference from looping this module over a
      list, which gives one transaction per item.
    - Two rows may not describe the same grant, meaning the same group, target role
      and granting role, since the second would only overwrite the options of the first.
    - An empty list means the target roles are to be a member of no group at all,
      which is what an empty I(groups) list means in the deprecated top-level form.
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
    default: true
    type: bool
  admin_option:
    description:
      - DEPRECATED as a top-level option. It will be removed in version 6.0.0.
        Use the C(admin_option) key of I(memberships) instead, which is not deprecated.
      - Controls the membership option C(ADMIN). When unset, the PostgreSQL default applies
        to a new grant and an existing grant keeps the setting it has.
      - Requires PostgreSQL 16 or later. Ignored when I(state=absent); with any other
        state, setting it against an older server makes the module fail.
    type: bool
    version_added: '5.0.0'
  inherit_option:
    description:
      - DEPRECATED as a top-level option. It will be removed in version 6.0.0.
        Use the C(inherit_option) key of I(memberships) instead, which is not deprecated.
      - Controls the membership option C(INHERIT). When unset, the PostgreSQL default applies
        to a new grant and an existing grant keeps the setting it has.
      - Requires PostgreSQL 16 or later. Ignored when I(state=absent); with any other
        state, setting it against an older server makes the module fail.
    type: bool
    version_added: '5.0.0'
  set_option:
    description:
      - DEPRECATED as a top-level option. It will be removed in version 6.0.0.
        Use the C(set_option) key of I(memberships) instead, which is not deprecated.
      - Controls the membership option C(SET). When unset, the PostgreSQL default applies
        to a new grant and an existing grant keeps the setting it has.
      - Requires PostgreSQL 16 or later. Ignored when I(state=absent); with any other
        state, setting it against an older server makes the module fail.
    type: bool
    version_added: '5.0.0'
  granted_by:
    description:
      - DEPRECATED as a top-level option. It will be removed in version 6.0.0.
        Use the C(granted_by) key of I(memberships) instead, which is not deprecated.
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
    - With I(memberships), I(state=exact) considers every group the rows name for a
      target role, so a group wanted by one row is not revoked because another row
      did not name it. The groups no row named are revoked without naming a granting
      role, since there is no row to take one from.
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
    If they are members of other groups, they will be removed from those groups
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

# alice is left a member of reporting and read_only and of nothing else, even
# though no single row names both.
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
    RoleCache,
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

# Keys a memberships row may carry. Each names the parameter of the same name, which
# describes one membership rather than the task as a whole. state, fail_on_role and
# the connection parameters are deliberately absent: they describe the task.
ROW_KEYS = ('groups', 'target_roles', 'granted_by') + OPTION_PARAMS

# Parameters that describe one membership and so may not be given at the top level
# next to memberships, where it would be ambiguous which rows they apply to.
# target_roles is the exception: the granting role and the options are properties of
# the group, never of the member, so sharing one list of members over the rows cannot
# make a row mean something else.
ROW_ONLY_PARAMS = tuple(key for key in ROW_KEYS if key != 'target_roles')


def parse_memberships(module):
    """Return the memberships of the task as a list of dicts.

    One dict per membership, carrying every key of ROW_KEYS, so that the caller can
    treat the memberships parameter and the top-level parameters the same way. The
    keys of a row are validated and coerced by the argument spec, which also fills
    in the ones a row leaves out, so only what the spec cannot express is done here.

    Args:
        module (AnsibleModule) -- object of ansible.module_utils.basic.AnsibleModule.

    Returns the memberships (list of dict).
    """
    rows = module.params['memberships']

    if rows is None:
        return [dict((key, module.params[key]) for key in ROW_KEYS)]

    # An empty list is how the top-level form spells "a member of no group at all",
    # as groups: [] with state=exact. Turned into the membership that produces, so
    # the idiom survives the deprecation of groups.
    if not rows:
        if not module.params['target_roles']:
            module.fail_json(msg="An empty memberships list needs target_roles at the top "
                                 "level, naming the roles that are to have no groups")

        membership = dict((key, None) for key in ROW_KEYS)
        membership.update(groups=[], target_roles=module.params['target_roles'])
        return [membership]

    memberships = []
    for index, row in enumerate(rows):
        # The one key a row may take from the top level, which the argument spec has
        # no way of expressing. Resolved here so everything downstream sees a
        # complete membership.
        membership = dict(row)
        membership['target_roles'] = row['target_roles'] or module.params['target_roles']
        if not membership['target_roles']:
            module.fail_json(msg="memberships[%d] has no target_roles, and none is set "
                                 "at the top level to fall back to" % index)

        memberships.append(membership)

    check_no_duplicate_grants(module, memberships)
    return memberships


def check_no_duplicate_grants(module, memberships):
    """Fail when two memberships describe the same grant.

    The module manages one grant per group, target role and granting role, so two
    memberships naming the same triple would have the second silently overwrite the
    first's options. Naming the same pair under a different granted_by is a different
    grant and stays allowed.

    Args:
        module (AnsibleModule) -- object of ansible.module_utils.basic.AnsibleModule.
        memberships (list) -- memberships as returned by parse_memberships.
    """
    seen = {}
    for index, membership in enumerate(memberships):
        for group in membership['groups']:
            for role in membership['target_roles']:
                grant = (group, role, membership['granted_by'])
                if grant in seen:
                    module.fail_json(
                        msg='memberships[%d] and memberships[%d] both grant "%s" to "%s"%s. '
                            'Describe a grant once, since the second would only overwrite '
                            'the options of the first'
                            % (seen[grant], index, group, role,
                               ' as "%s"' % membership['granted_by']
                               if membership['granted_by'] else ''))

                seen[grant] = index


def merge_role_lists(target, source):
    """Merge a granted or revoked mapping of one membership into the task's.

    Args:
        target (dict) -- group mapped to the target roles reported so far.
        source (dict) -- the same, from one PgMembership object.
    """
    for group, roles in source.items():
        # A role can be reported by two memberships naming the same group, and the
        # task made one change to it, not two.
        extend_unique(target.setdefault(group, []), roles)


def merge_by_group_and_role(target, source):
    """Merge a grants or effective_options mapping of one membership into the task's.

    Args:
        target (dict) -- group mapped to target role mapped to what was reported.
        source (dict) -- the same, from one PgMembership object.
    """
    for group, per_role in source.items():
        target.setdefault(group, {}).update(per_role)


def extend_unique(target, source):
    """Append the names of source that target does not have yet.

    Args:
        target (list) -- names collected so far, extended in place.
        source (list) -- names to add.
    """
    for name in source:
        if name not in target:
            target.append(name)


def main():
    argument_spec = postgres_common_argument_spec()
    argument_spec.update(
        groups=dict(type='list', elements='str', aliases=['group', 'source_role', 'source_roles'],
                    removed_in_version='6.0.0', removed_from_collection='community.postgresql'),
        target_roles=dict(type='list', elements='str', aliases=['target_role', 'user', 'users']),
        memberships=dict(type='list', elements='dict', options=dict(
            groups=dict(type='list', elements='str', required=True),
            target_roles=dict(type='list', elements='str'),
            granted_by=dict(type='str'),
            admin_option=dict(type='bool'),
            inherit_option=dict(type='bool'),
            set_option=dict(type='bool'),
        )),
        admin_option=dict(type='bool', default=None, removed_in_version='6.0.0',
                          removed_from_collection='community.postgresql'),
        inherit_option=dict(type='bool', default=None, removed_in_version='6.0.0',
                            removed_from_collection='community.postgresql'),
        set_option=dict(type='bool', default=None, removed_in_version='6.0.0',
                        removed_from_collection='community.postgresql'),
        granted_by=dict(type='str', removed_in_version='6.0.0',
                        removed_from_collection='community.postgresql'),
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
        # question of which one a grant came from. target_roles is not in the list
        # because memberships may take it as a default; see ROW_ONLY_PARAMS.
        required_one_of=[['groups', 'memberships']],
        mutually_exclusive=[[name, 'memberships'] for name in ROW_ONLY_PARAMS],
        # Naming groups without saying who they are for describes no membership.
        required_by=dict(groups=('target_roles',)),
    )

    fail_on_role = module.params['fail_on_role']
    state = module.params['state']
    session_role = module.params['session_role']
    memberships = parse_memberships(module)

    if not module.params['trust_input']:
        # Check input for potentially dangerous elements:
        for membership in memberships:
            check_input(module, membership['groups'], membership['target_roles'],
                        session_role, membership['granted_by'])

    # The options describe a grant, so a revoke cannot apply them.
    if state == 'absent':
        ignored = sorted(set(name for membership in memberships
                             for name in OPTION_PARAMS
                             if membership[name] is not None))
        if ignored:
            module.warn("The %s parameter(s) have no effect with state=absent "
                        "and are ignored" % ", ".join(ignored))

    # Ensure psycopg libraries are available before connecting to DB:
    ensure_required_libs(module)
    conn_params = get_conn_params(module, module.params, warn_db_default=False)
    db_connection, dummy = connect_to_db(module, conn_params, autocommit=False)
    cursor = db_connection.cursor(**pg_cursor_args)

    # Both the membership options and the granting role are PostgreSQL 16 features, and
    # this is the only place they are rejected, so fail here rather than let the server
    # reject a statement it cannot parse. See the notes section for the model itself.
    server_version = get_server_version(db_connection)
    if server_version < 160000:
        unsupported = set()
        for membership in memberships:
            if state != 'absent':
                unsupported.update(name for name in OPTION_PARAMS
                                   if membership[name] is not None)

            # Truthiness, not "is not None", so an empty granted_by means "not set"
            # here exactly as it does when the grantor is resolved.
            if membership['granted_by']:
                unsupported.add('granted_by')

        if unsupported:
            module.fail_json(msg="The %s parameter(s) require PostgreSQL 16 or later"
                                 % ", ".join(sorted(unsupported)))

    ##############
    # Create the objects and do main job:
    #
    # One object per membership, all on the same connection, so that a task naming
    # several of them is still one transaction and a failure part-way leaves nothing
    # behind. The role cache is shared so that a role named by several memberships is
    # looked up, and warned about, once for the task.
    role_cache = RoleCache()
    handlers = [
        PgMembership(module, cursor, membership['groups'], membership['target_roles'],
                     role_cache, server_version, fail_on_role,
                     dict((option, membership[membership_option_name(option)])
                          for option in MEMBERSHIP_OPTIONS),
                     membership['granted_by'])
        for membership in memberships
    ]

    changed = False
    queries = []
    granted = {}
    revoked = {}
    grants = {}
    effective_options = {}
    groups = []
    target_roles = []

    if state == 'exact':
        # Every group any membership assigns to a role is wanted, so the pruning runs
        # once over the union rather than once per membership, where each would revoke
        # what the others asked for. Grouped by that union so that roles wanting the
        # same thing are pruned together.
        wanted = {}
        for handler in handlers:
            for role in handler.target_roles:
                wanted.setdefault(role, set()).update(handler.groups)

        by_wanted = {}
        for role in sorted(wanted):
            by_wanted.setdefault(frozenset(wanted[role]), []).append(role)

        for wanted_groups in sorted(by_wanted, key=sorted):
            # No granted_by: the groups being revoked are the ones no membership named,
            # so there is no row to take a granting role from. That is what state=exact
            # has always done, and granted_by on a state=absent task remains the way to
            # remove a grant recorded under somebody else.
            pruner = PgMembership(module, cursor, sorted(wanted_groups),
                                  by_wanted[wanted_groups], role_cache, server_version,
                                  fail_on_role, {}, None)
            pruner.prune()

            changed |= pruner.changed
            queries.extend(pruner.executed_queries)
            merge_role_lists(revoked, pruner.revoked)

    for handler in handlers:
        if state == 'absent':
            handler.revoke()
        else:
            handler.grant()

        handler_grants, handler_effective = handler.report()

        changed |= handler.changed
        queries.extend(handler.executed_queries)
        merge_role_lists(granted, handler.granted)
        merge_role_lists(revoked, handler.revoked)
        merge_by_group_and_role(grants, handler_grants)
        merge_by_group_and_role(effective_options, handler_effective)
        extend_unique(groups, handler.groups)
        extend_unique(target_roles, handler.target_roles)

    # Rollback if it's possible and check_mode:
    if module.check_mode:
        db_connection.rollback()
    else:
        db_connection.commit()

    cursor.close()
    db_connection.close()

    # Make return values:
    return_dict = dict(
        changed=changed,
        state=state,
        groups=groups,
        target_roles=target_roles,
        queries=queries,
        grants=grants,
        effective_options=effective_options,
    )

    if state == 'present':
        return_dict['granted'] = granted
    elif state == 'absent':
        return_dict['revoked'] = revoked
    elif state == 'exact':
        return_dict['granted'] = granted
        return_dict['revoked'] = revoked

    module.exit_json(**return_dict)


if __name__ == '__main__':
    main()
