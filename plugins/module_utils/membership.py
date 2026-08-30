# Copyright: (c) 2026, Florian R. Hölzlwimmer (@Hoeze) <git.ich@frhoelzlwimmer.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.community.postgresql.plugins.module_utils.database import \
    pg_quote_name
from ansible_collections.community.postgresql.plugins.module_utils.postgres import \
    exec_sql

# Membership options, named by the keyword PostgreSQL uses for them in GRANT. The
# pg_auth_members column and the module parameter carrying each one are the keyword
# lowercased and suffixed with "_option", which membership_option_name builds, so the
# three spellings cannot drift apart.
MEMBERSHIP_OPTIONS = ('ADMIN', 'INHERIT', 'SET')


def membership_option_name(option):
    """Return the parameter and column name of a membership option.

    Args:
        option (str) -- option keyword as PostgreSQL names it, from MEMBERSHIP_OPTIONS.

    Returns the name used by pg_auth_members and by the module parameter (str).
    """
    return '%s_option' % option.lower()


def unique(names):
    """Return the names in order of first appearance, without repeats.

    Args:
        names (iterable) -- names, possibly repeated.

    Returns the distinct names (list).
    """
    return list(dict.fromkeys(names))


class PgMembershipBase(object):
    """What the two membership models share.

    Throughout this module, "group" is the role whose membership is granted, "role"
    is the member role, and "grants" is the list of grants of that (group, role) pair
    as returned by _role_grants.

    PostgreSQL 16 reshaped role membership: a pair can be granted independently by
    several roles, and each grant carries its own ADMIN, INHERIT and SET options. The
    two subclasses differ in what they take a membership to be. PgMembershipByPair
    takes it to be the pair, whoever granted it. PgMembershipByGrantor takes it to be
    one grant of the pair, identified by its granting role as well. Before 16
    pg_auth_members is unique on (roleid, member), so the two models coincide.

    A subclass sets groups, target_roles and pairs in __init__, restricted to roles
    that exist, and provides grant(), revoke() and prune(). Each returns self.changed
    after recording what it changed in granted and revoked through _record. It also
    sets GRANTOR_REMEDY, the sentence a failure of _check_grantors_privileges ends
    with, saying what the caller can do about it in that model.
    """

    GRANTOR_REMEDY = None

    def __init__(self, module, cursor, server_version, fail_on_role=True):
        """Set up what both models need.

        Args:
            module (AnsibleModule) -- object of ansible.module_utils.basic.AnsibleModule class.
            cursor (psycopg cursor) -- database cursor object.
            server_version (int) -- server version as returned by get_server_version.
                Decides whether memberships are per-grantor and whether the membership
                options can be set. No default: a wrong default would switch the
                model silently.

        Kwargs:
            fail_on_role (bool) -- fail when a passed role does not exist, otherwise
                warn and skip it (default True).
        """
        self.module = module
        self.cursor = cursor
        self.fail_on_role = fail_on_role
        self.executed_queries = []  # What exec_sql appends to; returned as queries.
        self.granted = {}
        self.revoked = {}
        self.changed = False

        # The options are per grant precisely because grants are per grantor, so one
        # flag covers both. Before 16 neither the inherit_option and set_option
        # columns nor the GRANT ... WITH <option> <boolean> syntax exist.
        self.per_grantor_membership = server_version >= 160000

        # The options the server records and report() gives back. ADMIN exists on
        # every supported version; INHERIT and SET arrived with the per-grantor model
        # in 16.
        self.recorded_options = (MEMBERSHIP_OPTIONS if self.per_grantor_membership
                                 else ('ADMIN',))

        # The three below are set by _resolve_connection from PostgreSQL 16 on, where
        # a statement names a granting role. Before 16 they keep these values and
        # nothing reads them. A superuser may act as any role, so the check that the
        # connection has the grantor's privileges does not apply to it.
        self.connected_as_superuser = False

        # PostgreSQL waives the ADMIN OPTION requirement for the bootstrap superuser
        # and for nobody else, not even another superuser, so the check that the
        # grantor holds it is skipped only then.
        self.bootstrap = None

        # The granting role of a memberships row that names none, and of the
        # memberships state=exact prunes, which no row describes. Never checked for,
        # being the connecting role's own.
        self.derived_grantor = None

        if self.per_grantor_membership:
            self._resolve_connection()

        # The groups and target roles of the task in order of first appearance, and the
        # (group, role) pairs it names. Set by the subclass, see the class docstring.
        self.groups = []
        self.target_roles = []
        self.pairs = []

    def _existing_roles(self, roles):
        """Return the subset of roles that exist.

        One array parameter, so the driver quotes the names and an empty list matches
        nothing instead of building an invalid "IN ()".

        Args:
            roles (iterable) -- role names to look up.

        Returns the names that exist (set of str).
        """
        query = "SELECT rolname FROM pg_catalog.pg_roles WHERE rolname = ANY(%s)"
        return set(row['rolname'] for row in
                   exec_sql(self, query, query_params=(list(roles),), add_to_executed=False))

    def _drop_missing_roles(self, groups, target_roles, existing):
        """Fail or warn about the groups and target roles that do not exist.

        Args:
            groups (list) -- group roles as passed.
            target_roles (list) -- member roles as passed.
            existing (set) -- the role names that exist, from _existing_roles.

        Returns the groups and the target roles that exist (two lists of str).
        """
        # Groups first, so that the failure names a missing group before a missing
        # target role. A name in both lists is reported once.
        for role in unique(list(groups) + list(target_roles)):
            if role in existing:
                continue

            if self.fail_on_role:
                self.module.fail_json(msg="Role %s does not exist" % role)

            self.module.warn("Role %s does not exist, pass" % role)

        return ([group for group in groups if group in existing],
                [role for role in target_roles if role in existing])

    def _role_grants(self):
        """Return every grant of the target roles' memberships, keyed by role then group.

        Returns a dict mapping each role (str) to a dict mapping a group name (str) to
        its grants (list of dict). A grant holds 'grantor' plus the options the server
        records, keyed by the PostgreSQL keyword. The grants of a pair are ordered by
        granting role, so the statements derived from them come out in a stable order.
        """
        columns = ", ".join("m.%s" % membership_option_name(option)
                            for option in self.recorded_options)

        # The grantor is LEFT JOINed: before PostgreSQL 16 dropping a role did not
        # check pg_auth_members.grantor, so a grant can carry an OID that no longer
        # resolves and comes back with grantor None. An inner join would hide such a
        # membership entirely and state=absent would silently leave it in place.
        # PostgreSQL 16 refuses to drop a role that a grant records as its grantor,
        # so from 16 on the grantor always resolves.
        query = """SELECT u.rolname AS member, g.rolname AS grp, gr.rolname AS grantor, %s
                   FROM pg_catalog.pg_auth_members m
                   JOIN pg_catalog.pg_roles g ON m.roleid = g.oid
                   JOIN pg_catalog.pg_roles u ON m.member = u.oid
                   LEFT JOIN pg_catalog.pg_roles gr ON m.grantor = gr.oid
                   WHERE u.rolname = ANY(%%s)
                   ORDER BY u.rolname, g.rolname, gr.rolname""" % columns

        memberships = dict((role, {}) for role in self.target_roles)
        for row in exec_sql(self, query, query_params=(list(self.target_roles),),
                            add_to_executed=False):
            grant = dict(grantor=row['grantor'])
            for option in self.recorded_options:
                grant[option] = row[membership_option_name(option)]
            memberships[row['member']].setdefault(row['grp'], []).append(grant)
        return memberships

    def _resolve_connection(self):
        """Read what the connecting role is, and derive the granting role from it.

        The derived role is the bootstrap superuser when connected as a superuser,
        since that is what PostgreSQL records for any superuser's grant, and
        CURRENT_ROLE otherwise. CURRENT_ROLE is not what PostgreSQL would pick for a
        non-superuser holding ADMIN OPTION indirectly, which is why granted_by exists.
        """
        # pg_authid is readable by superusers only, so the bootstrap superuser is
        # looked up by its fixed OID in pg_roles, which every role can select from.
        query = ("SELECT CURRENT_ROLE AS current_role, "
                 "(SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = CURRENT_ROLE) AS is_super, "
                 "(SELECT rolname FROM pg_catalog.pg_roles WHERE oid = 10) AS bootstrap")

        row = exec_sql(self, query, add_to_executed=False)[0]
        self.connected_as_superuser = row['is_super']
        self.bootstrap = row['bootstrap']
        self.derived_grantor = row['bootstrap'] if row['is_super'] else row['current_role']

    def _check_grantors_privileges(self, grantors):
        """Fail unless the connecting role has the privileges of every grantor.

        PostgreSQL lets a role record a grant as another role, and revoke one recorded
        under it, only when it has that role's privileges: has_privs_of_role, which is
        pg_has_role(..., 'USAGE'), not whether it can SET ROLE to it. The two differ
        on a membership granted WITH INHERIT TRUE, SET FALSE, and on its opposite.
        Checked only from the paths that emit a statement, so a task with nothing
        left to do keeps succeeding. The derived grantor is never queried: it is
        CURRENT_ROLE, or the check is skipped for a superuser.

        Args:
            grantors (set) -- granting roles a statement would be emitted under.
        """
        if not self.per_grantor_membership or self.connected_as_superuser:
            return

        for grantor in sorted(grantors):
            if grantor == self.derived_grantor:
                continue

            has_privs = exec_sql(self, "SELECT pg_catalog.pg_has_role(%s, 'USAGE') AS has_privs",
                                 query_params=(grantor,),
                                 add_to_executed=False)[0]['has_privs']

            if not has_privs:
                self.module.fail_json(
                    msg='The connecting role cannot act as the granting role "%s", because it '
                        'does not have the privileges of that role. %s'
                        % (grantor, self.GRANTOR_REMEDY))

    def _granted_by(self, grantor):
        """Return the GRANTED BY clause naming grantor, empty before PostgreSQL 16.

        Args:
            grantor (str) -- granting role to name.

        Returns the clause to append to a GRANT or REVOKE (str).
        """
        if not self.per_grantor_membership:
            return ''

        return ' GRANTED BY %s' % pg_quote_name(grantor)

    def _execute(self, query):
        """Run a GRANT or REVOKE and record it as a change.

        Args:
            query (str) -- the statement.
        """
        self.changed |= exec_sql(self, query, return_bool=True)

    @staticmethod
    def _record(mapping, group, role):
        """Add role to the roles reported for group, once.

        Args:
            mapping (dict) -- granted or revoked, group mapped to its target roles.
            group (str) -- group role the change is of.
            role (str) -- member role changed.
        """
        roles = mapping.setdefault(group, [])
        if role not in roles:
            roles.append(role)

    def match(self):
        """Leave the target roles a member of the wanted groups and of nothing else.

        Returns True when a change was made (bool).
        """
        self.prune()

        # grant() is idempotent and also reconciles the options of memberships that
        # already exist, so it runs for every wanted group, not only the new ones.
        return self.grant()

    def report(self):
        """Return the grants and effective options of the pairs the task names.

        Includes every grant of a pair, whoever made it, since PostgreSQL applies the
        options as their union. Pairs where the target role is not a member are left
        out.

        Returns two dicts keyed by group then target role: the grants of each pair
        (list of dict) and the options the target role effectively holds (dict of str
        to bool).
        """
        grants = {}
        effective_options = {}
        memberships = self._role_grants()

        for group, role in self.pairs:
            role_grants = memberships[role].get(group)
            if not role_grants:
                continue

            reported = []
            for grant in role_grants:
                entry = dict(grantor=grant['grantor'])
                for option in self.recorded_options:
                    entry[membership_option_name(option)] = grant[option]
                reported.append(entry)

            grants.setdefault(group, {})[role] = reported
            effective_options.setdefault(group, {})[role] = dict(
                (membership_option_name(option),
                 any(grant[option] for grant in role_grants))
                for option in self.recorded_options)

        return grants, effective_options


class PgMembershipByPair(PgMembershipBase):
    """Manage memberships as (group, role) pairs, whoever granted them.

    The model of the deprecated top-level groups parameter. It names no granting role
    and no option, so it has nothing to tell one grant of a pair from another, and
    treats the pair as the membership: present when any grant of it exists, granted
    by a GRANT that names no granting role and leaves the choice to PostgreSQL, and
    revoked by revoking every grant of it, one statement per granting role. Nothing
    is checked ahead of a GRANT, since it names no role that could be checked; the
    server refuses what it must. A REVOKE names the granting role found recorded,
    so the connecting role's privileges over it are checked first.
    """

    GRANTOR_REMEDY = 'Only a role that has them can revoke the grant recorded under it.'

    def __init__(self, module, cursor, groups, target_roles, server_version,
                 fail_on_role=True):
        """Manage the membership of target_roles in groups.

        Args:
            module (AnsibleModule) -- object of ansible.module_utils.basic.AnsibleModule class.
            cursor (psycopg cursor) -- database cursor object.
            groups (list) -- group roles whose membership is managed, stripped and
                deduplicated by the caller.
            target_roles (list) -- member roles that receive or lose the membership,
                stripped and deduplicated by the caller.
            server_version (int) -- server version as returned by get_server_version.

        Kwargs:
            fail_on_role (bool) -- fail when a passed role does not exist, otherwise
                warn and skip it (default True).
        """
        super(PgMembershipByPair, self).__init__(module, cursor, server_version, fail_on_role)

        existing = self._existing_roles(set(groups) | set(target_roles))
        self.groups, self.target_roles = self._drop_missing_roles(groups, target_roles, existing)

        # Grouped by target role, since that is the order the statements come out in.
        self.pairs = [(group, role) for role in self.target_roles for group in self.groups]

    def grant(self):
        """Grant every group to every target role that is not a member of it.

        Returns True when a change was made (bool).
        """
        # Seeded before the loop, which does not run when every target role was
        # filtered out as non-existent or none was passed, so that the reported groups
        # are the ones asked for either way.
        for group in self.groups:
            self.granted.setdefault(group, [])

        memberships = self._role_grants()
        for group, role in self.pairs:
            # Any grant satisfies the pair. No GRANTED BY: PostgreSQL picks a role that
            # holds ADMIN OPTION on the group, which is more than the connecting role
            # can be told to do, and this model does not care which role the grant is
            # recorded under.
            if memberships[role].get(group):
                continue

            self._execute('GRANT %s TO %s' % (pg_quote_name(group), pg_quote_name(role)))
            self._record(self.granted, group, role)

        return self.changed

    def revoke(self):
        """Revoke every grant of every group from every target role.

        Returns True when a change was made (bool).
        """
        for group in self.groups:
            self.revoked.setdefault(group, [])

        # Each REVOKE names the granting role it found recorded, so the connecting
        # role needs that role's privileges. Checked before anything is emitted, so
        # the failure names the role instead of passing the server's error through.
        memberships = self._role_grants()
        self._check_grantors_privileges(set(
            grant['grantor'] for group, role in self.pairs
            for grant in memberships[role].get(group, [])))

        for group, role in self.pairs:
            if self._revoke_pair(group, role, memberships[role].get(group, [])):
                self._record(self.revoked, group, role)

        return self.changed

    def prune(self):
        """Revoke every membership of the target roles outside self.groups.

        Returns True when a change was made (bool).
        """
        # revoked is not seeded: it lists the groups actually revoked, which are
        # discovered on the server rather than asked for. Sorted so the emitted
        # statements come out in a stable order.
        memberships = self._role_grants()
        outside = [(group, role, memberships[role][group]) for role in self.target_roles
                   for group in sorted(set(memberships[role]) - set(self.groups))]

        # As in revoke(): the grantors found recorded have to be usable before any
        # of them is named in a REVOKE.
        self._check_grantors_privileges(set(
            grant['grantor'] for dummy_group, dummy_role, grants in outside for grant in grants))

        for group, role, grants in outside:
            if self._revoke_pair(group, role, grants):
                self._record(self.revoked, group, role)

        return self.changed

    def _revoke_pair(self, group, role, grants):
        """Revoke every grant of group to role, one REVOKE per granting role.

        On PostgreSQL 16 and later REVOKE removes only the grant under the granting
        role it names, so each grant is named in turn and the membership actually goes
        away. Before 16 no granting role is named, so a grant whose granting role was
        dropped is revoked like any other.

        Args:
            group (str) -- group role that is revoked.
            role (str) -- member role that loses it.
            grants (list) -- grants of the pair as returned by _role_grants.

        Returns True when a statement was emitted (bool).
        """
        changed = False
        for grant in grants:
            self._execute('REVOKE %s FROM %s%s' % (
                pg_quote_name(group), pg_quote_name(role), self._granted_by(grant['grantor'])))
            changed = True

        return changed


class PgMembershipByGrantor(PgMembershipBase):
    """Manage memberships as grants, each identified by its granting role as well.

    The model of the memberships parameter. Each row names the role its grants are
    recorded under, or has it derived from the connection, and the module manages
    that one grant of a pair: it makes it when missing, reconciles its options, and
    revokes it and nothing else. The grants of the same pair recorded under other
    roles are warned about and left alone. Naming the granting role is what lets the
    module recognize its own grant on a later run and set the options, which are
    stored per grant.

    Before PostgreSQL 16 a pair has one grant and no options, so no granting role is
    named and the grant found is always the one managed.
    """

    GRANTOR_REMEDY = 'Set granted_by to a role it does have the privileges of.'

    def __init__(self, module, cursor, memberships, server_version, fail_on_role=True):
        """Manage the grants the memberships describe.

        Args:
            module (AnsibleModule) -- object of ansible.module_utils.basic.AnsibleModule class.
            cursor (psycopg cursor) -- database cursor object.
            memberships (list) -- one dict per row of the memberships parameter, with
                the keys groups (list), target_roles (list), granted_by (str or None)
                and the option parameters named by membership_option_name (bool, or
                None to leave the option as it is). Names are stripped and
                deduplicated by the caller, and granted_by is None rather than empty
                when not set. Two rows describing the same grant, by group, target
                role and granting role with the derived one filled in, are refused.
            server_version (int) -- server version as returned by get_server_version.

        Kwargs:
            fail_on_role (bool) -- fail when a passed role does not exist, otherwise
                warn and skip it (default True). A granted_by that does not exist
                always fails, since it would make state=present die with a raw server
                error and state=absent match nothing.
        """
        super(PgMembershipByGrantor, self).__init__(module, cursor, server_version, fail_on_role)

        groups = unique(group for row in memberships for group in row['groups'])
        target_roles = unique(role for row in memberships for role in row['target_roles'])
        grantors = unique(row['granted_by'] for row in memberships if row['granted_by'])

        existing = self._existing_roles(set(groups) | set(target_roles) | set(grantors))
        for grantor in grantors:
            if grantor not in existing:
                self.module.fail_json(msg="The granted_by role %s does not exist" % grantor)

        self.groups, self.target_roles = self._drop_missing_roles(groups, target_roles, existing)

        # One wanted grant per (row, target role, group), in that order, which is the
        # order the statements come out in. Each carries the granting role it is
        # recorded under and the options it is to have, a missing option meaning
        # "leave it as it is". Two rows describing the same grant are refused here,
        # where the derived granting role is known, since the second would only
        # overwrite the options of the first. The same pair under another granting
        # role is a different grant and stays allowed.
        self.wanted = []
        seen = {}
        for index, row in enumerate(memberships):
            if self.per_grantor_membership:
                grantor = row['granted_by'] or self.derived_grantor
            else:
                grantor = None

            options = dict((option, row.get(membership_option_name(option)))
                           for option in MEMBERSHIP_OPTIONS
                           if row.get(membership_option_name(option)) is not None)

            for role in row['target_roles']:
                for group in row['groups']:
                    if role not in self.target_roles or group not in self.groups:
                        continue

                    key = (group, role, grantor)
                    if key in seen:
                        self._fail_duplicate_grant(seen[key], (index, row), key)
                    seen[key] = (index, row)

                    self.wanted.append(dict(group=group, role=role, grantor=grantor,
                                            options=options))

        self.pairs = unique((wanted['group'], wanted['role']) for wanted in self.wanted)

    def _fail_duplicate_grant(self, first, second, key):
        """Fail because two rows describe the same grant.

        Args:
            first (tuple) -- index and row of the first description.
            second (tuple) -- index and row of the second.
            key (tuple) -- the grant, as (group, role, grantor).
        """
        group, role, grantor = key
        where = ''
        if grantor:
            where = ' under "%s"' % grantor
            if any(row['granted_by'] is None for dummy, row in (first, second)):
                where += ', the granting role derived for a row that names no granted_by'

        self.module.fail_json(
            msg='memberships[%d] and memberships[%d] both grant "%s" to "%s"%s. Describe a '
                'grant once, since the second would only overwrite the options of the first'
                % (first[0], second[0], group, role, where))

    def _is_own(self, grant, grantor):
        """Return whether a grant is the one recorded under grantor.

        Before PostgreSQL 16 a pair has only one grant, so it is always the one.

        Args:
            grant (dict) -- a grant as returned by _role_grants.
            grantor (str) -- granting role of the grant managed.

        Returns True when the grant is the one managed (bool).
        """
        return not self.per_grantor_membership or grant['grantor'] == grantor

    def _own_grant(self, grants, grantor):
        """Return the grant of a pair recorded under grantor, or None.

        Args:
            grants (list) -- grants of a pair as returned by _role_grants.
            grantor (str) -- granting role of the grant managed.

        Returns the grant managed (dict), or None when the pair has none.
        """
        return next((grant for grant in grants if self._is_own(grant, grantor)), None)

    def _foreign_grants(self, grants, grantor):
        """Return the grants of a pair recorded under other roles.

        Args:
            grants (list) -- grants of a pair as returned by _role_grants.
            grantor (str) -- granting role of the grant managed.

        Returns the grants made by other roles (list of dict).
        """
        return [grant for grant in grants if not self._is_own(grant, grantor)]

    def _grants_of(self, memberships, wanted):
        """Return the grants of the pair a wanted grant is of.

        Args:
            memberships (dict) -- grants of every target role, from _role_grants.
            wanted (dict) -- a wanted grant, from self.wanted.

        Returns the grants of the pair (list of dict).
        """
        return memberships[wanted['role']].get(wanted['group'], [])

    def _warn_foreign_membership(self, group, role, grantor, grants, pruning):
        """Warn that grants recorded under other roles keep the membership alive.

        Judged from the grants read before any statement ran, so the warning does not
        depend on what was emitted.

        Args:
            group (str) -- group role the membership is of.
            role (str) -- member role.
            grantor (str) -- granting role of the grant managed.
            grants (list) -- grants of the pair as returned by _role_grants.
            pruning (bool) -- whether the group is one no row names, which decides the
                advice: a row cannot set granted_by for a group it does not name.
        """
        # Foreign grants only exist from PostgreSQL 16 on, where the grantor of every
        # grant resolves, so the names are never None.
        grantors = sorted(grant['grantor'] for grant in self._foreign_grants(grants, grantor))
        if not grantors:
            return

        if pruning:
            advice = ('A state=absent task naming the group with granted_by set to one of '
                      'those roles can remove its grant')
        else:
            advice = 'Set granted_by to manage one of the other grants instead'

        self.module.warn(
            'Role "%s" remains a member of "%s" through the grant(s) recorded under %s. '
            'This module manages the grant recorded under "%s", so the membership and its '
            'effective options are not fully removed. %s, when the connecting role holds '
            'the privileges of that granting role.'
            % (role, group, ", ".join('"%s"' % g for g in grantors), grantor, advice))

    def _warn_foreign_options(self, wanted, grants):
        """Warn that grants recorded under other roles keep an option the caller cleared.

        Judged from the grants read before any statement ran, so the warning does not
        depend on what was emitted.

        Args:
            wanted (dict) -- a wanted grant, from self.wanted.
            grants (list) -- grants of the pair as returned by _role_grants.
        """
        foreign = self._foreign_grants(grants, wanted['grantor'])
        if not foreign:
            return

        for option, setting in wanted['options'].items():
            if setting:
                continue

            grantors = sorted(grant['grantor'] for grant in foreign if grant[option])
            if grantors:
                self.module.warn(
                    'Role "%s" keeps the %s option on "%s" through the grant(s) recorded under '
                    '%s. This module manages the grant recorded under "%s", so %s_option=false '
                    'does not remove it.'
                    % (wanted['role'], option, wanted['group'],
                       ", ".join('"%s"' % g for g in grantors),
                       wanted['grantor'], option.lower()))

    def _check_grantable(self, pending):
        """Fail unless every pending grant's granting role holds ADMIN OPTION on its group.

        A statement that does not name a granting role makes PostgreSQL pick one, and
        it picks per group: the connecting role itself when it holds ADMIN OPTION on
        that group, otherwise a role whose privileges it inherits that does. This
        model names the role instead, so a group that role cannot grant has to be
        reported here. Left to the server, the refusal names no role that holds the
        option, which is what the caller needs to fix it, and arrives only once a
        statement is attempted.

        Only called for granting. A grant exists only while its granting role holds
        ADMIN OPTION on the group (revoking the option fails, or removes the grant
        with CASCADE), so a grant this module finds under its own granting role can
        always be revoked.

        Args:
            pending (list) -- the wanted grants a GRANT would be emitted for, from
                self.wanted.
        """
        if not self.per_grantor_membership or not pending:
            return

        self._check_grantors_privileges(set(wanted['grantor'] for wanted in pending))

        # The one grantor PostgreSQL asks nothing of. Every other role has to hold the
        # option in pg_auth_members, a superuser included, so being connected as one
        # does not make the query below unnecessary.
        needed = set((wanted['grantor'], wanted['group']) for wanted in pending
                     if wanted['grantor'] != self.bootstrap)
        if not needed:
            return

        # LEFT JOINed so that a group nobody holds ADMIN OPTION on still comes back as
        # a row, which is what separates the three ways this can go wrong. holders are
        # all the roles that hold it, candidates the ones the connection could also
        # name, which for a superuser is all of them. DISTINCT, since a role holding
        # the option through grants from several granting roles has a row per grant.
        query = """SELECT g.rolname AS grp,
                          coalesce(array_agg(DISTINCT a.rolname ORDER BY a.rolname)
                                   FILTER (WHERE a.rolname IS NOT NULL), '{}') AS holders,
                          coalesce(array_agg(DISTINCT a.rolname ORDER BY a.rolname)
                                   FILTER (WHERE pg_catalog.pg_has_role(a.oid, 'USAGE')),
                                   '{}') AS candidates
                   FROM pg_catalog.pg_roles g
                   LEFT JOIN pg_catalog.pg_auth_members m
                     ON m.roleid = g.oid AND m.admin_option
                   LEFT JOIN pg_catalog.pg_roles a ON a.oid = m.member
                   WHERE g.rolname = ANY(%s)
                   GROUP BY g.rolname"""

        holders = dict((row['grp'], row) for row in
                       exec_sql(self, query, query_params=(sorted(set(group for dummy, group in needed)),),
                                add_to_executed=False))

        # Granting role mapped to the groups it lacks the option on and their candidates.
        needs_other_grantor = {}
        out_of_reach = {}
        nobody_holds_it = set()
        for grantor, group in sorted(needed):
            row = holders[group]
            if grantor in row['holders']:
                continue

            if row['candidates']:
                needs_other_grantor.setdefault(grantor, {})[group] = row['candidates']
            elif row['holders']:
                out_of_reach[group] = row['holders']
            else:
                nobody_holds_it.add(group)

        msg = []
        if nobody_holds_it:
            msg.append('No role holds ADMIN OPTION on %s, so it cannot be granted under '
                       'a named granting role.'
                       % ", ".join('"%s"' % g for g in sorted(nobody_holds_it)))

        if out_of_reach:
            msg.append('ADMIN OPTION on %s is held only by roles the connecting role does '
                       'not have the privileges of (%s).'
                       % (", ".join('"%s"' % g for g in sorted(out_of_reach)),
                          "; ".join('%s: %s' % (g, ", ".join(out_of_reach[g]))
                                    for g in sorted(out_of_reach))))

        for grantor in sorted(needs_other_grantor):
            groups = needs_other_grantor[grantor]
            msg.append('The granting role "%s" does not hold ADMIN OPTION on %s. Set '
                       'granted_by to a role that does (%s). granted_by applies to every '
                       'group of its memberships row, so groups needing a different '
                       'granting role have to be given a row each.'
                       % (grantor,
                          ", ".join('"%s"' % g for g in sorted(groups)),
                          "; ".join('%s: %s' % (g, ", ".join(groups[g]))
                                    for g in sorted(groups))))

        if msg:
            self.module.fail_json(msg=" ".join(msg))

    def _needs_grant(self, wanted, grants):
        """Return whether a GRANT has to be emitted for a wanted grant.

        Only the grant under the wanted granting role is compared, so a membership
        granted by another role does not suppress the GRANT (issue #757).
        _check_grantable sees exactly the wanted grants this returns True for, so a
        task with nothing left to do is never checked and stays green.

        Args:
            wanted (dict) -- a wanted grant, from self.wanted.
            grants (list) -- grants of the pair as returned by _role_grants.

        Returns True when a GRANT is needed (bool).
        """
        current = self._own_grant(grants, wanted['grantor'])
        return current is None or any(current[option] != setting
                                      for option, setting in wanted['options'].items())

    def _revoke_own(self, group, role, grantor, grants, pruning=False):
        """Revoke the grant of group to role recorded under grantor, if there is one.

        REVOKE removes only the grant under the grantor it names, so on PostgreSQL 16+
        another role's grant survives and is warned about, whether or not anything
        was revoked.

        Args:
            group (str) -- group role that is revoked.
            role (str) -- member role that loses it.
            grantor (str) -- granting role of the grant managed.
            grants (list) -- grants of the pair as returned by _role_grants.

        Kwargs:
            pruning (bool) -- whether no row names the group, see
                _warn_foreign_membership (default False).

        Returns True when a statement was emitted (bool).
        """
        changed = False
        if self._own_grant(grants, grantor) is not None:
            self._execute('REVOKE %s FROM %s%s' % (
                pg_quote_name(group), pg_quote_name(role), self._granted_by(grantor)))
            changed = True

        self._warn_foreign_membership(group, role, grantor, grants, pruning)
        return changed

    def grant(self):
        """Make every wanted grant, with its options.

        Returns True when a change was made (bool).
        """
        # Seeded before the loop, which does not run when every target role was
        # filtered out as non-existent or none was passed, so that the reported groups
        # are the ones asked for either way.
        for group in self.groups:
            self.granted.setdefault(group, [])

        # Read for every target role before anything is emitted, so that the grants
        # needed are known and can be checked against their granting roles up front.
        # Granting a group to one role does not touch another role's memberships, so
        # reading them all at once loses nothing.
        memberships = self._role_grants()
        needed = [self._needs_grant(wanted, self._grants_of(memberships, wanted))
                  for wanted in self.wanted]
        self._check_grantable([wanted for wanted, needs in zip(self.wanted, needed) if needs])

        for wanted, needs in zip(self.wanted, needed):
            self._warn_foreign_options(wanted, self._grants_of(memberships, wanted))
            if not needs:
                continue

            # One WITH list carrying every wanted option, not only the ones that
            # differ, so the statement states what the row states.
            query = 'GRANT %s TO %s' % (pg_quote_name(wanted['group']), pg_quote_name(wanted['role']))
            if wanted['options']:
                query += ' WITH %s' % ', '.join(
                    '%s %s' % (option, 'true' if setting else 'false')
                    for option, setting in sorted(wanted['options'].items()))
            query += self._granted_by(wanted['grantor'])

            self._execute(query)
            self._record(self.granted, wanted['group'], wanted['role'])

        return self.changed

    def revoke(self):
        """Revoke every wanted grant that exists.

        Returns True when a change was made (bool).
        """
        for group in self.groups:
            self.revoked.setdefault(group, [])

        # Revoking needs no ADMIN OPTION check: see _check_grantable. It does need the
        # grantor to be one the connecting role has the privileges of, which a
        # granted_by naming somebody else's grant need not be.
        memberships = self._role_grants()
        self._check_grantors_privileges(set(
            wanted['grantor'] for wanted in self.wanted
            if self._own_grant(self._grants_of(memberships, wanted), wanted['grantor']) is not None))

        for wanted in self.wanted:
            if self._revoke_own(wanted['group'], wanted['role'], wanted['grantor'],
                                self._grants_of(memberships, wanted)):
                self._record(self.revoked, wanted['group'], wanted['role'])

        return self.changed

    def prune(self):
        """Revoke every membership of the target roles that no row wants.

        Every group a target role is a member of is considered, whoever granted it, so
        that an unwanted membership this module cannot revoke is still reported instead
        of being silently left in place. What is revoked is the grant under the derived
        granting role: the groups being revoked are the ones no row named, so there is
        no row to take one from. granted_by on a state=absent task remains the way to
        remove somebody else's grant. The derived granting role needs no privilege
        check: it is CURRENT_ROLE, or the bootstrap superuser for a superuser, which
        has every role's privileges.

        Returns True when a change was made (bool).
        """
        wanted_groups = {}
        for wanted in self.wanted:
            wanted_groups.setdefault(wanted['role'], set()).add(wanted['group'])

        # revoked is not seeded: it lists the groups actually revoked, which are
        # discovered on the server rather than asked for. Sorted so the emitted
        # statements come out in a stable order.
        memberships = self._role_grants()
        for role in self.target_roles:
            for group in sorted(set(memberships[role]) - wanted_groups.get(role, set())):
                if self._revoke_own(group, role, self.derived_grantor, memberships[role][group],
                                    pruning=True):
                    self._record(self.revoked, group, role)

        return self.changed
