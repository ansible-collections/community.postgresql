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


class RoleCache(object):
    """Existence of roles, shared by the PgMembership objects of one task.

    A task naming several memberships builds one object per membership, and each
    checks the roles it was given. Without something shared, a name common to
    several of them is looked up once per object and, when fail_on_role is false,
    warned about that many times too.
    """

    def __init__(self):
        # Role name mapped to whether it exists, a dict of str to bool. Holds only
        # the names looked up so far.
        self.existence = {}

        # Names already warned about, a set of str, so the warning is emitted once
        # per task rather than once per object.
        self.warned = set()


def membership_option_name(option):
    """Return the parameter and column name of a membership option.

    Args:
        option (str) -- option keyword as PostgreSQL names it, from MEMBERSHIP_OPTIONS.

    Returns the name used by pg_auth_members and by the module parameter (str).
    """
    return '%s_option' % option.lower()


class PgMembership(object):
    def __init__(self, module, cursor, groups, target_roles, role_cache,
                 server_version, fail_on_role=True, membership_options=None,
                 granted_by=None):
        """Manage the membership of target_roles in groups.

        Throughout this class, "group" is the role whose membership is granted, "role"
        is the member role, and "grants" is the list of grants of that (group, role)
        pair as returned by __role_grants.

        Args:
            module (AnsibleModule) -- object of ansible.module_utils.basic.AnsibleModule class.
            cursor (psycopg cursor) -- database cursor object.
            groups (list) -- group roles whose membership is managed.
            target_roles (list) -- member roles that receive or lose the membership.
            role_cache (RoleCache) -- existence of roles, shared with the other objects
                of the same task so that a name several of them use is looked up, and
                warned about, once. Required rather than defaulted, since an object
                left with one of its own would silently repeat both.
            server_version (int) -- server version as returned by get_server_version.
                Decides whether memberships are per-grantor and whether the membership
                options can be set. Required rather than defaulted, since any default
                would name a version, and getting it wrong changes the model silently
                instead of failing.

        Kwargs:
            fail_on_role (bool) -- fail when a passed role does not exist, otherwise
                warn and skip it (default True).
            membership_options (dict) -- wanted membership options keyed by the
                PostgreSQL option keyword (ADMIN, INHERIT, SET), a value of None
                meaning "leave as it is" (default None).
            granted_by (str) -- role to record as the granting role, or None to derive
                it (default None).
        """
        self.module = module
        self.cursor = cursor
        self.role_cache = role_cache
        # Deduplicated: a repeated name would otherwise be processed twice against
        # the same snapshot, emitting the statement twice and adding the target role
        # twice to granted/revoked.
        self.target_roles = list(dict.fromkeys(r.strip() for r in target_roles))
        self.groups = list(dict.fromkeys(r.strip() for r in groups))
        self.executed_queries = []
        self.granted = {}
        self.revoked = {}
        self.fail_on_role = fail_on_role
        self.non_existent_roles = []
        self.changed = False

        # PostgreSQL 16 reshaped role membership: a (group, role) pair can be granted
        # independently by several roles, so a membership is identified by
        # (group, role, grantor), and each grant carries its own ADMIN, INHERIT and SET
        # options. The options are per grant precisely because grants are per grantor,
        # so one flag covers both. Before 16 pg_auth_members is unique on
        # (roleid, member), the grantor is not part of the membership identity, and
        # neither the option columns nor the GRANT ... WITH <option> <boolean> syntax
        # exist.
        self.per_grantor_membership = server_version >= 160000

        # The options the server records, which is also what report() gives back.
        # Kept as one list so that the column selected, the key of a grant and the
        # reported name are all derived from the same place. ADMIN is recorded on
        # every supported version; INHERIT and SET are columns PostgreSQL 16 added,
        # together with the per-grantor membership model.
        self.recorded_options = (MEMBERSHIP_OPTIONS if self.per_grantor_membership
                                 else ('ADMIN',))

        # Callers are responsible for not asking for options the server cannot set;
        # postgresql_membership rejects them before constructing this object.
        self.wanted_options = dict((name, setting)
                                   for name, setting in (membership_options or dict()).items()
                                   if setting is not None)

        # Set by __resolve_grantor. A superuser may act as any role, so the check
        # that the connection has the grantor's privileges does not apply to it.
        self.connected_as_superuser = False

        # Set by __resolve_grantor. PostgreSQL waives the ADMIN OPTION requirement
        # for the bootstrap superuser and for nobody else, not even another
        # superuser, so the check that the grantor holds it is skipped only then.
        self.grantor_is_bootstrap = False

        self.grantor = self.__resolve_grantor(granted_by) if self.per_grantor_membership else None

        self.__check_roles_exist()

    def __resolve_grantor(self, granted_by):
        """Return the role to record as the grantor of the grants this module makes.

        The module names the grantor rather than letting PostgreSQL pick one, so that
        it recognizes its own grant among the grants of a pair on a later run.

        Returns the bootstrap superuser when connected as a superuser, since that is
        what PostgreSQL records for any superuser's grant, and CURRENT_ROLE otherwise.
        CURRENT_ROLE is not what PostgreSQL would pick for a non-superuser holding
        ADMIN OPTION indirectly, which is why granted_by exists.

        Args:
            granted_by (str) -- grantor requested by the caller, or None to derive it.

        Returns a role name (str).
        """
        # Stripped like groups and target_roles are, so a value carrying whitespace
        # from a lookup is not reported as a role that does not exist.
        granted_by = granted_by.strip() if granted_by else None

        # pg_authid is readable by superusers only, so the bootstrap superuser is
        # looked up by its fixed OID in pg_roles, which every role can select from.
        query = ("SELECT CURRENT_ROLE AS current_role, "
                 "(SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = CURRENT_ROLE) AS is_super, "
                 "(SELECT rolname FROM pg_catalog.pg_roles WHERE oid = 10) AS bootstrap")

        row = exec_sql(self, query, add_to_executed=False)[0]
        self.connected_as_superuser = row['is_super']

        if granted_by:
            # A grantor that does not exist would make state=present die with a raw
            # server error and state=absent match nothing, exiting changed=false with
            # the membership still in place. Reject it here instead.
            if not self.__roles_exist([granted_by]):
                self.module.fail_json(msg="The granted_by role %s does not exist" % granted_by)

            grantor = granted_by
        else:
            grantor = row['bootstrap'] if row['is_super'] else row['current_role']

        self.grantor_is_bootstrap = grantor == row['bootstrap']
        return grantor

    def __is_ours(self, grant):
        """Return whether this is the grant the module manages.

        Before PostgreSQL 16 a pair has only one grant, so it is always ours.

        Args:
            grant (dict) -- a grant as returned by __role_grants.

        Returns True when the grant is the one we manage (bool).
        """
        return not self.per_grantor_membership or grant['grantor'] == self.grantor

    def __own_grant(self, grants):
        """Return the grant the module manages, or None.

        Args:
            grants (list) -- grants of a pair as returned by __role_grants.

        Returns the grant we manage (dict), or None when the pair has none.
        """
        return next((grant for grant in grants if self.__is_ours(grant)), None)

    def __foreign_grants(self, grants):
        """Return the grants of a pair made by other roles.

        Args:
            grants (list) -- grants of a pair as returned by __role_grants.

        Returns the grants made by other roles (list of dict).
        """
        return [grant for grant in grants if not self.__is_ours(grant)]

    def __warn_foreign_membership(self, group, role, grants):
        """Warn that grants made by other roles keep the membership alive.

        Reads grants captured before the change, so it is check_mode safe.

        Args:
            group (str) -- group role the membership is of.
            role (str) -- member role.
            grants (list) -- grants of the pair as returned by __role_grants.
        """
        foreign = self.__foreign_grants(grants)
        grantors = sorted(grant['grantor'] for grant in foreign
                          if grant['grantor'] is not None)

        if grantors:
            self.module.warn(
                'Role "%s" remains a member of "%s" through the grant(s) made by %s. '
                'This module manages the grant recorded as made by "%s", so the membership '
                'and its effective options are not fully removed. Set granted_by to manage '
                'one of the other grants instead, when the connecting role holds the '
                'privileges of that granting role.'
                % (role, group, ", ".join('"%s"' % g for g in grantors), self.grantor))

        # A grant whose grantor OID no longer resolves has no name to put in GRANTED BY,
        # so it cannot be revoked that way at all. Say so rather than staying silent.
        # Rare: PostgreSQL 16 refuses to drop a role that a grant records as its grantor,
        # so this only fires on a cluster upgraded from 15 or earlier carrying such a row.
        if len(grantors) < len(foreign):
            self.module.warn(
                'Role "%s" remains a member of "%s" through a grant whose granting role '
                'no longer exists. Naming a grantor cannot revoke it, so the membership '
                'has to be removed another way.' % (role, group))

    def __warn_foreign_options(self, group, role, grants):
        """Warn that grants made by other roles keep an option the caller cleared.

        Reads grants captured before the change, so it is check_mode safe.

        Args:
            group (str) -- group role the membership is of.
            role (str) -- member role.
            grants (list) -- grants of the pair as returned by __role_grants.
        """
        foreign = self.__foreign_grants(grants)
        if not foreign:
            return

        for option, wanted in self.wanted_options.items():
            if wanted:
                continue

            grantors = sorted(grant['grantor'] for grant in foreign
                              if grant[option] and grant['grantor'] is not None)
            if grantors:
                self.module.warn(
                    'Role "%s" keeps the %s option on "%s" through the grant(s) made by %s. '
                    'This module manages the grant recorded as made by "%s", so %s_option=false '
                    'does not remove it.'
                    % (role, option, group, ", ".join('"%s"' % g for g in grantors),
                       self.grantor, option.lower()))

    def __check_grantor_assumable(self):
        """Fail unless the connecting role has the privileges of the grantor.

        PostgreSQL lets a role record a grant as another role, and revoke one recorded
        under it, only when it has that role's privileges, which is has_privs_of_role
        and so pg_has_role(..., 'USAGE'). Not 'SET': the two differ on a membership
        granted WITH INHERIT TRUE, SET FALSE, which carries the privileges without
        being assumable, and on its opposite. Checked from the paths that
        emit a statement rather than where the grantor is resolved, so that a task with
        nothing left to do keeps succeeding. Always true for the derived grantor, so
        this only ever rejects a granted_by.
        """
        if not self.per_grantor_membership or self.connected_as_superuser:
            return

        assumable = exec_sql(self, "SELECT pg_catalog.pg_has_role(%s, 'USAGE') AS assumable",
                             query_params=(self.grantor,),
                             add_to_executed=False)[0]['assumable']

        if not assumable:
            self.module.fail_json(
                msg='The connecting role cannot act as the granting role "%s", because it '
                    'does not have the privileges of that role. Set granted_by to a role it '
                    'does have the privileges of.' % self.grantor)

    def __check_grantable(self, groups):
        """Fail unless the grantor holds ADMIN OPTION on every group passed.

        A statement that does not name a granting role makes PostgreSQL pick one, and
        it picks per group: the connecting role itself when it holds ADMIN OPTION on
        that group, otherwise a role it can assume that does. This module names one
        role for the whole task, so a group that role cannot grant has to be reported
        here. Left to the server it raises an error naming neither the option that is
        missing nor a role that holds it, which is what the caller needs to fix it.

        Only called for granting. PostgreSQL refuses to revoke ADMIN OPTION while a
        grant made under it exists, so a grant this module finds under its own grantor
        can always be revoked.

        Args:
            groups (set) -- groups a GRANT would be emitted for.
        """
        if not self.per_grantor_membership or not groups:
            return

        self.__check_grantor_assumable()

        # The one grantor PostgreSQL asks nothing of. Every other role has to hold the
        # option in pg_auth_members, a superuser included, so being connected as one
        # does not make the query below unnecessary.
        if self.grantor_is_bootstrap:
            return

        # LEFT JOINed so that a group nobody holds ADMIN OPTION on still comes back as
        # a row, which is what separates the three ways this can go wrong. holders are
        # all the roles that hold it, candidates the ones the connection could also
        # name, which for a superuser is all of them.
        query = """SELECT g.rolname AS grp,
                          coalesce(bool_or(a.rolname = %s), false) AS grantor_ok,
                          coalesce(array_agg(a.rolname ORDER BY a.rolname)
                                   FILTER (WHERE a.rolname IS NOT NULL), '{}') AS holders,
                          coalesce(array_agg(a.rolname ORDER BY a.rolname)
                                   FILTER (WHERE pg_catalog.pg_has_role(a.oid, 'USAGE')),
                                   '{}') AS candidates
                   FROM pg_catalog.pg_roles g
                   LEFT JOIN pg_catalog.pg_auth_members m
                     ON m.roleid = g.oid AND m.admin_option
                   LEFT JOIN pg_catalog.pg_roles a ON a.oid = m.member
                   WHERE g.rolname = ANY(%s)
                   GROUP BY g.rolname"""

        needs_other_grantor = {}
        out_of_reach = {}
        nobody_holds_it = []
        for row in exec_sql(self, query, query_params=(self.grantor, sorted(groups)),
                            add_to_executed=False):
            if row['grantor_ok']:
                continue

            if row['candidates']:
                needs_other_grantor[row['grp']] = row['candidates']
            elif row['holders']:
                out_of_reach[row['grp']] = row['holders']
            else:
                nobody_holds_it.append(row['grp'])

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

        if needs_other_grantor:
            msg.append('The granting role "%s" does not hold ADMIN OPTION on %s. Set '
                       'granted_by to a role that does (%s). granted_by applies to every '
                       'group of the task, so groups needing a different granting role '
                       'have to be split into separate tasks or given a memberships row '
                       'each.'
                       % (self.grantor,
                          ", ".join('"%s"' % g for g in sorted(needs_other_grantor)),
                          "; ".join('%s: %s' % (g, ", ".join(needs_other_grantor[g]))
                                    for g in sorted(needs_other_grantor))))

        if msg:
            self.module.fail_json(msg=" ".join(msg))

    def __granted_by(self):
        """Return the GRANTED BY clause, empty before PostgreSQL 16.

        Guarded on the same flag as __is_ours, so the statement emitted and the grant
        recognized cannot diverge.

        Returns the clause to append to a GRANT or REVOKE (str).
        """
        if not self.per_grantor_membership:
            return ''

        return ' GRANTED BY %s' % pg_quote_name(self.grantor)

    def __needs_grant(self, grants):
        """Return whether a GRANT has to be emitted for a pair.

        Shared with __groups_to_grant so that the groups the grantor is checked
        against are exactly the ones a statement is emitted for. Checking the
        others would fail a task that has nothing left to do, which is the run
        that has to stay green.

        Args:
            grants (list) -- grants of the pair as returned by __role_grants.

        Returns True when a GRANT is needed (bool).
        """
        current = self.__own_grant(grants)
        return current is None or any(current[option] != wanted
                                      for option, wanted in self.wanted_options.items())

    def __groups_to_grant(self, memberships):
        """Return the groups a GRANT would be emitted for, over all target roles.

        Args:
            memberships (dict) -- target role mapped to its grants keyed by group,
                as returned by __role_grants.

        Returns the group names (set).
        """
        return set(group for role_grants in memberships.values()
                   for group in self.groups
                   if self.__needs_grant(role_grants.get(group, [])))

    def __anything_to_revoke(self, memberships):
        """Return whether a REVOKE would be emitted for one of self.groups.

        What state=absent revokes.

        Args:
            memberships (dict) -- target role mapped to its grants keyed by group,
                as returned by __all_role_grants.

        Returns True when at least one REVOKE is needed (bool).
        """
        return any(self.__own_grant(role_grants.get(group, [])) is not None
                   for role_grants in memberships.values()
                   for group in self.groups)

    def __anything_to_prune(self, memberships):
        """Return whether a REVOKE would be emitted for a group nobody asked for.

        What state=exact revokes, the groups a target role is a member of that
        self.groups does not name.

        Args:
            memberships (dict) -- target role mapped to its grants keyed by group,
                as returned by __all_role_grants.

        Returns True when at least one REVOKE is needed (bool).
        """
        return any(self.__own_grant(role_grants.get(group, [])) is not None
                   for role_grants in memberships.values()
                   for group in set(role_grants) - set(self.groups))

    def __grant(self, group, role, grants):
        """Grant group to role and apply the wanted options.

        Only the module's own grant is compared, so a membership granted by another
        role does not suppress our GRANT (issue #757).

        Args:
            group (str) -- group role that is granted.
            role (str) -- member role that receives it.
            grants (list) -- grants of the pair as returned by __role_grants.

        Returns True when a change was made (bool).
        """
        self.__warn_foreign_options(group, role, grants)
        if not self.__needs_grant(grants):
            return False

        # PostgreSQL takes the options as one comma-separated list, and every
        # wanted option has to be restated in the statement that carries them.
        query = 'GRANT %s TO %s' % (pg_quote_name(group), pg_quote_name(role))
        if self.wanted_options:
            query += ' WITH %s' % ', '.join(
                '%s %s' % (option, 'true' if wanted else 'false')
                for option, wanted in sorted(self.wanted_options.items()))
        query += self.__granted_by()

        changed = exec_sql(self, query, return_bool=True)
        self.changed |= changed
        return changed

    def __revoke(self, group, role, grants):
        """Revoke the module's own grant of group to role.

        REVOKE removes only the grant under the grantor it names, so on PostgreSQL 16+
        another role's grant survives and is warned about.

        Args:
            group (str) -- group role that is revoked.
            role (str) -- member role that loses it.
            grants (list) -- grants of the pair as returned by __role_grants.

        Returns True when a change was made (bool).
        """
        changed = False
        if self.__own_grant(grants) is not None:
            query = 'REVOKE %s FROM %s%s' % (
                pg_quote_name(group), pg_quote_name(role), self.__granted_by())
            changed = exec_sql(self, query, return_bool=True)
            self.changed |= changed

        self.__warn_foreign_membership(group, role, grants)
        return changed

    def __role_grants(self, role):
        """Return every membership of role, keyed by group.

        Args:
            role (str) -- member role.

        Returns a dict mapping a group name (str) to its grants (list of dict). A grant
        holds 'grantor' plus the options the server records, keyed by the PostgreSQL
        keyword.
        """
        columns = ", ".join("m.%s" % membership_option_name(option)
                            for option in self.recorded_options)

        # The grantor is LEFT JOINed: before PostgreSQL 16 dropping a role did not
        # check pg_auth_members.grantor, so a membership can reference an OID that
        # no longer resolves. An inner join would hide such a membership entirely
        # and state=absent would silently leave it in place.
        query = """SELECT g.rolname AS grp, gr.rolname AS grantor, %s
                   FROM pg_catalog.pg_auth_members m
                   JOIN pg_catalog.pg_roles g ON m.roleid = g.oid
                   JOIN pg_catalog.pg_roles u ON m.member = u.oid
                   LEFT JOIN pg_catalog.pg_roles gr ON m.grantor = gr.oid
                   WHERE u.rolname = %%s;""" % columns

        memberships = {}
        for row in exec_sql(self, query, query_params=(role,),
                            add_to_executed=False):
            grant = dict(grantor=row['grantor'])
            for option in self.recorded_options:
                grant[option] = row[membership_option_name(option)]
            memberships.setdefault(row['grp'], []).append(grant)
        return memberships

    def __all_role_grants(self):
        """Return the grants of every target role, keyed by role then group.

        Returns a dict mapping a target role (str) to what __role_grants returns for
        it (dict).
        """
        return dict((role, self.__role_grants(role)) for role in self.target_roles)

    def grant(self):
        """Grant every group to every target role, with the wanted options.

        Returns True when a change was made (bool).
        """
        # Seeded outside the loop below, which does not run when every target role was
        # filtered out as non-existent or none was passed, so that the reported groups
        # are the ones asked for either way.
        for group in self.groups:
            self.granted.setdefault(group, [])

        # Read for every target role before anything is emitted, so that the groups a
        # GRANT is needed for are known and can be checked against the grantor's
        # privileges up front. Granting a group to one role does not touch another
        # role's memberships, so reading them all at once loses nothing.
        memberships = self.__all_role_grants()
        self.__check_grantable(self.__groups_to_grant(memberships))

        for role in self.target_roles:
            for group in self.groups:
                if self.__grant(group, role, memberships[role].get(group, [])):
                    self.granted[group].append(role)

        return self.changed

    def revoke(self):
        """Revoke the module's own grant of every group from every target role.

        Returns True when a change was made (bool).
        """
        for group in self.groups:
            self.revoked.setdefault(group, [])

        # Revoking needs no ADMIN OPTION check, since PostgreSQL refuses to revoke the
        # option while a grant made under it exists. It does need the grantor to be one
        # the connection can act as, which a granted_by naming somebody else's grant
        # need not be.
        memberships = self.__all_role_grants()
        if self.__anything_to_revoke(memberships):
            self.__check_grantor_assumable()

        for role in self.target_roles:
            for group in self.groups:
                if self.__revoke(group, role, memberships[role].get(group, [])):
                    self.revoked[group].append(role)

        return self.changed

    def prune(self):
        """Revoke every membership of the target roles outside self.groups.

        Split out of match() so that a task naming several memberships can prune
        once against the union of everything it wants, rather than once per
        membership, where each would revoke what the others asked for.

        Returns True when a change was made (bool).
        """
        # revoked is not seeded: it lists the groups actually revoked, which are
        # discovered on the server rather than asked for.
        all_memberships = self.__all_role_grants()

        # Revoking needs no ADMIN OPTION check, for the reason given in revoke(), but
        # it does need a grantor the connection can act as.
        if self.__anything_to_prune(all_memberships):
            self.__check_grantor_assumable()

        for role in self.target_roles:
            role_grants = all_memberships[role]

            # Every group the role is a member of is considered, whoever granted it,
            # so that an unwanted membership this module cannot revoke is still
            # reported instead of being silently left in place. __revoke revokes the
            # grant we manage, if any, and warns about the rest.
            #
            # Discovered on the server rather than named by the caller, so they are
            # sorted to keep the emitted statements in a stable order.
            for group in sorted(set(role_grants) - set(self.groups)):
                if self.__revoke(group, role, role_grants.get(group, [])):
                    self.revoked.setdefault(group, []).append(role)

        return self.changed

    def match(self):
        """Leave the target roles a member of self.groups and of nothing else.

        Returns True when a change was made (bool).
        """
        # Pruning first and granting second, rather than both per role, so that the
        # two halves stay the same code the multi-membership path runs.
        self.prune()

        # grant() is idempotent and also reconciles the options of memberships that
        # already exist, so it runs for every desired group, not only the new ones.
        return self.grant()

    def report(self):
        """Return the grants and effective options of the requested pairs.

        Includes grants the module does not manage, since PostgreSQL applies the
        options as their union. Only pairs where role is a member.

        Returns two dicts keyed by group then target role: the grants of each pair
        (list of dict) and the options the target role effectively holds (dict of str
        to bool).
        """
        grants = {}
        effective_options = {}

        for role in self.target_roles:
            memberships = self.__role_grants(role)

            for group in self.groups:
                role_grants = memberships.get(group)
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

    def __check_roles_exist(self):
        """Fail or warn about the passed roles that do not exist.

        Drops them from self.groups and self.target_roles when fail_on_role is false,
        so that everything downstream works on names known to exist.
        """
        if self.groups:
            existent_groups = self.__roles_exist(self.groups)

            for group in self.groups:
                if group not in existent_groups:
                    if self.fail_on_role:
                        self.module.fail_json(msg="Role %s does not exist" % group)
                    else:
                        self.__warn_once("Role %s does not exist, pass" % group, group)
                        self.non_existent_roles.append(group)

        existent_roles = self.__roles_exist(self.target_roles)
        for role in self.target_roles:
            if role not in existent_roles:
                if self.fail_on_role:
                    self.module.fail_json(msg="Role %s does not exist" % role)
                else:
                    self.__warn_once("Role %s does not exist, pass" % role, role)

                if role not in self.groups:
                    self.non_existent_roles.append(role)

                else:
                    # fail_on_role is necessarily false here: the branch above already
                    # exited through fail_json when it was true.
                    self.module.warn("Role role '%s' is a member of role '%s', pass" % (role, role))

        # Update role lists, excluding non existent roles:
        if self.groups:
            self.groups = [g for g in self.groups if g not in self.non_existent_roles]

        self.target_roles = [r for r in self.target_roles if r not in self.non_existent_roles]

    def __warn_once(self, message, role):
        """Warn about a role only the first time it comes up in the task.

        Args:
            message (str) -- warning to emit.
            role (str) -- role the warning is about, used as the key.
        """
        if role in self.role_cache.warned:
            return

        self.role_cache.warned.add(role)
        self.module.warn(message)

    def __roles_exist(self, roles):
        """Return the subset of roles that exist.

        One array parameter, so the driver quotes the names and an empty list matches
        nothing instead of building an invalid "IN ()".

        Args:
            roles (list) -- role names to look up.

        Returns the names that exist (list of str).
        """
        unknown = [role for role in roles if role not in self.role_cache.existence]
        if unknown:
            query = "SELECT rolname FROM pg_catalog.pg_roles WHERE rolname = ANY(%s)"
            found = set(row["rolname"] for row in
                        exec_sql(self, query, query_params=(unknown,), add_to_executed=False))

            for role in unknown:
                self.role_cache.existence[role] = role in found

        return [role for role in roles if self.role_cache.existence[role]]
