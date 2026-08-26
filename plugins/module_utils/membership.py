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

# ADMIN is recorded on every supported version. INHERIT and SET are columns
# PostgreSQL 16 added, together with the per-grantor membership model.
PRE_16_MEMBERSHIP_OPTIONS = ('ADMIN',)


def membership_option_name(option):
    """Return the parameter and column name of a membership option.

    Args:
        option (str) -- option keyword as PostgreSQL names it, from MEMBERSHIP_OPTIONS.

    Returns the name used by pg_auth_members and by the module parameter (str).
    """
    return '%s_option' % option.lower()


class PgMembership(object):
    def __init__(self, module, cursor, groups, target_roles, fail_on_role=True,
                 membership_options=None, server_version=0, granted_by=None):
        """Manage the membership of target_roles in groups.

        Throughout this class, "group" is the role whose membership is granted, "role"
        is the member role, and "grants" is the list of grants of that (group, role)
        pair as returned by __role_grants.

        Args:
            module (AnsibleModule) -- object of ansible.module_utils.basic.AnsibleModule class.
            cursor (psycopg cursor) -- database cursor object.
            groups (list) -- group roles whose membership is managed.
            target_roles (list) -- member roles that receive or lose the membership.

        Kwargs:
            fail_on_role (bool) -- fail when a passed role does not exist, otherwise
                warn and skip it (default True).
            membership_options (dict) -- wanted membership options keyed by the
                PostgreSQL option keyword (ADMIN, INHERIT, SET), a value of None
                meaning "leave as it is" (default None).
            server_version (int) -- server version as returned by get_server_version.
                Decides whether memberships are per-grantor and whether the membership
                options can be set (default 0).
            granted_by (str) -- role to record as the granting role, or None to derive
                it (default None).
        """
        self.module = module
        self.cursor = cursor
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
        # reported name are all derived from the same place.
        self.recorded_options = (MEMBERSHIP_OPTIONS if self.per_grantor_membership
                                 else PRE_16_MEMBERSHIP_OPTIONS)

        # Callers are responsible for not asking for options the server cannot set;
        # postgresql_membership rejects them before constructing this object.
        self.wanted_options = dict((name, setting)
                                   for name, setting in (membership_options or dict()).items()
                                   if setting is not None)

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

        if granted_by:
            # A grantor that does not exist would make state=present die with a raw
            # server error and state=absent match nothing, exiting changed=false with
            # the membership still in place. Reject it here instead.
            if not self.__roles_exist([granted_by]):
                self.module.fail_json(msg="The granted_by role %s does not exist" % granted_by)

            return granted_by

        # pg_authid is readable by superusers only, so the bootstrap superuser is
        # looked up by its fixed OID in pg_roles, which every role can select from.
        query = ("SELECT CURRENT_ROLE AS current_role, "
                 "(SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = CURRENT_ROLE) AS is_super, "
                 "(SELECT rolname FROM pg_catalog.pg_roles WHERE oid = 10) AS bootstrap")

        row = exec_sql(self, query, add_to_executed=False)[0]
        return row['bootstrap'] if row['is_super'] else row['current_role']

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
        """
        return next((grant for grant in grants if self.__is_ours(grant)), None)

    def __foreign_grants(self, grants):
        """Return the grants of a pair made by other roles.

        Args:
            grants (list) -- grants of a pair as returned by __role_grants.
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

    def __granted_by(self):
        """Return the GRANTED BY clause, empty before PostgreSQL 16.

        Guarded on the same flag as __is_ours, so the statement emitted and the grant
        recognized cannot diverge.
        """
        if not self.per_grantor_membership:
            return ''

        return ' GRANTED BY %s' % pg_quote_name(self.grantor)

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
        current = self.__own_grant(grants)
        if current is not None and all(current[option] == wanted
                                       for option, wanted in self.wanted_options.items()):
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

        Returns a dict mapping a group name to its list of grants. A grant is a dict of
        'grantor' plus the options the server records, keyed by the PostgreSQL keyword.
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

    def grant(self):
        # Seeded outside the loop below, which does not run when every target role was
        # filtered out as non-existent or none was passed, so that the reported groups
        # are the ones asked for either way.
        for group in self.groups:
            self.granted.setdefault(group, [])

        for role in self.target_roles:
            memberships = self.__role_grants(role)

            for group in self.groups:
                if self.__grant(group, role, memberships.get(group, [])):
                    self.granted[group].append(role)

        return self.changed

    def revoke(self):
        for group in self.groups:
            self.revoked.setdefault(group, [])

        for role in self.target_roles:
            memberships = self.__role_grants(role)

            for group in self.groups:
                if self.__revoke(group, role, memberships.get(group, [])):
                    self.revoked[group].append(role)

        return self.changed

    def match(self):
        # Only the granted side is seeded: revoked lists the groups actually revoked,
        # which are discovered on the server rather than asked for.
        for group in self.groups:
            self.granted.setdefault(group, [])

        for role in self.target_roles:
            memberships = self.__role_grants(role)

            # Every group the role is a member of is considered, whoever granted
            # it, so that an unwanted membership this module cannot revoke is
            # still reported instead of being silently left in place. __revoke
            # revokes the grant we manage, if any, and warns about the rest.
            unwanted_groups = set(memberships) - set(self.groups)

            # 1. Revoke the groups the role is a member of but that are not wanted.
            # They are discovered on the server rather than named by the caller, so
            # they are sorted to keep the emitted statements in a stable order.
            for group in sorted(unwanted_groups):
                if self.__revoke(group, role, memberships.get(group, [])):
                    self.revoked.setdefault(group, []).append(role)

            # 2. Ensure the role is a member of every desired group with the
            # wanted options. __grant is idempotent and also reconciles the
            # options of memberships that already exist, so it runs for all
            # desired groups, not only the newly added ones. self.groups is
            # iterated rather than a set of it so the statements come out in the
            # order the caller asked for.
            for group in self.groups:
                if self.__grant(group, role, memberships.get(group, [])):
                    self.granted[group].append(role)

        return self.changed

    def report(self):
        """Return the grants and effective options of the requested pairs.

        Includes grants the module does not manage, since PostgreSQL applies the
        options as their union. Only pairs where role is a member.

        Returns two dicts keyed by group then target role.
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
        if self.groups:
            existent_groups = self.__roles_exist(self.groups)

            for group in self.groups:
                if group not in existent_groups:
                    if self.fail_on_role:
                        self.module.fail_json(msg="Role %s does not exist" % group)
                    else:
                        self.module.warn("Role %s does not exist, pass" % group)
                        self.non_existent_roles.append(group)

        existent_roles = self.__roles_exist(self.target_roles)
        for role in self.target_roles:
            if role not in existent_roles:
                if self.fail_on_role:
                    self.module.fail_json(msg="Role %s does not exist" % role)
                else:
                    self.module.warn("Role %s does not exist, pass" % role)

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

    def __roles_exist(self, roles):
        """Return the subset of roles that exist.

        One array parameter, so the driver quotes the names and an empty list matches
        nothing instead of building an invalid "IN ()".

        Args:
            roles (list) -- role names to look up.

        Returns the names that exist (list of str).
        """
        query = "SELECT rolname FROM pg_catalog.pg_roles WHERE rolname = ANY(%s)"
        rows = exec_sql(self, query, query_params=(roles,), add_to_executed=False)
        return [row["rolname"] for row in rows]
