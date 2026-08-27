# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# Copyright (c), Ted Timmons <ted@timmons.me>, 2017.
# Most of this was originally added by other creators in the postgresql_user module.
#
# Simplified BSD License (see simplified_bsd.txt or https://opensource.org/licenses/BSD-2-Clause)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from datetime import timedelta, datetime
from decimal import Decimal
from os import environ

from ansible.module_utils.common.text.converters import to_native
from ansible.module_utils.basic import missing_required_lib
from ansible_collections.community.postgresql.plugins.module_utils.database import \
    pg_quote_name
from ansible_collections.community.postgresql.plugins.module_utils.version import \
    LooseVersion

psycopg = None  # This line is needed for unit tests
psycopg2 = None  # This line is needed for unit tests
pg_cursor_args = None  # This line is needed for unit tests
PSYCOPG_VERSION = LooseVersion("0.0")  # This line is needed for unit tests

try:
    import psycopg
    from psycopg import ClientCursor
    from psycopg.rows import dict_row

    from psycopg.types.datetime import TimestamptzLoader

    # We need Psycopg 3 to be at least 3.1.0 because we need Client-side-binding cursors
    # When a Linux distribution provides both Psycopg2 and Psycopg 3.0 we will use Psycopg2
    PSYCOPG_VERSION = LooseVersion(psycopg.__version__)
    if PSYCOPG_VERSION < LooseVersion("3.1"):
        raise ImportError
    HAS_PSYCOPG = True
    pg_cursor_args = {"row_factory": psycopg.rows.dict_row}
except ImportError:
    try:
        import psycopg2
        psycopg = psycopg2
        from psycopg2.extras import DictCursor
        PSYCOPG_VERSION = LooseVersion(psycopg2.__version__)
        HAS_PSYCOPG = True
        pg_cursor_args = {"cursor_factory": DictCursor}
    except ImportError:
        HAS_PSYCOPG = False

TYPES_NEED_TO_CONVERT = (Decimal, timedelta)


if PSYCOPG_VERSION >= LooseVersion("3"):
    class InfTimestamptzLoader(TimestamptzLoader):
        def load(self, data):
            if data == b"infinity":
                return datetime.max
            elif data == b"-infinity":
                return datetime.min
            else:
                return super().load(data)

    psycopg.adapters.register_loader("timestamptz", InfTimestamptzLoader)


def postgres_common_argument_spec():
    """
    Return a dictionary with connection options.

    The options are commonly used by most of PostgreSQL modules.
    """
    # Getting a dictionary of environment variables
    env_vars = environ

    return dict(
        login_user=dict(
            default='postgres' if not env_vars.get("PGUSER") else env_vars.get("PGUSER"),
            aliases=['login'], deprecated_aliases=[
                {
                    'name': 'login',
                    'version': '5.0.0',
                    'collection_name': 'community.postgresql',
                }
            ],
        ),
        login_password=dict(default='', no_log=True),
        login_host=dict(default='', aliases=['host'], deprecated_aliases=[
            {
                'name': 'host',
                'version': '5.0.0',
                'collection_name': 'community.postgresql',
            }],
        ),
        login_unix_socket=dict(default='', aliases=['unix_socket'], deprecated_aliases=[
            {
                'name': 'unix_socket',
                'version': '5.0.0',
                'collection_name': 'community.postgresql',
            }],
        ),
        login_port=dict(
            type='int',
            default=int(env_vars.get("PGPORT", 5432)),
            aliases=['port'], deprecated_aliases=[
                {
                    'name': 'port',
                    'version': '5.0.0',
                    'collection_name': 'community.postgresql',
                }
            ],
        ),
        ssl_mode=dict(
            default='prefer',
            choices=[
                'allow',
                'disable',
                'prefer',
                'require',
                'verify-ca',
                'verify-full'
            ]
        ),
        ca_cert=dict(aliases=['ssl_rootcert']),
        ssl_cert=dict(type='path'),
        ssl_key=dict(type='path'),
        connect_params=dict(default={}, type='dict'),
    )


def ensure_required_libs(module):
    """Check required libraries."""
    if not HAS_PSYCOPG:
        # TODO: Should we raise it as psycopg? That will be a breaking change
        module.fail_json(msg=missing_required_lib('psycopg2'))

    elif PSYCOPG_VERSION < LooseVersion("2.5.1"):
        module.warn("psycopg should be at least 2.5.1 to support all modules functionality")

    if module.params.get('ca_cert') and PSYCOPG_VERSION < LooseVersion('2.4.3'):
        module.fail_json(msg='psycopg2 must be at least 2.4.3 in order to use the ca_cert parameter')


def connect_to_db(module, conn_params, autocommit=False, fail_on_conn=True):
    """Connect to a PostgreSQL database.

    Return a tuple containing a psycopg connection object and error message / None.

    Args:
        module (AnsibleModule) -- object of ansible.module_utils.basic.AnsibleModule class
        conn_params (dict) -- dictionary with connection parameters

    Kwargs:
        autocommit (bool) -- commit automatically (default False)
        fail_on_conn (bool) -- fail if connection failed or just warn and return None (default True)
    """

    db_connection = None
    conn_err = None
    try:
        if PSYCOPG_VERSION >= LooseVersion("3.0"):
            conn_params["autocommit"] = autocommit
            conn_params["cursor_factory"] = ClientCursor
            conn_params["row_factory"] = dict_row
            db_connection = psycopg.connect(**conn_params)
        else:
            db_connection = psycopg2.connect(**conn_params)
            if autocommit:
                if PSYCOPG_VERSION >= LooseVersion("2.4.2"):
                    db_connection.set_session(autocommit=True)
                else:
                    db_connection.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)

        # Switch role, if specified:
        if module.params.get('session_role'):
            if PSYCOPG_VERSION >= LooseVersion("3.0"):
                cursor = db_connection.cursor(row_factory=psycopg.rows.dict_row)
            else:
                cursor = db_connection.cursor(cursor_factory=psycopg2.extras.DictCursor)

            try:
                cursor.execute('SET ROLE %s' % pg_quote_name(module.params['session_role']))
            except Exception as e:
                module.fail_json(msg="Could not switch role: %s" % to_native(e))
            finally:
                cursor.close()

        # Ensure proper datestyle, only supported in psycopg 3
        if PSYCOPG_VERSION >= LooseVersion("3.0"):
            cursor = db_connection.cursor(row_factory=psycopg.rows.dict_row)
            try:
                cursor.execute('SET datestyle TO iso')
            except Exception as e:
                module.fail_json(msg="Could not set date style: %s" % to_native(e))
            finally:
                cursor.close()

    except TypeError as e:
        if 'sslrootcert' in e.args[0]:
            module.fail_json(msg='Postgresql server must be at least '
                                 'version 8.4 to support sslrootcert')

        conn_err = to_native(e)

    except Exception as e:
        conn_err = to_native(e)

    if conn_err is not None:
        if fail_on_conn:
            module.fail_json(msg="unable to connect to database: %s" % conn_err)
        else:
            module.warn("PostgreSQL server is unavailable: %s" % conn_err)
            db_connection = None

    return db_connection, conn_err


def exec_sql(obj, query, query_params=None, return_bool=False, add_to_executed=True, dont_exec=False):
    """Execute SQL.

    Auxiliary function for PostgreSQL user classes.

    Returns a query result if possible or a boolean value.

    Args:
        obj (obj) -- must be an object of a user class.
            The object must have module (AnsibleModule class object) and
            cursor (psycopg cursor object) attributes
        query (str) -- SQL query to execute

    Kwargs:
        query_params (dict or tuple) -- Query parameters to prevent SQL injections,
            could be a dict or tuple
        return_bool (bool) -- return True instead of rows if a query was successfully executed.
            It's necessary for statements that don't return any result like DDL queries (default False).
        add_to_executed (bool) -- append the query to obj.executed_queries attribute
        dont_exec (bool) -- used with add_to_executed=True to generate a query, add it
            to obj.executed_queries list and return True (default False)
    """

    if dont_exec:
        # This is usually needed to return queries in check_mode
        # without execution
        query = obj.cursor.mogrify(query, query_params)
        if add_to_executed:
            obj.executed_queries.append(query)

        return True

    try:
        if query_params is not None:
            obj.cursor.execute(query, query_params)
        else:
            obj.cursor.execute(query)

        if add_to_executed:
            if query_params is not None:
                obj.executed_queries.append(obj.cursor.mogrify(query, query_params))
            else:
                obj.executed_queries.append(query)

        if not return_bool:
            res = obj.cursor.fetchall()
            return res
        return True
    except Exception as e:
        obj.module.fail_json(msg="Cannot execute SQL '%s': %s" % (query, to_native(e)))
    return False


def get_conn_params(module, params_dict, warn_db_default=True):
    """Get connection parameters from the passed dictionary.

    Return a dictionary with parameters to connect to PostgreSQL server.

    Args:
        module (AnsibleModule) -- object of ansible.module_utils.basic.AnsibleModule class
        params_dict (dict) -- dictionary with variables

    Kwargs:
        warn_db_default (bool) -- warn that the default DB is used (default True)
    """

    # To use defaults values, keyword arguments must be absent, so
    # check which values are empty and don't include in the return dictionary
    params_map = {
        "login_host": "host",
        "login_user": "user",
        "login_password": "password",
        "login_port": "port",
        "ssl_mode": "sslmode",
        "ca_cert": "sslrootcert",
        "ssl_cert": "sslcert",
        "ssl_key": "sslkey",
    }

    # Might be different in the modules:
    if PSYCOPG_VERSION >= LooseVersion("2.7.0"):
        if params_dict.get('db'):
            params_map['db'] = 'dbname'
        elif params_dict.get('database'):
            params_map['database'] = 'dbname'
        elif params_dict.get('login_db'):
            params_map['login_db'] = 'dbname'
        else:
            if warn_db_default:
                module.warn('Database name has not been passed, '
                            'used default database to connect to.')
    else:
        if params_dict.get('db'):
            params_map['db'] = 'database'
        elif params_dict.get('database'):
            params_map['database'] = 'database'
        elif params_dict.get('login_db'):
            params_map['login_db'] = 'database'
        else:
            if warn_db_default:
                module.warn('Database name has not been passed, '
                            'used default database to connect to.')

    kw = dict((params_map[k], v) for (k, v) in params_dict.items()
              if k in params_map and v != '' and v is not None)

    # If a login_unix_socket is specified, incorporate it here.
    is_localhost = False
    if 'host' not in kw or kw['host'] in [None, 'localhost']:
        is_localhost = True

    if is_localhost and params_dict["login_unix_socket"] != "":
        kw["host"] = params_dict["login_unix_socket"]

    # If connect_params is specified, merge it together
    if params_dict.get("connect_params"):
        kw.update(params_dict["connect_params"])

    return kw


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
        'grantor' plus the options the server records (ADMIN always; INHERIT and SET on
        PostgreSQL 16+).
        """
        # inherit_option and set_option are columns PostgreSQL 16 added.
        if self.per_grantor_membership:
            columns = "m.admin_option, m.inherit_option, m.set_option"
        else:
            columns = "m.admin_option"

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
            grant = dict(grantor=row['grantor'], ADMIN=row['admin_option'])
            if self.per_grantor_membership:
                grant['INHERIT'] = row['inherit_option']
                grant['SET'] = row['set_option']
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
        # ADMIN is recorded on every supported version; inherit_option and set_option
        # are columns PostgreSQL 16 added.
        known = ('ADMIN', 'INHERIT', 'SET') if self.per_grantor_membership else ('ADMIN',)

        for role in self.target_roles:
            memberships = self.__role_grants(role)

            for group in self.groups:
                role_grants = memberships.get(group)
                if not role_grants:
                    continue

                reported = []
                for grant in role_grants:
                    entry = dict(grantor=grant['grantor'])
                    for option in known:
                        entry['%s_option' % option.lower()] = grant[option]
                    reported.append(entry)

                grants.setdefault(group, {})[role] = reported
                effective_options.setdefault(group, {})[role] = dict(
                    ('%s_option' % option.lower(),
                     any(grant[option] for grant in role_grants))
                    for option in known)

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


def set_search_path(cursor, search_path):
    """Set session's search_path.

    Args:
        cursor (Psycopg cursor): Database cursor object.
        search_path (str): String containing comma-separated schema names.
    """
    cursor.execute('SET search_path TO %s' % search_path)


def convert_elements_to_pg_arrays(obj):
    """Convert list elements of the passed object
    to PostgreSQL arrays represented as strings.

    Args:
        obj (dict or list): Object whose elements need to be converted.

    Returns:
        obj (dict or list): Object with converted elements.
    """
    if isinstance(obj, dict):
        for (key, elem) in obj.items():
            if isinstance(elem, list):
                obj[key] = list_to_pg_array(elem)

    elif isinstance(obj, list):
        for i, elem in enumerate(obj):
            if isinstance(elem, list):
                obj[i] = list_to_pg_array(elem)

    return obj


def list_to_pg_array(elem):
    """Convert the passed list to PostgreSQL array
    represented as a string.

    Args:
        elem (list): List that needs to be converted.

    Returns:
        elem (str): String representation of PostgreSQL array.
    """
    elem = str(elem).strip('[]')
    elem = '{' + elem + '}'
    return elem


def convert_to_supported(val):
    """Convert unsupported type to appropriate.
    Args:
        val (any) -- Any value fetched from database.
    Returns value of appropriate type.
    """
    if isinstance(val, Decimal):
        return float(val)

    elif isinstance(val, timedelta):
        return str(val)

    return val  # By default returns the same value


def get_server_version(conn):
    """Get server version.

    Args:
        conn (psycopg.Connection) -- Psycopg connection object.

    Returns server version (int).
    """
    if PSYCOPG_VERSION >= LooseVersion("3.0.0"):
        return conn.info.server_version
    else:
        return conn.server_version


def set_autocommit(conn, autocommit):
    """Set autocommit.

    Args:
        conn (psycopg.Connection) -- Psycopg connection object.
        autocommit -- bool.
    """
    if PSYCOPG_VERSION >= LooseVersion("2.4.2"):
        conn.autocommit = autocommit
    else:
        if autocommit:
            conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        else:
            conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_READ_COMMITTED)


def get_comment(cursor, obj_type, obj_name):
    """Get DB object's comment.

    Args:
        cursor (Psycopg cursor) -- Database cursor object.
        obj_name (str) -- DB object name to get comment from.
        obj_type (str) -- Object type.

    Returns object's comment (str) if present or None.
    """
    query = ''
    if obj_type == 'role':
        query = ("SELECT pg_catalog.shobj_description(r.oid, 'pg_authid') AS comment "
                 "FROM pg_catalog.pg_roles AS r "
                 "WHERE r.rolname = %(obj_name)s")
    elif obj_type == 'extension':
        query = ("SELECT pg_catalog.obj_description(e.oid, 'pg_extension') AS comment "
                 "FROM pg_catalog.pg_extension AS e "
                 "WHERE e.extname = %(obj_name)s")

    cursor.execute(query, {'obj_name': obj_name})
    return cursor.fetchone()['comment']


def set_comment(cursor, comment, obj_type, obj_name, check_mode=True, executed_queries=None):
    """Get DB object's comment.

    Args:
        cursor (Psycopg cursor) -- Database cursor object.
        comment(str) -- Comment to set on object.
        obj_name (str) -- DB object name to set comment on.
        obj_type (str) -- Object type.
        executed_statements (list) -- List of executed state-modifying statements.
    """
    # Every caller passes a single unqualified name, so it is quoted as one identifier.
    query = 'COMMENT ON %s %s IS ' % (obj_type.upper(), pg_quote_name(obj_name, for_params=True))

    if not check_mode:
        cursor.execute(query + '%(comment)s', {'comment': comment})

    if executed_queries is not None:
        executed_queries.append(cursor.mogrify(query + '%(comment)s', {'comment': comment}))

    return True
