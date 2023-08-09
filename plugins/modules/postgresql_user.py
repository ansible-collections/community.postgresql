#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: postgresql_user
short_description: Create, alter, or remove a user (role) from a PostgreSQL server instance
description:
- Creates, alters, or removes a user (role) from a PostgreSQL server instance
  ("cluster" in PostgreSQL terminology) and, optionally,
  grants the user access to an existing database or tables.
- A user is a role with login privilege.
- You can also use it to grant or revoke user's privileges in a particular database.
- You cannot remove a user while it still has any privileges granted to it in any database.
- Set I(fail_on_user) to C(false) to make the module ignore failures when trying to remove a user.
  In this case, the module reports if changes happened as usual and separately reports
  whether the user has been removed or not.
- B(WARNING) The I(priv) option has been B(deprecated) and will be removed in community.postgresql 4.0.0. Please use the
  M(community.postgresql.postgresql_privs) module instead.
options:
  name:
    description:
    - Name of the user (role) to add or remove.
    type: str
    required: true
    aliases:
    - user
  password:
    description:
    - Set the user's password, before 1.4 this was required.
    - Password can be passed unhashed or hashed (MD5-hashed).
    - An unhashed password is automatically hashed when saved into the
      database if I(encrypted) is set, otherwise it is saved in
      plain text format.
    - When passing an MD5-hashed password, you must generate it with the format
      C('str["md5"] + md5[ password + username ]'), resulting in a total of
      35 characters. An easy way to do this is
      C(echo "md5`echo -n 'verysecretpasswordJOE' | md5sum | awk '{print $1}'`").
    - Note that if the provided password string is already in MD5-hashed
      format, then it is used as-is, regardless of I(encrypted) option.
    type: str
  db:
    description:
    - Name of database to connect to and where user's permissions are granted.
    type: str
    default: ''
    aliases:
    - login_db
  fail_on_user:
    description:
    - If C(true), fails when the user (role) cannot be removed. Otherwise just log and continue.
    default: true
    type: bool
    aliases:
    - fail_on_role
  priv:
    description:
    - This option has been B(deprecated) and will be removed in
      community.postgresql 4.0.0. Please use the M(community.postgresql.postgresql_privs) module to
      GRANT/REVOKE permissions instead.
    - "Slash-separated PostgreSQL privileges string: C(priv1/priv2), where
      you can define the user's privileges for the database ( allowed options - 'CREATE',
      'CONNECT', 'TEMPORARY', 'TEMP', 'ALL'. For example C(CONNECT) ) or
      for table ( allowed options - 'SELECT', 'INSERT', 'UPDATE', 'DELETE',
      'TRUNCATE', 'REFERENCES', 'TRIGGER', 'ALL'. For example
      C(table:SELECT) ). Mixed example of this string:
      C(CONNECT/CREATE/table1:SELECT/table2:INSERT)."
    - When I(priv) contains tables, the module uses the schema C(public) by default.
      If you need to specify a different schema, use the C(schema_name.table_name) notation,
      for example, C(pg_catalog.pg_stat_database:SELECT).
    type: str
  role_attr_flags:
    description:
    - "PostgreSQL user attributes string in the format: CREATEDB,CREATEROLE,SUPERUSER."
    - Note that '[NO]CREATEUSER' is deprecated.
    - To create a simple role for using it like a group, use C(NOLOGIN) flag.
    - See the full list of supported flags in documentation for your PostgreSQL version.
    type: str
    default: ''
  session_role:
    description:
    - Switch to session role after connecting.
    - The specified session role must be a role that the current login_user is a member of.
    - Permissions checking for SQL commands is carried out as though the session role
      were the one that had logged in originally.
    type: str
  state:
    description:
    - The user (role) state.
    type: str
    default: present
    choices: [ absent, present ]
  encrypted:
    description:
    - Whether the password is stored hashed in the database.
    - You can specify an unhashed password, and PostgreSQL ensures
      the stored password is hashed when I(encrypted=true) is set.
      If you specify a hashed password, the module uses it as-is,
      regardless of the setting of I(encrypted).
    - "Note: Postgresql 10 and newer does not support unhashed passwords."
    - Previous to Ansible 2.6, this was C(false) by default.
    default: true
    type: bool
  expires:
    description:
    - The date at which the user's password is to expire.
    - If set to C('infinity'), user's password never expires.
    - Note that this value must be a valid SQL date and time type.
    type: str
  no_password_changes:
    description:
    - If C(true), does not inspect the database for password changes.
      If the user already exists, skips all password related checks.
      Useful when C(pg_authid) is not accessible (such as in AWS RDS).
      Otherwise, makes password changes as necessary.
    default: false
    type: bool
  conn_limit:
    description:
    - Specifies the user (role) connection limit.
    type: int
  ssl_mode:
    description:
      - Determines how an SSL session is negotiated with the server.
      - See U(https://www.postgresql.org/docs/current/static/libpq-ssl.html) for more information on the modes.
      - Default of C(prefer) matches libpq default.
    type: str
    default: prefer
    choices: [ allow, disable, prefer, require, verify-ca, verify-full ]
  ca_cert:
    description:
      - Specifies the name of a file containing SSL certificate authority (CA) certificate(s).
      - If the file exists, verifies that the server's certificate is signed by one of these authorities.
    type: str
    aliases: [ ssl_rootcert ]
  comment:
    description:
    - Adds a comment on the user (equivalent to the C(COMMENT ON ROLE) statement).
    type: str
    version_added: '0.2.0'
  trust_input:
    description:
    - If C(false), checks whether values of options I(name), I(password), I(privs), I(expires),
      I(role_attr_flags), I(comment), I(session_role) are potentially dangerous.
    - It makes sense to use C(false) only when SQL injections through the options are possible.
    type: bool
    default: true
    version_added: '0.2.0'
notes:
- The module creates a user (role) with login privilege by default.
  Use C(NOLOGIN) I(role_attr_flags) to change this behaviour.
- If you specify C(PUBLIC) as the user (role), then the privilege changes apply to all users (roles).
  You may not specify password or role_attr_flags when the C(PUBLIC) user is specified.
- SCRAM-SHA-256-hashed passwords (SASL Authentication) require PostgreSQL version 10 or newer.
  On the previous versions the whole hashed string is used as a password.
- 'Working with SCRAM-SHA-256-hashed passwords, be sure you use the I(environment:) variable
  C(PGOPTIONS: "-c password_encryption=scram-sha-256") (see the provided example).'
- On some systems (such as AWS RDS), C(pg_authid) is not accessible, thus, the module cannot compare
  the current and desired C(password). In this case, the module assumes that the passwords are
  different and changes it reporting that the state has been changed.
  To skip all password related checks for existing users, use I(no_password_changes=true).
- On some systems (such as AWS RDS), C(SUPERUSER) is unavailable. This means the C(SUPERUSER) and
  C(NOSUPERUSER) I(role_attr_flags) should not be specified to preserve idempotency and avoid
  InsufficientPrivilege errors.

attributes:
  check_mode:
    support: full

seealso:
- module: community.postgresql.postgresql_privs
- module: community.postgresql.postgresql_membership
- module: community.postgresql.postgresql_owner
- name: PostgreSQL database roles
  description: Complete reference of the PostgreSQL database roles documentation.
  link: https://www.postgresql.org/docs/current/user-manag.html
- name: PostgreSQL SASL Authentication
  description: Complete reference of the PostgreSQL SASL Authentication.
  link: https://www.postgresql.org/docs/current/sasl-authentication.html
author:
- Ansible Core Team
extends_documentation_fragment:
- community.postgresql.postgres
'''

EXAMPLES = r'''
# This example uses the 'priv' argument which is deprecated.
# You should use the 'postgresql_privs' module instead.
- name: Connect to acme database, create django user, and grant access to database and products table
  community.postgresql.postgresql_user:
    db: acme
    name: django
    password: ceec4eif7ya
    priv: "CONNECT/products:ALL"
    expires: "Jan 31 2020"

- name: Add a comment on django user
  community.postgresql.postgresql_user:
    db: acme
    name: django
    comment: This is a test user

# Connect to default database, create rails user, set its password (MD5- or SHA256-hashed),
# and grant privilege to create other databases and demote rails from super user status if user exists
# the hash from the corresponding pg_authid entry.
- name: Create rails user, set MD5-hashed password, grant privs
  community.postgresql.postgresql_user:
    name: rails
    password: md59543f1d82624df2b31672ec0f7050460
    # password: SCRAM-SHA-256$4096:zFuajwIVdli9mK=NJkcv1Q++$JC4gWIrEHmF6sqRbEiZw5FFW45HUPrpVzNdoM72o730+;fqA4vLN3mCZGbhcbQyvNYY7anCrUTsem1eCh/4YA94=
    role_attr_flags: CREATEDB,NOSUPERUSER
  # When using sha256-hashed password:
  #environment:
  #  PGOPTIONS: "-c password_encryption=scram-sha-256"

# This example uses the 'priv' argument which is deprecated.
# You should use the 'postgresql_privs' module instead.
- name: Connect to acme database and remove test user privileges from there
  community.postgresql.postgresql_user:
    db: acme
    name: test
    priv: "ALL/products:ALL"
    state: absent
    fail_on_user: false

# This example uses the 'priv' argument which is deprecated.
# You should use the 'postgresql_privs' module instead.
- name: Connect to test database, remove test user from cluster
  community.postgresql.postgresql_user:
    db: test
    name: test
    priv: ALL
    state: absent

# This example uses the 'priv' argument which is deprecated.
# You should use the 'postgresql_privs' module instead.
- name: Connect to acme database and set user's password with no expire date
  community.postgresql.postgresql_user:
    db: acme
    name: django
    password: mysupersecretword
    priv: "CONNECT/products:ALL"
    expires: infinity

# Example privileges string format
# INSERT,UPDATE/table:SELECT/anothertable:ALL

- name: Connect to test database and remove an existing user's password
  community.postgresql.postgresql_user:
    db: test
    user: test
    password: ""

# Create user with a cleartext password if it does not exist or update its password.
# The password will be encrypted with SCRAM algorithm (available since PostgreSQL 10)
- name: Create appclient user with SCRAM-hashed password
  community.postgresql.postgresql_user:
    name: appclient
    password: "secret123"
  environment:
    PGOPTIONS: "-c password_encryption=scram-sha-256"

# This example uses the 'priv' argument which is deprecated.
# You should use the 'postgresql_privs' module instead.
- name: Create a user, grant SELECT on pg_catalog.pg_stat_database
  community.postgresql.postgresql_user:
    name: monitoring
    priv: 'pg_catalog.pg_stat_database:SELECT'
'''

RETURN = r'''
queries:
  description: List of executed queries.
  returned: success
  type: list
  sample: ['CREATE USER "alice"', 'GRANT CONNECT ON DATABASE "acme" TO "alice"']
'''

import itertools
import re
import traceback
from hashlib import md5, sha256
import hmac
from base64 import b64decode

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six import iteritems
from ansible.module_utils._text import to_bytes, to_native, to_text
from ansible_collections.community.postgresql.plugins.module_utils.version import LooseVersion
from ansible_collections.community.postgresql.plugins.module_utils.database import (
    pg_quote_identifier,
    SQLParseError,
    check_input,
)
from ansible_collections.community.postgresql.plugins.module_utils.postgres import (
    connect_to_db,
    ensure_required_libs,
    get_conn_params,
    get_server_version,
    pg_cursor_args,
    postgres_common_argument_spec,
    HAS_PSYCOPG,
    PSYCOPG_VERSION
)
from ansible_collections.community.postgresql.plugins.module_utils import saslprep

if HAS_PSYCOPG and PSYCOPG_VERSION < LooseVersion("3.0"):
    import psycopg2 as psycopg
elif HAS_PSYCOPG:
    import psycopg

try:
    # pbkdf2_hmac is missing on python 2.6, we can safely assume,
    # that postresql 10 capable instance have at least python 2.7 installed
    from hashlib import pbkdf2_hmac
    pbkdf2_found = True
except ImportError:
    pbkdf2_found = False


FLAGS = ('SUPERUSER', 'CREATEROLE', 'CREATEDB', 'INHERIT', 'LOGIN', 'REPLICATION')
FLAGS_BY_VERSION = {'BYPASSRLS': 90500}

SCRAM_SHA256_REGEX = r'^SCRAM-SHA-256\$(\d+):([A-Za-z0-9+\/=]+)\$([A-Za-z0-9+\/=]+):([A-Za-z0-9+\/=]+)$'

# WARNING: privs are deprecated and will  be removed in community.postgresql 4.0.0
VALID_PRIVS = dict(table=frozenset(('SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER', 'ALL')),
                   database=frozenset(
                       ('CREATE', 'CONNECT', 'TEMPORARY', 'TEMP', 'ALL')),
                   )

# map to cope with idiosyncrasies of SUPERUSER and LOGIN
PRIV_TO_AUTHID_COLUMN = dict(SUPERUSER='rolsuper', CREATEROLE='rolcreaterole',
                             CREATEDB='rolcreatedb', INHERIT='rolinherit', LOGIN='rolcanlogin',
                             REPLICATION='rolreplication', BYPASSRLS='rolbypassrls')

executed_queries = []

# This is a special list for debugging.
# If you need to fetch information (e.g. results of cursor.fetchall(),
# queries built with cursor.mogrify(), vars values, etc.):
# 1. Put debug_info.append(<information_you_need>) as many times as you need.
# 2. Run integration tests or you playbook with -vvv
# 3. If it's not empty, you'll see the list in the returned json.
debug_info = []


class InvalidFlagsError(Exception):
    pass


class InvalidPrivsError(Exception):
    pass

# ===========================================
# PostgreSQL module specific support methods.
#


def user_exists(cursor, user):
    # The PUBLIC user is a special case that is always there
    if user == 'PUBLIC':
        return True
    query = "SELECT rolname FROM pg_roles WHERE rolname=%(user)s"
    cursor.execute(query, {'user': user})
    return cursor.rowcount > 0


def user_add(cursor, user, password, role_attr_flags, encrypted, expires, conn_limit):
    """Create a new database user (role)."""
    # Note: role_attr_flags escaped by parse_role_attrs and encrypted is a
    # literal
    query_password_data = dict(password=password, expires=expires)
    query = ['CREATE USER "%(user)s"' %
             {"user": user}]
    if password is not None and password != '':
        query.append("WITH %(crypt)s" % {"crypt": encrypted})
        query.append("PASSWORD %(password)s")
    if expires is not None:
        query.append("VALID UNTIL %(expires)s")
    if conn_limit is not None:
        query.append("CONNECTION LIMIT %(conn_limit)s" % {"conn_limit": conn_limit})
    query.append(role_attr_flags)
    query = ' '.join(query)
    executed_queries.append(query)
    cursor.execute(query, query_password_data)
    return True


def user_should_we_change_password(current_role_attrs, user, password, encrypted):
    """Check if we should change the user's password.

    Compare the proposed password with the existing one, comparing
    hashes if encrypted. If we can't access it assume yes.
    """

    if current_role_attrs is None:
        # on some databases, E.g. AWS RDS instances, there is no access to
        # the pg_authid relation to check the pre-existing password, so we
        # just assume password is different
        return True

    # Do we actually need to do anything?
    pwchanging = False
    if password is not None:
        # Empty password means that the role shouldn't have a password, which
        # means we need to check if the current password is None.
        if password == '':
            if current_role_attrs['rolpassword'] is not None:
                pwchanging = True
        # If the provided password is a SCRAM hash, compare it directly to the current password
        elif re.match(SCRAM_SHA256_REGEX, password):
            if password != current_role_attrs['rolpassword']:
                pwchanging = True

        # SCRAM hashes are represented as a special object, containing hash data:
        # `SCRAM-SHA-256$<iteration count>:<salt>$<StoredKey>:<ServerKey>`
        # for reference, see https://www.postgresql.org/docs/current/catalog-pg-authid.html
        elif current_role_attrs['rolpassword'] is not None \
                and pbkdf2_found \
                and re.match(SCRAM_SHA256_REGEX, current_role_attrs['rolpassword']):

            r = re.match(SCRAM_SHA256_REGEX, current_role_attrs['rolpassword'])
            try:
                # extract SCRAM params from rolpassword
                it = int(r.group(1))
                salt = b64decode(r.group(2))
                server_key = b64decode(r.group(4))
                # we'll never need `storedKey` as it is only used for server auth in SCRAM
                # storedKey = b64decode(r.group(3))

                # from RFC5802 https://tools.ietf.org/html/rfc5802#section-3
                # SaltedPassword  := Hi(Normalize(password), salt, i)
                # ServerKey       := HMAC(SaltedPassword, "Server Key")
                normalized_password = saslprep.saslprep(to_text(password))
                salted_password = pbkdf2_hmac('sha256', to_bytes(normalized_password), salt, it)

                server_key_verifier = hmac.new(salted_password, digestmod=sha256)
                server_key_verifier.update(b'Server Key')

                if server_key_verifier.digest() != server_key:
                    pwchanging = True
            except Exception:
                # We assume the password is not scram encrypted
                # or we cannot check it properly, e.g. due to missing dependencies
                pwchanging = True

        # 32: MD5 hashes are represented as a sequence of 32 hexadecimal digits
        #  3: The size of the 'md5' prefix
        # When the provided password looks like a MD5-hash, value of
        # 'encrypted' is ignored.
        elif (password.startswith('md5') and len(password) == 32 + 3) or encrypted == 'UNENCRYPTED':
            if password != current_role_attrs['rolpassword']:
                pwchanging = True
        elif encrypted == 'ENCRYPTED':
            hashed_password = 'md5{0}'.format(md5(to_bytes(password) + to_bytes(user)).hexdigest())
            if hashed_password != current_role_attrs['rolpassword']:
                pwchanging = True

    return pwchanging


def user_alter(db_connection, module, user, password, role_attr_flags, encrypted, expires, no_password_changes, conn_limit):
    """Change user password and/or attributes. Return True if changed, False otherwise."""
    changed = False

    cursor = db_connection.cursor(**pg_cursor_args)
    # Note: role_attr_flags escaped by parse_role_attrs and encrypted is a
    # literal
    if user == 'PUBLIC':
        if password is not None:
            module.fail_json(msg="cannot change the password for PUBLIC user")
        elif role_attr_flags != '':
            module.fail_json(msg="cannot change the role_attr_flags for PUBLIC user")
        else:
            return False

    # Handle passwords.
    if not no_password_changes and (password is not None or role_attr_flags != '' or expires is not None or conn_limit is not None):
        # Select password and all flag-like columns in order to verify changes.
        try:
            select = "SELECT * FROM pg_authid where rolname=%(user)s"
            cursor.execute(select, {"user": user})
            # Grab current role attributes.
            current_role_attrs = cursor.fetchone()
        except psycopg.ProgrammingError:
            current_role_attrs = None
            db_connection.rollback()

        pwchanging = user_should_we_change_password(current_role_attrs, user, password, encrypted)

        if current_role_attrs is None:
            try:
                # AWS RDS instances does not allow user to access pg_authid
                # so try to get current_role_attrs from pg_roles tables
                select = "SELECT * FROM pg_roles where rolname=%(user)s"
                cursor.execute(select, {"user": user})
                # Grab current role attributes from pg_roles
                current_role_attrs = cursor.fetchone()
            except psycopg.ProgrammingError as e:
                db_connection.rollback()
                module.fail_json(msg="Failed to get role details for current user %s: %s" % (user, e))

        role_attr_flags_changing = False
        if role_attr_flags:
            role_attr_flags_dict = {}
            for r in role_attr_flags.split(' '):
                if r.startswith('NO'):
                    role_attr_flags_dict[r.replace('NO', '', 1)] = False
                else:
                    role_attr_flags_dict[r] = True

            for role_attr_name, role_attr_value in role_attr_flags_dict.items():
                if current_role_attrs[PRIV_TO_AUTHID_COLUMN[role_attr_name]] != role_attr_value:
                    role_attr_flags_changing = True

        if expires is not None:
            cursor.execute("SELECT %s::timestamptz exp_timestamp", (expires,))
            expires_with_tz = cursor.fetchone()["exp_timestamp"]
            expires_changing = expires_with_tz != current_role_attrs.get('rolvaliduntil')
        else:
            expires_changing = False

        conn_limit_changing = (conn_limit is not None and conn_limit != current_role_attrs['rolconnlimit'])

        if not pwchanging and not role_attr_flags_changing and not expires_changing and not conn_limit_changing:
            return False

        alter = ['ALTER USER "%(user)s"' % {"user": user}]
        if pwchanging:
            if password != '':
                alter.append("WITH %(crypt)s" % {"crypt": encrypted})
                alter.append("PASSWORD %(password)s")
            else:
                alter.append("WITH PASSWORD NULL")
            alter.append(role_attr_flags)
        elif role_attr_flags:
            alter.append('WITH %s' % role_attr_flags)
        if expires is not None:
            alter.append("VALID UNTIL %(expires)s")
        if conn_limit is not None:
            alter.append("CONNECTION LIMIT %(conn_limit)s" % {"conn_limit": conn_limit})

        query_password_data = dict(password=password, expires=expires)
        try:
            statement = ' '.join(alter)
            cursor.execute(statement, query_password_data)
            changed = True
            executed_queries.append(statement)
        # We could catch psycopg.errors.ReadOnlySqlTransaction directly,
        # but that was added only in Psycopg 2.8
        except psycopg.InternalError as e:
            if e.diag.sqlstate == "25006":
                # Handle errors due to read-only transactions indicated by pgcode 25006
                # ERROR:  cannot execute ALTER ROLE in a read-only transaction
                changed = False
                module.fail_json(msg=e.diag.message_primary, exception=traceback.format_exc())
                return changed
            else:
                raise psycopg.InternalError(e)
        except psycopg.NotSupportedError as e:
            module.fail_json(msg=e.diag.message_primary, exception=traceback.format_exc())

    elif no_password_changes and role_attr_flags != '':
        # Grab role information from pg_roles instead of pg_authid
        select = "SELECT * FROM pg_roles where rolname=%(user)s"
        cursor.execute(select, {"user": user})
        # Grab current role attributes.
        current_role_attrs = cursor.fetchone()

        role_attr_flags_changing = False

        if role_attr_flags:
            role_attr_flags_dict = {}
            for r in role_attr_flags.split(' '):
                if r.startswith('NO'):
                    role_attr_flags_dict[r.replace('NO', '', 1)] = False
                else:
                    role_attr_flags_dict[r] = True

            for role_attr_name, role_attr_value in role_attr_flags_dict.items():
                if current_role_attrs[PRIV_TO_AUTHID_COLUMN[role_attr_name]] != role_attr_value:
                    role_attr_flags_changing = True

        if not role_attr_flags_changing:
            return False

        alter = ['ALTER USER "%(user)s"' %
                 {"user": user}]
        if role_attr_flags:
            alter.append('WITH %s' % role_attr_flags)

        try:
            statement = ' '.join(alter)
            cursor.execute(statement)
            executed_queries.append(statement)

        except psycopg.InternalError as e:
            if e.diag.sqlstate == "25006":
                # Handle errors due to read-only transactions indicated by pgcode 25006
                # ERROR:  cannot execute ALTER ROLE in a read-only transaction
                changed = False
                module.fail_json(msg=e.diag.message_primary, exception=traceback.format_exc())
                return changed
            else:
                raise psycopg.InternalError(e)

        # Grab new role attributes.
        cursor.execute(select, {"user": user})
        new_role_attrs = cursor.fetchone()

        # Detect any differences between current_ and new_role_attrs.
        changed = current_role_attrs != new_role_attrs

    return changed


def user_delete(cursor, user):
    """Try to remove a user. Returns True if successful otherwise False"""
    cursor.execute("SAVEPOINT ansible_pgsql_user_delete")
    try:
        query = 'DROP USER "%s"' % user
        executed_queries.append(query)
        cursor.execute(query)
    except Exception:
        cursor.execute("ROLLBACK TO SAVEPOINT ansible_pgsql_user_delete")
        cursor.execute("RELEASE SAVEPOINT ansible_pgsql_user_delete")
        return False

    cursor.execute("RELEASE SAVEPOINT ansible_pgsql_user_delete")
    return True


# WARNING: privs are deprecated and will  be removed in community.postgresql 4.0.0
def has_table_privileges(cursor, user, table, privs):
    """
    Return the difference between the privileges that a user already has and
    the privileges that they desire to have.

    :returns: tuple of:
        * privileges that they have and were requested
        * privileges they currently hold but were not requested
        * privileges requested that they do not hold
    """
    cur_privs = get_table_privileges(cursor, user, table)
    have_currently = cur_privs.intersection(privs)
    other_current = cur_privs.difference(privs)
    desired = privs.difference(cur_privs)
    return (have_currently, other_current, desired)


# WARNING: privs are deprecated and will  be removed in community.postgresql 4.0.0
def get_table_privileges(cursor, user, table):
    if '.' in table:
        schema, table = table.split('.', 1)
    else:
        schema = 'public'
    query = ("SELECT privilege_type FROM information_schema.role_table_grants "
             "WHERE grantee=%(user)s AND table_name=%(table)s AND table_schema=%(schema)s")
    cursor.execute(query, {'user': user, 'table': table, 'schema': schema})
    return frozenset([x["privilege_type"] for x in cursor.fetchall()])


# WARNING: privs are deprecated and will  be removed in community.postgresql 4.0.0
def grant_table_privileges(cursor, user, table, privs):
    # Note: priv escaped by parse_privs
    privs = ', '.join(privs)
    query = 'GRANT %s ON TABLE %s TO "%s"' % (
        privs, pg_quote_identifier(table, 'table'), user)
    executed_queries.append(query)
    cursor.execute(query)


# WARNING: privs are deprecated and will  be removed in community.postgresql 4.0.0
def revoke_table_privileges(cursor, user, table, privs):
    # Note: priv escaped by parse_privs
    privs = ', '.join(privs)
    query = 'REVOKE %s ON TABLE %s FROM "%s"' % (
        privs, pg_quote_identifier(table, 'table'), user)
    executed_queries.append(query)
    cursor.execute(query)


# WARNING: privs are deprecated and will  be removed in community.postgresql 4.0.0
def get_database_privileges(cursor, user, db):
    priv_map = {
        'C': 'CREATE',
        'T': 'TEMPORARY',
        'c': 'CONNECT',
    }
    query = 'SELECT datacl::text FROM pg_database WHERE datname = %s'
    cursor.execute(query, (db,))
    datacl = cursor.fetchone()["datacl"]
    if datacl is None:
        return set()
    r = re.search(r'%s\\?"?=(C?T?c?)/[^,]+,?' % user, datacl)
    if r is None:
        return set()
    o = set()
    for v in r.group(1):
        o.add(priv_map[v])
    return normalize_privileges(o, 'database')


# WARNING: privs are deprecated and will  be removed in community.postgresql 4.0.0
def has_database_privileges(cursor, user, db, privs):
    """
    Return the difference between the privileges that a user already has and
    the privileges that they desire to have.

    :returns: tuple of:
        * privileges that they have and were requested
        * privileges they currently hold but were not requested
        * privileges requested that they do not hold
    """
    cur_privs = get_database_privileges(cursor, user, db)
    have_currently = cur_privs.intersection(privs)
    other_current = cur_privs.difference(privs)
    desired = privs.difference(cur_privs)
    return (have_currently, other_current, desired)


# WARNING: privs are deprecated and will  be removed in community.postgresql 4.0.0
def grant_database_privileges(cursor, user, db, privs):
    # Note: priv escaped by parse_privs
    privs = ', '.join(privs)
    if user == "PUBLIC":
        query = 'GRANT %s ON DATABASE %s TO PUBLIC' % (
                privs, pg_quote_identifier(db, 'database'))
    else:
        query = 'GRANT %s ON DATABASE %s TO "%s"' % (
                privs, pg_quote_identifier(db, 'database'), user)

    executed_queries.append(query)
    cursor.execute(query)


# WARNING: privs are deprecated and will  be removed in community.postgresql 4.0.0
def revoke_database_privileges(cursor, user, db, privs):
    # Note: priv escaped by parse_privs
    privs = ', '.join(privs)
    if user == "PUBLIC":
        query = 'REVOKE %s ON DATABASE %s FROM PUBLIC' % (
                privs, pg_quote_identifier(db, 'database'))
    else:
        query = 'REVOKE %s ON DATABASE %s FROM "%s"' % (
                privs, pg_quote_identifier(db, 'database'), user)

    executed_queries.append(query)
    cursor.execute(query)


# WARNING: privs are deprecated and will  be removed in community.postgresql 4.0.0
def revoke_privileges(cursor, user, privs):
    if privs is None:
        return False

    revoke_funcs = dict(table=revoke_table_privileges,
                        database=revoke_database_privileges)
    check_funcs = dict(table=has_table_privileges,
                       database=has_database_privileges)

    changed = False
    for type_ in privs:
        for name, privileges in iteritems(privs[type_]):
            # Check that any of the privileges requested to be removed are
            # currently granted to the user
            differences = check_funcs[type_](cursor, user, name, privileges)
            if differences[0]:
                revoke_funcs[type_](cursor, user, name, privileges)
                changed = True
    return changed


# WARNING: privs are deprecated and will  be removed in community.postgresql 4.0.0
def grant_privileges(cursor, user, privs):
    if privs is None:
        return False

    grant_funcs = dict(table=grant_table_privileges,
                       database=grant_database_privileges)
    check_funcs = dict(table=has_table_privileges,
                       database=has_database_privileges)

    changed = False
    for type_ in privs:
        for name, privileges in iteritems(privs[type_]):
            # Check that any of the privileges requested for the user are
            # currently missing
            differences = check_funcs[type_](cursor, user, name, privileges)
            if differences[2]:
                grant_funcs[type_](cursor, user, name, privileges)
                changed = True
    return changed


def parse_role_attrs(role_attr_flags, srv_version):
    """
    Parse role attributes string for user creation.
    Format:

        attributes[,attributes,...]

    Where:

        attributes := CREATEDB,CREATEROLE,NOSUPERUSER,...
        [ "[NO]SUPERUSER","[NO]CREATEROLE", "[NO]CREATEDB",
                            "[NO]INHERIT", "[NO]LOGIN", "[NO]REPLICATION",
                            "[NO]BYPASSRLS" ]

    Note: "[NO]BYPASSRLS" role attribute introduced in 9.5
    Note: "[NO]CREATEUSER" role attribute is deprecated.

    """
    flags = frozenset(role.upper() for role in role_attr_flags.split(',') if role)

    valid_flags = frozenset(itertools.chain(FLAGS, get_valid_flags_by_version(srv_version)))
    valid_flags = frozenset(itertools.chain(valid_flags, ('NO%s' % flag for flag in valid_flags)))

    if not flags.issubset(valid_flags):
        raise InvalidFlagsError('Invalid role_attr_flags specified: %s' %
                                ' '.join(flags.difference(valid_flags)))

    return ' '.join(flags)


# WARNING: privs are deprecated and will  be removed in community.postgresql 4.0.0
def normalize_privileges(privs, type_):
    new_privs = set(privs)
    if 'ALL' in new_privs:
        new_privs.update(VALID_PRIVS[type_])
        new_privs.remove('ALL')
    if 'TEMP' in new_privs:
        new_privs.add('TEMPORARY')
        new_privs.remove('TEMP')

    return new_privs


# WARNING: privs are deprecated and will  be removed in community.postgresql 4.0.0
def parse_privs(privs, db):
    """
    Parse privilege string to determine permissions for database db.
    Format:

        privileges[/privileges/...]

    Where:

        privileges := DATABASE_PRIVILEGES[,DATABASE_PRIVILEGES,...] |
            TABLE_NAME:TABLE_PRIVILEGES[,TABLE_PRIVILEGES,...]
    """
    if privs is None:
        return privs

    o_privs = {
        'database': {},
        'table': {}
    }
    for token in privs.split('/'):
        if ':' not in token:
            type_ = 'database'
            name = db
            priv_set = frozenset(x.strip().upper()
                                 for x in token.split(',') if x.strip())
        else:
            type_ = 'table'
            name, privileges = token.split(':', 1)
            priv_set = frozenset(x.strip().upper()
                                 for x in privileges.split(',') if x.strip())

        if not priv_set.issubset(VALID_PRIVS[type_]):
            raise InvalidPrivsError('Invalid privs specified for %s: %s' %
                                    (type_, ' '.join(priv_set.difference(VALID_PRIVS[type_]))))

        priv_set = normalize_privileges(priv_set, type_)
        o_privs[type_][name] = priv_set

    return o_privs


def get_valid_flags_by_version(srv_version):
    """
    Some role attributes were introduced after certain versions. We want to
    compile a list of valid flags against the current Postgres version.
    """
    return [
        flag
        for flag, version_introduced in FLAGS_BY_VERSION.items()
        if srv_version >= version_introduced
    ]


def get_comment(cursor, user):
    """Get user's comment."""
    query = ("SELECT pg_catalog.shobj_description(r.oid, 'pg_authid') obj_desc "
             "FROM pg_catalog.pg_roles r "
             "WHERE r.rolname = %(user)s")
    cursor.execute(query, {'user': user})
    return cursor.fetchone()["obj_desc"]


def add_comment(cursor, user, comment):
    """Add comment on user."""
    if comment != get_comment(cursor, user):
        query = 'COMMENT ON ROLE "%s" IS ' % user
        cursor.execute(query + '%(comment)s', {'comment': comment})
        executed_queries.append(cursor.mogrify(query + '%(comment)s', {'comment': comment}))
        return True
    else:
        return False


# ===========================================
# Module execution.
#

def main():
    argument_spec = postgres_common_argument_spec()
    argument_spec.update(
        user=dict(type='str', required=True, aliases=['name']),
        password=dict(type='str', default=None, no_log=True),
        state=dict(type='str', default='present', choices=['absent', 'present']),
        priv=dict(type='str', default=None, removed_in_version='4.0.0', removed_from_collection='community.postgreql'),
        db=dict(type='str', default='', aliases=['login_db']),
        fail_on_user=dict(type='bool', default=True, aliases=['fail_on_role']),
        role_attr_flags=dict(type='str', default=''),
        encrypted=dict(type='bool', default=True),
        no_password_changes=dict(type='bool', default=False, no_log=False),
        expires=dict(type='str', default=None),
        conn_limit=dict(type='int', default=None),
        session_role=dict(type='str'),
        comment=dict(type='str', default=None),
        trust_input=dict(type='bool', default=True),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    user = module.params["user"]
    password = module.params["password"]
    state = module.params["state"]
    fail_on_user = module.params["fail_on_user"]
    # WARNING: privs are deprecated and will  be removed in community.postgresql 4.0.0
    if module.params['db'] == '' and module.params["priv"] is not None:
        module.fail_json(msg="privileges require a database to be specified")
    # WARNING: privs are deprecated and will  be removed in community.postgresql 4.0.0
    privs = parse_privs(module.params["priv"], module.params["db"])
    no_password_changes = module.params["no_password_changes"]
    if module.params["encrypted"]:
        encrypted = "ENCRYPTED"
    else:
        encrypted = "UNENCRYPTED"
    expires = module.params["expires"]
    conn_limit = module.params["conn_limit"]
    role_attr_flags = module.params["role_attr_flags"]
    comment = module.params["comment"]
    session_role = module.params['session_role']

    trust_input = module.params['trust_input']
    if not trust_input:
        # Check input for potentially dangerous elements:
        check_input(module, user, password, privs, expires,
                    role_attr_flags, comment, session_role)

    # Ensure psycopg libraries are available before connecting to DB:
    ensure_required_libs(module)
    conn_params = get_conn_params(module, module.params, warn_db_default=False)
    db_connection, dummy = connect_to_db(module, conn_params)
    cursor = db_connection.cursor(**pg_cursor_args)

    srv_version = get_server_version(db_connection)

    try:
        role_attr_flags = parse_role_attrs(role_attr_flags, srv_version)
    except InvalidFlagsError as e:
        module.fail_json(msg=to_native(e), exception=traceback.format_exc())

    kw = dict(user=user)
    changed = False
    user_removed = False

    if state == "present":
        if user_exists(cursor, user):
            try:
                changed = user_alter(db_connection, module, user, password,
                                     role_attr_flags, encrypted, expires, no_password_changes, conn_limit)
            except SQLParseError as e:
                module.fail_json(msg=to_native(e), exception=traceback.format_exc())
        else:
            try:
                changed = user_add(cursor, user, password,
                                   role_attr_flags, encrypted, expires, conn_limit)
            except psycopg.ProgrammingError as e:
                module.fail_json(msg="Unable to add user with given requirement "
                                     "due to : %s" % to_native(e),
                                 exception=traceback.format_exc())
            except SQLParseError as e:
                module.fail_json(msg=to_native(e), exception=traceback.format_exc())
        # WARNING: privs are deprecated and will  be removed in community.postgresql 4.0.0
        try:
            changed = grant_privileges(cursor, user, privs) or changed
        except SQLParseError as e:
            module.fail_json(msg=to_native(e), exception=traceback.format_exc())

        if comment is not None:
            try:
                changed = add_comment(cursor, user, comment) or changed
            except Exception as e:
                module.fail_json(msg='Unable to add comment on role: %s' % to_native(e),
                                 exception=traceback.format_exc())

    else:
        if user_exists(cursor, user):
            if module.check_mode:
                changed = True
                kw['user_removed'] = True
            else:
                # WARNING: privs are deprecated and will  be removed in community.postgresql 4.0.0
                try:
                    changed = revoke_privileges(cursor, user, privs)
                    user_removed = user_delete(cursor, user)
                except SQLParseError as e:
                    module.fail_json(msg=to_native(e), exception=traceback.format_exc())
                changed = changed or user_removed
                if fail_on_user and not user_removed:
                    msg = "Unable to remove user"
                    module.fail_json(msg=msg)
                kw['user_removed'] = user_removed

    if module.check_mode:
        db_connection.rollback()
    else:
        db_connection.commit()

    cursor.close()
    db_connection.close()

    kw['changed'] = changed
    kw['queries'] = executed_queries
    if debug_info:
        kw['debug_info'] = debug_info
    module.exit_json(**kw)


if __name__ == '__main__':
    main()
