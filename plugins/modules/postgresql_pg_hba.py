#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Sebastiaan Mannem (@sebasmannem) <sebastiaan.mannem@enterprisedb.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

'''
This module is used to manage postgres pg_hba files with Ansible.
'''

__metaclass__ = type

DOCUMENTATION = r'''
---
module: postgresql_pg_hba
short_description: Add, remove or modify a rule in a pg_hba file
description:
   - The fundamental function of the module is to create, or delete lines in pg_hba files.
   - The lines in the file should be in a typical pg_hba form and lines should be unique per key (type, databases, users, source).
     If they are not unique and the SID is 'the one to change', only one for I(state=present) or
     none for I(state=absent) of the SID's will remain.
extends_documentation_fragment: files
options:
  address:
    description:
      - The source address/net where the connections could come from.
      - Will not be used for entries of I(type)=C(local).
      - You can also use keywords C(all), C(samehost), and C(samenet).
    default: samehost
    type: str
    aliases: [ source, src ]
  backup:
    description:
      - If set, create a backup of the C(pg_hba) file before it is modified.
        The location of the backup is returned in the (backup) variable by this module.
    default: false
    type: bool
  backup_file:
    description:
      - Write backup to a specific backupfile rather than a temp file.
    type: str
  create:
    description:
      - Create an C(pg_hba) file if none exists.
      - When set to false, an error is raised when the C(pg_hba) file doesn't exist.
    default: false
    type: bool
  contype:
    description:
      - Type of the rule. If not set, C(postgresql_pg_hba) will only return contents.
    type: str
    choices: [ local, host, hostnossl, hostssl, hostgssenc, hostnogssenc ]
  comment:
    description:
      - A comment that will be placed in the same line behind the rule. See also the I(keep_comments_at_rules) parameter.
    type: str
    version_added: '1.5.0'
  databases:
    description:
      - Databases this line applies to.
    default: all
    type: str
  dest:
    description:
      - Path to C(pg_hba) file to modify.
    type: path
    required: true
  method:
    description:
      - Authentication method to be used.
    type: str
    choices: [ cert, gss, ident, krb5, ldap, md5, pam, password, peer, radius, reject, scram-sha-256 , sspi, trust ]
    default: md5
  netmask:
    description:
      - The netmask of the source address.
    type: str
  options:
    description:
      - Additional options for the authentication I(method).
    type: str
  overwrite:
    description:
      - Remove all existing rules before adding rules. (Like I(state=absent) for all pre-existing rules.)
    type: bool
    default: false
  keep_comments_at_rules:
    description:
      - If C(true), comments that stand together with a rule in one line are kept behind that line.
      - If C(false), such comments are moved to the beginning of the file, like all other comments.
    type: bool
    default: false
    version_added: '1.5.0'
  rules:
    description:
      - A list of objects, specifying rules for the pg_hba.conf. Use this to manage multiple rules at once.
      - "Each object can have the following keys (the 'rule-specific arguments'), which are treated the same as if they were arguments of this module:"
      - C(address), C(comment), C(contype), C(databases), C(method), C(netmask), C(options), C(state), C(users)
      - See also C(rules_behavior).
    type: list
    elements: dict
  rules_behavior:
    description:
      - "Configure how the I(rules) argument works together with the rule-specific arguments outside the I(rules) argument."
      - See I(rules) for the complete list of rule-specific arguments.
      - When set to C(conflict), fail if I(rules) and, for example, I(address) are set.
      - If C(combine), the normal rule-specific arguments are not defining a rule, but are used as defaults for the arguments in the I(rules) argument.
      - Is used only when I(rules) is specified, ignored otherwise.
    type: str
    choices: [ conflict, combine ]
    default: conflict
  state:
    description:
      - The lines will be added/modified when C(state=present) and removed when C(state=absent).
    type: str
    default: present
    choices: [ absent, present ]
  users:
    description:
      - Users this line applies to.
    type: str
    default: all

notes:
   - The default authentication assumes that on the host, you are either logging in as or
     sudo'ing to an account with appropriate permissions to read and modify the file.
   - This module also returns the pg_hba info. You can use this module to only retrieve it by only specifying I(dest).
     The info can be found in the returned data under key pg_hba, being a list, containing a dict per rule.
   - This module will sort resulting C(pg_hba) files if a rule change is required.
     This could give unexpected results with manual created hba files, if it was improperly sorted.
     For example a rule was created for a net first and for a ip in that net range next.
     In that situation, the 'ip specific rule' will never hit, it is in the C(pg_hba) file obsolete.
     After the C(pg_hba) file is rewritten by the M(community.postgresql.postgresql_pg_hba) module, the ip specific rule will be sorted above the range rule.
     And then it will hit, which will give unexpected results.

seealso:
- name: PostgreSQL pg_hba.conf file reference
  description: Complete reference of the PostgreSQL pg_hba.conf file documentation.
  link: https://www.postgresql.org/docs/current/auth-pg-hba-conf.html

requirements:
  - ipaddress

attributes:
  check_mode:
    support: full
    description: Can run in check_mode and return changed status prediction without modifying target
  diff_mode:
    support: full
    description: Will return details on what has changed (or possibly needs changing in check_mode), when in diff mode

author:
- Sebastiaan Mannem (@sebasmannem)
- Felix Hamme (@betanummeric)
'''

EXAMPLES = '''
- name: Grant users joe and simon access to databases sales and logistics from ipv6 localhost ::1/128 using peer authentication
  community.postgresql.postgresql_pg_hba:
    dest: /var/lib/postgres/data/pg_hba.conf
    contype: host
    users: joe,simon
    source: ::1
    databases: sales,logistics
    method: peer
    create: true

- name: Grant user replication from network 192.168.0.100/24 access for replication with client cert authentication
  community.postgresql.postgresql_pg_hba:
    dest: /var/lib/postgres/data/pg_hba.conf
    contype: host
    users: replication
    source: 192.168.0.100/24
    databases: replication
    method: cert

- name: Revoke access from local user mary on database mydb
  community.postgresql.postgresql_pg_hba:
    dest: /var/lib/postgres/data/pg_hba.conf
    contype: local
    users: mary
    databases: mydb
    state: absent

- name: Grant some_user access to some_db, comment that and keep other rule-specific comments attached to their rules
  community.postgresql.postgresql_pg_hba:
    dest: /var/lib/postgres/data/pg_hba.conf
    contype: host
    users: some_user
    databases: some_db
    method: md5
    source: ::/0
    keep_comments_at_rules: true
    comment: "this rule is an example"

- name: Replace everything with a new set of rules
  community.postgresql.postgresql_pg_hba:
    dest: /var/lib/postgres/data/pg_hba.conf
    overwrite: true # remove preexisting rules

    # custom defaults
    rules_behavior: combine
    contype: hostssl
    address: 2001:db8::/64
    comment: added in bulk

    rules:
    - users: user1
      databases: db1
      # contype, address and comment come from custom default
    - users: user2
      databases: db2
      comment: added with love # overwrite custom default for this rule
      # contype and address come from custom default
    - users: user3
      databases: db3
      # contype, address and comment come from custom default
'''

RETURN = r'''
msgs:
    description: List of textual messages what was done.
    returned: success
    type: list
    sample:
       "msgs": [
          "Removing",
          "Changed",
          "Writing"
        ]
backup_file:
    description: File that the original pg_hba file was backed up to.
    returned: changed
    type: str
    sample: /tmp/pg_hba_jxobj_p
pg_hba:
    description: List of the pg_hba rules as they are configured in the specified hba file.
    returned: success
    type: list
    sample:
      "pg_hba": [
         {
            "db": "all",
            "method": "md5",
            "src": "samehost",
            "type": "host",
            "usr": "all"
         }
      ]
'''

import os
import re
import traceback

IPADDRESS_IMP_ERR = None
try:
    import ipaddress
except ImportError:
    IPADDRESS_IMP_ERR = traceback.format_exc()

import shutil
import tempfile

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

# from ansible.module_utils.postgres import postgres_common_argument_spec

PG_HBA_METHODS = ["trust", "reject", "md5", "password", "gss", "sspi", "krb5", "ident", "peer",
                  "ldap", "radius", "cert", "pam", "scram-sha-256"]
PG_HBA_TYPES = ["local", "host", "hostssl", "hostnossl", "hostgssenc", "hostnogssenc"]
PG_HBA_HDR = ['type', 'db', 'usr', 'src', 'mask', 'method', 'options']

WHITESPACES_RE = re.compile(r'\s+')
TOKEN_SPLIT_RE = re.compile(r'(?<=[\s"])')
WHITESPACE_OR_QUOTE_RE = re.compile(r'[\s"]')
ONLY_SPACES_RE = re.compile(r"^\s+$")
OPTION_RE = re.compile(r"([^=]+)=(.+)")
IPV4_ADDR_RE = re.compile(r'^"?((\d{1,3}\.){3}\d{1,3})(/(\d{1,2}))?"?$')
# this regex allows for some invalid IPv6 addresses like ':::', but I honestly don't care
IPV6_ADDR_RE = re.compile(r'^"?([a-f0-9]*:[a-f0-9:]*:[a-f0-9]*)(/(\d{1,3}))?"?$')


class PgHbaError(Exception):
    '''
    This exception is raised when parsing the pg_hba file ends in an error.
    '''


class PgHbaRuleError(PgHbaError):
    '''
    This exception is raised when parsing the pg_hba file ends in an error.
    '''


class PgHbaRuleChanged(PgHbaRuleError):
    '''
    This exception is raised when a new parsed rule is a changed version of an existing rule.
    '''


class PgHbaValueError(PgHbaError):
    '''
    This exception is raised when a new parsed rule is a changed version of an existing rule.
    '''


class PgHbaRuleValueError(PgHbaRuleError):
    '''
    This exception is raised when a new parsed rule is a changed version of an existing rule.
    '''


class TokenizerException(Exception):
    """
    This exception is raised when a string can't be tokenized
    """


def parse_hba_file(input_string):
    """
    This function parses a complete pg_hba.conf file into a list of tuples where each tuple represents a rule in the
    file.
    :param input_string: The whole string in the pg_hba.conf file (not just a single line)
    :return: A list of Rule objects that represents the contents of the input string.
    """
    rules = []
    line_iter = iter(input_string.split("\n"))
    line = next(line_iter, None)
    while line is not None:
        # if that line continues, we just glue the next line onto the end until it ends
        # we can and have to do that, as continuation even applies within comments and quoted strings [sic]
        # https://www.postgresql.org/docs/current/auth-pg-hba-conf.html#AUTH-PG-HBA-CONF
        comment = None
        while line.endswith("\\"):
            cont_line = next(line_iter, None)
            if cont_line is None:
                # we got a line continuation, but there was no more line
                raise PgHbaRuleError("The last line ended with a '\\' (line continuation).")
            line += "\n" + cont_line  # add the newline so we don't lose that information
        # handle comment-only lines
        if line.strip().startswith('#'):
            parsed_line = "COMMENT"
            comment = line
        # handle empty lines
        elif line == '' or ONLY_SPACES_RE.match(line):
            parsed_line = "EMPTY"
        # handle "normal" lines
        else:
            # handle lines with comments
            sanitized_line = line
            if line.find('#') >= 0:
                comment = sanitized_line[sanitized_line.index("#"):]
                sanitized_line = sanitized_line[0:sanitized_line.index("#")]
            # remove continuation tokens
            sanitized_line = sanitized_line.replace("\\\n", "")
            tokens = tokenize(sanitized_line)
            parsed_line = tokens
        # create Rule
        rules.append({"tokens": parsed_line, "line": line, "comment": comment})
        line = next(line_iter, None)
    return rules


def tokenize(string):
    """
    This function tokenizes a string respecting quotes. It needs to be fed a complete string where all quotes are
    properly closed (there needs to be an even amount of `"`) otherwise it raises an exception.
    You can, for example use this to tokenize a full line of a pg_hba-file (make sure to handle any escaped newlines or
    comments before) or a string of options.
    :param string: A string to tokenize
    :return: The tokenized string as a list of strings
    """

    # We need to do this charade for splitting to be compatible with Python 3.6 which has been EOL for three years
    # at the time of writing. If you come across this after support for Python 3.6 has been dropped, please replace
    # WHITESPACE_OR_QUOTE_RE in the beginning of the file with `TOKEN_SPLIT_RE = re.compile(r'(?<=[\s"])')`
    # and the next 8 lines (including bare_tokens.append) with `bare_tokens = TOKEN_SPLIT_RE.split(string)`
    bare_tokens = []
    lastpos = 0
    nextmatch = WHITESPACE_OR_QUOTE_RE.search(string)
    while nextmatch:
        bare_tokens.append(string[lastpos:nextmatch.end()])
        lastpos = nextmatch.end()
        nextmatch = WHITESPACE_OR_QUOTE_RE.search(string, lastpos)
    bare_tokens.append(string[lastpos:])

    tokens = []
    state = "START"
    current_symbol = ""

    for token in bare_tokens:

        # if the previous token ended a quoted string, we need to decide how to continue
        if state == "QUOTE_END":
            state = "START"
            # if the token consists of only spaces, we know for sure this symbol is finished
            if token == "" or ONLY_SPACES_RE.match(token):
                tokens.append(current_symbol.strip())
                current_symbol = ""
                continue
            # otherwise it might continue with more characters or even another quote

        if token == "":
            continue

        # we either start a new symbol or continue after a finished quote
        if state == "START":
            # outside of quotes, whitespaces are ignored
            if ONLY_SPACES_RE.match(token):
                continue

            current_symbol += token
            # we use endswith here, to correctly handle stings like 'somekey="somevalue"'
            # if there was a space before it, the quote will be alone, so that is not an issue
            if token.endswith("\""):
                state = "QUOTE"
            else:
                tokens.append(current_symbol.strip())
                current_symbol = ""

        # if we are inside a quoted string we consume and append tokens until the quoted string ends
        elif state == "QUOTE":
            current_symbol += token
            if token.endswith("\""):
                state = "QUOTE_END"

    if state != "START":
        raise TokenizerException("Unterminated quote")

    return tokens


class PgHba(object):
    """
    PgHba object to read/write entries to/from.
    pg_hba_file - the pg_hba file almost always /etc/pg_hba
    """

    def __init__(self, pg_hba_file=None, backup=False, create=False, keep_comments_at_rules=False):
        self.pg_hba_file = pg_hba_file
        self.rules = None
        self.comment = None
        self.backup = backup
        self.last_backup = None
        self.create = create
        self.keep_comments_at_rules = keep_comments_at_rules
        self.unchanged()
        # self.databases will be update by add_rule and gives some idea of the number of databases
        # (at least that are handled by this pg_hba)
        self.databases = set(['postgres', 'template0', 'template1'])

        # self.databases will be update by add_rule and gives some idea of the number of users
        # (at least that are handled by this pg_hba) since this might also be groups with multiple
        # users, this might be totally off, but at least it is some info...
        self.users = set(['postgres'])

        self.preexisting_rules = None
        self.read()

    def clear_rules(self):
        self.rules = {}

    def unchanged(self):
        '''
        This method resets self.diff to a empty default
        '''
        self.diff = {'before': {'file': self.pg_hba_file, 'pg_hba': []},
                     'after': {'file': self.pg_hba_file, 'pg_hba': []}}

    def read(self):
        '''
        Read in the pg_hba from the system
        '''
        self.rules = {}
        self.comment = []
        # read the pg_hbafile
        try:
            with open(self.pg_hba_file, 'r') as file:
                hba_string = file.read()
        except IOError:
            return

        for line in parse_hba_file(hba_string):
            if line["tokens"] == "COMMENT":
                self.comment.append(line["comment"])
            elif line["tokens"] != "EMPTY":
                if not line["comment"]:
                    self._from_tokens(line["tokens"])
                else:
                    if self.keep_comments_at_rules:
                        self._from_tokens(line["tokens"], line["comment"])
                    else:
                        self.comment.append(line["comment"])
                        self._from_tokens(line["tokens"])
        self.unchanged()
        self.preexisting_rules = dict(self.rules)

    def _from_tokens(self, symbols, comment=None):
        if len(symbols) < 4:
            raise PgHbaRuleError("The rule has too few symbols")

        contype = _strip_quotes(symbols[0])
        if contype not in PG_HBA_TYPES:
            raise PgHbaRuleValueError("Found an unknown connection-type {0}".format(symbols[0]))

        # don't strip quotes from database or user, as they have a special meaning there [sic]
        # > Quoting one of the keywords in a database, user, or address field (e.g., all or replication) makes the word
        # > lose its special meaning, and just match a database, user, or host with that name.
        database = handle_db_and_user_strings(symbols[1])
        user = handle_db_and_user_strings(symbols[2])

        mask = None
        address = None
        if contype == "local":
            method_token = 3
        else:
            address, address_type, prefix_len = handle_address_field(symbols[3])
            # it is an IP, but without a CIDR suffix, so we expect a netmask in the next token
            if address_type.startswith("IP") and prefix_len == -1:
                mask, mask_type, prefix_len = handle_netmask_field(symbols[4], raise_not_valid=False)
                if mask_type == "invalid":
                    raise PgHbaRuleError("The rule either needs a hostname, full CIDR or an IP-address and a netmask")
                if mask_type != address_type:
                    raise PgHbaRuleError("Can't mix IPv4 and IPv6 netmasks and addresses")
                if len(symbols) < 6:
                    raise PgHbaRuleError("The rule has too few symbols")
                method_token = 5  # the method should be after the netmask
            # if it is anything but a bare IP address, we expect the method on index 4
            else:
                if len(symbols) < 5:
                    raise PgHbaRuleError("The rule has too few symbols")
                method_token = 4
            # convert address so the rule understands it, we will handle it better in the future
            if address_type != "hostname":
                address = str(address) + "/" + str(prefix_len)

        auth_method = _strip_quotes(symbols[method_token])
        if auth_method not in PG_HBA_METHODS:
            raise PgHbaRuleValueError("Found an unknown method: {0}".format(symbols[method_token]))

        auth_options = None
        # if there is anything after the method, that must be options
        if len(symbols) > method_token + 1:
            # we will handle options in a smarter way in the future
            # auth_options = parse_auth_options(symbols[method_token + 1:])
            # now we run it just to validate the options
            parse_auth_options(symbols[method_token + 1:])
            auth_options = " ".join(symbols[method_token + 1:])

        self.add_rule(
            PgHbaRule(contype=contype, databases=database, users=user, source=address, netmask=mask, method=auth_method,
                      options=auth_options, comment=comment))

    def write(self, backup_file=''):
        '''
        This method writes the PgHba rules (back) to a file.
        '''
        if not self.changed():
            return False

        contents = self.render()
        if self.pg_hba_file:
            if not (os.path.isfile(self.pg_hba_file) or self.create):
                raise PgHbaError("pg_hba file '{0}' doesn't exist. "
                                 "Use create option to autocreate.".format(self.pg_hba_file))
            if self.backup and os.path.isfile(self.pg_hba_file):
                if backup_file:
                    self.last_backup = backup_file
                else:
                    _backup_file_h, self.last_backup = tempfile.mkstemp(prefix='pg_hba')
                shutil.copy(self.pg_hba_file, self.last_backup)
            fileh = open(self.pg_hba_file, 'w')
        else:
            filed, _path = tempfile.mkstemp(prefix='pg_hba')
            fileh = os.fdopen(filed, 'w')

        fileh.write(contents)
        self.unchanged()
        fileh.close()
        return True

    def add_rule(self, rule):
        '''
        This method can be used to add a rule to the list of rules in this PgHba object
        '''
        key = rule.key()
        try:
            try:
                oldrule = self.rules[key]
            except KeyError:
                raise PgHbaRuleChanged
            ekeys = set(list(oldrule.keys()) + list(rule.keys()))
            ekeys.remove('line')
            for k in ekeys:
                if oldrule.get(k) != rule.get(k):
                    raise PgHbaRuleChanged('{0} changes {1}'.format(rule, oldrule))
        except PgHbaRuleChanged:
            self.rules[key] = rule
            self.diff['after']['pg_hba'].append(rule.line())
            if rule['db'] not in ['all', 'samerole', 'samegroup', 'replication']:
                databases = set(rule['db'].split(','))
                self.databases.update(databases)
            if rule['usr'] != 'all':
                user = rule['usr']
                if user[0] == '+':
                    user = user[1:]
                self.users.add(user)

    def remove_rule(self, rule):
        '''
        This method can be used to find and remove a rule. It doesn't look for the exact rule, only
        the rule with the same key.
        '''
        keys = rule.key()
        try:
            del self.rules[keys]
            self.diff['before']['pg_hba'].append(rule.line())
        except KeyError:
            pass

    def get_rules(self, with_lines=False):
        '''
        This method returns all the rules of the PgHba object
        '''
        rules = sorted(self.rules.values())
        for rule in rules:
            ret = {}
            for key, value in rule.items():
                ret[key] = value
            if not with_lines:
                if 'line' in ret:
                    del ret['line']
            else:
                ret['line'] = rule.line()

            yield ret

    def render(self):
        '''
        This method renders the content of the PgHba rules and comments.
        The returning value can be used directly to write to a new file.
        '''
        comment = '\n'.join(self.comment)
        rule_lines = []
        for rule in self.get_rules(with_lines=True):
            if 'comment' in rule:
                if not rule['comment'].startswith('#'):
                    rule_lines.append(rule['line'] + '\t#' + rule['comment'])
                else:
                    rule_lines.append(rule['line'] + '\t' + rule['comment'])
            else:
                rule_lines.append(rule['line'])
        result = comment + '\n' + '\n'.join(rule_lines)
        # End it properly with a linefeed (if not already).
        if result and result[-1] not in ['\n', '\r']:
            result += '\n'
        return result

    def changed(self):
        '''
        This method can be called to detect if the PgHba file has been changed.
        '''
        if not self.preexisting_rules and not self.rules:
            return False
        return self.preexisting_rules != self.rules


class PgHbaRule(dict):
    '''
    This class represents one rule as defined in a line in a PgHbaFile.
    '''

    def __init__(self, contype=None, databases=None, users=None, source=None, netmask=None,
                 method=None, options=None, line=None, comment=None):
        '''
        This function can be called with a comma separated list of databases and a comma separated
        list of users and it will act as a generator that returns a expanded list of rules one by
        one.
        '''

        super(PgHbaRule, self).__init__()

        if line:
            # Read values from line if parsed
            self.fromline(line)

        if comment:
            self['comment'] = comment

        # read rule cols from parsed items
        rule = dict(zip(PG_HBA_HDR, [contype, databases, users, source, netmask, method, options]))
        for key, value in rule.items():
            if value:
                self[key] = value

        # Some sanity checks
        for key in ['method', 'type']:
            if key not in self:
                raise PgHbaRuleError('Missing {method} in rule {rule}'.format(method=key, rule=self))

        if self['method'] not in PG_HBA_METHODS:
            msg = "invalid method {method} (should be one of '{valid_methods}')."
            raise PgHbaRuleValueError(msg.format(method=self['method'], valid_methods="', '".join(PG_HBA_METHODS)))

        if self['type'] not in PG_HBA_TYPES:
            msg = "invalid connection type {0} (should be one of '{1}')."
            raise PgHbaRuleValueError(msg.format(self['type'], "', '".join(PG_HBA_TYPES)))

        if self['type'] == 'local':
            self.unset('src')
            self.unset('mask')
        elif 'src' not in self:
            raise PgHbaRuleError('Missing src in rule {rule}'.format(rule=self))
        elif '/' in self['src']:
            self.unset('mask')
        else:
            self['src'] = str(self.source())
            self.unset('mask')

    def unset(self, key):
        '''
        This method is used to unset certain columns if they exist
        '''
        if key in self:
            del self[key]

    def line(self):
        '''
        This method can be used to return (or generate) the line
        '''
        try:
            return self['line']
        except KeyError:
            self['line'] = "\t".join([self[k] for k in PG_HBA_HDR if k in self.keys()])
            return self['line']

    def fromline(self, line):
        '''
        split into 'type', 'db', 'usr', 'src', 'mask', 'method', 'options' cols
        '''
        if WHITESPACES_RE.sub('', line) == '':
            # empty line. skip this one...
            return
        cols = WHITESPACES_RE.split(line)
        if len(cols) < 4:
            msg = "Rule {0} has too few columns."
            raise PgHbaValueError(msg.format(line))
        if cols[0] not in PG_HBA_TYPES:
            msg = "Rule {0} has unknown type: {1}."
            raise PgHbaValueError(msg.format(line, cols[0]))
        if cols[0] == 'local':
            cols.insert(3, None)  # No address
            cols.insert(3, None)  # No IP-mask
        if len(cols) < 6:
            cols.insert(4, None)  # No IP-mask
        elif cols[5] not in PG_HBA_METHODS:
            cols.insert(4, None)  # No IP-mask
        if cols[5] not in PG_HBA_METHODS:
            raise PgHbaValueError("Rule {0} of '{1}' type has invalid auth-method '{2}'".format(line, cols[0], cols[5]))

        if len(cols) < 7:
            cols.insert(6, None)  # No auth-options
        else:
            cols[6] = " ".join(cols[6:])  # combine all auth-options
        rule = dict(zip(PG_HBA_HDR, cols[:7]))
        for key, value in rule.items():
            if value:
                self[key] = value

    def key(self):
        '''
        This method can be used to get the key from a rule.
        '''
        if self['type'] == 'local':
            source = 'local'
        else:
            source = str(self.source())
        return (source, self['db'], self['usr'])

    def source(self):
        '''
        This method is used to get the source of a rule as an ipaddress object if possible.
        '''
        if 'mask' in self.keys():
            try:
                ipaddress.ip_address(u'{0}'.format(self['src']))
            except ValueError:
                raise PgHbaValueError('Mask was specified, but source "{0}" '
                                      'is not valid ip'.format(self['src']))
            # ipaddress module cannot work with ipv6 netmask, so lets convert it to prefixlen
            # furthermore ipv4 with bad netmask throws 'Rule {} doesn't seem to be an ip, but has a
            # mask error that doesn't seem to describe what is going on.
            try:
                mask_as_ip = ipaddress.ip_address(u'{0}'.format(self['mask']))
            except ValueError:
                raise PgHbaValueError('Mask {0} seems to be invalid'.format(self['mask']))
            binvalue = "{0:b}".format(int(mask_as_ip))
            if '01' in binvalue:
                raise PgHbaValueError('IP mask {0} seems invalid '
                                      '(binary value has 1 after 0)'.format(self['mask']))
            prefixlen = binvalue.count('1')
            sourcenw = '{0}/{1}'.format(self['src'], prefixlen)
            try:
                return ipaddress.ip_network(u'{0}'.format(sourcenw), strict=False)
            except ValueError:
                raise PgHbaValueError('{0} is not valid address range'.format(sourcenw))

        try:
            return ipaddress.ip_network(u'{0}'.format(self['src']), strict=False)
        except ValueError:
            return self['src']

    def __lt__(self, other):
        """This function helps sorted to decide how to sort.

        It just checks itself against the other and decides on some key values
        if it should be sorted higher or lower in the list.
        The way it works:
        For networks, every 1 in 'netmask in binary' makes the subnet more specific.
        Therefore I chose to use prefix as the weight.
        So a single IP (/32) should have twice the weight of a /16 network.
        To keep everything in the same weight scale,
        - for ipv6, we use a weight scale of 0 (all possible ipv6 addresses) to 128 (single ip)
        - for ipv4, we use a weight scale of 0 (all possible ipv4 addresses) to 128 (single ip)
        Therefore for ipv4, we use prefixlen (0-32) * 4 for weight,
        which corresponds to ipv6 (0-128).
        """
        myweight = self.source_weight()
        hisweight = other.source_weight()
        if myweight != hisweight:
            return myweight > hisweight

        myweight = self.db_weight()
        hisweight = other.db_weight()
        if myweight != hisweight:
            return myweight < hisweight

        myweight = self.user_weight()
        hisweight = other.user_weight()
        if myweight != hisweight:
            return myweight < hisweight
        try:
            return self['src'] < other['src']
        except TypeError:
            return self.source_type_weight() < other.source_type_weight()
        except Exception:
            # When all else fails, just compare the exact line.
            return self.line() < other.line()

    def source_weight(self):
        """Report the weight of this source net.

        Basically this is the netmask, where IPv4 is normalized to IPv6
        (IPv4/32 has the same weight as IPv6/128).
        """
        if self['type'] == 'local':
            return 130

        sourceobj = self.source()
        if isinstance(sourceobj, ipaddress.IPv4Network):
            return sourceobj.prefixlen * 4
        if isinstance(sourceobj, ipaddress.IPv6Network):
            return sourceobj.prefixlen
        if isinstance(sourceobj, str):
            # You can also write all to match any IP address,
            # samehost to match any of the server's own IP addresses,
            # or samenet to match any address in any subnet that the server is connected to.
            if sourceobj == 'all':
                # (all is considered the full range of all ips, which has a weight of 0)
                return 0
            if sourceobj == 'samehost':
                # (sort samehost second after local)
                return 129
            if sourceobj == 'samenet':
                # Might write some fancy code to determine all prefix's
                # from all interfaces and find a sane value for this one.
                # For now, let's assume IPv4/24 or IPv6/96 (both have weight 96).
                return 96
            if sourceobj[0] == '.':
                # suffix matching (domain name), let's assume a very large scale
                # and therefore a very low weight IPv4/16 or IPv6/64 (both have weight 64).
                return 64
            # hostname, let's assume only one host matches, which is
            # IPv4/32 or IPv6/128 (both have weight 128)
            return 128
        raise PgHbaValueError('Cannot deduct the source weight of this source {sourceobj}'.format(sourceobj=sourceobj))

    def source_type_weight(self):
        """Give a weight on the type of this source.

        Basically make sure that IPv6Networks are sorted higher than IPv4Networks.
        This is a 'when all else fails' solution in __lt__.
        """
        if self['type'] == 'local':
            return 3

        sourceobj = self.source()
        if isinstance(sourceobj, ipaddress.IPv4Network):
            return 2
        if isinstance(sourceobj, ipaddress.IPv6Network):
            return 1
        if isinstance(sourceobj, str):
            return 0
        raise PgHbaValueError('This source {0} is of an unknown type...'.format(sourceobj))

    def db_weight(self):
        """Report the weight of the database.

        Normally, just 1, but for replication this is 0, and for 'all', this is more than 2.
        """
        if self['db'] == 'all':
            return 100000
        if self['db'] == 'replication':
            return 0
        if self['db'] in ['samerole', 'samegroup']:
            return 1
        return 1 + self['db'].count(',')

    def user_weight(self):
        """Report weight when comparing users."""
        if self['usr'] == 'all':
            return 1000000
        return 1


def _strip_quotes(string):
    if not string:
        return string
    return string[1:-1] if string.startswith("\"") else string


def parse_auth_options(options):
    option_dict = {}
    for option in options:
        split_option = OPTION_RE.match(_strip_quotes(option))
        if not split_option:
            raise PgHbaRuleValueError(
                "Found invalid option '{}'. Options need to be in the format 'key=value'".format(option))
        if split_option.group(1) in option_dict.keys():
            raise PgHbaRuleValueError(
                "The rule contains two options with the same key ('{0}')".format(split_option.group(1)))
        option_dict[split_option.group(1)] = split_option.group(2)

    return option_dict


def handle_db_and_user_strings(string):
    # if the string is quoted or a regex, we return it unaltered
    if "\"" in string or string.startswith("/"):
        return string
    # we sort the dbs/users alphabetically
    else:
        return ",".join(sorted(string.split(",")))


def handle_address_field(address):
    ret_addr = ""
    ret_type = ""
    suffix = -1

    # only IPv6 addresses contain colons
    if ":" in address:
        ip_addr_check = IPV6_ADDR_RE.match(address)
        if not ip_addr_check:
            raise PgHbaRuleValueError("Address '{0}' contains a ':', but is not a valid IPv6 address".format(address))
        ret_addr = ip_addr_check.group(1)
        ret_type = "IPv6"
    else:
        ip_addr_check = IPV4_ADDR_RE.match(address)
        if ip_addr_check:
            ret_addr = ip_addr_check.group(1)
            ret_type = "IPv4"

    # if it is an address, check if there is a suffix
    if ret_addr:
        if ip_addr_check.group(3):
            suffix = int(ip_addr_check.group(3).strip('/'))
            if ret_type == "IPv4" and suffix > 32:
                raise PgHbaRuleValueError(
                    "The suffix '{0}' exceeds the maximum of 32 for IPv4 addresses".format(suffix))
            elif ret_type == "IPv6" and suffix > 128:
                raise PgHbaRuleValueError(
                    "The suffix '{0}' exceeds the maximum of 128 for IPv6 addresses".format(suffix))
    # if it doesn't match the IPv4 or IPv6 regex, we assume it is a hostname
    else:
        ret_addr = address
        ret_type = "hostname"

    return ret_addr, ret_type, suffix


def handle_netmask_field(netmask, raise_not_valid=True):
    mask = _strip_quotes(netmask)
    prefix_len = -1

    if ":" in mask:
        verify_mask = IPV6_ADDR_RE.match(mask)
        if not verify_mask:
            raise PgHbaRuleValueError("Netmask '{0}' contains a ':', but is not a valid IPv6 netmask".format(mask))
        mask_type = "IPv6"
    else:
        verify_mask = IPV4_ADDR_RE.match(netmask)
        mask_type = "IPv4"

    if not verify_mask:  # it is not a netmask, at all
        if raise_not_valid:
            raise PgHbaRuleValueError("The string '{0}' is not a valid netmask".format(netmask))
        else:
            mask = ""
            mask_type = "invalid"
    else:
        if verify_mask.group(3):  # somebody put a cidr-suffix on the netmask
            raise PgHbaRuleValueError("The netmask can't have a CIDR suffix")
        mask_as_ip = ipaddress.ip_address(u'{0}'.format(mask))
        binvalue = "{0:b}".format(int(mask_as_ip))
        if '01' in binvalue:
            raise PgHbaValueError('IP mask {0} is invalid (binary value has 1 after 0)'.format(mask))
        prefix_len = binvalue.count('1')

    return mask, mask_type, prefix_len


def main():
    '''
    This function is the main function of this module
    '''
    # argument_spec = postgres_common_argument_spec()
    argument_spec = dict()
    argument_spec.update(
        address=dict(type='str', default='samehost', aliases=['source', 'src']),
        backup=dict(type='bool', default=False),
        backup_file=dict(type='str'),
        contype=dict(type='str', default=None, choices=PG_HBA_TYPES),
        comment=dict(type='str', default=None),
        create=dict(type='bool', default=False),
        databases=dict(type='str', default='all'),
        dest=dict(type='path', required=True),
        method=dict(type='str', default='md5', choices=PG_HBA_METHODS),
        netmask=dict(type='str'),
        options=dict(type='str'),
        keep_comments_at_rules=dict(type='bool', default=False),
        state=dict(type='str', default="present", choices=["absent", "present"]),
        users=dict(type='str', default='all'),
        rules=dict(type='list', elements='dict'),
        rules_behavior=dict(type='str', default='conflict', choices=['combine', 'conflict']),
        overwrite=dict(type='bool', default=False),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        add_file_common_args=True,
        supports_check_mode=True
    )
    if IPADDRESS_IMP_ERR is not None:
        module.fail_json(msg=missing_required_lib('ipaddress'), exception=IPADDRESS_IMP_ERR)

    create = bool(module.params["create"] or module.check_mode)
    if module.check_mode:
        backup = False
    else:
        backup = module.params['backup']
    dest = module.params["dest"]
    keep_comments_at_rules = module.params["keep_comments_at_rules"]
    rules = module.params["rules"]
    rules_behavior = module.params["rules_behavior"]
    overwrite = module.params["overwrite"]

    ret = {'msgs': []}
    try:
        pg_hba = PgHba(dest, backup=backup, create=create, keep_comments_at_rules=keep_comments_at_rules)
    except PgHbaError as error:
        module.fail_json(msg='Error reading file:\n{0}'.format(error))

    if overwrite:
        pg_hba.clear_rules()

    rule_keys = [
        'address',
        'comment',
        'contype',
        'databases',
        'method',
        'netmask',
        'options',
        'state',
        'users'
    ]
    if rules is None:
        single_rule = dict()
        for key in rule_keys:
            single_rule[key] = module.params[key]
        rules = [single_rule]
    else:
        if rules_behavior == 'conflict':
            # it's ok if the module default is set
            used_rule_keys = [key for key in rule_keys if module.params[key] != argument_spec[key].get('default', None)]
            if len(used_rule_keys) > 0:
                module.fail_json(msg='conflict: either argument "rules_behavior" needs to be changed or "rules" must'
                                     ' not be set or {0} must not be set'.format(used_rule_keys))

        new_rules = []
        for index, rule in enumerate(rules):
            # alias handling
            address_keys = [key for key in rule.keys() if key in ('address', 'source', 'src')]
            if len(address_keys) > 1:
                module.fail_json(msg='rule number {0} of the "rules" argument ({1}) uses ambiguous settings: '
                                     '{2} are aliases, only one is allowed'.format(index, address_keys, rule))
            if len(address_keys) == 1:
                address = rule[address_keys[0]]
                del rule[address_keys[0]]
                rule['address'] = address

            for key in rule_keys:
                if key not in rule:
                    if rules_behavior == 'combine':
                        # use user-supplied defaults or module defaults
                        rule[key] = module.params[key]
                    else:
                        # use module defaults
                        rule[key] = argument_spec[key].get('default', None)
            new_rules.append(rule)
        rules = new_rules

    for rule in rules:
        if rule.get('contype', None) is None:
            continue

        try:
            for database in rule['databases'].split(','):
                for user in rule['users'].split(','):
                    if len(tokenize(database)) != 1:
                        module.fail_json(msg="Invalid string for database: {0}".format(database))
                    if len(tokenize(user)) != 1:
                        module.fail_json(msg="Invalid string for users: {0}".format(user))
                    pg_hba_rule = PgHbaRule(rule['contype'], database, user, rule['address'], rule['netmask'],
                                            rule['method'], rule['options'], comment=rule['comment'])
                    if rule['state'] == "present":
                        ret['msgs'].append('Adding rule {0}'.format(pg_hba_rule))
                        pg_hba.add_rule(pg_hba_rule)
                    else:
                        ret['msgs'].append('Removing rule {0}'.format(pg_hba_rule))
                        pg_hba.remove_rule(pg_hba_rule)
        except PgHbaError as error:
            module.fail_json(msg='Error modifying rules:\n{0}'.format(error))
    file_args = module.load_file_common_arguments(module.params)
    ret['changed'] = changed = pg_hba.changed()
    if changed:
        ret['msgs'].append('Changed')
        ret['diff'] = pg_hba.diff

        if not module.check_mode:
            ret['msgs'].append('Writing')
            try:
                if pg_hba.write(module.params['backup_file']):
                    module.set_fs_attributes_if_different(file_args, True, pg_hba.diff,
                                                          expand=False)
            except PgHbaError as error:
                module.fail_json(msg='Error writing file:\n{0}'.format(error))
            if pg_hba.last_backup:
                ret['backup_file'] = pg_hba.last_backup

    ret['pg_hba'] = list(pg_hba.get_rules())
    module.exit_json(**ret)


if __name__ == '__main__':
    main()
