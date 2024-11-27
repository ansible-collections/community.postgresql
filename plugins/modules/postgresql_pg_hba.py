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
- Thomas Ziegler (@toydarian)
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

import copy
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
PG_HBA_REQUIRED_FIELDS = ['contype', 'databases', 'users', 'method']

RULE_KEYS = ['contype', 'databases', 'users', 'address', 'netmask', 'method', 'options',]
PG_HBA_HDR_MAP = dict(zip(RULE_KEYS, PG_HBA_HDR))
PG_HBA_HDR_NOMAP = dict(zip(RULE_KEYS, RULE_KEYS))

WHITESPACES_RE = re.compile(r'\s+')
TOKEN_SPLIT_RE = re.compile(r'(?<=[\s"#])')
WHITESPACE_QUOTE_OR_COMMENT_RE = re.compile(r'[\s"#]')
ONLY_SPACES_RE = re.compile(r"^\s+$")
OPTION_RE = re.compile(r"([^=]+)=(.+)")
IPV4_ADDR_RE = re.compile(r'^"?((\d{1,3}\.){3}\d{1,3})(/(\d{1,2}))?"?$')
# this regex allows for some invalid IPv6 addresses like ':::', but I honestly don't care
IPV6_ADDR_RE = re.compile(r'^"?([a-f0-9]*:[a-f0-9:]*:[a-f0-9]*)(/(\d{1,3}))?"?$')


class PgHbaError(Exception):
    """
    This exception is raised when parsing the pg_hba file ends in an error.
    """


class PgHbaRuleError(PgHbaError):
    """
    This exception is raised when parsing the pg_hba file ends in an error.
    """


class PgHbaRuleChanged(PgHbaRuleError):
    """
    This exception is raised when a new parsed rule is a changed version of an existing rule.
    """


class PgHbaValueError(PgHbaError):
    """
    This exception is raised when a new parsed rule is a changed version of an existing rule.
    """


class PgHbaRuleValueError(PgHbaRuleError):
    """
    This exception is raised when a new parsed rule is a changed version of an existing rule.
    """


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
    this_line_nr = 1
    next_line_nr = 1
    while line is not None:
        # if that line continues, we just glue the next line onto the end until it ends
        # we can and have to do that, as continuation even applies within comments and quoted strings [sic]
        # https://www.postgresql.org/docs/current/auth-pg-hba-conf.html#AUTH-PG-HBA-CONF
        comment = None
        while line.endswith("\\"):
            next_line_nr += 1
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
        elif not line.strip():
            parsed_line = "EMPTY"
        # handle "normal" lines
        else:
            # remove continuation tokens
            sanitized_line = line.replace("\\\n", "")
            try:
                tokens = tokenize(sanitized_line)
            except TokenizerException as e:
                raise TokenizerException("Error in line {0}: {1}".format(this_line_nr, e.args[0]))
            parsed_line = tokens
            # a comment would always be the last token
            if parsed_line[-1].startswith("#"):
                comment = parsed_line[-1]
                parsed_line = parsed_line[:-1]
        # create Rule
        rules.append({"tokens": parsed_line, "line": line, "comment": comment, "line_nr": this_line_nr})
        line = next(line_iter, None)
        this_line_nr = next_line_nr + 1
        next_line_nr = this_line_nr
    return rules


def tokenize(string):
    """
    This function tokenizes a string respecting quotes. It needs to be fed a complete string where all quotes are
    properly closed (there needs to be an even amount of `"`) otherwise it raises an exception.
    You can, for example use this to tokenize a full line of a pg_hba-file (make sure to handle any escaped newlines)
    or a string of options.
    :param string: A string to tokenize
    :return: The tokenized string as a list of strings
    """

    # We need to do this charade for splitting to be compatible with Python 3.6 which has been EOL for three years
    # at the time of writing. If you come across this after support for Python 3.6 has been dropped, please replace
    # WHITESPACE_OR_QUOTE_RE in the beginning of the file with `TOKEN_SPLIT_RE = re.compile(r'(?<=[\s"#])')`
    # and the next 8 lines (including bare_tokens.append) with `bare_tokens = TOKEN_SPLIT_RE.split(string)`
    bare_tokens = []
    lastpos = 0
    nextmatch = WHITESPACE_QUOTE_OR_COMMENT_RE.search(string)
    while nextmatch:
        bare_tokens.append(string[lastpos:nextmatch.end()])
        lastpos = nextmatch.end()
        nextmatch = WHITESPACE_QUOTE_OR_COMMENT_RE.search(string, lastpos)
    bare_tokens.append(string[lastpos:])

    tokens = []
    state = "START"
    current_symbol = ""

    for token in bare_tokens:

        # if the previous token ended a quoted string, we need to decide how to continue
        if state == "QUOTE_END":
            state = "START"
            # if the token consists of only spaces, we know for sure this symbol is finished
            if token == "" or not token.strip():
                tokens.append(current_symbol.strip())
                current_symbol = ""
                continue
            # otherwise it might continue with more characters or even another quote

        if token == "":
            continue

        # we either start a new symbol or continue after a finished quote
        if state == "START":
            # outside of quotes, whitespaces are ignored
            if not token.strip():
                continue

            current_symbol += token
            # we use endswith here, to correctly handle strings like 'somekey="somevalue"'
            # if there was a space before it, the quote will be alone, so that is not an issue
            if token.endswith("\""):
                state = "QUOTE"
            elif token.endswith("#"):
                # handle edge-case of a comment having no space before the #-symbol like "... md5#some comment"
                if not token.startswith("#"):
                    current_symbol = current_symbol[:-1]
                    tokens.append(current_symbol.strip())
                    current_symbol = "#"
                state = "COMMENT"
            else:
                tokens.append(current_symbol.strip())
                current_symbol = ""

        elif state == "COMMENT":
            current_symbol += token

        # if we are inside a quoted string we consume and append tokens until the quoted string ends
        elif state == "QUOTE":
            current_symbol += token
            if token.endswith("\""):
                state = "QUOTE_END"

    if state == "COMMENT":
        tokens.append(current_symbol)
    elif state == "QUOTE":
        raise TokenizerException("Unterminated quote")

    return tokens


def from_rule_list(rule_list):
    """
    Creates a list of Rule objects from a list of dicts.
    :param rule_list: A list of dicts where each item in the list represents a rule
    :return: A list of Rule objects created from the items in the list
    """
    rules = []
    for rule in rule_list:
        if rule == {}:
            rules.append(PgHbaRule(tokens="EMPTY", line=''))
        elif not rule['contype'] and rule['comment']:
            rules.append(PgHbaRule(tokens="COMMENT", comment=rule['comment']))
        else:
            rules.append(PgHbaRule(rule_dict=rule))
    return rules


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
                try:
                    if not line["comment"]:
                        self.add_rule(PgHbaRule(tokens=line["tokens"], line=line["line"]))
                    else:
                        if self.keep_comments_at_rules:
                            self.add_rule(PgHbaRule(tokens=line["tokens"], line=line["line"], comment=line["comment"]))
                        else:
                            self.comment.append(line["comment"])
                            self.add_rule(PgHbaRule(tokens=line["tokens"], line=line["line"]))
                except PgHbaError as e:
                    raise e.__class__("Error in line {0}: {1}".format(line["line_nr"], e.args[0]))

        self.unchanged()
        self.preexisting_rules = copy.deepcopy(self.rules)

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
        """
        This method can be used to add a rule to the list of rules in this PgHba object
        :param rule: The rule to add
        """
        key = rule.key()

        if key in self.rules:
            if not self.rules[key].is_identical(rule):
                self.diff['after']['pg_hba'].append(rule.serialize(use_line=False))
                self.rules[key] = rule
        else:
            self.rules[key] = rule

    def remove_rule(self, rule):
        '''
        This method can be used to find and remove a rule. It doesn't look for the exact rule, only
        the rule with the same key.
        '''
        keys = rule.key()
        try:
            del self.rules[keys]
            self.diff['before']['pg_hba'].append(rule.serialize(use_line=False))
        except KeyError:
            pass

    def get_rules(self, with_lines=False):
        '''
        This method returns all the rules of the PgHba object
        '''
        rules = sorted(self.rules.values())
        for rule in rules:
            yield rule.to_dict(header_map=PG_HBA_HDR_MAP)

    def render(self):
        '''
        This method renders the content of the PgHba rules and comments.
        The returning value can be used directly to write to a new file.
        '''
        comment = '\n'.join(self.comment)
        rule_lines = []
        for rule in sorted(self.rules.values()):
            if rule.comment:
                if not rule.comment.startswith('#'):
                    rule_lines.append(rule.serialize(use_line=False, with_comment=False) + '\t#' + rule.comment)
                else:
                    rule_lines.append(rule.serialize(use_line=False, with_comment=False) + '\t' + rule.comment)
            else:
                rule_lines.append(rule.serialize(use_line=False, with_comment=False))
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
        if (not self.preexisting_rules and self.rules) or (self.preexisting_rules and not self.rules):
            return True
        if len(self.preexisting_rules) != len(self.rules):
            return True
        for key in self.rules.keys():
            if key not in self.preexisting_rules:
                return True
            if not self.rules[key].is_identical(self.preexisting_rules[key]):
                return True
        return False


class PgHbaRule:
    """
    This class represents one rule as defined in a line in a PgHbaFile.
    """

    def __init__(self, tokens=None, rule_dict=None, line=None, comment=None):
        """
        Creates a new PgHbaRule object, either from a list of tokens or a dictionary of fields. It will validate the
        input and raise an exception if the rule is invalid. It will also decide if a rule is special in a sense that
        it only contains a comment, is an include or an empty line.
        Either tokens or rule_dict may be not None.
        :param tokens: A list of tokens to create the rule from (mutually exclusive with rule_dict)
        :param rule_dict: A dictionary representing the rule (mutually exclusive with tokens)
        :param line: The line this rule was created from (if it was parsed from a file, None is fine)
        :param comment: A comment associated with that rule
        """
        self._type = None
        self._database = None
        self._user = None
        self._address = None
        self._mask = None
        self._auth_method = None
        self._auth_options = None

        self._address_type = None
        self._prefix_len = None

        # includes, comment-only lines and empty lines are special
        self._is_special = False
        self._line = line
        # normalize comment so we can safely compare it if we have to
        if comment:
            self._comment = comment.strip()
            self._comment = '# ' + self._comment if not self._comment.startswith('#') else self._comment
        else:
            self._comment = comment

        # parse tokens into a rule
        if tokens is not None:
            self._from_tokens(tokens)
        elif rule_dict is not None:
            self._from_rule_dict(rule_dict)

        if (tokens is None and rule_dict is None) or (tokens is not None and rule_dict is not None):
            raise PgHbaRuleError(
                "Exactly one of 'tokens' and 'rule_dict' needs to be specified when creating a Rule-object")

        # construct the line from the comment if there is no line, but a comment
        if self._is_special and not line and comment:
            self._line = self._comment

    @property
    def line(self):
        return self._line

    @property
    def is_special(self):
        return self._is_special

    @property
    def comment(self):
        return self._comment

    @property
    def type(self):
        return self._type

    @property
    def user(self):
        return self._user

    @property
    def database(self):
        return self._database

    @property
    def address(self):
        return self._address

    @property
    def netmask(self):
        return self._mask

    @property
    def method(self):
        return self._auth_method

    @property
    def options(self):
        return copy.copy(self._auth_options)

    @property
    def source(self):
        """
        This method is used to get the source of a rule as an ipaddress object if possible.
        """
        if self._type == "local":
            return ""
        if self._address_type == "hostname":
            return self._address
        else:
            return ipaddress.ip_network("{0}/{1}".format(self._address, self._prefix_len), strict=False)

    @property
    def source_type(self):
        return self._address_type

    def __eq__(self, other):
        """
        Rules are considered "equal" if they have the same key, as in type, user, database and source.
        Special rules are equal if they are identical
        """
        # comments are only compared if they are not attached to a rule
        if self.is_special and other.is_special:
            if self.comment and other.comment:
                return self.comment == other.comment
            return self.line == other.line

        # normal rules are equal if they key matches
        return (self._type == other.type
                and self._user == other.user
                and self._database == other.database
                and self.source == other.source)

    def __lt__(self, other):
        """This function helps sorted to decide how to sort.

        It just checks itself against the other and decides on some key values
        if it should be sorted higher or lower in the list.
        The way it works:
        For networks, every 1 in 'netmask in binary' makes the subnet more specific.
        Therefore, I chose to use prefix as the weight.
        So a single IP (/32) should have twice the weight of a /16 network.
        To keep everything in the same weight scale,
        - for ipv6, we use a weight scale of 0 (all possible ipv6 addresses) to 128 (single ip)
        - for ipv4, we use a weight scale of 0 (all possible ipv4 addresses) to 128 (single ip)
        Therefore for ipv4, we use prefixlen (0-32) * 4 for weight,
        which corresponds to ipv6 (0-128).
        """

        if self.is_special and other.is_special:
            myweight = self.special_weight()
            hisweight = other.special_weight()
            if myweight != hisweight:
                return myweight < hisweight
            else:
                return self.line < other.line

        # comments go before anything else, the rest goes last
        if self.is_special and not other.is_special:
            return bool(self._comment)
        if not self.is_special and other.is_special:
            return bool(other.comment)

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

        myweight = self.source_type_weight()
        hisweight = other.source_type_weight()
        if myweight != hisweight:
            return myweight > hisweight
        elif self.source != other.source:
            return self.source < other.source

        # When all else fails, just compare the rendered lines
        return self.serialize() < other.serialize()

    def __str__(self):
        return self.serialize()

    def __copy__(self):
        return PgHbaRule(rule_dict=self.to_dict(), line=self._line, comment=self._comment)

    def source_weight(self):
        """Report the weight of this source net.

        Basically this is the netmask, where IPv4 is normalized to IPv6
        (IPv4/32 has the same weight as IPv6/128).
        """

        if self._type == "local":
            return 130

        if self._address_type == "IPv4":
            return self._prefix_len * 4
        elif self._address_type == "IPv6":
            return self._prefix_len
        else:
            # You can also write all to match any IP address,
            # samehost to match any of the server's own IP addresses,
            # or samenet to match any address in any subnet that the server is connected to.
            if self._address == 'all':
                # (all is considered the full range of all ips, which has a weight of 0)
                return 0
            if self._address == 'samehost':
                # (sort samehost second after local)
                return 129
            if self._address == 'samenet':
                # Might write some fancy code to determine all prefix's
                # from all interfaces and find a sane value for this one.
                # For now, let's assume IPv4/24 or IPv6/96 (both have weight 96).
                return 96
            if self._address.startswith('.'):
                # suffix matching (domain name), let's assume a very large scale
                # and therefore a very low weight IPv4/16 or IPv6/64 (both have weight 64).
                return 64
            # hostname, let's assume only one host matches, which is
            # IPv4/32 or IPv6/128 (both have weight 128)
            return 128

    def source_type_weight(self):
        """Give a weight on the type of this source.

        Basically make sure that IPv6Networks are sorted higher than IPv4Networks.
        This is a 'when all else fails' solution in __lt__.
        """
        if self._type == 'local':
            return 3

        sourceobj = self.source
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
        if self._database.startswith("\""):
            # keywords lose their special meaning if quoted
            return 3
        db_list = self._database.split(',')
        if "all" in db_list:
            return 100000
        if self._database == 'replication':
            return 0
        if self._database in ['samerole', 'samegroup']:
            return 2
        return 3 + len(db_list)

    def user_weight(self):
        """Report weight when comparing users."""
        if self._user.startswith("\""):
            # keywords lose their special meaning if quoted
            return 1
        user_list = self._user.split(',')
        if "all" in user_list:
            # if "all" is in the list, we sort it to the bottom
            return 100000
        return 1 + len(user_list)

    def special_weight(self):
        """Determines the weight to sort special lines"""
        if self.comment:
            return 1
        if self._line.startswith("include_if_exists"):
            return 3
        if self._line.startswith("include_dir"):
            return 4
        if self._line.startswith("include"):
            return 2

        return 99  # only empty lines

    def to_dict(self, header_map=None):
        if header_map is None:
            header_map = PG_HBA_HDR_NOMAP
        if self._is_special:
            if not self._comment:
                return {}
            else:
                return {'comment': self._comment}

        ret_dict = {header_map['contype']: self._type,
                    header_map['databases']: self._database,
                    header_map['users']: self._user,
                    header_map['method']: self._auth_method}
        if self._address:
            ret_dict[header_map['address']] = str(self.source)
        if self._auth_options:
            # we might want to change the return-type to a dict at some point, but right now we return a string
            # to not introduce breaking changes
            # ret_dict[header_map['options']] = copy.copy(self._auth_options)
            ret_dict[header_map['options']] = self._serialize_auth_options(delimiter=" ")
        if self._comment:
            ret_dict['comment'] = self._comment
        return ret_dict

    def is_identical(self, other):
        """Rules are identical if they share the same key, method and options"""
        return (self == other
                and self._auth_method == other.method
                and self._auth_options == other.options)

    def serialize(self, delimiter="\t", use_line=True, with_comment=True):
        """
        Serializes a rule into a string that can be placed in a pg_hba.conf file. If `line` is not None (mostly if this
        rule has been parsed from a pg_hba.conf file previously) and use_line is True, this returns the line this rule
        was originally parsed from. Otherwise, it creates a line from the rule.
        :param delimiter: The character to use to separate the fields
        :param use_line: Use the line this rule was parsed from, if it exists
        :param with_comment: Include comment when serializing
        :return: A string from the rule that can be used in a pg_hba.conf file
        """
        if self._line and use_line:
            return self._line

        if self._is_special:
            if not self._comment:
                return ""
            else:
                return self.comment

        rule = self._type + delimiter + self._database + delimiter + self._user + delimiter
        if self._type != "local":
            rule += str(self.source) + delimiter
        rule += self._auth_method

        if self._auth_options:
            rule += delimiter + self._serialize_auth_options(delimiter=" ")

        if self._comment and with_comment:
            if self._comment.startswith("#"):
                rule += delimiter + self.comment
            else:
                rule += delimiter + "# " + self._comment

        return rule

    def key(self):
        """
        This method can be used to get the key from a rule.
        """
        if self._type == 'local':
            source = 'local'
        else:
            source = str(self.source)
        return source, self._database, self._user, self._type

    def _serialize_auth_options(self, delimiter):
        options = []
        for key in sorted(self._auth_options.keys()):
            options.append(key + "=" + self._auth_options[key])
        return delimiter.join(options)

    def _from_tokens(self, symbols):
        # empty lines, full line comments and includes are special
        if symbols == "EMPTY" or symbols == "COMMENT" or symbols[0].startswith("include"):
            self._is_special = True
            return

        if len(symbols) < 4:
            raise PgHbaRuleError("The rule has too few symbols")

        self._type = _strip_quotes(symbols[0])
        if self._type not in PG_HBA_TYPES:
            raise PgHbaRuleValueError("Found an unknown connection-type {0}".format(symbols[0]))

        # don't strip quotes from database or user, as they have a special meaning there [sic]
        # > Quoting one of the keywords in a database, user, or address field (e.g., all or replication) makes the word
        # > lose its special meaning, and just match a database, user, or host with that name.
        self._database = handle_db_and_user_strings(symbols[1])
        self._user = handle_db_and_user_strings(symbols[2])

        if self._type == "local":
            method_token = 3
        else:
            self._address, self._address_type, self._prefix_len = handle_address_field(symbols[3])
            # it is an IP, but without a CIDR suffix, so we expect a netmask in the next token
            if self._address_type.startswith("IP") and self._prefix_len == -1:
                self._mask, mask_type, self._prefix_len = handle_netmask_field(symbols[4], raise_not_valid=False)
                if mask_type == "invalid":
                    raise PgHbaRuleError("The rule either needs a hostname, full CIDR or an IP-address and a netmask")
                if mask_type != self._address_type:
                    raise PgHbaRuleError("Can't mix IPv4 and IPv6 netmasks and addresses")
                if len(symbols) < 6:
                    raise PgHbaRuleError("The rule has too few symbols")
                method_token = 5  # the method should be after the netmask
            # if it is anything but a bare IP address, we expect the method on index 4
            else:
                if len(symbols) < 5:
                    raise PgHbaRuleError("The rule has too few symbols")
                method_token = 4

        self._auth_method = _strip_quotes(symbols[method_token])
        if self._auth_method not in PG_HBA_METHODS:
            raise PgHbaRuleValueError("Found an unknown method: {0}".format(symbols[method_token]))

        # if there is anything after the method, that must be options
        if len(symbols) > method_token + 1:
            self._auth_options = parse_auth_options(symbols[method_token + 1:])

    def _from_rule_dict(self, rule_dict):
        # handle special cases
        if not rule_dict or len(rule_dict) == 1 and "comment" in rule_dict:
            self._is_special = True
        if "comment" in rule_dict and rule_dict["comment"]:
            self._comment = rule_dict['comment'].strip()
        # if the rule is special, we are done now
        if self._is_special:
            return

        # make sure each rule includes all required fields
        for field in PG_HBA_REQUIRED_FIELDS:
            if field not in rule_dict:
                raise PgHbaRuleError("All rules need to contain '{0}'".format(field))

        # verify contype and set databases and users
        self._type = _strip_quotes(rule_dict["contype"])
        if self._type not in PG_HBA_TYPES:
            raise PgHbaRuleValueError("Unknown type {0}".format(self._type))
        self._database = rule_dict["databases"]
        self._user = rule_dict["users"]

        # verify address and netmask if the contype isn't "local"
        if self._type != "local":
            if "address" not in rule_dict:
                raise PgHbaRuleError("If the contype isn't 'local', the rule needs to contain an address")
            self._address, self._address_type, self._prefix_len = handle_address_field(rule_dict["address"])
            # verify the netmask if there is one
            if "netmask" in rule_dict and rule_dict['netmask']:
                if (self._address_type.startswith("IP") and self._prefix_len > -1) or self._address_type == "hostname":
                    raise PgHbaRuleError("Rule can't contain a netmask if address is a full CIDR or hostname")
                self._mask, mask_type, self._prefix_len = handle_netmask_field(rule_dict["netmask"])
                if mask_type != self._address_type:
                    raise PgHbaRuleError("Can't mix IPv4 and IPv6 netmasks and addresses")
            else:
                if self._address_type.startswith("IP") and self._prefix_len == -1:
                    raise PgHbaRuleError("If the address is a bare ip-address without a CIDR suffix, "
                                         "the rule needs to contain a netmask")

        # if the contype is "local", the rule can't contain an address or netmask
        else:
            if (("address" in rule_dict and rule_dict["address"])
                    or ("netmask" in rule_dict and rule_dict["netmask"])):
                raise PgHbaRuleError("Rule can't contain an address and netmask if the connection-type is 'local'")

        # verify the method
        self._auth_method = _strip_quotes(rule_dict["method"])
        if self._auth_method not in PG_HBA_METHODS:
            raise PgHbaRuleValueError("Unknown method {0}".format(self._auth_method))

        if "options" in rule_dict and rule_dict["options"]:
            if isinstance(rule_dict["options"], dict):
                self._auth_options = copy.deepcopy(rule_dict['options'])
            elif isinstance(rule_dict["options"], str):
                self._auth_options = parse_auth_options(tokenize(rule_dict["options"]))
            elif isinstance(rule_dict["options"], list):
                self._auth_options = parse_auth_options(rule_dict["options"])
            else:
                raise PgHbaValueError(
                    "Invalid type {} for options, needs to be either dict, list or str"
                    .format(type(rule_dict["options"])))


def _strip_quotes(string):
    if not string:
        return string
    return string[1:-1] if string.startswith("\"") else string


def parse_auth_options(options):
    """
    Parses a list of strings into a dict. Each input-string needs to be in the format key=value, if that isn't the case
    it raises an exception. If the same key is used twice, an exception is raised, as well.
    :param options: A list of strings, where each string is an option
    :return: A dict mapping str -> str where the key is the part before the first "=" in the input and the value is the
    rest
    """
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
    """
    Sorts a comma-delimited string of dbs or users alphabetically but returns quoted strings or regexes as-is.
    :param string: The string to work with
    :return: The new string
    """
    # if the string is quoted or a regex, we return it unaltered
    if "\"" in string or string.startswith("/"):
        return string
    # we sort the dbs/users alphabetically
    else:
        return ",".join(sorted(string.split(",")))


def handle_address_field(address):
    """
    Parses and address field and does some basic validation. Will detect IPv4 and IPv6 addresses and networks.
    Otherwise, assumes it is a hostname and checks for basic invalid characters, but doesn't do a full validation.
    Will raise an exception if the network has host bits set or is an invalid range in another way.
    :param address: The address to process
    :return: A tuple of (address, type, suffix) where type is "IPv4", "IPv6" or "hostname" and suffix is the size of the
    network if the address is an IP address. If it is a keyword (like "samehost", we still return "hostname" as type)
    """
    suffix = -1

    try:
        # try to parse it to a network
        ret_addr = ipaddress.ip_network(address, strict=True)
        ret_type = "IPv" + str(ret_addr.version)
        if "/" in address:
            # if it contains a slash, it is a network
            suffix = ret_addr.prefixlen
        ret_addr = str(ret_addr.network_address)
    except ValueError as e:
        # it is a network, but has host bits set
        if "has host bits set" in e.args[0]:
            raise PgHbaValueError("{0} has host bits set".format(address))
        # it might be a quoted address or network
        if address.startswith("\""):
            ret_addr, ret_type, suffix = handle_address_field(_strip_quotes(address))
            # if it was a quoted address, we return it without quotes
            if ret_type != "hostname":
                return ret_addr, ret_type, suffix
        # not a valid network or address, may be a hostname or keyword
        if re.search(r'[:\\/@+ ]', address) or IPV4_ADDR_RE.match(address):
            raise PgHbaValueError(
                "The string '{0}' is neither a valid IP address, network, hostname or keyword".format(address))
        else:
            ret_addr = address
            ret_type = "hostname"

    return ret_addr, ret_type, suffix


def handle_netmask_field(netmask, raise_not_valid=True):
    """
    Processes a netmask-field and validates it. Will raise an exception if the netmask is a valid IP address, but the
    binary representation has at least one zero before a one.
    :param netmask: The netmask to process
    :param raise_not_valid: If True, an exception is raised if the netmask is not a valid IP address
    :return: A tuple of (netmask, type, length) where type is "IPv4" or "IPv6" and length is the size of the network
    if `raise_not_valid` is `False` and the netmask is not a valid IP address, the type-field is "invalid"
    """
    mask = _strip_quotes(netmask)

    try:
        mask_as_ip = ipaddress.ip_address(u'{0}'.format(mask))
        binvalue = "{0:b}".format(int(mask_as_ip))
        if '01' in binvalue:
            raise PgHbaValueError('IP mask {0} is invalid (binary value has 1 after 0)'.format(mask))
        return mask, "IPv" + str(mask_as_ip.version), binvalue.count('1')
    except ValueError:
        if raise_not_valid:
            raise PgHbaValueError("The string '{0}' is not a valid netmask".format(mask))
        else:
            return "", "invalid", -1


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
    except (PgHbaError, TokenizerException) as error:
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
                    new_rule = copy.deepcopy(rule)
                    new_rule['databases'] = database
                    new_rule['users'] = user
                    pg_hba_rule = PgHbaRule(rule_dict=new_rule, comment=rule['comment'])
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
