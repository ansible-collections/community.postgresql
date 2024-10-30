#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Sebastiaan Mannem (@sebasmannem) <sebastiaan.mannem@enterprisedb.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


'''
This module is used to manage postgres pg_hba files with Ansible.
'''

from __future__ import absolute_import, division, print_function

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
      - This option has been B(deprecated) and will be removed in community.postgresql 5.0.0
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
      - A comment is only added or updated if the rule itself changes.
    type: str
    version_added: '1.5.0'
  databases:
    description:
      - Databases this line applies to.
    default: all
    type: str
  path:
    description:
      - Path to C(pg_hba) file to modify.
    type: path
    required: true
    aliases:
      - dest
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
      - Make sure to quote the value correctly, if it includes spaces. It will be added "as is".
    type: dict
  overwrite:
    description:
      - Remove all existing rules before adding rules. (Like I(state=absent) for all pre-existing rules.)
    type: bool
    default: false
  rules:
    description:
      - A list of objects, specifying rules for the pg_hba.conf. Use this to manage multiple rules at once.
      - "Each object can have the following keys (the 'rule-specific arguments'), which are treated the same as if they were arguments of this module:"
      - C(address), C(comment), C(contype), C(databases), C(method), C(netmask), C(options), C(state), C(users)
      - See also C(rules_behavior).
      - Comments are only added or updated, if the rule itself changes.
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
  sort_rules:
    description:
      - Sorts the rules in the file only if a change is required. It will sort the rules so more specific rules are at
        the top. For example, a rule matching a single host will be before a rule that matches an ip-range.
      - The order of rules is important, as they are evaluated top-down and the first one that matches is used.
        This means changing the order of rules in the file can change how your instance behaves.
      - Will sort comments to the top, includes to the bottom and remove empty lines.
      - I would advise to turn this off when managing a file that receives manual changes, as well or if the order
        you specify your rules in is important.
    type: bool
    default: true
    version_added: '4.0.0'
  prepend_rules:
    description:
      - Instead of appending the rule to then end of the file, add it in the beginning (before all other rules).
      - Will have no effect if C(sort_rules=true).
    type: bool
    default: false

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
pg_hba_dicts:
    description: List of the pg_hba rules as they are configured in the specified hba file. Doesn't include comments that aren't associated with a rule.
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
pg_hba:
    description: The string that is or would be written to the file.
    returned: success
    type: str
    sample: "local\tall\tall\tident\nhost\tall\tall\tsamehost\tmd5"
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
TOKEN_SPLIT_RE = re.compile(r'(?<=[\s"])')
ONLY_SPACES_RE = re.compile(r"^\s+$")
# STRIP_COMMENT_RE = re.compile(r'^[^#]*(?=#)')
OPTION_RE = re.compile(r"([^=]+)=(.+)")
IPV4_ADDR_RE = re.compile(r'^"?((\d{1,3}\.){3}\d{1,3})(/(\d{1,2}))?"?$')
# this regex allows for some invalid IPv6 addresses like ':::', but I honestly don't care
IPV6_ADDR_RE = re.compile(r'^"?([a-f0-9]*:[a-f0-9:]*:[a-f0-9]*)(/(\d{1,3}))?"?$')


# todo add insert after


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
    while line is not None:
        # if that line continues, we just glue the next line onto the end until it ends
        # we can and have to do that, as continuation even applies withing comments and quoted strings [sic]
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
        rules.append(Rule(tokens=parsed_line, line=line, comment=comment))
        line = next(line_iter, None)
    return rules


def from_rule_list(rule_list):
    """
    Creates a list of Rule objects from a list of dicts.
    :param rule_list: A list of dicts where each item in the list represents a rule
    :return: A list of Rule objects created from the items in the list
    """
    rules = []
    for rule in rule_list:
        if rule == {}:
            rules.append(Rule(tokens="EMPTY", line=''))
        elif not rule['contype'] and rule['comment']:
            rules.append(Rule(tokens="COMMENT", comment=rule['comment']))
        else:
            rules.append(Rule(rule_dict=rule))
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
    bare_tokens = TOKEN_SPLIT_RE.split(string)
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


class Rule(object):
    def __init__(self, tokens=None, rule_dict=None, line=None, comment=None):
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

    def _from_tokens(self, symbols):
        # empty lines, full line comments and includes are special
        if symbols == "EMPTY" or symbols == "COMMENT" or symbols[0].startswith("include"):
            self._is_special = True
            return

        if len(symbols) < 4:
            raise PgHbaRuleError("The rule has too few symbols")

        self._type = _strip_quotes(symbols[0])
        if self._type not in PG_HBA_TYPES:
            raise PgHbaRuleValueError(f"Found an unknown connection-type {symbols[0]}")

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
            raise PgHbaRuleValueError(f"Found an unknown method: {symbols[method_token]}")

        # if there is anything after the method, that must be options
        if len(symbols) > method_token + 1:
            self._auth_options = parse_auth_options(symbols[method_token + 1:])

    def _from_rule_dict(self, rule_dict):
        # handle special cases
        if not rule_dict or len(rule_dict) == 1 and "comment" in rule_dict:
            self._is_special = True
        if "comment" in rule_dict and rule_dict["comment"]:
            comment = rule_dict['comment'].strip()
            self._comment = f"{'# ' if not comment.startswith('#') else ''}{comment}"
        # if the rule is special, we are done now
        if self._is_special:
            return

        # make sure each rule includes all required fields
        for field in PG_HBA_REQUIRED_FIELDS:
            if field not in rule_dict:
                raise PgHbaRuleError(f"All rules need to contain '{field}'")

        # verify contype and set databases and users
        self._type = _strip_quotes(rule_dict["contype"])
        if self._type not in PG_HBA_TYPES:
            raise PgHbaRuleValueError(f"Unknown type {self._type}")
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
            raise PgHbaRuleValueError(f"Unknown method {self._auth_method}")

        if "options" in rule_dict:
            self._auth_options = copy.deepcopy(rule_dict['options'])

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
            return ipaddress.ip_network(f"{self._address}/{self._prefix_len}", strict=False)

    @property
    def source_type(self):
        return self._address_type

    def __eq__(self, other):
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

        if self.source_type == other.source_type and self.source != other.source:
            return self.source < other.source

        myweight = self.source_type_weight()
        hisweight = other.source_type_weight()
        if myweight != hisweight:
            return myweight > hisweight

        # When all else fails, just compare the rendered lines
        return self.serialize() < other.serialize()

    def __str__(self):
        return self.serialize()

    def __copy__(self):
        return Rule(rule_dict=self.to_dict(), line=self._line, comment=self._comment)

    def is_identical(self, other):
        return (self == other
                and self._auth_method == other.method
                and self._auth_options == other.options)

    def serialize(self, delimiter="\t"):
        if self._line:
            return self._line

        if self._is_special:
            if not self._comment:
                return ""
            else:
                return self.comment

        rule = f"{self._type}{delimiter}{self._database}{delimiter}{self._user}{delimiter}"
        if self._type != "local":
            rule += f"{self.source}{delimiter}"
        rule += self._auth_method

        if self._auth_options:
            rule += self._serialize_auth_options(delimiter)

        if self._comment:
            rule += f"{delimiter}{self._comment}"

        return rule

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

    def db_weight(self):
        """Report the weight of the database.

        Normally, just 1, but for replication this is 0, and for 'all', this is more than 2.
        """
        if self._database.startswith("\""):
            # keywords lose their special meaning if quoted
            return 2
        db_list = self._database.split(',')
        if "all" in db_list:
            return 100000
        if self._database == 'replication':
            return 0
        if self._database in ['samerole', 'samegroup']:
            return 1
        return 2 + len(db_list)

    def user_weight(self):
        """Report weight when comparing users."""
        if self._database.startswith("\""):
            # keywords lose their special meaning if quoted
            return 1
        user_list = self._user.split(',')
        if "all" in user_list:
            return 100000
        return 1 + len(user_list)

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
            ret_dict[header_map['options']] = copy.copy(self._auth_options)
        if self._comment:
            ret_dict['comment'] = self._comment
        return ret_dict

    def _serialize_auth_options(self, delimiter):
        option_string = ""
        for key, value in self._auth_options.items():
            option_string += f"{delimiter}{key}={value}"
        return option_string


def _strip_quotes(string):
    if not string:
        return string
    return string[1:-1] if string.startswith("\"") else string


def parse_auth_options(options):
    option_dict = {}
    for option in options:
        split_option = OPTION_RE.match(_strip_quotes(option))
        if not split_option:
            raise PgHbaRuleValueError(f"Found invalid option '{option}'. Options need to be in the format 'key=value'")
        if split_option.group(1) in option_dict.keys():
            raise PgHbaRuleValueError(f"The rule contains two options with the same key ('{split_option.group(1)}')")
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
            raise PgHbaRuleValueError(f"Address '{address}' contains a ':', but is not a valid IPv6 address")
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
                raise PgHbaRuleValueError(f"The suffix '{suffix}' exceeds the maximum of 32 for IPv4 addresses")
            elif ret_type == "IPv6" and suffix > 128:
                raise PgHbaRuleValueError(f"The suffix '{suffix}' exceeds the maximum of 128 for IPv6 addresses")
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
            raise PgHbaRuleValueError(f"Netmask '{mask}' contains a ':', but is not a valid IPv6 netmask")
        mask_type = "IPv6"
    else:
        verify_mask = IPV4_ADDR_RE.match(netmask)
        mask_type = "IPv4"

    if not verify_mask:  # it is not a netmask, at all
        if raise_not_valid:
            raise PgHbaRuleValueError(f"The string '{netmask}' is not a valid netmask")
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


def _from_file(file_path):
    if not os.path.isfile(file_path):
        return []
    with open(file_path, 'r') as file:
        return parse_hba_file(file.read())


def write_hba_file(file_path, rule_string, create, module, file_args, diff):
    """
    Writes a set of rules to a file
    :param file_path: The path to the file to write
    :param rule_string: The rules rendered into a string to write
    :param create: If `True` the file will be created if it doesn't exist
    :param module: The module-object
    :param file_args: Arguments for the destination file
    :param diff: Diff to add changes to
    """
    if not (os.path.isfile(file_path) or create):
        raise module.fail_json(msg="pg_hba file '{0}' doesn't exist. "
                                   "Use the create option to autocreate.".format(file_path))

    # tempfile.NamedTemporaryFile has delete_on_close only for Python>=3.12
    tmpfile = None
    try:
        tmpfile = tempfile.NamedTemporaryFile(mode='w', delete=False)
        tmpfile.write(rule_string)
        tmpfile.close()
        module.atomic_move(tmpfile.name, file_path, unsafe_writes=module.params["unsafe_writes"])
    finally:
        # try to remove the temporary file if something goes wrong
        if tmpfile and os.path.isfile(tmpfile.name):
            os.unlink(tmpfile.name)

    module.set_fs_attributes_if_different(file_args, True, diff, expand=False)


def render_rule_list(rule_list, delimiter="\t"):
    """
    Turns a list of rules into a string to write into the hba-file
    :param rule_list: The list of rules to render
    :param delimiter: The character or sequence used to separate fields
    :return: A valid string for a pg_hba file
    """
    return "\n".join([r.serialize(delimiter) for r in rule_list])


def rule_list_to_dict_list(rule_list, header_map=None):
    dict_list = []
    for rule in rule_list:
        if not rule.is_special:
            dict_list.append(rule.to_dict(header_map=header_map))
    return dict_list


def search_rule(rules, rule):
    if not rules:
        return -1
    for i in range(0, len(rules)):
        if rules[i] == rule:
            return i
    return -1


def update_rules(new_rules, existing_rules, prepend_rules=False):
    """
    Updates existing rules with new rules. The existing rules are updated in place.
    This method exists to extract this part of the logic for better testability.
    :param new_rules: A list of new rules for updating the existing ones
    :param existing_rules: The list of rules to update
    :param prepend_rules: Add new rules to the top instead of in the end
    :return: changed, msgs, diff_before, diff_after
    """
    changed = False
    msgs = []
    diff_after = []
    diff_before = []

    for rule in new_rules:
        if 'contype' in rule and rule['contype']:
            rule['databases'] = handle_db_and_user_strings(rule['databases'])
            rule['users'] = handle_db_and_user_strings(rule['users'])
            pg_hba_rule = Rule(rule_dict=rule)
        else:
            if 'comment' in rule:
                pg_hba_rule = Rule(tokens="COMMENT", comment=rule['comment'])
            else:
                continue
        index = search_rule(existing_rules, pg_hba_rule)

        # append rule if it doesn't exist
        if rule['state'] == "present" and index == -1:
            msgs.append('Adding rule {0}'.format(pg_hba_rule))
            diff_after.append(str(pg_hba_rule))
            if prepend_rules:
                existing_rules.insert(0, pg_hba_rule)
            else:
                existing_rules.append(pg_hba_rule)
            changed = True
        # update rule if it exists but is not correct
        elif rule['state'] == "present" and index > -1:
            if not existing_rules[index].is_identical(pg_hba_rule):
                msgs.append('Updating rule {0}'.format(pg_hba_rule))
                diff_before.append(str(existing_rules[index]))
                diff_after.append(str(pg_hba_rule))
                existing_rules[index] = pg_hba_rule
                changed = True
        # delete rule if it exists
        elif rule['state'] == "absent" and index > -1:
            msgs.append('Removing rule {0}'.format(pg_hba_rule))
            diff_before.append(str(existing_rules[index]))
            del existing_rules[index]
            changed = True

    return changed, msgs, diff_before, diff_after


def sort_rules(rules):
    """
    Sorts a list of rules in place.
    :param rules: A list of rules to sort
    """
    # remove blank lines before sorting
    index_lst = list(range(0, len(rules)))
    index_lst.reverse()
    for i in index_lst:
        if rules[i].is_special and not rules[i].line and not rules[i].comment:
            del rules[i]
    rules.sort()


def main():
    """
    This function is the main function of this module
    """
    # argument_spec = postgres_common_argument_spec()
    argument_spec = dict()
    argument_spec.update(
        # REVIEW: imho, the default here should be 'None' otherwise this crashes when 'contype' is 'local'
        address=dict(type='str', default='samehost', aliases=['source', 'src']),
        backup=dict(type='bool', default=False),
        # DEPRECATED, will be removed in 5.0.0
        backup_file=dict(type='str'),
        contype=dict(type='str', default=None, choices=PG_HBA_TYPES),
        comment=dict(type='str', default=None),
        create=dict(type='bool', default=False),
        databases=dict(type='str', default='all'),
        path=dict(type='path', required=True, aliases=['dest']),
        method=dict(type='str', default='md5', choices=PG_HBA_METHODS),
        netmask=dict(type='str'),
        # ?? do strings like "key=value another_key=another_value" get parsed automatically?
        options=dict(type='dict'),
        # REVIEW: I think this option is useless and should be removed
        # keep_comments_at_rules=dict(type='bool', default=False),
        state=dict(type='str', default="present", choices=["absent", "present"]),
        users=dict(type='str', default='all'),
        rules=dict(type='list', elements='dict'),
        rules_behavior=dict(type='str', default='conflict', choices=['combine', 'conflict']),
        overwrite=dict(type='bool', default=False),
        sort_rules=dict(type='bool', default=True),
        prepend_rules=dict(type='bool', default=False),
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
        backup_file = ""
    else:
        backup = module.params['backup']
        backup_file = module.params['backup_file']
    dest = module.params["path"]
    rules = module.params["rules"]
    rules_behavior = module.params["rules_behavior"]
    overwrite = module.params["overwrite"]
    sorted_rules = module.params["sort_rules"]
    prepend_rules = module.params["prepend_rules"]

    ret = {'msgs': []}
    diff = {'before': {'file': dest, 'pg_hba': []},
            'after': {'file': dest, 'pg_hba': []}}
    pg_hba_rules = []
    try:
        pg_hba_rules = _from_file(dest)
    except PgHbaError as error:
        module.fail_json(msg='Error reading file:\n{0}'.format(error))
    nof_initial_rules = len(pg_hba_rules)

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
    if rules is None or not rules:
        # if both of those aren't set, we just read the rules from the file
        if not module.params['contype'] and not module.params['comment']:
            rules = []
        else:
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
                elif key == "options" and isinstance(rule["options"], str):
                    module.warn("You should use a dictionary for options, "
                                "parsing them from strings might be removed in the future")
                    try:
                        rule["options"] = parse_auth_options(tokenize(rule["options"]))
                    except TokenizerException as e:
                        module.fail_json(f"Failed to parse options: {e.args[0]}")

            new_rules.append(rule)
        rules = new_rules

    # If we add rules to the top, reverse the order so the rules are in the same order as they were specified
    # in the `rules` argument
    if prepend_rules and not overwrite:
        rules.reverse()

    changed = False
    try:
        changed, msgs, diff_before, diff_after = update_rules(rules, pg_hba_rules, prepend_rules=prepend_rules)
        ret['msgs'] += msgs
        diff['before']['pg_hba'] += diff_before
        diff['after']['pg_hba'] += diff_after

        # if overwrite is set and there are changes or the number of rules doesn't match we rewrite the file
        if (changed or nof_initial_rules != len(rules)) and overwrite:
            changed = True
            pg_hba_rules = from_rule_list(rules)
    except PgHbaError as error:
        module.fail_json(msg='Error modifying rules:\n{0}'.format(error))

    ret['changed'] = changed
    if not changed:
        hba_string = render_rule_list(pg_hba_rules)
    else:
        if sorted_rules:
            sort_rules(pg_hba_rules)
        hba_string = render_rule_list(pg_hba_rules)
        ret['msgs'].append('Changed')
        file_args = module.load_file_common_arguments(module.params)
        if not module.check_mode:
            if backup:
                ret['msgs'].append('Creating Backup')
                backup_file_args = module.load_file_common_arguments(module.params)
                if backup_file:
                    # can't use tempfile.TemporaryFile, as we need to write to it and then move it away,
                    # without it getting removed after we wrote to it
                    _tmp_file_path = None
                    try:
                        _tmp_file_h, _tmp_file_path = tempfile.mkstemp(prefix="pg_hba")
                        os.close(_tmp_file_h)  # close it directly, so we can use shutil.copy and atomic_move
                        shutil.copy(dest, _tmp_file_path)
                        module.atomic_move(_tmp_file_path, backup_file, backup_file_args.get("unsafe_writes"))
                    finally:
                        if _tmp_file_path and os.path.isfile(_tmp_file_path):
                            os.unlink(_tmp_file_path)  # removing the temporary file, as it has served its purpose
                else:
                    backup_file = module.backup_local(dest)
                backup_file_args['path'] = backup_file
                module.set_fs_attributes_if_different(backup_file_args, True, diff, expand=False)
                ret['backup_file'] = backup_file

            ret['msgs'].append('Writing')
            write_hba_file(dest, hba_string, create, module, file_args, diff)
            ret['diff'] = diff
        elif not os.path.isfile(dest) and not create:
            module.warn(f"The file '{dest}' doesn't exist and `create` is `false`. This will cause the module to fail"
                        "when not running in check-mode. Set `create: true` to prevent this and create the file.")

    ret['pg_hba'] = hba_string
    ret['pg_hba_dicts'] = rule_list_to_dict_list(pg_hba_rules, header_map=PG_HBA_HDR_MAP)
    module.exit_json(**ret)


if __name__ == '__main__':
    main()
