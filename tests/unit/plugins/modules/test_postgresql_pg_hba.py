# -*- coding: utf-8 -*-

# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import copy
import sys

import pytest

if sys.version_info[0] == 3:
    from plugins.modules.postgresql_pg_hba import Rule, search_rule, parse_hba_file, from_rule_list, PgHbaError, \
    PgHbaRuleError, PgHbaRuleValueError, handle_db_and_user_strings, handle_address_field, handle_netmask_field, \
    PG_HBA_HDR_MAP, tokenize, TokenizerException, PgHbaValueError, update_rules, render_rule_list, \
    rule_list_to_dict_list, sort_rules
elif sys.version_info[0] == 2:
    from ansible_collections.community.postgresql.plugins.modules.postgresql_pg_hba import (Rule, search_rule,
        parse_hba_file, from_rule_list, PgHbaError, PgHbaRuleError, PgHbaRuleValueError, handle_db_and_user_strings,
        handle_address_field, handle_netmask_field, PG_HBA_HDR_MAP, tokenize, TokenizerException, PgHbaValueError,
        update_rules, render_rule_list, rule_list_to_dict_list, sort_rules)

VALID_PG_HBA = \
    r'''local   all             all                                     trust
    host    all             all             127.0.0.1/32            trust
    host    all             all             127.0.0.1       255.255.255.255     trust
    host    all             all             ::1/128                 trust
    host    all             all             fe80::          ffff::  md5
    host    all             all             localhost               trust
    host    "/^db\d{2,4}$"  all             localhost               trust
    host    postgres        all             192.168.93.0/24         ident
    host    postgres        all             192.168.12.10/32        scram-sha-256
    host    all             mike            .example.com            md5
    host    all             all             .example.com            scram-sha-256
    host    all             all             192.168.54.1/32         reject
    hostgssenc all          all             0.0.0.0/0               gss
    host    all             all             192.168.12.10/32        gss
    host    all             all             192.168.0.0/16          ident map=omicron
    local   sameuser        all                                     md5
    local   all             /^.*helpdesk$                           md5
    local   all             @admins                                 md5
    local   all             +support                                md5
    local   all             @admins,+support                        md5
    local   db1,db2,@demodbs  all                                   md5
    host    all             all                0.0.0.0/0            radius radiusservers="server1,server2" radiussecrets="""secret one"",""secret two"""
    host    all             all  10.0.0.0 255.0.0.0                 radius radiusservers="server1,server2" radiussecrets="""secret one"",""secret two"""'''

VALID_RULE_DICTS = [
    {'contype': 'local', 'databases': 'all', 'users': 'all', 'method': 'trust'},
    {'contype': 'host', 'databases': 'all', 'users': 'all', 'method': 'trust', 'address': '127.0.0.1/32'},
    {'contype': 'host', 'databases': 'all', 'users': 'all', 'method': 'trust', 'address': '127.0.0.1/32'},
    {'contype': 'host', 'databases': 'all', 'users': 'all', 'method': 'trust', 'address': '::1/128'},
    {'contype': 'host', 'databases': 'all', 'users': 'all', 'method': 'md5', 'address': 'fe80::/16'},
    {'contype': 'host', 'databases': 'all', 'users': 'all', 'method': 'trust', 'address': 'localhost'},
    {'contype': 'host', 'databases': '"/^db\\d{2,4}$"', 'users': 'all', 'method': 'trust', 'address': 'localhost'},
    {'contype': 'host', 'databases': 'postgres', 'users': 'all', 'method': 'ident', 'address': '192.168.93.0/24'},
    {'contype': 'host', 'databases': 'postgres', 'users': 'all', 'method': 'scram-sha-256',
     'address': '192.168.12.10/32'},
    {'contype': 'host', 'databases': 'all', 'users': 'mike', 'method': 'md5', 'address': '.example.com'},
    {'contype': 'host', 'databases': 'all', 'users': 'all', 'method': 'scram-sha-256', 'address': '.example.com'},
    {'contype': 'host', 'databases': 'all', 'users': 'all', 'method': 'reject', 'address': '192.168.54.1/32'},
    {'contype': 'hostgssenc', 'databases': 'all', 'users': 'all', 'method': 'gss', 'address': '0.0.0.0/0'},
    {'contype': 'host', 'databases': 'all', 'users': 'all', 'method': 'gss', 'address': '192.168.12.10/32'},
    {'contype': 'host', 'databases': 'all', 'users': 'all', 'method': 'ident', 'address': '192.168.0.0/16',
     'options': {'map': 'omicron'}},
    {'contype': 'local', 'databases': 'sameuser', 'users': 'all', 'method': 'md5'},
    {'contype': 'local', 'databases': 'all', 'users': '/^.*helpdesk$', 'method': 'md5'},
    {'contype': 'local', 'databases': 'all', 'users': '@admins', 'method': 'md5'},
    {'contype': 'local', 'databases': 'all', 'users': '+support', 'method': 'md5'},
    {'contype': 'local', 'databases': 'all', 'users': '+support,@admins', 'method': 'md5'},
    {'contype': 'local', 'databases': '@demodbs,db1,db2', 'users': 'all', 'method': 'md5'},
    {'contype': 'host', 'databases': 'all', 'users': 'all', 'method': 'radius', 'address': '0.0.0.0/0',
     'options': {'radiusservers': '"server1,server2"', 'radiussecrets': '"""secret one"",""secret two"""'}},
    {'contype': 'host', 'databases': 'all', 'users': 'all', 'method': 'radius', 'address': '10.0.0.0/8',
     'options': {'radiusservers': '"server1,server2"', 'radiussecrets': '"""secret one"",""secret two"""'}},
]

PG_HBA_REQUIRED_FIELDS = ['contype', 'databases', 'users', 'method']


def test_tokenize():
    assert tokenize('one two three') == ["one", "two", "three"]
    assert tokenize('"one" two three') == ['"one"', 'two', 'three']
    assert tokenize('"one two" three') == ['"one two"', "three"]
    assert tokenize('one="two three" four') == ['one="two three"', "four"]
    assert tokenize('"one two"') == ['"one two"']
    assert tokenize('"one"') == ['"one"']
    with pytest.raises(TokenizerException, match="Unterminated quote"):
        tokenize('one="two three four')
    with pytest.raises(TokenizerException, match="Unterminated quote"):
        tokenize('one two"')


def test_rule_creation():
    """Test creating rules from a string and from dicts"""
    rules_from_str = parse_hba_file(VALID_PG_HBA)
    rules_from_dict = from_rule_list(VALID_RULE_DICTS)
    assert len(rules_from_dict) == len(rules_from_str)
    for i in range(0, len(rules_from_dict)):
        assert rules_from_str[i].is_identical(rules_from_dict[i])


def test_rule_validations_from_tokens():
    """Test if rules are correctly validated when created from a list of tokens"""
    with pytest.raises(PgHbaRuleError, match="The rule has too few symbols"):
        Rule(tokens=["only", "three", "tokens"])
    with pytest.raises(PgHbaRuleValueError, match="Found an unknown connection-type notype"):
        Rule(tokens=["notype", "two", "three", "four"])
    with pytest.raises(PgHbaRuleError,
                       match="The rule either needs a hostname, full CIDR or an IP-address and a netmask"):
        Rule(tokens=["host", "all", "all", "123.45.67.89", "md5"])
    with pytest.raises(PgHbaRuleError,
                       match="The rule either needs a hostname, full CIDR or an IP-address and a netmask"):
        Rule(tokens=["host", "all", "all", "1234:ffff::", "md5"])
    with pytest.raises(PgHbaRuleValueError, match="The netmask can't have a CIDR suffix"):
        Rule(tokens=["host", "all", "all", "123.45.67.89", "255.255.255.255/32", "md5"])
    with pytest.raises(PgHbaRuleValueError, match=".* exceeds the maximum of 32 for IPv4 addresses"):
        Rule(tokens=["host", "all", "all", "123.45.67.89/64", "md5"])
    with pytest.raises(PgHbaRuleError, match="The rule has too few symbols"):
        Rule(tokens=["host", "all", "all", "123.45.67.89", "255.255.255.255"])
    with pytest.raises(PgHbaRuleError, match="The rule has too few symbols"):
        Rule(tokens=["host", "all", "all", "123.45.67.89/32"])
    with pytest.raises(PgHbaRuleValueError, match="Found an unknown method: nomethod"):
        Rule(tokens=["host", "all", "all", "123.45.67.89/32", "nomethod"])
    with pytest.raises(PgHbaRuleValueError,
                       match="Found invalid option 'someopt'. Options need to be in the format 'key=value'"):
        Rule(tokens=["host", "all", "all", "123.45.67.89/32", "md5", "someopt"])
    with pytest.raises(PgHbaRuleValueError, match="The rule contains two options with the same key.*"):
        Rule(tokens=["host", "all", "all", "123.45.67.89/32", "md5", "key=v", "key=w"])
    with pytest.raises(PgHbaRuleError, match="Can't mix IPv4 and IPv6 netmasks and addresses"):
        Rule(tokens=["host", "all", "all", "1.2.3.4", "ffff:ffff::", "md5"])
    with pytest.raises(PgHbaRuleError, match="Can't mix IPv4 and IPv6 netmasks and addresses"):
        Rule(tokens=["host", "all", "all", "1234:ffff:abcf::", "255.255.255.0", "md5"])
    with pytest.raises(PgHbaRuleValueError, match="The netmask can't have a CIDR suffix"):
        Rule(tokens=["host", "all", "all", "1234:ffff::", "ffff::/100", "md5"])
    with pytest.raises(PgHbaRuleValueError, match=".* exceeds the maximum of 128 for IPv6 addresses"):
        Rule(tokens=["host", "all", "all", "::/256", "md5"])


def test_rule_validation_from_dict():
    """Test if rules are correctly validated when created from a dict"""
    base_dict = {'contype': 'local', 'databases': 'all', 'users': 'all', 'method': 'ident'}
    for field in PG_HBA_REQUIRED_FIELDS:
        d = copy.copy(base_dict)
        del d[field]
        with pytest.raises(PgHbaRuleError, match="All rules need to contain .*"):
            Rule(rule_dict=d)
    d = copy.copy(base_dict)
    d['contype'] = 'notype'
    with pytest.raises(PgHbaRuleValueError, match="Unknown type notype"):
        Rule(rule_dict=d)
    d = copy.copy(base_dict)
    d['method'] = 'nomethod'
    with pytest.raises(PgHbaRuleValueError, match="Unknown method nomethod"):
        Rule(rule_dict=d)

    d = copy.copy(base_dict)
    d['address'] = '127.0.0.1/32'
    with pytest.raises(PgHbaRuleError,
                       match="Rule can't contain an address and netmask if the connection-type is 'local'"):
        Rule(rule_dict=d)
    d = copy.copy(base_dict)
    d['address'] = '255.255.255.255'
    with pytest.raises(PgHbaRuleError,
                       match="Rule can't contain an address and netmask if the connection-type is 'local'"):
        Rule(rule_dict=d)
    d = copy.copy(base_dict)
    d['address'] = '127.0.0.1/32'
    d['address'] = '255.255.255.255'
    with pytest.raises(PgHbaRuleError,
                       match="Rule can't contain an address and netmask if the connection-type is 'local'"):
        Rule(rule_dict=d)
    base_dict['contype'] = 'host'
    with pytest.raises(PgHbaRuleError, match="If the contype isn't 'local', the rule needs to contain an address"):
        Rule(rule_dict=base_dict)
    base_dict['address'] = "127.0.0.1/32"
    base_dict['netmask'] = '255.255.255.255'
    with pytest.raises(PgHbaRuleError, match="Rule can't contain a netmask if address is a full CIDR or hostname"):
        Rule(rule_dict=base_dict)
    base_dict['address'] = "db.example.com"
    with pytest.raises(PgHbaRuleError, match="Rule can't contain a netmask if address is a full CIDR or hostname"):
        Rule(rule_dict=base_dict)
    base_dict['address'] = "127.0.0.1"
    base_dict['netmask'] = '255.255.255.255/32'
    with pytest.raises(PgHbaRuleValueError, match="The netmask can't have a CIDR suffix"):
        Rule(rule_dict=base_dict)
    base_dict['netmask'] = 'lalala'
    with pytest.raises(PgHbaRuleValueError, match=".* is not a valid netmask"):
        Rule(rule_dict=base_dict)
    del base_dict["netmask"]
    with pytest.raises(PgHbaRuleError, match="If the address is a bare ip-address without a CIDR suffix, "
                                             "the rule needs to contain a netmask"):
        Rule(rule_dict=base_dict)
    base_dict['address'] = "127.0.0.1/32"
    base_dict['netmask'] = ""
    Rule(rule_dict=base_dict)


def test_rule_is_identical():
    """Test if Rule.is_identical works correctly"""
    rdict1 = {'contype': 'local',
              'databases': 'all',
              'users': 'all',
              'method': 'ident',
              'options': {'key1': 'value1', 'key2': 'value2'}}
    rdict1_1 = copy.deepcopy(rdict1)
    rdict1_1['comment'] = "# some comment"
    r1 = Rule(rule_dict=rdict1)
    r2 = Rule(rule_dict=rdict1_1)

    assert r1.is_identical(r1)  # a rule should be identical to itself
    assert r1.is_identical(r2)  # a comment doesn't change being identical
    assert r2.is_identical(r1)  # it should work both ways
    rdict1_1['options']['key1'] = "other_value"
    r2 = Rule(rule_dict=rdict1_1)
    assert not r1.is_identical(r2)  # we changed an option -> not identical anymore
    rdict1_1['options']['key1'] = "value1"
    r2 = Rule(rule_dict=rdict1_1)
    assert r1.is_identical(r2)  # we changed it back -> identical again

    r3 = Rule(tokens=["host", "all", "all", "10.0.0.0/8", "md5"])
    r4 = Rule(tokens=["host", "all", "all", "10.0.0.0", "255.0.0.0", "md5"])
    assert r3.is_identical(r4)
    assert r3.is_identical(r3)
    assert r4.is_identical(r4)
    r5 = Rule(tokens=["host", "all", "all", "10.0.0.0/16", "md5"])
    r6 = Rule(tokens=["host", "all", "all", "10.0.0.0", "255.255.0.0", "md5"])
    assert not r5.is_identical(r3)
    assert not r6.is_identical(r4)
    r7 = Rule(tokens=["host", "all", "all", "abcd:1234::/32", "md5"])
    r8 = Rule(tokens=["host", "all", "all", "abcd:1234::", "ffff:ffff::", "md5"])
    assert r7.is_identical(r8)


def test_rule_eq():
    assert (Rule(tokens=["local", "all", "all", "ident"], comment=" ident  ") ==
            Rule(tokens=["local", "all", "all", "ident"], comment="ident"))
    assert (Rule(
        rule_dict={"contype": "local", "databases": "all", "users": "all", "method": "ident", "comment": " ident "}) ==
            Rule(rule_dict={"contype": "local", "databases": "all", "users": "all", "method": "ident",
                            "comment": "ident"}))


def test_rule_lt():
    r1 = Rule(tokens=["host", "all", "all", "127.0.0.1/32", "md5"])
    r2 = Rule(tokens=["host", "all", "all", "::1/128", "md5"])
    r3 = Rule(tokens=["host", "all", "all", "2001:db8::1/128", "md5"])
    rh1 = Rule(tokens=["host", "all", "all", "host.example.com", "md5"])
    r4 = Rule(tokens=["host", "all", "all", "0:ff00::/120", "md5"])
    r5 = Rule(tokens=["host", "all", "all", "192.168.0.0/24", "md5"])

    rdb_1 = Rule(tokens=["host", "adb", "all", "127.0.0.0/32", "md5"])
    rdb_2 = Rule(tokens=["host", "postgres", "all", "127.0.0.1/32", "md5"])

    rusr_1 = Rule(tokens=["host", "all", "ausr", "127.0.0.0/32", "md5"])
    rusr_2 = Rule(tokens=["host", "all", "postgres", "127.0.0.1/32", "md5"])

    rlocal = Rule(tokens=["local", "postgres", "postgres", "trust"])

    assert r1 < r2
    assert r2 < r3
    assert r3 < r4
    assert r4 < r5
    assert r3 < rh1

    assert rdb_1 < rdb_2
    assert rdb_2 < r1

    assert rusr_1 < rusr_2
    assert rusr_2 < r1

    assert rlocal < r1
    assert rlocal < rusr_1
    assert rlocal < rdb_1


def test_rule_to_dict():
    rules_from_dict = from_rule_list(VALID_RULE_DICTS)
    rules = [r.to_dict() for r in rules_from_dict]
    assert len(rules) == len(VALID_RULE_DICTS)
    for i in range(0, len(rules)):
        assert rules[i] == VALID_RULE_DICTS[i]
    # test header mapping
    rule = from_rule_list([
        {'contype': 'host', 'databases': 'all', 'users': 'all', 'method': 'trust', 'address': '127.0.0.1',
         'netmask': '255.255.255.255'},])[0]
    assert rule.to_dict(PG_HBA_HDR_MAP) == {'type': 'host', 'db': 'all', 'usr': 'all', 'method': 'trust',
                                            'src': '127.0.0.1/32'}


def test_rule_serialize():
    assert Rule(tokens="COMMENT", line="# comment", comment="# comment").serialize(" ") == "# comment"
    assert Rule(tokens="EMPTY", line='').serialize(" ") == ""
    assert Rule(tokens=['local', 'all', 'all', 'ident']).serialize(" ") == "local all all ident"
    assert (Rule(tokens=['local', 'all', 'all', 'ident'], comment="# comment").serialize(" ") ==
            "local all all ident # comment")
    assert Rule(tokens=['host', 'all', 'all', '127.0.0.1/32', 'md5']).serialize(" ") == "host all all 127.0.0.1/32 md5"
    assert (Rule(tokens=['host', 'all', 'all', '127.0.0.1', '255.255.255.255', 'md5']).serialize(" ") ==
            "host all all 127.0.0.1/32 md5")
    assert (Rule(tokens=['host', 'all', 'all', '0.0.0.0/0', 'radius', 'radiusservers="server1,server2"',
                         'radiussecrets="""secret one"",""secret two"""']).serialize(" ") ==
            'host all all 0.0.0.0/0 radius radiusservers="server1,server2" '
            'radiussecrets="""secret one"",""secret two"""')


def test_search_rule():
    """Test if search_rule works correctly"""
    ruleset = [
        Rule(rule_dict={'contype': 'local',
                        'databases': 'all',
                        'users': 'all',
                        'method': 'ident', }),
        Rule(rule_dict={'contype': 'host',
                        'databases': 'all',
                        'users': 'admin',
                        'address': '10.0.0.0/8',
                        'method': 'cert', }),
        Rule(rule_dict={'contype': 'host',
                        'databases': 'app',
                        'users': 'appuser',
                        'address': '10.0.0.0/8',
                        'method': 'md5', }),
    ]
    # look for exact rule
    assert search_rule(ruleset, Rule(rule_dict={'contype': 'host',
                                                'databases': 'all',
                                                'users': 'admin',
                                                'address': '10.0.0.0/8',
                                                'method': 'cert', })) == 1
    # look for prefix
    assert search_rule(ruleset, Rule(rule_dict={'contype': 'host',
                                                'databases': 'app',
                                                'users': 'appuser',
                                                'address': '10.0.0.0/8',
                                                'method': 'cert', })) == 2
    # look for non-existent rule
    assert search_rule(ruleset, Rule(rule_dict={'contype': 'host',
                                                'databases': 'notadatabase',
                                                'users': 'appuser',
                                                'address': '0.0.0.0/0',
                                                'method': 'md5', })) == -1


def test_render_rule_list():
    rules = [
        Rule(tokens="COMMENT", line="# This is a comment", comment="# This is a comment"),
        Rule(tokens="EMPTY"),
    ]
    seed = [
        {'contype': 'local', 'databases': 'all', 'users': '+support,@admins', 'method': 'md5'},
        {'contype': 'local', 'databases': '@demodbs,db1,db2', 'users': 'all', 'method': 'md5'},
        {'contype': 'host', 'databases': 'all', 'users': 'all', 'method': 'radius', 'address': '0.0.0.0/0',
         'options': {'radiusservers': '"server1,server2"', 'radiussecrets': '"""secret one"",""secret two"""'},
         'comment': "a comment"},
        {'comment': " this is another comment "},
        {'comment': "   # this is a third comment "},
    ]
    for s in seed:
        rules.append(Rule(rule_dict=s))
    rules.append(Rule(tokens=["local", "all", "all", "trust"], line="local all all \\\ntrust"))
    rules.append(Rule(tokens=["include", "somefile.conf"], line="include somefile.conf"))
    assert render_rule_list(rules, " ") == '''# This is a comment

local all +support,@admins md5
local @demodbs,db1,db2 all md5
host all all 0.0.0.0/0 radius radiusservers="server1,server2" radiussecrets="""secret one"",""secret two""" # a comment
# this is another comment
# this is a third comment
local all all \\
trust
include somefile.conf'''


def test_sort_rules():
    seed = [
        {'contype': 'local', 'databases': 'all', 'users': '+support,@admins', 'method': 'md5'},
        {'contype': 'local', 'databases': '@demodbs,db1,db2', 'users': 'all', 'method': 'md5'},
        {'contype': 'host', 'databases': 'all', 'users': 'all', 'method': 'radius', 'address': '0.0.0.0/0',
         'options': {'radiusservers': '"server1,server2"', 'radiussecrets': '"""secret one"",""secret two"""'},
         'comment': "a comment"},
    ]
    rules = from_rule_list(seed)
    rules.append(Rule(tokens="EMPTY"))
    rules.append(Rule(tokens=["include_dir", "some/dir"], line="include_dir some/dir"))
    rules.append(Rule(tokens="EMPTY"))
    rules.append(Rule(tokens=["include_if_exists", "somefile.conf"], line="include_if_exists somefile.conf"))
    rules.append(Rule(tokens="EMPTY"))
    rules.append(Rule(tokens="COMMENT", line="# This is a comment", comment="# This is a comment"))
    rules.append(Rule(tokens="EMPTY"))
    rules.append(Rule(tokens=["include", "somefile.conf"], line="include somefile.conf"))

    sort_rules(rules)
    assert render_rule_list(rules, " ") == '''# This is a comment
local @demodbs,db1,db2 all md5
local all +support,@admins md5
host all all 0.0.0.0/0 radius radiusservers="server1,server2" radiussecrets="""secret one"",""secret two""" # a comment
include somefile.conf
include_if_exists somefile.conf
include_dir some/dir'''


def test_handle_db_and_user_strings():
    assert handle_db_and_user_strings("a,b,c") == "a,b,c"
    assert handle_db_and_user_strings("c,b,a") == "a,b,c"
    assert handle_db_and_user_strings('"c,b,a"') == '"c,b,a"'
    assert handle_db_and_user_strings("all") == "all"
    assert handle_db_and_user_strings('"all"') == '"all"'


def test_handle_address_field():
    assert handle_address_field("1.2.3.4") == ("1.2.3.4", "IPv4", -1)
    assert handle_address_field("1.2.3.4/8") == ("1.2.3.4", "IPv4", 8)
    assert handle_address_field('"1.2.3.4/8"') == ("1.2.3.4", "IPv4", 8)
    assert handle_address_field("ffff::") == ("ffff::", "IPv6", -1)
    assert handle_address_field("ffff::/8") == ("ffff::", "IPv6", 8)
    assert handle_address_field('"ffff::/8"') == ("ffff::", "IPv6", 8)
    assert handle_address_field("host.example.com") == ("host.example.com", "hostname", -1)
    assert handle_address_field('"host.example.com"') == ('"host.example.com"', "hostname", -1)

    with pytest.raises(PgHbaRuleValueError, match=".* contains a ':', but is not a valid IPv6 address"):
        handle_address_field("host.example.com:1234")
    with pytest.raises(PgHbaRuleValueError, match=".* exceeds the maximum of 32 for IPv4 addresses"):
        handle_address_field("1.2.3.4/33")
    with pytest.raises(PgHbaRuleValueError, match=".* exceeds the maximum of 128 for IPv6 addresses"):
        handle_address_field("1234:ffff::/129")


def test_handle_netmask_field():
    assert handle_netmask_field("255.255.255.0") == ("255.255.255.0", "IPv4", 24)
    assert handle_netmask_field('"255.255.255.0"') == ("255.255.255.0", "IPv4", 24)
    assert handle_netmask_field("ffff:ffff::") == ("ffff:ffff::", "IPv6", 32)
    assert handle_netmask_field('"ffff:ffff::"') == ("ffff:ffff::", "IPv6", 32)
    assert handle_netmask_field('hello', raise_not_valid=False) == ("", "invalid", -1)

    with pytest.raises(PgHbaRuleValueError, match="The netmask can't have a CIDR suffix"):
        handle_netmask_field("255.0.0.0/8")
    with pytest.raises(PgHbaRuleValueError, match="The netmask can't have a CIDR suffix"):
        handle_netmask_field("ffff::/8")
    with pytest.raises(PgHbaRuleValueError, match=".* contains a ':', but is not a valid IPv6 netmask"):
        handle_netmask_field("1:2.3.4")
    with pytest.raises(PgHbaValueError, match="IP mask .* is invalid .*"):
        handle_netmask_field("255.255.0.255")
    with pytest.raises(PgHbaValueError, match="IP mask .* is invalid .*"):
        handle_netmask_field("ffff:ffff::ffff")


def test_update_rules():
    rules = parse_hba_file("local all all ident\nhost user db 192.168.10.0/24 md5")

    new_rules = [
        {"contype": "hostssl",
         "databases": "somedb",
         "users": "appuser",
         "address": "10.8.16.10/32",
         "method": "md5",
         "state": "present"}]
    changed, msgs, diff_before, diff_after = update_rules(new_rules, rules)
    assert changed
    assert msgs[0].startswith("Adding rule")
    assert len(diff_after) == 1
    assert len(diff_before) == 0
    assert len(rules) == 3
    assert rules[2].user == "appuser"

    tmp_rule_dict = rule_list_to_dict_list(rules)
    local_all = {"contype": "local", "databases": "all", "users": "all", "method": "ident", "state": "present"}
    changed, _, _, _ = update_rules([local_all], rules)
    assert not changed
    assert tmp_rule_dict == rule_list_to_dict_list(rules)

    local_all["method"] = "trust"
    changed, _, _, _ = update_rules([local_all], rules)
    assert changed
    assert rules[0].method == "trust"

    local_all["state"] = "absent"
    changed, _, _, _ = update_rules([local_all], rules)
    assert changed
    assert len(rules) == 2
    assert rules[0].method == "md5"
