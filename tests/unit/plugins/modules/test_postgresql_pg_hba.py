# -*- coding: utf-8 -*-

# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import copy
import sys
import pytest


if sys.version_info[0] == 3:
    from plugins.modules.postgresql_pg_hba import tokenize, TokenizerException, handle_address_field, \
        handle_netmask_field, handle_db_and_user_strings, PgHbaRuleValueError, PgHbaValueError, parse_auth_options, \
        parse_hba_file, PgHbaRuleError, PgHbaRule, from_rule_list, PG_HBA_HDR_MAP, search_rule, update_rules, \
        sort_rules, render_rule_list, rule_list_to_dict_list, rule_list_from_hba_file
elif sys.version_info[0] == 2:
    from ansible_collections.community.postgresql.plugins.modules.postgresql_pg_hba import tokenize, \
        TokenizerException, handle_address_field, handle_netmask_field, handle_db_and_user_strings, \
        PgHbaRuleValueError, PgHbaValueError, parse_auth_options, parse_hba_file, PgHbaRuleError, PgHbaRule, \
        from_rule_list, PG_HBA_HDR_MAP, search_rule, update_rules, sort_rules, render_rule_list, \
        rule_list_to_dict_list, rule_list_from_hba_file

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
     'options': 'map=omicron'},
    {'contype': 'local', 'databases': 'sameuser', 'users': 'all', 'method': 'md5'},
    {'contype': 'local', 'databases': 'all', 'users': '/^.*helpdesk$', 'method': 'md5'},
    {'contype': 'local', 'databases': 'all', 'users': '@admins', 'method': 'md5'},
    {'contype': 'local', 'databases': 'all', 'users': '+support', 'method': 'md5'},
    {'contype': 'local', 'databases': 'all', 'users': '+support,@admins', 'method': 'md5'},
    {'contype': 'local', 'databases': '@demodbs,db1,db2', 'users': 'all', 'method': 'md5'},
    {'contype': 'host', 'databases': 'all', 'users': 'all', 'method': 'radius', 'address': '0.0.0.0/0',
     'options': 'radiussecrets="""secret one"",""secret two""" radiusservers="server1,server2"'},
    {'contype': 'host', 'databases': 'all', 'users': 'all', 'method': 'radius', 'address': '10.0.0.0/8',
     'options': 'radiussecrets="""secret one"",""secret two""" radiusservers="server1,server2"'},
]

PG_HBA_REQUIRED_FIELDS = ['contype', 'databases', 'users', 'method']


def test_tokenize():
    assert tokenize('one two three') == ["one", "two", "three"]
    assert tokenize(' one two three ') == ["one", "two", "three"]
    assert tokenize(' "one two" "three" ') == ['"one two"', '"three"']
    assert tokenize('"one" two three') == ['"one"', 'two', 'three']
    assert tokenize('"one two" three') == ['"one two"', "three"]
    assert tokenize('one="two three" four') == ['one="two three"', "four"]
    assert tokenize('"one two"') == ['"one two"']
    assert tokenize('"one"') == ['"one"']
    assert tokenize('one two # three four') == ['one', 'two', '# three four']
    assert tokenize('one\ttwo\t#\tthree\tfour') == ['one', 'two', '#\tthree\tfour']
    assert tokenize('one two# three four') == ['one', 'two', '# three four']
    assert tokenize('one two#three four') == ['one', 'two', '#three four']
    assert tokenize('one "two # three" four # five six') == ['one', '"two # three"', 'four', "# five six"]
    assert tokenize('# one two') == ['# one two']
    assert tokenize(' # one two') == ['# one two']
    assert tokenize('one # two "three four" five') == ['one', '# two "three four" five']
    assert tokenize('one # two "three four" five # six seven') == ['one', '# two "three four" five # six seven']
    assert tokenize('one ##two') == ['one', "##two"]
    with pytest.raises(TokenizerException, match="Unterminated quote"):
        tokenize('one="two three four')
    with pytest.raises(TokenizerException, match="Unterminated quote"):
        tokenize('one two"')


def test_rule_creation():
    """Test creating rules from a string and from dicts"""
    # it seems that test breaks for Python 2.7 and in 2024, I'm not going to work around that
    # if you still run 2.7, that is your problem
    try:
        import ipaddress
    except ImportError:
        return
    ipaddress.ip_address("0.0.0.0")  # otherwise flake complains
    rules_from_str = []
    for rule in rule_list_from_hba_file(VALID_PG_HBA):
        rules_from_str.append(rule)
    rules_from_dict = from_rule_list(VALID_RULE_DICTS)
    assert len(rules_from_dict) == len(rules_from_str)
    for i in range(0, len(rules_from_dict)):
        assert rules_from_str[i].is_identical(rules_from_dict[i])


def test_rule_validations_from_tokens():
    """Test if rules are correctly validated when created from a list of tokens"""
    # it seems that test breaks for Python 2.7 and in 2024, I'm not going to work around that
    # if you still run 2.7, that is your problem
    try:
        import ipaddress
    except ImportError:
        return
    ipaddress.ip_address("0.0.0.0")  # otherwise flake complains
    with pytest.raises(PgHbaRuleError, match="The rule has too few symbols"):
        PgHbaRule(tokens=["only", "three", "tokens"])
    with pytest.raises(PgHbaRuleValueError, match="Found an unknown connection-type notype"):
        PgHbaRule(tokens=["notype", "two", "three", "four"])
    with pytest.raises(PgHbaRuleError,
                       match="The rule either needs a hostname, full CIDR or an IP-address and a netmask"):
        PgHbaRule(tokens=["host", "all", "all", "123.45.67.89", "md5"])
    with pytest.raises(PgHbaRuleError,
                       match="The rule either needs a hostname, full CIDR or an IP-address and a netmask"):
        PgHbaRule(tokens=["host", "all", "all", "1234:ffff::", "md5"])
    with pytest.raises(PgHbaRuleError,
                       match="The rule either needs a hostname, full CIDR or an IP-address and a netmask"):
        PgHbaRule(tokens=["host", "all", "all", "123.45.67.89", "255.255.255.255/32", "md5"])
    with pytest.raises(PgHbaValueError, match=".* is neither a valid IP address, network, hostname or keyword"):
        PgHbaRule(tokens=["host", "all", "all", "123.45.67.89/64", "md5"])
    with pytest.raises(PgHbaRuleError, match="The rule has too few symbols"):
        PgHbaRule(tokens=["host", "all", "all", "123.45.67.89", "255.255.255.255"])
    with pytest.raises(PgHbaRuleError, match="The rule has too few symbols"):
        PgHbaRule(tokens=["host", "all", "all", "123.45.67.89/32"])
    with pytest.raises(PgHbaRuleValueError, match="Found an unknown method: nomethod"):
        PgHbaRule(tokens=["host", "all", "all", "123.45.67.89/32", "nomethod"])
    with pytest.raises(PgHbaRuleValueError,
                       match="Found invalid option 'someopt'. Options need to be in the format 'key=value'"):
        PgHbaRule(tokens=["host", "all", "all", "123.45.67.89/32", "md5", "someopt"])
    with pytest.raises(PgHbaRuleValueError, match="The rule contains two options with the same key.*"):
        PgHbaRule(tokens=["host", "all", "all", "123.45.67.89/32", "md5", "key=v", "key=w"])
    with pytest.raises(PgHbaRuleError, match="Can't mix IPv4 and IPv6 netmasks and addresses"):
        PgHbaRule(tokens=["host", "all", "all", "1.2.3.4", "ffff:ffff::", "md5"])
    with pytest.raises(PgHbaRuleError, match="Can't mix IPv4 and IPv6 netmasks and addresses"):
        PgHbaRule(tokens=["host", "all", "all", "1234:ffff:abcf::", "255.255.255.0", "md5"])
    with pytest.raises(PgHbaRuleError,
                       match="The rule either needs a hostname, full CIDR or an IP-address and a netmask"):
        PgHbaRule(tokens=["host", "all", "all", "1234:ffff::", "ffff::/100", "md5"])
    with pytest.raises(PgHbaValueError, match=".* is neither a valid IP address, network, hostname or keyword"):
        PgHbaRule(tokens=["host", "all", "all", "::/256", "md5"])


def test_rule_validation_from_dict():
    """Test if rules are correctly validated when created from a dict"""
    # it seems that test breaks for Python 2.7 and in 2024, I'm not going to work around that
    # if you still run 2.7, that is your problem
    try:
        import ipaddress
    except ImportError:
        return
    ipaddress.ip_address("0.0.0.0")  # otherwise flake complains
    base_dict = {'contype': 'local', 'databases': 'all', 'users': 'all', 'method': 'ident'}
    for field in PG_HBA_REQUIRED_FIELDS:
        d = copy.copy(base_dict)
        del d[field]
        with pytest.raises(PgHbaRuleError, match="All rules need to contain .*"):
            PgHbaRule(rule_dict=d)
    d = copy.copy(base_dict)
    d['contype'] = 'notype'
    with pytest.raises(PgHbaRuleValueError, match="Unknown type notype"):
        PgHbaRule(rule_dict=d)
    d = copy.copy(base_dict)
    d['method'] = 'nomethod'
    with pytest.raises(PgHbaRuleValueError, match="Unknown method nomethod"):
        PgHbaRule(rule_dict=d)

    d = copy.copy(base_dict)
    d['address'] = '127.0.0.1/32'
    assert not PgHbaRule(rule_dict=d).address

    d = copy.copy(base_dict)
    d['netmask'] = '255.255.255.255'
    assert not PgHbaRule(rule_dict=d).netmask

    d = copy.copy(base_dict)
    d['address'] = '127.0.0.1/32'
    d['address'] = '255.255.255.255'
    rule = PgHbaRule(rule_dict=d)
    assert (not rule.address) and (not rule.netmask)

    base_dict['contype'] = 'host'
    with pytest.raises(PgHbaRuleError, match="If the contype isn't 'local', the rule needs to contain an address"):
        PgHbaRule(rule_dict=base_dict)
    base_dict['address'] = "127.0.0.1/32"
    base_dict['netmask'] = '255.255.255.255'
    with pytest.raises(PgHbaRuleError, match="Rule can't contain a netmask if address is a full CIDR or hostname"):
        PgHbaRule(rule_dict=base_dict)
    base_dict['address'] = "db.example.com"
    with pytest.raises(PgHbaRuleError, match="Rule can't contain a netmask if address is a full CIDR or hostname"):
        PgHbaRule(rule_dict=base_dict)
    base_dict['address'] = "127.0.0.1"
    base_dict['netmask'] = '255.255.255.255/32'
    with pytest.raises(PgHbaValueError, match=".* is not a valid netmask"):
        PgHbaRule(rule_dict=base_dict)
    base_dict['netmask'] = 'lalala'
    with pytest.raises(PgHbaValueError, match=".* is not a valid netmask"):
        PgHbaRule(rule_dict=base_dict)
    del base_dict["netmask"]
    with pytest.raises(PgHbaRuleError, match="If the address is a bare ip-address without a CIDR suffix, "
                                             "the rule needs to contain a netmask"):
        PgHbaRule(rule_dict=base_dict)
    base_dict['address'] = "127.0.0.1/32"
    base_dict['netmask'] = ""
    PgHbaRule(rule_dict=base_dict)


def test_rule_is_identical():
    """Test if Rule.is_identical works correctly"""
    # it seems that test breaks for Python 2.7 and in 2024, I'm not going to work around that
    # if you still run 2.7, that is your problem
    try:
        import ipaddress
    except ImportError:
        return
    ipaddress.ip_address("0.0.0.0")  # otherwise flake complains
    rdict1 = {'contype': 'local',
              'databases': 'all',
              'users': 'all',
              'method': 'ident',
              'options': {'key1': 'value1', 'key2': 'value2'}}
    rdict1_1 = copy.deepcopy(rdict1)
    rdict1_1['comment'] = "# some comment"
    r1 = PgHbaRule(rule_dict=rdict1)
    r2 = PgHbaRule(rule_dict=rdict1_1)

    assert r1.is_identical(r1)  # a rule should be identical to itself
    assert r1.is_identical(r2)  # a comment doesn't change being identical
    assert r2.is_identical(r1)  # it should work both ways
    rdict1_1['options']['key1'] = "other_value"
    r2 = PgHbaRule(rule_dict=rdict1_1)
    assert not r1.is_identical(r2)  # we changed an option -> not identical anymore
    rdict1_1['options']['key1'] = "value1"
    r2 = PgHbaRule(rule_dict=rdict1_1)
    assert r1.is_identical(r2)  # we changed it back -> identical again

    r3 = PgHbaRule(tokens=["host", "all", "all", "10.0.0.0/8", "md5"])
    r4 = PgHbaRule(tokens=["host", "all", "all", "10.0.0.0", "255.0.0.0", "md5"])
    assert r3.is_identical(r4)
    assert r3.is_identical(r3)
    assert r4.is_identical(r4)
    r5 = PgHbaRule(tokens=["host", "all", "all", "10.0.0.0/16", "md5"])
    r6 = PgHbaRule(tokens=["host", "all", "all", "10.0.0.0", "255.255.0.0", "md5"])
    assert not r5.is_identical(r3)
    assert not r6.is_identical(r4)
    r7 = PgHbaRule(tokens=["host", "all", "all", "abcd:1234::/32", "md5"])
    r8 = PgHbaRule(tokens=["host", "all", "all", "abcd:1234::", "ffff:ffff::", "md5"])
    assert r7.is_identical(r8)


def test_rule_eq():
    # it seems that test breaks for Python 2.7 and in 2024, I'm not going to work around that
    # if you still run 2.7, that is your problem
    try:
        import ipaddress
    except ImportError:
        return
    ipaddress.ip_address("0.0.0.0")  # otherwise flake complains
    assert (PgHbaRule(tokens=["local", "all", "all", "ident"], comment=" ident  ")
            == PgHbaRule(tokens=["local", "all", "all", "ident"], comment="ident"))
    assert (PgHbaRule(rule_dict={"contype": "local",
                                 "databases": "all",
                                 "users": "all",
                                 "method": "ident",
                                 "comment": " ident "})
            == PgHbaRule(rule_dict={"contype": "local",
                                    "databases": "all",
                                    "users": "all",
                                    "method": "ident",
                                    "comment": "ident"})
            )


def test_rule_lt():
    # it seems that test breaks for Python 2.7 and in 2024, I'm not going to work around that
    # if you still run 2.7, that is your problem
    try:
        import ipaddress
    except ImportError:
        return
    ipaddress.ip_address("0.0.0.0")  # otherwise flake complains
    r1 = PgHbaRule(tokens=["host", "all", "all", "127.0.0.1/32", "md5"])
    r2 = PgHbaRule(tokens=["host", "all", "all", "::1/128", "md5"])
    r3 = PgHbaRule(tokens=["host", "all", "all", "2001:db8::1/128", "md5"])
    rh1 = PgHbaRule(tokens=["host", "all", "all", "host.example.com", "md5"])
    r4 = PgHbaRule(tokens=["host", "all", "all", "0:ff00::/120", "md5"])
    r5 = PgHbaRule(tokens=["host", "all", "all", "192.168.0.0/24", "md5"])

    rdb_1 = PgHbaRule(tokens=["host", "adb", "all", "127.0.0.0/32", "md5"])
    rdb_2 = PgHbaRule(tokens=["host", "postgres", "all", "127.0.0.1/32", "md5"])

    rusr_1 = PgHbaRule(tokens=["host", "all", "ausr", "127.0.0.0/32", "md5"])
    rusr_2 = PgHbaRule(tokens=["host", "all", "postgres", "127.0.0.1/32", "md5"])

    rlocal = PgHbaRule(tokens=["local", "postgres", "postgres", "trust"])

    all_normal_rules = [r1, r2, r3, rh1, r4, r5, rdb_1, rdb_2, rusr_1, rusr_2, rlocal]

    full_comment = PgHbaRule(tokens="COMMENT", comment="# some full line comment", line_nr=10)
    include = PgHbaRule(tokens=["include", "some_file"], line="include somefile", line_nr=7)
    include_dir = PgHbaRule(tokens=["include_dir", "some_dir"], line="include_dir some_dir", line_nr=8)
    include_if_exists = (
        PgHbaRule(tokens=["include_if_exists", "some_other_file"], line="include_if_exists some_other_file",
                  line_nr=9)
    )

    another_comment = PgHbaRule(tokens="COMMENT", comment="# xxx full line comment", line_nr=9)
    another_comment_2 = PgHbaRule(tokens="COMMENT", comment="# aaa full line comment", line_nr=0)
    another_comment_3 = PgHbaRule(tokens="COMMENT", comment="# zzz full line comment", line_nr=0)

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

    for r in all_normal_rules:
        assert r > full_comment
        assert r < include
        assert r < include_dir
        assert r < include_if_exists

    assert another_comment < full_comment
    assert full_comment < another_comment_2
    assert another_comment_2 < another_comment_3

    assert full_comment < include
    assert include < include_dir
    assert include_dir < include_if_exists


def test_rule_to_dict():
    # it seems that test breaks for Python 2.7 and in 2024, I'm not going to work around that
    # if you still run 2.7, that is your problem
    try:
        import ipaddress
    except ImportError:
        return
    ipaddress.ip_address("0.0.0.0")  # otherwise flake complains
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
    # it seems that test breaks for Python 2.7 and in 2024, I'm not going to work around that
    # if you still run 2.7, that is your problem
    try:
        import ipaddress
    except ImportError:
        return
    ipaddress.ip_address("0.0.0.0")  # otherwise flake complains
    assert PgHbaRule(tokens="COMMENT", line="# comment", comment="# comment").serialize(" ") == "# comment"
    assert PgHbaRule(tokens="EMPTY", line='').serialize(" ") == ""
    assert PgHbaRule(tokens=['local', 'all', 'all', 'ident']).serialize(" ") == "local all all ident"
    assert (PgHbaRule(tokens=['local', 'all', 'all', 'ident'], comment="# comment").serialize(" ")
            == "local all all ident # comment")
    assert (PgHbaRule(tokens=['host', 'all', 'all', '127.0.0.1/32', 'md5']).serialize(" ")
            == "host all all 127.0.0.1/32 md5")
    assert (PgHbaRule(tokens=['host', 'all', 'all', '127.0.0.1', '255.255.255.255', 'md5']).serialize(" ")
            == "host all all 127.0.0.1/32 md5")
    assert (PgHbaRule(tokens=['host', 'all', 'all', '0.0.0.0/0', 'radius', 'radiusservers="server1,server2"',
                              'radiussecrets="""secret one"",""secret two"""']).serialize(" ")
            == 'host all all 0.0.0.0/0 radius radiussecrets="""secret one"",""secret two""" '
               'radiusservers="server1,server2"')


def test_parse_hba_file():
    string_1 = "one two\n# comment\none two #three"
    expected_1 = [
        {"line": "one two",
         "tokens": ["one", "two"],
         "comment": None,
         "line_nr": 1},
        {"line": "# comment",
         "tokens": "COMMENT",
         "comment": "# comment",
         "line_nr": 2},
        {"line": "one two #three",
         "tokens": ["one", "two"],
         "comment": "#three",
         "line_nr": 3},
    ]
    assert parse_hba_file(string_1) == expected_1

    string_2 = "one two\n# comment\none \\\ntwo #three\nfour"
    expected_2 = [
        {"line": "one two",
         "tokens": ["one", "two"],
         "comment": None,
         "line_nr": 1},
        {"line": "# comment",
         "tokens": "COMMENT",
         "comment": "# comment",
         "line_nr": 2},
        {"line": "one \\\ntwo #three",
         "tokens": ["one", "two"],
         "comment": "#three",
         "line_nr": 3},
        {"line": "four",
         "tokens": ["four"],
         "comment": None,
         "line_nr": 5},
    ]
    assert parse_hba_file(string_2) == expected_2

    string_3 = "one two\n\n# comment\none \\\ntwo #three\nfour"
    expected_3 = [
        {"line": "one two",
         "tokens": ["one", "two"],
         "comment": None,
         "line_nr": 1},
        {"line": "",
         "tokens": "EMPTY",
         "comment": None,
         "line_nr": 2},
        {"line": "# comment",
         "tokens": "COMMENT",
         "comment": "# comment",
         "line_nr": 3},
        {"line": "one \\\ntwo #three",
         "tokens": ["one", "two"],
         "comment": "#three",
         "line_nr": 4},
        {"line": "four",
         "tokens": ["four"],
         "comment": None,
         "line_nr": 6},
    ]
    assert parse_hba_file(string_3) == expected_3

    string_err = "one two\" three"
    with pytest.raises(TokenizerException, match="Error in line 1: Unterminated quote"):
        parse_hba_file(string_err)

    string_err = "asdf\none two\" three"
    with pytest.raises(TokenizerException, match="Error in line 2: Unterminated quote"):
        parse_hba_file(string_err)

    string_err = "asdf\\\nxxx\none two\" three"
    with pytest.raises(TokenizerException, match="Error in line 3: Unterminated quote"):
        parse_hba_file(string_err)


def test_handle_db_and_user_strings():
    assert handle_db_and_user_strings("a,b,c") == "a,b,c"
    assert handle_db_and_user_strings("c,b,a") == "a,b,c"
    assert handle_db_and_user_strings('"c,b,a"') == '"c,b,a"'
    assert handle_db_and_user_strings("all") == "all"
    assert handle_db_and_user_strings('"all"') == '"all"'


def test_handle_address_field():
    # it seems that test breaks for Python 2.7 and in 2024, I'm not going to work around that
    # if you still run 2.7, that is your problem
    try:
        import ipaddress
    except ImportError:
        return
    ipaddress.ip_address("0.0.0.0")  # otherwise flake complains
    assert handle_address_field("1.2.3.4") == ("1.2.3.4", "IPv4", -1)
    assert handle_address_field("1.0.0.0/8") == ("1.0.0.0", "IPv4", 8)
    assert handle_address_field('"1.0.0.0/8"') == ("1.0.0.0", "IPv4", 8)
    assert handle_address_field("ffff::") == ("ffff::", "IPv6", -1)
    assert handle_address_field("ffff::/16") == ("ffff::", "IPv6", 16)
    assert handle_address_field('"ffff::/16"') == ("ffff::", "IPv6", 16)
    assert handle_address_field("host.example.com") == ("host.example.com", "hostname", -1)
    assert handle_address_field('"host.example.com"') == ('"host.example.com"', "hostname", -1)
    assert handle_address_field("samehost") == ("samehost", "hostname", -1)

    with pytest.raises(PgHbaValueError, match=".* has host bits set"):
        handle_address_field("1.2.3.4/8")
    with pytest.raises(PgHbaValueError, match=".* has host bits set"):
        handle_address_field("ffff::/8")

    with pytest.raises(PgHbaValueError, match=".* is neither a valid IP address, network, hostname or keyword"):
        handle_address_field("host.example.com:1234")
    with pytest.raises(PgHbaValueError, match=".* is neither a valid IP address, network, hostname or keyword"):
        handle_address_field("1.2.3.4/33")
    with pytest.raises(PgHbaValueError, match=".* is neither a valid IP address, network, hostname or keyword"):
        handle_address_field("1234:ffff::/129")


def test_handle_netmask_field():
    # it seems that test breaks for Python 2.7 and in 2024, I'm not going to work around that
    # if you still run 2.7, that is your problem
    try:
        import ipaddress
    except ImportError:
        return
    ipaddress.ip_address("0.0.0.0")  # otherwise flake complains
    assert handle_netmask_field("255.255.255.0") == ("255.255.255.0", "IPv4", 24)
    assert handle_netmask_field('"255.255.255.0"') == ("255.255.255.0", "IPv4", 24)
    assert handle_netmask_field("ffff:ffff::") == ("ffff:ffff::", "IPv6", 32)
    assert handle_netmask_field('"ffff:ffff::"') == ("ffff:ffff::", "IPv6", 32)
    assert handle_netmask_field('hello', raise_not_valid=False) == ("", "invalid", -1)

    with pytest.raises(PgHbaValueError, match=".* is not a valid netmask"):
        handle_netmask_field("255.0.0.0/8")
    with pytest.raises(PgHbaValueError, match=".* is not a valid netmask"):
        handle_netmask_field("ffff::/16")
    with pytest.raises(PgHbaValueError, match=".* is not a valid netmask"):
        handle_netmask_field("1:2.3.4")
    with pytest.raises(PgHbaValueError, match="IP mask .* is invalid .*"):
        handle_netmask_field("255.255.0.255")
    with pytest.raises(PgHbaValueError, match="IP mask .* is invalid .*"):
        handle_netmask_field("ffff:ffff::ffff")


def test_parse_auth_options():
    assert parse_auth_options(["key=value"]) == {"key": "value"}
    assert parse_auth_options(["key1=value1", "key2=value2"]) == {"key1": "value1", "key2": "value2"}
    assert parse_auth_options(["key=value=with=equal=signs"]) == {"key": "value=with=equal=signs"}
    assert (parse_auth_options(['radiusservers="server1,server2"', 'radiussecrets="""secret one"",""secret two"""'])
            == {'radiusservers': '"server1,server2"', 'radiussecrets': '"""secret one"",""secret two"""'})
    with pytest.raises(PgHbaRuleValueError, match="Found invalid option"):
        parse_auth_options(["notkeyvalue"])
    with pytest.raises(PgHbaRuleValueError, match="The rule contains two options with the same key"):
        parse_auth_options(["key=value", "key=value2"])


def test_search_rule():
    """Test if search_rule works correctly"""
    # it seems that test breaks for Python 2.7 and in 2024, I'm not going to work around that
    # if you still run 2.7, that is your problem
    try:
        import ipaddress
    except ImportError:
        return
    ipaddress.ip_address("0.0.0.0")  # otherwise flake complains
    ruleset = [
        PgHbaRule(rule_dict={'contype': 'local',
                             'databases': 'all',
                             'users': 'all',
                             'method': 'ident', }),
        PgHbaRule(rule_dict={'contype': 'host',
                             'databases': 'all',
                             'users': 'admin',
                             'address': '10.0.0.0/8',
                             'method': 'cert', }),
        PgHbaRule(rule_dict={'contype': 'host',
                             'databases': 'app',
                             'users': 'appuser',
                             'address': '10.0.0.0/8',
                             'method': 'md5', }),
    ]
    # look for exact rule
    assert search_rule(ruleset, PgHbaRule(rule_dict={'contype': 'host',
                                                     'databases': 'all',
                                                     'users': 'admin',
                                                     'address': '10.0.0.0/8',
                                                     'method': 'cert', })) == 1
    # look for prefix
    assert search_rule(ruleset, PgHbaRule(rule_dict={'contype': 'host',
                                                     'databases': 'app',
                                                     'users': 'appuser',
                                                     'address': '10.0.0.0/8',
                                                     'method': 'cert', })) == 2
    # look for non-existent rule
    assert search_rule(ruleset, PgHbaRule(rule_dict={'contype': 'host',
                                                     'databases': 'notadatabase',
                                                     'users': 'appuser',
                                                     'address': '0.0.0.0/0',
                                                     'method': 'md5', })) == -1


def test_render_rule_list():
    # it seems that test breaks for Python 2.7 and in 2024, I'm not going to work around that
    # if you still run 2.7, that is your problem
    try:
        import ipaddress
    except ImportError:
        return
    ipaddress.ip_address("0.0.0.0")  # otherwise flake complains
    rules = [
        PgHbaRule(tokens="COMMENT", line="# This is a comment", comment="# This is a comment"),
        PgHbaRule(tokens="EMPTY"),
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
        rules.append(PgHbaRule(rule_dict=s))
    rules.append(PgHbaRule(tokens=["local", "all", "all", "trust"], comment="# comment"))
    rules.append(PgHbaRule(tokens=["local", "all", "all", "trust"], line="local all all \\\ntrust"))
    rules.append(PgHbaRule(tokens=["include", "somefile.conf"], line="include somefile.conf"))
    assert render_rule_list(rules, " ") == '''# This is a comment

local all +support,@admins md5
local @demodbs,db1,db2 all md5
host all all 0.0.0.0/0 radius radiussecrets="""secret one"",""secret two""" radiusservers="server1,server2" #a comment
#this is another comment
# this is a third comment
local all all trust # comment
local all all \\
trust
include somefile.conf'''


def test_sort_rules():
    # it seems that test breaks for Python 2.7 and in 2024, I'm not going to work around that
    # if you still run 2.7, that is your problem
    try:
        import ipaddress
    except ImportError:
        return
    ipaddress.ip_address("0.0.0.0")  # otherwise flake complains
    seed = [
        {'contype': 'local', 'databases': 'all', 'users': '+support,@admins', 'method': 'md5'},
        {'contype': 'local', 'databases': '@demodbs,db1,db2', 'users': 'all', 'method': 'md5'},
        {'contype': 'host', 'databases': 'all', 'users': 'all', 'method': 'radius', 'address': '0.0.0.0/0',
         'options': {'radiusservers': '"server1,server2"', 'radiussecrets': '"""secret one"",""secret two"""'},
         'comment': "a comment"},
    ]
    rules = from_rule_list(seed)
    rules.append(PgHbaRule(tokens="EMPTY"))
    rules.append(PgHbaRule(tokens=["include_dir", "some/dir"], line="include_dir some/dir", line_nr=7))
    rules.append(PgHbaRule(tokens="EMPTY"))
    rules.append(
        PgHbaRule(tokens=["include_if_exists", "somefile.conf"], line="include_if_exists somefile.conf", line_nr=8))
    rules.append(PgHbaRule(tokens="EMPTY"))
    rules.append(PgHbaRule(tokens="COMMENT", line="# This is a comment", comment="# This is a comment"))
    rules.append(PgHbaRule(tokens="EMPTY"))
    rules.append(PgHbaRule(tokens=["include", "somefile.conf"], line="include somefile.conf", line_nr=9))

    sort_rules(rules)
    assert render_rule_list(rules, " ") == '''# This is a comment
local @demodbs,db1,db2 all md5
local all +support,@admins md5
host all all 0.0.0.0/0 radius radiussecrets="""secret one"",""secret two""" radiusservers="server1,server2" #a comment
include_dir some/dir
include_if_exists somefile.conf
include somefile.conf'''


def test_update_rules():
    # it seems that test breaks for Python 2.7 and in 2024, I'm not going to work around that
    # if you still run 2.7, that is your problem
    try:
        import ipaddress
    except ImportError:
        return
    ipaddress.ip_address("0.0.0.0")  # otherwise flake complains
    rules = rule_list_from_hba_file("local all all ident\nhost user db 192.168.10.0/24 md5")

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
    changed, a, b, c = update_rules([local_all], rules)
    assert not changed
    assert tmp_rule_dict == rule_list_to_dict_list(rules)

    local_all["method"] = "trust"
    changed, a, b, c = update_rules([local_all], rules)
    assert changed
    assert rules[0].method == "trust"

    local_all["state"] = "absent"
    changed, a, b, c = update_rules([local_all], rules)
    assert changed
    assert len(rules) == 2
    assert rules[0].method == "md5"
