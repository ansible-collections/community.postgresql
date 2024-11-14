# -*- coding: utf-8 -*-

# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import sys
import pytest


if sys.version_info[0] == 3:
    from plugins.modules.postgresql_pg_hba import tokenize, TokenizerException, handle_address_field, \
        handle_netmask_field, handle_db_and_user_strings, PgHbaRuleValueError, PgHbaValueError, parse_auth_options, \
        parse_hba_file
elif sys.version_info[0] == 2:
    from ansible_collections.community.postgresql.plugins.modules.postgresql_pg_hba import tokenize, \
        TokenizerException, handle_address_field, handle_netmask_field, handle_db_and_user_strings, \
        PgHbaRuleValueError, PgHbaValueError, parse_auth_options, parse_hba_file


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
