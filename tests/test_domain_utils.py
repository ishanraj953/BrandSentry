#!/usr/bin/env python3
"""Tests for src/utils/domain.py."""

import pytest

from src.utils.domain import (
    brand_skeleton,
    confusable_skeleton,
    contains_arabic,
    is_mixed_script,
    is_subdomain_of,
    leet_normalize,
    levenshtein,
    matches_any,
    normalize_arabic,
    normalize_domain,
    parse_domain,
    registrable_domain,
    scripts_in,
    shannon_entropy,
    similarity,
    split_suffix,
    to_ascii,
    to_unicode,
    tokens_of,
    typo_threshold,
)


class TestNormalize:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("NBK.com", "nbk.com"),
            ("https://Login.NBK.com.kw:443/path?x=1#f", "login.nbk.com.kw"),
            ("  *.nbk-secure.xyz  ", "nbk-secure.xyz"),
            ("user:pass@evil.example/login", "evil.example"),
            ("evil.example.", "evil.example"),
            ("http://EVIL.example\\admin", "evil.example"),
            ("", ""),
            (None, ""),
            ("nbк.com", "xn--nb-3lc.com"),
        ],
    )
    def test_normalize(self, raw, expected):
        assert normalize_domain(raw) == expected

    def test_roundtrip_unicode(self):
        ascii_form = to_ascii("بنك-الوطني.com")
        assert ascii_form.startswith("xn--")
        assert to_unicode(ascii_form) == "بنك-الوطني.com"

    def test_to_unicode_keeps_invalid_labels(self):
        assert to_unicode("xn--$$$.com") == "xn--$$$.com"


class TestParse:
    def test___second_level(self):
        p = parse_domain("login.nbk.com.kw")
        assert p.label == "nbk"
        assert p.suffix == "com.kw"
        assert p.registrable == "nbk.com.kw"
        assert p.subdomain == "login"
        assert p.tld == "kw"
        assert p.searchable_labels == ["login", "nbk"]

    def test_gov_kw(self):
        p = parse_domain("www.e.gov.kw")
        assert p.label == "e"
        assert p.registrable == "e.gov.kw"

    def test_plain_com(self):
        p = parse_domain("kw.zain.com")
        assert p.label == "zain"
        assert p.subdomain == "kw"
        assert p.registrable == "zain.com"

    def test_free_hosting_platform(self):
        p = parse_domain("nbk-login.web.app")
        assert p.hosting_platform == "web.app"
        assert p.label == "nbk-login"
        assert p.registrable == "nbk-login.web.app"

    def test_wildcard_flag(self):
        p = parse_domain("*.nbk-secure.xyz")
        assert p.is_wildcard is True
        assert p.hostname == "nbk-secure.xyz"

    def test_idn_decoding(self):
        p = parse_domain("nbк.com")
        assert p.is_idn is True
        assert p.hostname == "xn--nb-3lc.com"
        assert p.unicode_hostname == "nbк.com"
        assert p.unicode_label == "nbк"

    def test_punycode_input(self):
        p = parse_domain("xn--nb-fma.com")
        assert p.is_idn
        assert p.unicode_label == "nbč"

    def test_ipv4(self):
        p = parse_domain("http://192.168.1.10/login")
        assert p.is_ip is True
        assert p.registrable == "192.168.1.10"
        assert p.unicode_label == "192.168.1.10"

    def test_deep_subdomain_abuse(self):
        p = parse_domain("moi.gov.kw.verify-account.tk")
        assert p.label == "verify-account"
        assert p.suffix == "tk"
        assert p.subdomain == "moi.gov.kw"
        assert p.depth == 5

    def test_empty(self):
        p = parse_domain("")
        assert p.valid is False
        assert p.registrable == ""

    def test_invalid_label_marks_invalid(self):
        assert parse_domain("bad domain.com").valid is False
        assert parse_domain("ok-domain.com").valid is True

    def test_to_dict(self):
        d = parse_domain("nbk.com").to_dict()
        assert d["registrable"] == "nbk.com"
        assert "depth" in d

    def test_registrable_helper(self):
        assert registrable_domain("a.b.c.nbk.com.kw") == "nbk.com.kw"

    def test_split_suffix_prefers_longest(self):
        assert split_suffix(["bucket", "s3", "amazonaws", "com"]) == (
            ["bucket"],
            "s3.amazonaws.com",
        )
        assert split_suffix(["nbk", "com"]) == (["nbk"], "com")
        assert split_suffix(["com"]) == ([], "com")


class TestRelationships:
    def test_subdomain_of(self):
        assert is_subdomain_of("login.nbk.com", "nbk.com")
        assert is_subdomain_of("nbk.com", "NBK.com")
        assert not is_subdomain_of("nbk.com.evil.com", "nbk.com")
        assert not is_subdomain_of("notnbk.com", "nbk.com")

    def test_matches_any(self):
        assert matches_any("m.kfh.com", ["nbk.com", "kfh.com"]) == "kfh.com"
        assert matches_any("kfh-login.com", ["nbk.com", "kfh.com"]) is None


class TestScripts:
    def test_scripts_detection(self):
        assert scripts_in("nbk") == {"LATIN"}
        assert scripts_in("nbк") == {"LATIN", "CYRILLIC"}
        assert is_mixed_script("nbк") is True
        assert is_mixed_script("nbk-123") is False

    def test_confusable_skeleton(self):
        assert confusable_skeleton("nbк") == "nbk"
        assert confusable_skeleton("pаypаl") == "paypal"
        assert confusable_skeleton("αpple") == "apple"
        assert confusable_skeleton("ﬁnance") == "finance"
        assert confusable_skeleton("café") == "cafe"

    def test_leet_and_visual(self):
        assert leet_normalize("nbk0nline") == "nbkonline"
        assert leet_normalize("g00gle") == "google"
        assert leet_normalize("rnicrosoft") == "microsoft"
        assert brand_skeleton("n-b-k") == "nbk"
        assert brand_skeleton("КFH") == "kfh"

    def test_arabic(self):
        assert contains_arabic("بنك") is True
        assert contains_arabic("bank") is False
        assert normalize_arabic("بَنْكُ الوطنيّ") == "بنك الوطني"
        assert normalize_arabic("أحمد") == "احمد"


class TestMetrics:
    def test_levenshtein(self):
        assert levenshtein("kitten", "sitting") == 3
        assert levenshtein("nbk", "nbk") == 0
        assert levenshtein("nbk", "kfh", max_distance=1) > 1
        assert levenshtein("", "abc") == 3

    def test_similarity(self):
        assert similarity("nbk", "nbk") == 1.0
        assert 0.7 < similarity("nbk", "nbkk") < 0.8

    def test_typo_threshold(self):
        assert typo_threshold(3) == 1
        assert typo_threshold(6) == 2
        assert typo_threshold(12) == 3

    def test_entropy(self):
        assert shannon_entropy("") == 0.0
        assert shannon_entropy("aaaa") == 0.0
        assert shannon_entropy("x9q2z8k1m3") > 3.0

    def test_tokens(self):
        assert tokens_of("nbk-secure-login2") == ["nbk", "secure", "login"]
