#!/usr/bin/env python3
"""Tests for src/core/domain_analyzer.py."""

import pytest

from src.config.settings import DomainAnalysisConfig
from src.core.domain_analyzer import DomainAnalyzer, detect_techniques


@pytest.fixture
def analyzer():
    return DomainAnalyzer(DomainAnalysisConfig())


def techniques(domain_label, brand_label, **kw):
    return detect_techniques(domain_label, brand_label, **kw)["techniques"]


class TestDetectTechniques:
    def test_identical_is_not_an_attack(self):
        info = detect_techniques("nbk", "nbk")
        assert info["techniques"] == [] and info["similarity"] == 1.0

    def test_homoglyph(self):
        assert "homoglyph" in techniques("xn--nb-3lc", "nbk", unicode_label="nbк")

    def test_leet(self):
        assert techniques("nbk0nline", "nbk") == ["combo_squat"]
        assert techniques("kn3t", "knet") == ["leet_substitution"]

    def test_hyphenation(self):
        assert techniques("k-net", "knet") == ["hyphenation"]

    @pytest.mark.parametrize(
        "label,brand,keyword",
        [
            ("nbk-login", "nbk", "login"),
            ("nbklogin", "nbk", "login"),
            ("login-novapay", "novapay", "login"),
            ("knetpay", "knet", "pay"),
            ("wwwnbk", "nbk", "www"),
            ("mynbkbank", "nbk", "bank"),
            ("_airways-booking", "_airways", "booking"),
        ],
    )
    def test_combo_squat(self, label, brand, keyword):
        info = detect_techniques(label, brand)
        assert "combo_squat" in info["techniques"]
        assert keyword in info["combo_keywords"]

    def test_addition_of_digits(self):
        assert techniques("nbk2024", "nbk") == ["addition"]

    def test_brand_embedding_requires_token_or_long_brand(self):
        assert techniques("nbk-xyzzy", "nbk") == ["brand_embedding"]
        assert techniques("burganxyz", "burgan") == ["brand_embedding"]
        assert techniques("kibana", "kib") == []
        assert techniques("knetwork", "knet") == []
        assert techniques("pacific", "paci") == []
        assert techniques("mohammed", "moh") == []

    def test_typos_scaled_to_length(self):
        assert "typosquat" in techniques("nbkk", "nbk")
        assert "repetition" in techniques("nbkk", "nbk")
        assert "transposition" in techniques("nkb", "nbk")
        assert techniques("kfh", "nbk") == []  # 3 edits on a 3-char brand
        assert "insertion" in techniques("bourgan", "burgan")
        assert "omission" in techniques("bugan", "burgan")
        assert "vowel_swap" in techniques("bergan", "burgan")

    def test_short_brand_single_edits_are_weak(self):
        info = detect_techniques("nbc", "nbk")
        assert "bitsquat" in info["techniques"] and info["weak"] is True
        info = detect_techniques("nbl", "nbk")
        assert info["weak"] is True
        assert detect_techniques("nkb", "nbk")["weak"] is False

    def test_generic_word_inside_long_brand_is_ignored(self):
        assert techniques("_", "nbk_") == []

    def test_allow_typo_false(self):
        assert techniques("nbkk", "nbk", allow_typo=False) == []


class TestAnalyzer:
    def test_exact_and_legit_subdomains_ignored(self, analyzer):
        assert analyzer.analyze("novapay.com") == []
        assert analyzer.analyze("login.novapay.com") == []
        assert analyzer.analyze("https://www.novapay.com/login") == []

    def test_other_protected_brand_is_not_a_typo(self, analyzer):
        results = analyzer.analyze("novapay.xyz")
        assert [r.target_domain for r in results] == ["novapay.com"]
        assert results[0].attack_types == ["tld_swap"]
        assert results[0].risk_level == "high"

    def test_legitimate_domains_extension(self):
        a = DomainAnalyzer(DomainAnalysisConfig(), legitimate_domains=["novapay.io"])
        assert a.analyze("www.novapay.io") == []

    def test_allowlist(self):
        cfg = DomainAnalysisConfig(allowlist=["novapay-login.com"])
        assert DomainAnalyzer(cfg).analyze("www.novapay-login.com") == []

    @pytest.mark.parametrize(
        "domain,brand,attack",
        [
            ("novapay-login.com", "novapay.com", "combo_squat"),
            ("novapay.com.verify-login.tk", "novapay.com", "subdomain_abuse"),
            ("novapay.evil.com", "novapay.com", "subdomain_abuse"),
            ("novapay-secure-login.web.app", "novapay.com", "combo_squat"),
            ("kestrelmart-pay.info", "kestrelmart.com", "combo_squat"),
            ("halcyonhealth.xyz", "halcyonhealth.org", "tld_swap"),
            ("kestrel-mart.com", "kestrelmart.com", "hyphenation"),
        ],
    )
    def test_detections(self, analyzer, domain, brand, attack):
        results = analyzer.analyze(domain)
        match = [r for r in results if r.target_domain == brand]
        assert match, f"{domain} should match {brand}: {results}"
        assert attack in match[0].attack_types

    @pytest.mark.parametrize(
        "domain",
        [
            "google.com",
            "example.com",
            "kibana.io",
            "mohammed.com",
            "pacific.com",
            "abc.com",
            "mom.com",
            "192.168.1.1",
            "",
        ],
    )
    def test_no_false_positives(self, analyzer, domain):
        assert analyzer.analyze(domain) == []

    def test_weak_match_with_context_is_reported(self, analyzer):
        results = analyzer.analyze("novapxy-login.top")
        assert any(r.target_domain == "novapay.com" for r in results)

    def test_risk_escalation_on_risky_tld(self, analyzer):
        plain = analyzer.analyze("novapay-login.com")[0]
        risky = analyzer.analyze("novapay-login.tk")[0]
        assert plain.risk_level == "high"
        assert risky.risk_level == "critical"
        assert "tld:high" in risky.details["context"]

    def test_result_to_dict(self, analyzer):
        r = analyzer.analyze("novapay-login.com")[0]
        d = r.to_dict()
        assert d["target"] == "novapay.com"
        assert d["attack_types"] == ["combo_squat"]
        assert 0 < d["confidence"] <= 1

    def test_results_sorted_by_confidence(self, analyzer):
        results = analyzer.analyze("novapay.xyz")
        assert len(results) >= 1
        if len(results) >= 2:
            assert results[0].confidence >= results[1].confidence

    def test_legacy_helpers(self, analyzer):
        assert analyzer._levenshtein("kitten", "sitting") == 3
        assert analyzer._check_bitsquat("nbj", "nbk") is True
        assert analyzer._check_bitsquat("nbk", "nbl") is False
        assert analyzer._check_homoglyph("nbк", "nbk") is True
        assert analyzer._check_vowel_swap("bergan", "burgan") is True


class TestPermutations:
    def test_label_permutations_backwards_compatible(self, analyzer):
        perms = analyzer.generate_permutations("nbk.com")
        assert len(perms) > 10
        assert "bk" in perms  # omission
        assert "bnk" in perms  # transposition
        assert "nbkk" in perms  # repetition
        assert "n-bk" in perms  # hyphenation
        assert "nbk-login" in perms  # combo
        assert "nbk" not in perms

    def test_detailed_permutations(self, analyzer):
        perms = analyzer.generate_permutations_detailed(
            "nbk.com", tlds=["com", "kw", "com.kw"], max_results=500
        )
        domains = {p["domain"] for p in perms}
        assert "nbk.kw" in domains and "nbk.com.kw" in domains
        assert "nbk.com" not in domains
        by_tech = {p["technique"] for p in perms}
        assert {"tld_swap", "omission", "transposition", "combo_squat", "homoglyph"} <= by_tech
        assert all(p["domain"].isascii() for p in perms)
        assert len(perms) <= 500

    def test_detailed_flags(self, analyzer):
        perms = analyzer.generate_permutations_detailed(
            "knet.com.kw", include_combos=False, include_homoglyphs=False
        )
        techs = {p["technique"] for p in perms}
        assert "combo_squat" not in techs and "homoglyph" not in techs and "addition" not in techs
        assert all(p["tld"] == "com.kw" for p in perms)

    def test_max_permutations_config(self):
        a = DomainAnalyzer(DomainAnalysisConfig(max_permutations=25))
        assert len(a.generate_permutations_detailed("burgan.com", tlds=["com", "net"])) == 25
