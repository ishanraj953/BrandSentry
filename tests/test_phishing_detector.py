#!/usr/bin/env python3
"""Tests for src/core/phishing_detector.py."""

import json

import pytest

from src.config.settings import Settings
from src.core.phishing_detector import PhishingDetector


@pytest.fixture
def detector():
    return PhishingDetector()


def types(verdict):
    return {i["type"] for i in verdict.indicators}


class TestCleanAndLegit:
    @pytest.mark.parametrize(
        "domain",
        ["google.com", "paypal.com", "github.com", "_news.com", "example.org", "bbc.co.uk"],
    )
    def test_clean(self, detector, domain):
        v = detector.analyze(domain)
        assert v.risk_level == "clean", v.indicators
        assert v.is_phishing is False
        assert v.parsed["registrable"]

    @pytest.mark.parametrize("domain", ["novapay.com", "login.novapay.com", "www.kestrelmart.com", "halcyonhealth.org"])
    def test_protected_brand_domains_are_clean(self, detector, domain):
        v = detector.analyze(domain)
        assert v.risk_score == 0 and v.risk_level == "clean"
        assert "protected_brand_domain" in types(v)

    def test_allowlist_from_config_and_argument(self):
        settings = Settings()
        settings.domain_analysis.allowlist = ["nbk-login.com"]
        d = PhishingDetector(settings, allowlist=["kfh-login.com"])
        assert "allowlisted" in types(d.analyze("www.nbk-login.com"))
        assert "allowlisted" in types(d.analyze("kfh-login.com"))

    def test_false_positive_override(self, detector):
        assert detector.analyze("nbk-login.com").is_phishing
        detector.mark_false_positive("nbk-login.com")
        v = detector.analyze("nbk-login.com")
        assert v.risk_score == 0 and "false_positive_override" in types(v)

    def test_empty_input(self, detector):
        v = detector.analyze("")
        assert v.risk_level == "clean" and v.indicators == []


class TestLayers:
    def test_keywords_score_by_position(self, detector):
        v = detector.analyze("secure-login-verify.example")
        kws = [i for i in v.indicators if i["type"] == "phishing_keyword"]
        assert {i["keyword"] for i in kws} == {"secure", "login", "verify"}
        assert all(i["weight"] == 12.0 for i in kws)
        sub = detector.analyze("login.example.com")
        assert [i["weight"] for i in sub.indicators if i["type"] == "phishing_keyword"] == [8.0]

    def test_brand_combo_is_phishing(self, detector):
        v = detector.analyze("nbk-login-verify-secure.xyz")
        assert v.is_phishing and v.risk_score > 50
        assert "brand_impersonation" in v.categories
        assert v.matched_brands[0] == "NBK"
        assert "brand_combo" in types(v)

    def test_homograph_is_critical(self, detector):
        v = detector.analyze("nbк.com")
        assert "idn_homograph" in types(v)
        assert "mixed_script" in types(v)
        assert "punycode_idn" in types(v)
        assert v.risk_level in ("high", "critical")
        assert v.parsed["unicode_hostname"] == "nbк.com"

    def test_legacy_punycode_indicator(self, detector):
        v = detector.analyze("xn--nbk-fma.com")
        assert any(i["type"] == "punycode_idn" for i in v.indicators)

    def test_arabic_lure_and_brand(self, detector):
        v = detector.analyze("بيتك-تحديث.com")
        kinds = types(v)
        assert "arabic_brand_keyword" in kinds
        assert "arabic_lure_keyword" in kinds
        assert "KFH" in v.matched_brands
        assert v.is_phishing

    def test_leet_brand(self, detector):
        v = detector.analyze("nbk0nline.com")
        assert v.matched_brands[0] == "NBK"
        assert v.risk_score >= 25

    def test_typosquat_and_weak_typo_needs_context(self, detector):
        assert "brand_typosquat" in types(detector.analyze("novapxy.com"))
        assert "brand_typosquat" not in types(detector.analyze("abc.com"))
        assert types(detector.analyze("novapxy-portal-login.top")) & {"brand_typosquat", "brand_combo"}

    def test_brand_in_subdomain(self, detector):
        v = detector.analyze("nbk.com.verify-account.tk")
        assert "brand_in_subdomain" in types(v)
        assert "subdomain_abuse" in v.categories
        assert v.risk_level == "critical"

    def test_tld_risk_and_synergy(self, detector):
        plain = detector.analyze("_-bank.tk")
        assert plain.risk_score > 20
        assert "high_risk_tld" in types(plain)
        brand = detector.analyze("nbk-login.tk")
        assert "brand_on_risky_tld" in types(brand)
        assert brand.risk_score > plain.risk_score
        assert "medium_risk_tld" in types(detector.analyze("random-shop.xyz"))

    def test_structure_indicators(self, detector):
        v = detector.analyze(
            "a.b.c.d.this-is-a-very-long-suspicious-domain-name-targeting-_123456.xyz"
        )
        kinds = types(v)
        assert {
            "excessive_subdomains",
            "excessive_hyphens",
            "long_domain",
            "numeric_padding",
        } <= kinds
        assert v.risk_score > 30

    def test_embedded_tld_and_fake_official(self, detector):
        v = detector.analyze("gov-portal-online.com")
        kinds = types(v)
        assert "fake_official" in kinds
        assert v.is_phishing
        assert "fake_official" not in types(detector.analyze("portal.gov"))

    def test_entropy(self, detector):
        assert "high_entropy" in types(detector.analyze("x9q2z8k1m3w7v5p4.com"))
        assert "high_entropy" not in types(detector.analyze("aaaaaaaaaaaa.com"))

    def test_free_hosting(self, detector):
        v = detector.analyze("nbk-secure-login.web.app")
        assert "free_hosting_platform" in types(v)
        assert v.parsed["hosting_platform"] == "web.app"
        assert v.risk_level == "critical"

    def test_ip_host(self, detector):
        v = detector.analyze("http://192.168.1.10/login")
        assert "ip_address_host" in types(v)
        assert v.parsed["is_ip"] is True

    def test_certificate_context(self, detector):
        base = detector.analyze("nbk-login.com")
        ctx = detector.analyze(
            "nbk-login.com", {"issuer": "C=US, O=Let's Encrypt, CN=R3", "is_wildcard": True}
        )
        assert ctx.risk_score > base.risk_score
        assert {"free_certificate", "wildcard_certificate"} <= types(ctx)

    def test_global_brand(self, detector):
        v = detector.analyze("paypal-account-verify.com")
        assert "Paypal" in v.matched_brands
        assert v.is_phishing

    def test_second_brand_adds_little(self, detector):
        v = detector.analyze("cbk-nbk-login.com")
        assert len(v.matched_brands) >= 2
        assert v.risk_score <= 100


class TestVerdict:
    def test_to_dict_serializable(self, detector):
        v = detector.analyze("nbk-login.xyz")
        data = json.loads(json.dumps(v.to_dict()))
        assert data["risk_level"] in ("high", "critical")
        assert data["explanation"].startswith(data["risk_level"].upper())
        assert data["parsed"]["suffix"] == "xyz"
        assert "NBK" in data["recommendation"]

    def test_score_capped_and_levels(self, detector):
        v = detector.analyze("nbk-login-verify-secure-update-account-otp.tk")
        assert v.risk_score <= 100 and v.risk_level == "critical"
        assert v.confidence <= 0.99
        assert detector._score_to_level(75) == "high"
        assert detector._score_to_level(45) == "medium"

    def test_detection_count_and_many(self, detector):
        verdicts = detector.analyze_many(["nbk.com", "nbk-login.com"])
        assert len(verdicts) == 2
        assert detector.detection_count == 2


def test_hosting_platform_is_scored_once():
    """The platform indicator stands alone: no TLD points for a hosting platform's own suffix."""
    v = PhishingDetector().analyze("verify-account-portal.pages.dev")
    kinds = {i["type"] for i in v.indicators}
    assert "free_hosting_platform" in kinds
    assert not {"medium_risk_tld", "high_risk_tld", "brand_on_risky_tld"} & kinds


def test_leading_www_does_not_add_structure():
    """A leading www must not push a name across a score threshold."""
    det = PhishingDetector()
    plain = det.analyze("portal.secure-update.xyz")
    www = det.analyze("www.portal.secure-update.xyz")
    assert www.risk_score == plain.risk_score
    assert "excessive_subdomains" not in {i["type"] for i in www.indicators}
