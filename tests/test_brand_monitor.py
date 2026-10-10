#!/usr/bin/env python3
"""Tests for src/core/brand_monitor.py."""

import pytest

from src.config.settings import Settings
from src.core.brand_monitor import DEFAULT_BRANDS, BrandMonitor, BrandProfile


@pytest.fixture
def monitor():
    return BrandMonitor(dedupe_window_seconds=0)


def alert_types(monitor, domain):
    return {(a.brand_name, a.alert_type, a.severity) for a in monitor.check_domain(domain)}


class TestProfiles:
    def test_default_brand_count_and_shape(self):
        assert len(DEFAULT_BRANDS) >= 25
        names = {b.short_name for b in DEFAULT_BRANDS}
        assert {"NovaPay", "Kestrel", "Halcyon", "NBK", "KFH", "KNET", "PACI", "MOI", "Zain", "Global Airways"} <= names
        for b in DEFAULT_BRANDS:
            assert b.domains and b.keywords
            assert b.priority in ("critical", "high", "medium", "low")

    def test_short_labels_are_excluded(self):
        egov = next(b for b in DEFAULT_BRANDS if b.short_name == "eGov")
        assert "e" not in egov.primary_labels()
        assert "sahel" in egov.alias_labels()

    def test_labels_split_primary_and_alias(self):
        nbk = next(b for b in DEFAULT_BRANDS if b.short_name == "NBK")
        assert nbk.primary_labels() == {"nbk", "nbkcapital"}
        assert "nbkonline" in nbk.alias_labels()
        assert "watani" in nbk.alias_labels()
        assert nbk.labels() == nbk.primary_labels() | nbk.alias_labels()

    def test_phrases(self):
        kfh = next(b for b in DEFAULT_BRANDS if b.short_name == "KFH")
        assert ["key", "finance", "house"] in kfh.phrases()

    def test_from_dict_and_to_dict_roundtrip(self):
        data = {
            "name": "Test Bank",
            "domains": ["TestBank.com"],
            "keywords": ["testbank", "test bank"],
            "aliases": ["tbank"],
            "arabic_keywords": ["تست"],
            "industry": "banking",
            "priority": "critical",
        }
        profile = BrandProfile.from_dict(data)
        assert profile.domains == ["testbank.com"]
        assert profile.to_dict()["priority"] == "critical"
        assert profile.is_legitimate("login.testbank.com")


class TestLegitimateAndTraps:
    @pytest.mark.parametrize(
        "domain",
        [
            "novapay.com",
            "login.novapay.com",
            "kestrelmart.com",
            "halcyonhealth.org",
            "nbk.com",
            "login.nbk.com",
            "kfh.com",
            "e-gov.org",
            "paci-gov.org",
            "google.com",
            "example.com",
            "kibana.io",
            "mohammed.com",
            "pacific.com",
            "moisture.com",
            "stcoupon.com",
            "zainab.com",
            "knetwork.com",
            "nbc.com",
            "kfc.com",
            "abc.com",
            "mom.com",
            "10.0.0.1",
            "",
        ],
    )
    def test_no_alert(self, monitor, domain):
        assert monitor.check_domain(domain) == []

    def test_allowlist(self):
        m = BrandMonitor(dedupe_window_seconds=0, allowlist=["nbk-login.com"])
        assert m.check_domain("nbk-login.com") == []
        assert m.check_domain("www.nbk-login.com") == []
        assert m.get_stats()["allowlisted"] == 2
        m.remove_allowlist("nbk-login.com")
        assert m.check_domain("nbk-login.com")


class TestDetections:
    @pytest.mark.parametrize(
        "domain,short,alert_type,severity",
        [
            ("nbk.xyz", "NBK", "domain_squat", "critical"),
            ("nbk-login.com", "NBK", "combo_squat", "critical"),
            ("nbк.com", "NBK", "idn_homograph", "critical"),
            ("nbk0nline.com", "NBK", "domain_squat", "critical"),
            ("nbkk.com", "NBK", "typosquat", "high"),
            ("nbk.com.verify-login.tk", "NBK", "subdomain_abuse", "critical"),
            ("nationalbankingcorporation.com", "NBK", "brand_keyword_abuse", "high"),
            ("xn----zmcb6dvcikfqw.com", "NBK", "arabic_brand_keyword", "high"),
            ("بيتك-تحديث.com", "KFH", "arabic_brand_keyword", "high"),
            ("key-finance-house.com", "KFH", "brand_keyword_abuse", "medium"),
            ("knetpay.info", "KNET", "domain_squat", "critical"),
            ("k-net.com", "KNET", "domain_squat", "high"),
            ("moi-gov-login.com", "MOI", "combo_squat", "critical"),
            ("paci-civilid.com", "PACI", "brand_keyword_abuse", "medium"),
            ("sahel-app.com", "eGov", "combo_squat", "critical"),
            ("bourgan.com", "Burgan", "typosquat", "medium"),
            ("zainpay.com", "Zain", "combo_squat", "high"),
            ("stc-login.com", "stc", "combo_squat", "critical"),
            ("talabat-offers.com", "Talabat", "combo_squat", "medium"),
            ("globalairways-booking.com", "Global Airways", "combo_squat", "high"),
            ("nbk-secure-login.web.app", "NBK", "combo_squat", "critical"),
            ("novapay-login.com", "NovaPay", "combo_squat", "critical"),
            ("kestrelmart-shop.com", "Kestrel", "combo_squat", "high"),
        ],
    )
    def test_detection(self, monitor, domain, short, alert_type, severity):
        brand = monitor.get_brand(short)
        alerts = [a for a in monitor.check_domain(domain) if a.brand_name == brand.name]
        assert alerts, f"{domain} should alert for {short}"
        assert alerts[0].alert_type == alert_type
        assert alerts[0].severity == severity

    def test_strong_match_suppresses_noise_for_other_brands(self, monitor):
        alerts = monitor.check_domain("nbk.xyz")
        assert {a.brand_name for a in alerts} == {"National Banking Corporation (NBK)"}

    def test_ambiguous_typo_reports_both(self, monitor):
        brands = {a.brand_name for a in monitor.check_domain("bourgan.com")}
        assert {"Burgan Bank", "Boubyan Bank"} == brands

    def test_evidence_contents(self, monitor):
        alert = monitor.check_domain("nbk-login.tk")[0]
        ev = alert.evidence
        assert ev["suspicious_domain"] == "nbk-login.tk"
        assert ev["registrable_domain"] == "nbk-login.tk"
        assert ev["tld_risk"] == "high"
        assert "login" in ev["phishing_keywords"]
        assert ev["combo_keywords"] == ["login"]
        assert alert.risk_score == 90.0
        assert alert.domain == "nbk-login.tk"
        assert alert.alert_id.startswith("BA-")
        assert alert.to_dict()["brand"] == alert.brand_name

    def test_wildcard_and_url_inputs(self, monitor):
        assert monitor.check_domain("*.nbk-login.com")
        assert monitor.check_domain("https://NBK-login.com/verify")

    def test_source_recorded(self, monitor):
        alert = monitor.check_domain("nbk-login.com", source="certstream")[0]
        assert alert.evidence["source"] == "certstream"


class TestDedupeAndState:
    def test_dedupe_window(self):
        clock = {"t": 1000.0}
        m = BrandMonitor(dedupe_window_seconds=60, now=lambda: clock["t"])
        assert len(m.check_domain("nbk-login.com")) == 1
        assert m.check_domain("nbk-login.com") == []
        assert m.check_domain("www.nbk-login.com")  # different hostname
        clock["t"] += 61
        assert len(m.check_domain("nbk-login.com")) == 1
        assert m.get_stats()["deduplicated"] == 1

    def test_record_false_skips_state(self, monitor):
        alerts = monitor.check_domain("nbk-login.com", record=False)
        assert alerts and monitor.alerts == []

    def test_alert_management(self, monitor):
        monitor.check_domain("nbk-login.com")
        monitor.check_domain("kfh-login.com")
        alert = monitor.alerts[0]
        assert monitor.get_alerts(severity="critical")
        assert monitor.get_alerts(brand="key finance")
        updated = monitor.update_alert_status(alert.alert_id, "resolved", assignee="analyst")
        assert updated.status == "resolved" and updated.assignee == "analyst"
        assert monitor.get_alerts(status="open")
        assert monitor.update_alert_status("missing", "resolved") is None
        stats = monitor.get_stats()
        assert stats["total_alerts"] == 2
        assert stats["by_industry"]["banking"] == 2
        assert stats["by_type"]["combo_squat"] == 2
        monitor.clear_alerts()
        assert monitor.alerts == []

    def test_add_remove_get_brand(self, monitor):
        monitor.add_brand(
            BrandProfile(name="Acme Corp", domains=["acmecorp.com"], keywords=["acmecorp"])
        )
        assert monitor.get_brand("acme corp")
        assert monitor.check_domain("acmecorp-login.com")
        assert monitor.find_brand_by_domain("shop.acmecorp.com").name == "Acme Corp"
        assert monitor.remove_brand("Acme Corp") is True
        assert monitor.remove_brand("Acme Corp") is False
        assert "nbk.com" in monitor.protected_domains()

    def test_from_settings_merges_custom_brands(self):
        settings = Settings()
        settings.brands = [
            {"name": "Test Bank", "domains": ["testbank.com"], "keywords": ["testbank"]},
            {"name": "Broken", "domains": [], "keywords": []},
        ]
        settings.domain_analysis.allowlist = ["nbk-login.com"]
        m = BrandMonitor.from_settings(settings)
        assert m.get_brand("Test Bank")
        assert len(m.brands) == len(DEFAULT_BRANDS) + 1
        assert m.check_domain("nbk-login.com") == []
        settings.brands_replace_defaults = True
        only = BrandMonitor.from_settings(settings)
        assert [b.name for b in only.brands] == ["Test Bank"]
