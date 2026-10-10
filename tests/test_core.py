#!/usr/bin/env python3
"""
BrandSentra - Test Suite
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestPhishingDetector:
    """Tests for the phishing detection engine."""

    def setup_method(self):
        from src.core.phishing_detector import PhishingDetector

        self.detector = PhishingDetector()

    def test_clean_domain(self):
        result = self.detector.analyze("google.com")
        assert result.risk_level in ("clean", "low")

    def test_suspicious_keywords(self):
        result = self.detector.analyze("nbk-login-verify-secure.xyz")
        assert result.is_phishing is True
        assert result.risk_score > 50

    def test_high_risk_tld(self):
        result = self.detector.analyze("secure-bank.tk")
        assert result.risk_score > 20

    def test_brand_impersonation(self):
        result = self.detector.analyze("nbk-secure-login.com")
        assert "brand_impersonation" in result.categories or result.risk_score > 30

    def test_idn_detection(self):
        result = self.detector.analyze("xn--nbk-fma.com")
        assert any(i["type"] == "punycode_idn" for i in result.indicators)

    def test_long_domain(self):
        result = self.detector.analyze(
            "this-is-a-very-long-suspicious-domain-name-targeting-enterprise.xyz"
        )
        assert result.risk_score > 30


class TestDomainAnalyzer:
    """Tests for the domain squatting analyzer."""

    def setup_method(self):
        from src.core.domain_analyzer import DomainAnalyzer
        from src.config.settings import DomainAnalysisConfig

        self.analyzer = DomainAnalyzer(DomainAnalysisConfig())

    def test_typosquatting(self):
        results = self.analyzer.analyze("novapay.xyz")
        # Should detect TLD swap for novapay.com
        assert len(results) > 0

    def test_exact_match_ignored(self):
        results = self.analyzer.analyze("novapay.com")
        # Exact match should be ignored
        assert len(results) == 0

    def test_levenshtein(self):
        dist = self.analyzer._levenshtein("kitten", "sitting")
        assert dist == 3

    def test_bitsquat(self):
        assert self.analyzer._check_bitsquat("nbk", "nbl") is False
        # 'k' (0x6B) and 'j' (0x6A) differ by 1 bit
        assert self.analyzer._check_bitsquat("nbj", "nbk") is True

    def test_permutation_generation(self):
        perms = self.analyzer.generate_permutations("nbk.com")
        assert len(perms) > 10
        assert "bk" in perms  # character omission
        assert "bnk" in perms  # character swap


class TestBrandMonitor:
    """Tests for the brand protection monitor."""

    def setup_method(self):
        from src.core.brand_monitor import BrandMonitor

        self.monitor = BrandMonitor()

    def test_brand_detection(self):
        alerts = self.monitor.check_domain("novapay-secure-login.com")
        assert len(alerts) > 0
        assert alerts[0].brand_name == "NovaPay"

    def test_legitimate_domain_ignored(self):
        alerts = self.monitor.check_domain("example.com")
        assert len(alerts) == 0

    def test_stats(self):
        self.monitor.check_domain("nbk-phish.com")
        stats = self.monitor.get_stats()
        assert stats["total_alerts"] > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
