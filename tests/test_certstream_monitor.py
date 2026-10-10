#!/usr/bin/env python3
"""Tests for src/core/certstream_monitor.py (no network)."""

import pytest

from src.config.settings import CertStreamConfig
from src.core.certstream_monitor import STATE_KEY, CertStreamMonitor
from src.models.database import Database


def message(domains, issuer=None, source="Argon2026"):
    return {
        "message_type": "certificate_update",
        "data": {
            "source": {"name": source},
            "leaf_cert": {
                "all_domains": domains,
                "issuer": issuer or {"O": "Let's Encrypt", "CN": "R3"},
                "fingerprint": "AA:BB",
                "not_before": 1,
                "not_after": 2,
                "serial_number": "01",
            },
        },
    }


@pytest.fixture
def monitor():
    cfg = CertStreamConfig(keywords=["nbk", "novapay", "kestrel", "sentra"], heartbeat_interval=2)
    return CertStreamMonitor(cfg)


class TestMatching:
    def test_short_keywords_match_tokens_only(self, monitor):
        assert monitor.match_keywords("hawkwind.com") == []
        assert monitor.match_keywords("nbk-sentra.com") == ["nbk", "sentra"]
        assert monitor.match_keywords("login.something.sentra") == []
        assert monitor.match_keywords("kestrelcar.com") == ["kestrel"]

    def test_short_keywords_anchor_to_token_edges(self):
        cfg = CertStreamConfig(keywords=["nov", "cbk", "kpay", "kuna", "novapay"])
        m = CertStreamMonitor(cfg)
        assert m.match_keywords("novapaybank.com") == ["nov", "novapay"]
        assert m.match_keywords("e-cbk.com") == ["cbk"]
        assert m.match_keywords("lkpay.example.com") == ["kpay"]
        assert m.match_keywords("fckvvqrxxcfveswhtjskuw.example.dev") == []
        assert m.match_keywords("cbkfmcdtytlkzfswjwrtsj.example.dev") == []
        assert m.match_keywords("kkunalsanga123.workers.dev") == []
        assert m.match_keywords("qpojmlgcbklmxprow.com") == []

    def test_long_keywords_substring(self, monitor):
        assert monitor.match_keywords("nbkonline.com") == ["nbk"]
        assert monitor.match_keywords("mynbkonline.com") == []  # mid-token: left to deep match
        assert monitor.match_keywords("SENTRAbank.tk") == ["sentra"]


class TestProcessing:
    def test_events_dedupe_wildcards_and_dispatch(self, monitor):
        got = []
        monitor.add_callback(got.append)
        monitor._handle_message(
            message(["*.nbk-login.xyz", "nbk-login.xyz", "www.nbk-login.xyz", "other.com"])
        )
        assert [e.domain for e in got] == ["nbk-login.xyz", "www.nbk-login.xyz"]
        first = got[0]
        assert first.is_wildcard is True
        assert first.matched_keywords == ["nbk"]
        assert first.source == "Argon2026"
        assert first.issuer_name == "Let's Encrypt"
        assert first.risk_score > 20
        assert first.to_dict()["domain"] == "nbk-login.xyz"
        stats = monitor.get_stats()
        assert stats["total_certs"] == 1
        assert stats["matched_certs"] == 1
        assert stats["matched_domains"] == 2
        assert stats["last_event"]

    def test_ignore_wildcards_option(self):
        cfg = CertStreamConfig(keywords=["nbk"], ignore_wildcards=True)
        m = CertStreamMonitor(cfg)
        events = m.process_certificate(message(["*.nbk.xyz"])["data"])
        assert events == []

    def test_non_certificate_messages_ignored(self, monitor):
        monitor._handle_message({"message_type": "heartbeat"})
        assert monitor.get_stats()["total_certs"] == 0

    def test_callback_errors_are_counted(self, monitor):
        def bad(event):
            raise RuntimeError("boom")

        monitor.add_callback(bad)
        monitor._handle_message(message(["nbk.xyz"]))
        assert monitor.get_stats()["callback_errors"] == 1

    def test_risk_score_heuristics(self, monitor):
        low = monitor.process_certificate(message(["nbk-news.com"])["data"])[0].risk_score
        high = monitor.process_certificate(
            message(["a.b.c.nbk-secure-login-verify-2024.tk"])["data"]
        )[0].risk_score
        assert high > low
        assert high <= 100

    def test_malformed_message_counts_error(self, monitor):
        monitor._handle_message(
            {
                "message_type": "certificate_update",
                "data": {"leaf_cert": {"all_domains": [None, 5]}},
            }
        )
        assert monitor.get_stats()["total_certs"] == 1


class TestPersistence:
    def test_events_and_heartbeat_persisted(self, tmp_path):
        db = Database(str(tmp_path / "m.db"))
        cfg = CertStreamConfig(keywords=["nbk"], heartbeat_interval=2)
        m = CertStreamMonitor(cfg, db=db)
        m._handle_message(message(["nbk-a.com"]))
        assert db.count_certstream_events() == 1
        assert db.get_state(STATE_KEY) is None
        m._handle_message(message(["nbk-b.com"]))
        state = db.get_state(STATE_KEY)
        assert state["total_certs"] == 2 and state["matched_domains"] == 2
        assert db.get_recent_certstream_events()[0]["domain"] == "nbk-b.com"
        m.stop()
        assert db.get_state(STATE_KEY)["status"] == "stopped"

    def test_persist_events_disabled(self, tmp_path):
        db = Database(str(tmp_path / "m2.db"))
        cfg = CertStreamConfig(keywords=["nbk"], persist_events=False)
        m = CertStreamMonitor(cfg, db=db)
        m._handle_message(message(["nbk-a.com"]))
        assert db.count_certstream_events() == 0

    def test_start_requires_certstream(self, monitor, monkeypatch):
        import src.core.certstream_monitor as mod

        monkeypatch.setattr(mod, "certstream", None)
        monitor.config.source = "certstream"
        with pytest.raises(ImportError):
            monitor.start()
