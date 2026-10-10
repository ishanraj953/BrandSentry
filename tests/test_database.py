#!/usr/bin/env python3
"""Tests for src/models/database.py."""

import sqlite3

import pytest

from src.models.database import ALERT_STATUSES, SCHEMA_VERSION, Database


@pytest.fixture
def db(tmp_path):
    return Database(str(tmp_path / "test.db"))


def _alert(alert_id="BA-000001", domain="nbk-login.xyz", severity="critical", **extra):
    base = {
        "alert_id": alert_id,
        "brand_name": "National Banking Corporation (NBK)",
        "alert_type": "domain_squat",
        "severity": severity,
        "description": "test",
        "evidence": {"suspicious_domain": domain},
        "domain": domain,
    }
    base.update(extra)
    return base


class TestDomains:
    def test_add_and_get(self, db):
        db.add_domain(
            "NBK-login.xyz", 85, "critical", True, ["brand_impersonation"], "scan", ["nbk"]
        )
        row = db.get_domain("nbk-login.xyz")
        assert row["risk_level"] == "critical"
        assert row["is_phishing"] is True
        assert row["categories"] == ["brand_impersonation"]
        assert row["seen_count"] == 1

    def test_upsert_increments_seen_count(self, db):
        db.add_domain("x.com", 10, "clean", False, [])
        db.add_domain("x.com", 60, "high", True, ["keyword_abuse"])
        row = db.get_domain("x.com")
        assert row["seen_count"] == 2
        assert row["risk_score"] == 60
        assert db.count_domains() == 1

    def test_recent_and_top(self, db):
        db.add_domain("a.com", 10, "clean", False, [])
        db.add_domain("b.com", 90, "critical", True, [])
        assert [d["domain"] for d in db.get_top_domains(min_risk=50)] == ["b.com"]
        assert len(db.get_recent_domains(limit=10)) == 2
        assert len(db.get_recent_domains(min_risk=50)) == 1
        assert db.count_domains(phishing_only=True) == 1


class TestAlerts:
    def test_add_get_and_duplicate(self, db):
        assert db.add_alert(_alert()) is True
        assert db.add_alert(_alert()) is False
        row = db.get_alert("BA-000001")
        assert row["status"] == "open"
        assert row["evidence"]["suspicious_domain"] == "nbk-login.xyz"
        assert row["domain"] == "nbk-login.xyz"

    def test_requires_alert_id(self, db):
        with pytest.raises(ValueError):
            db.add_alert({"alert_type": "x", "severity": "low", "domain": "a.com"})

    def test_filters_and_pagination(self, db):
        for i in range(5):
            db.add_alert(_alert(f"BA-{i:06d}", severity="critical" if i % 2 else "low"))
        assert db.count_alerts() == 5
        assert db.count_alerts(severity="critical") == 2
        assert db.count_alerts(severity="critical,low") == 5
        page = db.get_alerts(limit=2, offset=0)
        assert len(page) == 2
        assert db.get_alerts(limit=2, offset=4)[0]["alert_id"] == "BA-000000"
        assert db.count_alerts(brand="NBK") == 5
        assert db.count_alerts(domain="nbk-login") == 5
        assert db.count_alerts(alert_type="nope") == 0

    def test_lifecycle_and_history(self, db):
        db.add_alert(_alert())
        updated = db.update_alert("BA-000001", status="investigating", assignee="ali", actor="ali")
        assert updated["status"] == "investigating"
        assert updated["assignee"] == "ali"
        assert updated["resolved_at"] is None
        closed = db.update_alert("BA-000001", status="resolved", notes="takedown done")
        assert closed["resolved_at"]
        history = db.get_alert_history("BA-000001")
        assert [h["field"] for h in history] == ["status", "assignee", "status", "notes"]
        assert history[0]["old_value"] == "open"
        assert db.count_alerts(open_only=True) == 0

    def test_invalid_status(self, db):
        db.add_alert(_alert())
        with pytest.raises(ValueError):
            db.update_alert("BA-000001", status="bogus")
        assert db.update_alert("missing", status="resolved") is None
        assert set(ALERT_STATUSES) >= {"open", "resolved"}

    def test_no_change_returns_current(self, db):
        db.add_alert(_alert())
        same = db.update_alert("BA-000001", status="open")
        assert same["status"] == "open"
        assert db.get_alert_history("BA-000001") == []

    def test_alert_counts(self, db):
        db.add_alert(_alert("A", severity="critical"))
        db.add_alert(_alert("B", severity="high"))
        db.update_alert("B", status="false_positive")
        counts = db.alert_counts()
        assert counts["total"] == 2
        assert counts["open"] == 1
        assert counts["by_severity"] == {"critical": 1, "high": 1}
        assert counts["by_status"]["false_positive"] == 1


class TestScansEventsState:
    def test_scan_history(self, db):
        db.add_scan("NBK.com", "domain", {"risk": 1}, risk_score=10, risk_level="low", actor="ali")
        db.add_scan("evil.xyz", "domain", {"risk": 9}, risk_score=90, risk_level="critical")
        rows = db.get_scan_history(limit=10)
        assert len(rows) == 2
        assert rows[0]["domain"] == "evil.xyz"
        assert rows[0]["result"] == {"risk": 9}
        assert db.get_scan_history(domain="nbk")[0]["actor"] == "ali"
        assert db.count_scans() == 2

    def test_certstream_events(self, db):
        db.add_certstream_event(
            {
                "domain": "NBK-secure.xyz",
                "all_domains": ["nbk-secure.xyz", "www.nbk-secure.xyz"],
                "issuer": {"O": "Let's Encrypt"},
                "fingerprint": "AB:CD",
                "risk_score": 55,
                "matched_keywords": ["nbk"],
                "source": "test-log",
                "timestamp": "2026-01-01T00:00:00+00:00",
            }
        )
        events = db.get_recent_certstream_events()
        assert events[0]["domain"] == "nbk-secure.xyz"
        assert events[0]["all_domains"] == ["nbk-secure.xyz", "www.nbk-secure.xyz"]
        assert db.count_certstream_events() == 1

    def test_state(self, db):
        db.set_state("monitor", {"total": 5})
        db.set_state("monitor", {"total": 6})
        assert db.get_state("monitor") == {"total": 6}
        assert db.get_state("missing", "dflt") == "dflt"
        entry = db.get_state_entry("monitor")
        assert entry["value"] == {"total": 6} and entry["updated_at"]
        assert db.get_all_state() == {"monitor": {"total": 6}}


class TestAllowlist:
    def test_crud_and_parent_matching(self, db):
        assert db.add_allowlist("*.Example.com", reason="ours", added_by="ali") is True
        assert db.add_allowlist("example.com") is False
        assert db.is_allowlisted("example.com")
        assert db.is_allowlisted("login.example.com")
        assert not db.is_allowlisted("example.com.evil.com")
        assert db.allowlist_domains() == ["example.com"]
        assert db.get_allowlist()[0]["reason"] == "ours"
        assert db.remove_allowlist("example.com") is True
        assert db.remove_allowlist("example.com") is False
        assert not db.is_allowlisted("example.com")

    def test_empty_rejected(self, db):
        with pytest.raises(ValueError):
            db.add_allowlist("   ")


class TestSightings:
    def test_upsert_and_status(self, db):
        is_new, row = db.upsert_sighting("nbkk.com", "nbk.com", "repetition", ["1.2.3.4"])
        assert is_new is True and row["status"] == "new" and row["ips"] == ["1.2.3.4"]
        is_new, row = db.upsert_sighting(
            "nbkk.com", "nbk.com", "repetition", ["1.2.3.4", "5.6.7.8"]
        )
        assert is_new is False and row["seen_count"] == 2 and len(row["ips"]) == 2
        assert db.count_sightings() == 1
        assert db.count_sightings(status="new") == 1
        assert db.update_sighting_status("nbkk.com", "monitoring")["status"] == "monitoring"
        assert db.update_sighting_status("missing.com", "monitoring") is None
        with pytest.raises(ValueError):
            db.update_sighting_status("nbkk.com", "bogus")
        assert db.get_sightings(brand="nbk")[0]["domain"] == "nbkk.com"
        assert db.get_sighting("nbkk.com")["technique"] == "repetition"


class TestReporting:
    def test_stats_and_timeseries(self, db):
        db.add_domain("evil.xyz", 90, "critical", True, [])
        db.add_alert(_alert())
        db.add_scan("evil.xyz", "domain", {})
        db.upsert_sighting("nbkk.com", "nbk.com")
        stats = db.get_stats()
        assert stats["total_domains"] == 1
        assert stats["phishing_detected"] == 1
        assert stats["critical_threats"] == 1
        assert stats["open_alerts"] == 1
        assert stats["total_scans"] == 1
        assert stats["squat_sightings"] == 1
        series = db.daily_timeseries(days=3)
        assert len(series) == 3
        today = series[-1]
        assert today["domains"] == 1 and today["alerts"] == 1
        assert today["scans"] == 1 and today["sightings"] == 1
        assert today["critical_alerts"] == 1

    def test_indicator_records_merge_domains_and_alerts(self, db):
        db.add_domain("evil.xyz", 90, "critical", True, ["brand_impersonation"])
        db.add_alert(_alert("A", domain="evil.xyz"))
        db.add_alert(_alert("B", domain="other-nbk.com", severity="high"))
        records = list(db.iter_indicator_records(min_risk=40))
        domains = [r["domain"] for r in records]
        assert domains == ["evil.xyz", "other-nbk.com"]
        assert records[1]["brand"].startswith("National Bank")
        assert records[1]["risk_score"] == 70

    def test_purge(self, db):
        db.add_alert(_alert("A", created_at="2000-01-01T00:00:00+00:00"))
        db.update_alert("A", status="resolved")
        db.add_scan("old.com", "domain", {})
        removed = db.purge_older_than(30)
        assert removed["alerts"] == 1
        assert db.count_alerts() == 0


class TestSchema:
    def test_memory_database(self):
        db = Database(":memory:")
        db.add_domain("a.com", 1, "clean", False, [])
        assert db.count_domains() == 1
        db.close()

    def test_migration_from_v1_schema(self, tmp_path):
        path = tmp_path / "old.db"
        conn = sqlite3.connect(str(path))
        conn.executescript("""
            CREATE TABLE domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL, first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL, risk_score REAL DEFAULT 0, risk_level TEXT DEFAULT 'clean',
                is_phishing INTEGER DEFAULT 0, categories TEXT DEFAULT '[]', source TEXT DEFAULT '',
                matched_keywords TEXT DEFAULT '[]', UNIQUE(domain));
            CREATE TABLE alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT UNIQUE NOT NULL, brand_name TEXT,
                alert_type TEXT NOT NULL, severity TEXT NOT NULL, domain TEXT NOT NULL,
                description TEXT, evidence TEXT DEFAULT '{}', status TEXT DEFAULT 'open',
                created_at TEXT NOT NULL, updated_at TEXT, assignee TEXT);
            CREATE TABLE scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL, scan_type TEXT NOT NULL,
                result TEXT NOT NULL, scanned_at TEXT NOT NULL);
            CREATE TABLE certstream_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL, all_domains TEXT,
                issuer TEXT, fingerprint TEXT, risk_score REAL DEFAULT 0, matched_keywords TEXT,
                timestamp TEXT NOT NULL);
            INSERT INTO alerts (alert_id, alert_type, severity, domain, created_at)
                VALUES ('OLD-1', 'domain_squat', 'high', 'old.com', '2026-01-01T00:00:00+00:00');
            """)
        conn.commit()
        conn.close()

        db = Database(str(path))
        row = db.get_alert("OLD-1")
        assert row["notes"] == ""
        assert db.update_alert("OLD-1", status="resolved")["resolved_at"]
        with sqlite3.connect(str(path)) as check:
            assert check.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
