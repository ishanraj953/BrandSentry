#!/usr/bin/env python3
"""Tests for src/core/reports.py."""

import csv
import io

import pytest

from src.core.reports import (
    alerts_to_csv,
    build_summary,
    indicators_to_csv,
    render_markdown,
    render_prometheus,
    rows_to_csv,
)
from src.models.database import Database


@pytest.fixture
def db(tmp_path):
    db = Database(str(tmp_path / "r.db"))
    db.add_domain("evil.xyz", 90, "critical", True, ["brand_impersonation"], "certstream")
    db.add_domain("meh.com", 10, "clean", False, [])
    db.add_alert(
        {
            "alert_id": "BA-1",
            "brand_name": "NBK",
            "alert_type": "combo_squat",
            "severity": "critical",
            "domain": "evil.xyz",
            "description": "bad",
            "evidence": {"x": 1},
        }
    )
    db.add_scan("evil.xyz", "domain", {"risk_score": 90}, 90, "critical")
    db.upsert_sighting("nbkk.com", "nbk.com", "repetition", ["1.2.3.4"])
    db.set_state("certstream.monitor", {"status": "running", "total_certs": 10, "matched_certs": 2})
    db.set_state("squat_watcher.last_run", {"finished_at": "t", "brands": 1, "live": 1, "new": 1})
    return db


def test_build_summary_shape(db):
    s = build_summary(db, days=3, extra={"engine": {"x": 1}})
    assert s["period_days"] == 3
    assert s["totals"]["total_domains"] == 2
    assert s["alerts"]["total"] == 1
    assert len(s["timeseries"]) == 3
    assert s["top_domains"][0]["domain"] == "evil.xyz"
    assert s["recent_alerts"][0]["alert_id"] == "BA-1"
    assert s["new_sightings"][0]["domain"] == "nbkk.com"
    assert s["monitor"]["status"] == "running"
    assert s["watcher"]["new"] == 1
    assert s["engine"] == {"x": 1}


def test_render_markdown(db):
    md = render_markdown(build_summary(db, days=2))
    assert md.startswith("# BrandSentra Report (2 days)")
    for fragment in (
        "## Totals",
        "| Total Domains | 2 |",
        "## Alerts (last 2 days)",
        "By severity: critical: 1",
        "## Daily activity",
        "`evil.xyz`",
        "## Open alerts",
        "## New typosquat sightings",
        "1.2.3.4",
        "## CertStream monitor",
        "## Squat watcher",
    ):
        assert fragment in md, fragment


def test_render_markdown_empty_sections():
    md = render_markdown({"period_days": 7, "totals": {}, "alerts": {}})
    assert "## Totals" in md and "## Open alerts" not in md


def test_csv_helpers(db):
    text = alerts_to_csv(db.get_alerts())
    rows = list(csv.DictReader(io.StringIO(text)))
    assert rows[0]["alert_id"] == "BA-1" and rows[0]["severity"] == "critical"
    ind = indicators_to_csv(db.iter_indicator_records(min_risk=40))
    rows = list(csv.DictReader(io.StringIO(ind)))
    assert rows[0]["domain"] == "evil.xyz"
    assert rows[0]["categories"] == "brand_impersonation"
    generic = rows_to_csv([{"a": {"k": "v"}, "b": None, "c": [1, 2]}], ["a", "b", "c"])
    assert generic.splitlines()[1] == "k=v,,1|2"


def test_render_prometheus(db):
    text = render_prometheus(
        db.get_stats(),
        db.alert_counts(),
        db.get_state("certstream.monitor"),
        extra={"engine_detections": 5},
        uptime_seconds=12.5,
    )
    assert "# HELP brandsentra_total_domains" in text
    assert "brandsentra_total_domains 2" in text
    assert 'brandsentra_alerts_by_severity{severity="critical"} 1' in text
    assert "brandsentra_info{version=" in text
    assert "brandsentra_uptime_seconds 12.5" in text
    assert "brandsentra_certstream_total_certs 10" in text
    assert "brandsentra_certstream_running 1" in text
    assert "brandsentra_engine_detections 5" in text
    assert text.count("# TYPE brandsentra_alerts_by_severity gauge") == 1
    assert text.endswith("\n")


def test_prometheus_ignores_non_numeric():
    text = render_prometheus({"last_domain_seen": "2026-01-01", "total": 3})
    assert "last_domain_seen" not in text and "brandsentra_total 3" in text
