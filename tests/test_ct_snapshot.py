#!/usr/bin/env python3
"""Tests for the relay-feed snapshot script (scripts/ct_snapshot.py)."""

import json
from datetime import datetime, timedelta, timezone

from scripts.ct_snapshot import run_snapshot
from src.config.settings import Settings
from src.core.certstream_monitor import CertStreamMonitor
from tests.test_ct_tailer import FakeLog, certificate, leaf_input, make_fetcher


def test_snapshot_writes_latest_and_archive(tmp_path):
    log = FakeLog(
        [
            leaf_input(certificate("login.novapay-secure.xyz", ["login.novapay-secure.xyz"]), 0),
            leaf_input(certificate("example.org", ["example.org"]), 0),
            leaf_input(certificate("kestrel-verify.online", ["kestrel-verify.online"]), 1),
        ]
    )
    clock = {"t": datetime(2026, 9, 24, 12, 0, tzinfo=timezone.utc)}

    def now():
        clock["t"] += timedelta(seconds=1)
        return clock["t"]

    settings = Settings()
    monitor = CertStreamMonitor(settings.certstream, db=None)
    result = run_snapshot(
        seconds=5,
        out_dir=tmp_path / "feed",
        logs=["https://fake.log/"],
        settings=settings,
        monitor=monitor,
        now=now,
        sleep=lambda s: None,
        tailer_kwargs=dict(
            fetcher=make_fetcher({"https://fake.log/": log}),
            bytes_fetcher=make_fetcher({"https://fake.log/": log}),
            batch_size=10,
            poll_interval=0,
        ),
    )
    assert [m["domain"] for m in result["matches"]] == [
        "login.novapay-secure.xyz",
        "kestrel-verify.online",
    ]
    assert result["matches"][0]["score"] > 50 and "NovaPay" in result["matches"][0]["brands"]
    assert result["alert_candidates"] >= 1 and "alerts" not in result
    assert result["kind"] == "observations" and "not accusations" in result["notice"]
    assert result["logs"][0]["name"] == "https://fake.log/" and result["entries"] == 3
    latest = json.loads((tmp_path / "feed" / "latest.json").read_text())
    assert latest["generated_at"].startswith("2026-09-24") and len(latest["matches"]) == 2
    archive = tmp_path / "feed" / "archive"
    day = json.loads((archive / "2026-09-24.json").read_text())
    assert len(day["matches"]) == 2
    assert json.loads((archive / "index.json").read_text()) == ["2026-09-24"]

    # a second run the same day merges without duplicating
    monitor2 = CertStreamMonitor(settings.certstream, db=None)
    run_snapshot(
        seconds=5,
        out_dir=tmp_path / "feed",
        logs=["https://fake.log/"],
        settings=settings,
        monitor=monitor2,
        now=now,
        sleep=lambda s: None,
        tailer_kwargs=dict(
            fetcher=make_fetcher({"https://fake.log/": log}),
            bytes_fetcher=make_fetcher({"https://fake.log/": log}),
            batch_size=10,
            poll_interval=0,
        ),
    )
    day = json.loads((archive / "2026-09-24.json").read_text())
    assert len(day["matches"]) == 4  # new timestamps, same domains → kept as separate sightings


def test_snapshot_with_no_reachable_log(tmp_path):
    def fetch(url, timeout):
        raise RuntimeError("offline")

    settings = Settings()
    result = run_snapshot(
        seconds=1,
        out_dir=tmp_path / "feed",
        logs=["https://dead.log/"],
        settings=settings,
        sleep=lambda s: None,
        tailer_kwargs=dict(fetcher=fetch, bytes_fetcher=fetch, poll_interval=0),
    )
    assert result["matches"] == [] and result["logs"] == []
    assert (tmp_path / "feed" / "latest.json").exists()
