#!/usr/bin/env python3
"""Tests for src/core/squat_watcher.py."""

from types import SimpleNamespace

import pytest

from src.config.settings import DomainAnalysisConfig, SquatWatcherConfig
from src.core.domain_analyzer import DomainAnalyzer
from src.core.squat_watcher import STATE_KEY, Sighting, SquatWatcher
from src.models.database import Database

LIVE = {"nbkk.com": ["1.2.3.4"], "nbk-login.com": ["5.6.7.8", "5.6.7.9"], "nbk.xyz": ["9.9.9.9"]}


def fake_resolver(domain):
    if domain == "boom.com":
        raise RuntimeError("resolver exploded")
    return LIVE.get(domain, [])


@pytest.fixture
def analyzer():
    return DomainAnalyzer(DomainAnalysisConfig(protected_brands=["nbk.com", "kfh.com"]))


@pytest.fixture
def db(tmp_path):
    return Database(str(tmp_path / "w.db"))


def make_watcher(analyzer, db=None, **kw):
    cfg = SquatWatcherConfig(tlds=["com", "xyz"], max_workers=4, interval_seconds=1)
    return SquatWatcher(analyzer, cfg, db=db, resolver=fake_resolver, **kw)


class TestCandidates:
    def test_candidates_exclude_legitimate(self, analyzer):
        w = make_watcher(analyzer)
        domains = {c["domain"] for c in w.candidates("nbk.com")}
        assert "nbk.com" not in domains
        assert "nbk.xyz" in domains and "nbkk.com" in domains and "nbk-login.com" in domains
        assert "kfh.com" not in domains

    def test_default_brands_from_analyzer(self, analyzer):
        w = make_watcher(analyzer)
        assert w.brands == ["nbk.com", "kfh.com"]
        assert make_watcher(analyzer, brands=["kfh.com"]).brands == ["kfh.com"]

    def test_resolve_many_handles_errors(self, analyzer):
        w = make_watcher(analyzer)
        out = w.resolve_many(["nbkk.com", "nope.com", "boom.com", "nbkk.com"])
        assert out == {"nbkk.com": ["1.2.3.4"], "nope.com": [], "boom.com": []}
        assert w.resolve_many([]) == {}


class TestRuns:
    def test_check_brand_without_db(self, analyzer):
        seen = []
        w = make_watcher(analyzer, on_new=seen.append)
        sightings = w.check_brand("nbk.com")
        assert {s.domain for s in sightings} == set(LIVE)
        assert all(isinstance(s, Sighting) and s.is_new for s in sightings)
        assert {s.domain for s in seen} == set(LIVE)
        techniques = {s.domain: s.technique for s in sightings}
        assert techniques["nbk.xyz"] == "tld_swap"
        assert techniques["nbkk.com"] == "repetition"
        assert techniques["nbk-login.com"] == "combo_squat"

    def test_persistence_and_new_detection(self, analyzer, db):
        events = []
        w = make_watcher(analyzer, db=db, on_new=events.append)
        first = w.run_once(brands=["nbk.com"])
        assert first["live"] == 3 and first["new"] == 3 and first["brands"] == 1
        assert len(events) == 3
        assert db.count_sightings() == 3
        second = w.run_once(brands=["nbk.com"])
        assert second["live"] == 3 and second["new"] == 0
        assert len(events) == 3
        row = db.get_sighting("nbk-login.com")
        assert row["seen_count"] == 2 and row["ips"] == ["5.6.7.8", "5.6.7.9"]
        state = db.get_state(STATE_KEY)
        assert state["live"] == 3 and "sightings" not in state
        assert state["new_domains"] == []
        assert w.stats["runs"] == 2

    def test_callback_errors_do_not_break_run(self, analyzer):
        def bad(_):
            raise ValueError("boom")

        w = make_watcher(analyzer, on_new=bad)
        assert len(w.check_brand("nbk.com")) == 3

    def test_run_once_records_brand_errors(self, analyzer):
        w = make_watcher(analyzer)
        w.analyzer.generate_permutations_detailed = lambda *a, **k: (_ for _ in ()).throw(
            RuntimeError("gen failed")
        )
        summary = w.run_once(brands=["nbk.com"])
        assert summary["errors"] == {"nbk.com": "gen failed"}

    def test_run_forever_respects_max_runs_and_stop(self, analyzer):
        w = make_watcher(analyzer)
        sleeps = []
        assert w.run_forever(interval=5, max_runs=2, sleep=sleeps.append) == 2
        assert sleeps == [5]
        w2 = make_watcher(analyzer)

        def stop_after(_):
            w2.stop()

        assert w2.run_forever(interval=1, sleep=stop_after) == 1

    def test_sighting_to_dict(self):
        s = Sighting("a.com", "nbk.com", "omission", ["1.1.1.1"], True, "t0", "t1")
        assert s.to_dict()["technique"] == "omission"

    def test_config_defaults_with_namespace(self, analyzer):
        w = SquatWatcher(analyzer, SimpleNamespace(), resolver=fake_resolver)
        assert w.max_workers == 32 and w.tlds == [] and w.include_combos is True
