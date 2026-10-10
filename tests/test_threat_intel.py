#!/usr/bin/env python3
"""
BrandSentra - Threat intelligence engine tests.

Everything runs offline: HTTP is answered by ``StaticFetcher`` and time comes
from a fake clock, so the suite is deterministic and needs no network.
"""

import asyncio
import json
import sys
from types import SimpleNamespace
from typing import Any, Dict

import pytest

from src import __version__
from src.core.threat_intel import (
    OPENPHISH_FEED_URL,
    AiohttpFetcher,
    FetchResponse,
    StaticFetcher,
    ThreatIntelEngine,
    ThreatIntelResult,
    json_response,
)

# --------------------------------------------------------------------------- #
# Fixtures and canned upstream answers
# --------------------------------------------------------------------------- #


class FakeClock:
    """Injectable ``now()`` returning a controllable epoch time."""

    def __init__(self, start: float = 1_700_000_000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def make_config(**overrides: Any) -> SimpleNamespace:
    base: Dict[str, Any] = {
        "virustotal_api_key": "vt-key",
        "urlscan_api_key": "us-key",
        "phishtank_api_key": "pt-key",
        "google_safebrowsing_key": "gsb-key",
        "openphish_enabled": True,
        "urlhaus_enabled": True,
        "cache_ttl_seconds": 3600,
        "feed_refresh_seconds": 3600,
        "request_timeout": 5,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


VT_HIT = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 3,
                "suspicious": 1,
                "harmless": 60,
                "undetected": 10,
            },
            "reputation": -12,
            "categories": {
                "Forcepoint ThreatSeeker": "phishing",
                "Sophos": "Phishing and Fraud",
                "BitDefender": "phishing",
            },
            "last_analysis_date": 1_700_000_000,
        }
    }
}
VT_CLEAN = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 0,
                "suspicious": 0,
                "harmless": 70,
                "undetected": 5,
            },
            "reputation": 4,
            "categories": {},
        }
    }
}


def vt_with_malicious(count: int) -> Dict[str, Any]:
    return {"data": {"attributes": {"last_analysis_stats": {"malicious": count}}}}


URLSCAN_HIT = {
    "results": [
        {
            "result": "https://urlscan.io/api/v1/result/aaa/",
            "verdicts": {"overall": {"malicious": True}},
        },
        {
            "result": "https://urlscan.io/api/v1/result/bbb/",
            "verdicts": {"overall": {"malicious": False}},
        },
        {"result": "https://urlscan.io/api/v1/result/ccc/"},
    ]
}
URLSCAN_CLEAN: Dict[str, Any] = {"results": []}

GSB_HIT = {
    "matches": [
        {"threatType": "SOCIAL_ENGINEERING"},
        {"threatType": "MALWARE"},
        {"threatType": "SOCIAL_ENGINEERING"},
    ]
}
GSB_CLEAN: Dict[str, Any] = {}

PHISHTANK_HIT = {
    "results": {
        "in_database": True,
        "verified": "y",
        "valid": "y",
        "phish_id": 8675309,
        "phish_detail_page": "http://www.phishtank.com/phish_detail.php?phish_id=8675309",
    }
}
PHISHTANK_CLEAN = {"results": {"in_database": False}}

URLHAUS_LISTED = {
    "query_status": "ok",
    "url_count": "3",
    "firstseen": "2024-01-02 03:04:05 UTC",
    "blacklists": {"spamhaus_dbl": "abused_legit_phish", "surbl": "not listed"},
}
URLHAUS_CLEAN = {"query_status": "no_results"}

OPENPHISH_FEED = "\n".join(
    [
        "https://evil.example/login",
        "https://cdn.evil.example/kit/index.php",
        "http://phish.nbk-secure.com.kw/verify",
        "",
        "# not a url",
        "https://other.test/x",
    ]
    + [f"https://many.example/path{i}" for i in range(7)]
)
OPENPHISH_ENTRY_COUNT = 4 + 7

VT_PREFIX = "GET https://www.virustotal.com/api/v3/domains/"
URLSCAN_PREFIX = "GET https://urlscan.io/api/v1/search/"
GSB_PREFIX = "POST https://safebrowsing.googleapis.com/v4/threatMatches:find"
PHISHTANK_PREFIX = "POST https://checkurl.phishtank.com/checkurl/"
OPENPHISH_PREFIX = "GET https://openphish.com/feed.txt"
URLHAUS_PREFIX = "POST https://urlhaus-api.abuse.ch/v1/host/"


def clean_routes(**overrides: Any) -> Dict[str, Any]:
    routes: Dict[str, Any] = {
        VT_PREFIX: VT_CLEAN,
        URLSCAN_PREFIX: URLSCAN_CLEAN,
        GSB_PREFIX: GSB_CLEAN,
        PHISHTANK_PREFIX: PHISHTANK_CLEAN,
        OPENPHISH_PREFIX: FetchResponse(200, OPENPHISH_FEED),
        URLHAUS_PREFIX: URLHAUS_CLEAN,
    }
    routes.update(overrides)
    return routes


def hit_routes() -> Dict[str, Any]:
    return clean_routes(
        **{
            VT_PREFIX: VT_HIT,
            URLSCAN_PREFIX: URLSCAN_HIT,
            GSB_PREFIX: GSB_HIT,
            PHISHTANK_PREFIX: PHISHTANK_HIT,
            URLHAUS_PREFIX: URLHAUS_LISTED,
        }
    )


def make_engine(tmp_path, routes=None, config=None, clock=None):
    fetcher = StaticFetcher(clean_routes() if routes is None else routes)
    engine = ThreatIntelEngine(
        config or make_config(),
        fetcher=fetcher,
        cache_dir=str(tmp_path / "intel_cache"),
        now=clock or FakeClock(),
    )
    return engine, fetcher


def lookup(engine: ThreatIntelEngine, domain: str, **kwargs: Any) -> ThreatIntelResult:
    return asyncio.run(engine.lookup(domain, **kwargs))


def calls_to(fetcher: StaticFetcher, prefix: str):
    method, url_prefix = prefix.split(" ", 1)
    return [c for c in fetcher.calls if c["method"] == method and c["url"].startswith(url_prefix)]


# --------------------------------------------------------------------------- #
# Configuration and input handling
# --------------------------------------------------------------------------- #


def test_enabled_sources_reflects_config(tmp_path):
    engine, _ = make_engine(tmp_path)
    assert engine.enabled_sources() == [
        "virustotal",
        "urlscan",
        "google_safebrowsing",
        "phishtank",
        "openphish",
        "urlhaus",
    ]

    minimal = ThreatIntelEngine(SimpleNamespace(), fetcher=StaticFetcher(), cache_dir=str(tmp_path))
    assert minimal.enabled_sources() == ["openphish", "urlhaus"]
    assert minimal.cache_ttl == 3600.0
    assert minimal.feed_refresh == 3600.0
    assert minimal.timeout == 10.0

    partial_cfg = make_config(
        urlscan_api_key="",
        phishtank_api_key="",
        google_safebrowsing_key="",
        openphish_enabled=False,
        urlhaus_enabled=False,
    )
    partial, _ = make_engine(tmp_path, config=partial_cfg)
    assert partial.enabled_sources() == ["virustotal"]


def test_empty_domain_returns_input_error_without_network(tmp_path):
    engine, fetcher = make_engine(tmp_path)
    for raw in ("", "   ", "https://", None):
        result = lookup(engine, raw)
        assert result.errors == {"input": "empty domain"}
        assert result.total_score == 0
        assert result.is_malicious is False
        assert result.sources_checked == []
    assert fetcher.calls == []


def test_url_input_is_normalised_to_hostname(tmp_path):
    engine, fetcher = make_engine(tmp_path)
    result = lookup(engine, "https://Evil.example/login?next=1")
    assert result.domain == "evil.example"
    vt_calls = calls_to(fetcher, VT_PREFIX)
    assert vt_calls[0]["url"] == "https://www.virustotal.com/api/v3/domains/evil.example"
    assert calls_to(fetcher, URLHAUS_PREFIX)[0]["data"] == {"host": "evil.example"}
    # Same normalised domain -> served from cache, so no new calls.
    before = len(fetcher.calls)
    again = lookup(engine, "EVIL.EXAMPLE:443")
    assert again.cached is True
    assert len(fetcher.calls) == before


# --------------------------------------------------------------------------- #
# Per-source parsing
# --------------------------------------------------------------------------- #


def test_virustotal_parsing_and_request(tmp_path):
    engine, fetcher = make_engine(tmp_path, clean_routes(**{VT_PREFIX: VT_HIT}))
    result = lookup(engine, "evil.example")
    assert result.detections["virustotal"] == {
        "malicious": 3,
        "suspicious": 1,
        "harmless": 60,
        "undetected": 10,
        "reputation": -12,
        "categories": ["phishing", "Phishing and Fraud"],
        "last_analysis_date": 1_700_000_000,
    }
    call = calls_to(fetcher, VT_PREFIX)[0]
    assert call["headers"] == {"x-apikey": "vt-key"}
    assert call["timeout"] == 5


def test_urlscan_parsing_and_request(tmp_path):
    engine, fetcher = make_engine(tmp_path, clean_routes(**{URLSCAN_PREFIX: URLSCAN_HIT}))
    result = lookup(engine, "evil.example")
    assert result.detections["urlscan"] == {
        "total_scans": 3,
        "malicious": 1,
        "last_scan": "https://urlscan.io/api/v1/result/aaa/",
    }
    call = calls_to(fetcher, URLSCAN_PREFIX)[0]
    assert call["url"] == "https://urlscan.io/api/v1/search/?q=domain:evil.example"
    assert call["headers"] == {"API-Key": "us-key"}

    clean_engine, _ = make_engine(tmp_path / "b")
    clean = lookup(clean_engine, "benign.example")
    assert clean.detections["urlscan"] == {"total_scans": 0, "malicious": 0, "last_scan": None}


def test_google_safebrowsing_parsing_and_request(tmp_path):
    engine, fetcher = make_engine(tmp_path, clean_routes(**{GSB_PREFIX: GSB_HIT}))
    result = lookup(engine, "evil.example")
    assert result.detections["google_safebrowsing"] == {
        "threats": ["MALWARE", "SOCIAL_ENGINEERING"],
        "malicious": 2,
    }
    call = calls_to(fetcher, GSB_PREFIX)[0]
    assert call["params"] == {"key": "gsb-key"}
    body = call["json"]
    assert body["client"] == {"clientId": "brandsentra", "clientVersion": __version__}
    info = body["threatInfo"]
    assert info["threatTypes"] == [
        "MALWARE",
        "SOCIAL_ENGINEERING",
        "UNWANTED_SOFTWARE",
        "POTENTIALLY_HARMFUL_APPLICATION",
    ]
    assert info["platformTypes"] == ["ANY_PLATFORM"]
    assert info["threatEntryTypes"] == ["URL"]
    assert info["threatEntries"] == [
        {"url": "http://evil.example/"},
        {"url": "https://evil.example/"},
    ]


def test_phishtank_parsing_and_request(tmp_path):
    engine, fetcher = make_engine(tmp_path, clean_routes(**{PHISHTANK_PREFIX: PHISHTANK_HIT}))
    result = lookup(engine, "evil.example")
    detection = result.detections["phishtank"]
    assert detection["in_database"] is True
    assert detection["verified"] is True
    assert detection["valid"] is True
    assert detection["phish_id"] == 8675309
    assert detection["malicious"] == 1
    call = calls_to(fetcher, PHISHTANK_PREFIX)[0]
    assert call["data"] == {"url": "http://evil.example/", "format": "json", "app_key": "pt-key"}
    assert call["headers"] == {"User-Agent": "phishtank/brandsentra"}

    clean_engine, _ = make_engine(tmp_path / "b")
    clean = lookup(clean_engine, "benign.example")
    assert clean.detections["phishtank"]["in_database"] is False
    assert clean.detections["phishtank"]["malicious"] == 0


def test_openphish_matching_by_hostname_and_registrable(tmp_path):
    engine, _ = make_engine(tmp_path)

    exact = lookup(engine, "evil.example").detections["openphish"]
    assert exact["in_feed"] is True
    assert exact["malicious"] == 1
    assert exact["feed_entries"] == OPENPHISH_ENTRY_COUNT
    assert exact["matched_urls"] == [
        "https://evil.example/login",
        "https://cdn.evil.example/kit/index.php",
    ]

    # A sibling subdomain shares the registrable domain with feed entries.
    sibling = lookup(engine, "www.evil.example").detections["openphish"]
    assert sibling["in_feed"] is True
    assert len(sibling["matched_urls"]) == 2

    # _ second-level registry: feed host phish.nbk-secure.com.kw -> nbk-secure.com.kw
    kw = lookup(engine, "nbk-secure.com.kw").detections["openphish"]
    assert kw["in_feed"] is True
    assert kw["matched_urls"] == ["http://phish.nbk-secure.com.kw/verify"]

    capped = lookup(engine, "many.example").detections["openphish"]
    assert capped["in_feed"] is True
    assert len(capped["matched_urls"]) == 5

    benign = lookup(engine, "benign.example").detections["openphish"]
    assert benign == {
        "in_feed": False,
        "matched_urls": [],
        "feed_entries": OPENPHISH_ENTRY_COUNT,
        "malicious": 0,
    }


def test_urlhaus_listed_and_no_results(tmp_path):
    engine, fetcher = make_engine(tmp_path, clean_routes(**{URLHAUS_PREFIX: URLHAUS_LISTED}))
    result = lookup(engine, "evil.example")
    assert result.detections["urlhaus"] == {
        "listed": True,
        "url_count": 3,
        "blacklists": {"spamhaus_dbl": "abused_legit_phish", "surbl": "not listed"},
        "firstseen": "2024-01-02 03:04:05 UTC",
        "malicious": 3,
    }
    assert result.first_seen == "2024-01-02 03:04:05 UTC"
    assert calls_to(fetcher, URLHAUS_PREFIX)[0]["data"] == {"host": "evil.example"}

    clean_engine, _ = make_engine(tmp_path / "b")
    clean = lookup(clean_engine, "benign.example")
    assert clean.detections["urlhaus"] == {"listed": False, "url_count": 0, "malicious": 0}
    assert clean.first_seen is None

    weird_engine, _ = make_engine(
        tmp_path / "c", clean_routes(**{URLHAUS_PREFIX: {"query_status": "invalid_host"}})
    )
    weird = lookup(weird_engine, "benign.example")
    assert "urlhaus" not in weird.detections
    assert "invalid_host" in weird.errors["urlhaus"]


# --------------------------------------------------------------------------- #
# Failure isolation
# --------------------------------------------------------------------------- #


def test_non_200_is_recorded_without_breaking_other_sources(tmp_path):
    routes = clean_routes(
        **{
            VT_PREFIX: json_response({"error": "quota"}, status=429),
            GSB_PREFIX: FetchResponse(500, "boom"),
            URLHAUS_PREFIX: URLHAUS_LISTED,
        }
    )
    engine, _ = make_engine(tmp_path, routes)
    result = lookup(engine, "evil.example")
    assert result.errors == {"virustotal": "http 429", "google_safebrowsing": "http 500"}
    assert "virustotal" not in result.detections
    assert set(result.sources_checked) == {"urlscan", "phishtank", "openphish", "urlhaus"}
    assert result.detections["urlhaus"]["listed"] is True
    assert result.is_malicious is True


def test_exception_and_bad_json_are_recorded_in_errors(tmp_path):
    routes = clean_routes(
        **{
            VT_PREFIX: TimeoutError("vt timed out"),
            URLSCAN_PREFIX: FetchResponse(200, "<html>not json</html>"),
            PHISHTANK_PREFIX: ConnectionError(),
        }
    )
    engine, _ = make_engine(tmp_path, routes)
    result = lookup(engine, "benign.example")
    assert result.errors["virustotal"] == "vt timed out"
    assert result.errors["phishtank"] == "ConnectionError"
    assert "urlscan" in result.errors
    assert set(result.sources_checked) == {"google_safebrowsing", "openphish", "urlhaus"}
    assert result.total_score == 0
    assert "clean" in result.tags


# --------------------------------------------------------------------------- #
# Scoring, verdict and tags
# --------------------------------------------------------------------------- #


def test_aggregate_score_uses_weights_and_thresholds(tmp_path):
    cfg = make_config(
        phishtank_api_key="",
        google_safebrowsing_key="",
        openphish_enabled=False,
        urlhaus_enabled=False,
    )
    routes = {VT_PREFIX: vt_with_malicious(2), URLSCAN_PREFIX: URLSCAN_HIT}
    engine, _ = make_engine(tmp_path, routes, config=cfg)
    result = lookup(engine, "evil.example")
    # virustotal: 35 * (2 / 5) = 14 ; urlscan: 15 * min(1 / 1, 1) = 15
    assert result.total_score == pytest.approx(29.0)
    assert result.is_malicious is False
    assert "malicious" not in result.tags
    assert "clean" not in result.tags


def test_authoritative_source_raises_floor_to_70(tmp_path):
    cfg = make_config(
        virustotal_api_key="",
        urlscan_api_key="",
        phishtank_api_key="",
        google_safebrowsing_key="",
        openphish_enabled=False,
    )
    listed_once = dict(URLHAUS_LISTED, url_count=1)
    engine, _ = make_engine(tmp_path, {URLHAUS_PREFIX: listed_once}, config=cfg)
    result = lookup(engine, "evil.example")
    # Raw contribution would be 20 * (1 / 5) = 4, but URLhaus listing is authoritative.
    assert result.total_score == 70.0
    assert result.is_malicious is True
    assert result.tags == ["malicious", "urlhaus"]


def test_is_malicious_threshold_at_50(tmp_path):
    cfg = make_config(
        phishtank_api_key="",
        google_safebrowsing_key="",
        openphish_enabled=False,
        urlhaus_enabled=False,
    )
    at_threshold, _ = make_engine(
        tmp_path / "a", {VT_PREFIX: vt_with_malicious(5), URLSCAN_PREFIX: URLSCAN_HIT}, config=cfg
    )
    result = lookup(at_threshold, "evil.example")
    assert result.total_score == 50.0
    assert result.is_malicious is True

    below, _ = make_engine(
        tmp_path / "b", {VT_PREFIX: vt_with_malicious(4), URLSCAN_PREFIX: URLSCAN_HIT}, config=cfg
    )
    result = lookup(below, "evil.example")
    assert result.total_score == pytest.approx(43.0)
    assert result.is_malicious is False


def test_tags_and_cap_when_every_source_fires(tmp_path):
    engine, _ = make_engine(tmp_path, hit_routes())
    result = lookup(engine, "evil.example")
    assert result.total_score == 100.0
    assert result.is_malicious is True
    assert result.tags == [
        "malicious",
        "known_phish",
        "safebrowsing:malware",
        "safebrowsing:social_engineering",
        "urlhaus",
        "vt:phishing",
        "vt:phishing and fraud",
    ]
    assert result.first_seen == "2024-01-02 03:04:05 UTC"
    assert result.errors == {}
    assert len(result.sources_checked) == 6


def test_clean_tag_when_all_sources_answer_clean(tmp_path):
    engine, _ = make_engine(tmp_path)
    result = lookup(engine, "benign.example")
    assert result.total_score == 0
    assert result.is_malicious is False
    assert result.tags == ["clean"]

    # No successful source -> no "clean" claim either.
    nothing, _ = make_engine(tmp_path / "b", {})
    empty = lookup(nothing, "benign.example")
    assert empty.sources_checked == []
    assert empty.tags == []
    assert set(empty.errors) == set(nothing.enabled_sources())


# --------------------------------------------------------------------------- #
# Caching
# --------------------------------------------------------------------------- #


def test_cache_hit_and_expiry_with_fake_clock(tmp_path):
    clock = FakeClock()
    engine, fetcher = make_engine(tmp_path, clock=clock)

    first = lookup(engine, "benign.example")
    assert first.cached is False
    calls_after_first = len(fetcher.calls)

    second = lookup(engine, "benign.example")
    assert second.cached is True
    assert second.domain == first.domain
    assert second.detections == first.detections
    assert len(fetcher.calls) == calls_after_first

    # Mutating a cached copy must not leak into later hits.
    second.tags.append("tampered")
    assert "tampered" not in lookup(engine, "benign.example").tags

    clock.advance(3600)
    third = lookup(engine, "benign.example")
    assert third.cached is False
    assert len(fetcher.calls) > calls_after_first


def test_force_refresh_and_clear_cache(tmp_path):
    engine, fetcher = make_engine(tmp_path)
    lookup(engine, "benign.example")
    n = len(fetcher.calls)

    refreshed = lookup(engine, "benign.example", force_refresh=True)
    assert refreshed.cached is False
    assert len(fetcher.calls) > n
    n = len(fetcher.calls)

    assert lookup(engine, "benign.example").cached is True
    engine.clear_cache()
    cleared = lookup(engine, "benign.example")
    assert cleared.cached is False
    assert len(fetcher.calls) > n
    # The feed survives clear_cache(): no second feed download happened.
    assert len(calls_to(fetcher, OPENPHISH_PREFIX)) == 1


# --------------------------------------------------------------------------- #
# Synchronous wrapper
# --------------------------------------------------------------------------- #


def test_lookup_sync_without_running_loop(tmp_path):
    engine, _ = make_engine(tmp_path, hit_routes())
    result = engine.lookup_sync("evil.example")
    assert isinstance(result, ThreatIntelResult)
    assert result.is_malicious is True
    assert engine.lookup_sync("evil.example").cached is True
    assert engine.lookup_sync("evil.example", force_refresh=True).cached is False


def test_lookup_sync_inside_running_event_loop(tmp_path):
    engine, _ = make_engine(tmp_path, hit_routes())

    async def body():
        assert asyncio.get_running_loop().is_running()
        first = engine.lookup_sync("evil.example")
        second = engine.lookup_sync("evil.example")
        return first, second

    first, second = asyncio.run(body())
    assert first.domain == "evil.example"
    assert first.is_malicious is True
    assert first.cached is False
    assert second.cached is True


# --------------------------------------------------------------------------- #
# OpenPhish feed persistence and status
# --------------------------------------------------------------------------- #


def test_openphish_disk_cache_is_reused_then_refreshed(tmp_path):
    clock = FakeClock()
    cfg = make_config(
        virustotal_api_key="",
        urlscan_api_key="",
        phishtank_api_key="",
        google_safebrowsing_key="",
        urlhaus_enabled=False,
    )
    cache_dir = tmp_path / "intel_cache"

    fetcher1 = StaticFetcher({OPENPHISH_PREFIX: FetchResponse(200, OPENPHISH_FEED)})
    engine1 = ThreatIntelEngine(cfg, fetcher=fetcher1, cache_dir=str(cache_dir), now=clock)
    assert lookup(engine1, "evil.example").detections["openphish"]["in_feed"] is True
    assert len(fetcher1.calls) == 1

    feed_file = cache_dir / "openphish_feed.txt"
    meta_file = cache_dir / "openphish_meta.json"
    assert feed_file.is_file()
    assert "https://evil.example/login" in feed_file.read_text().splitlines()
    meta = json.loads(meta_file.read_text())
    assert meta["fetched_at"] == clock.t
    assert meta["entries"] == OPENPHISH_ENTRY_COUNT

    # A new engine with a fresh disk copy must not touch the network at all.
    fetcher2 = StaticFetcher()
    engine2 = ThreatIntelEngine(cfg, fetcher=fetcher2, cache_dir=str(cache_dir), now=clock)
    result = lookup(engine2, "evil.example")
    assert fetcher2.calls == []
    assert result.errors == {}
    assert result.sources_checked == ["openphish"]
    assert result.detections["openphish"]["in_feed"] is True
    assert result.detections["openphish"]["feed_entries"] == OPENPHISH_ENTRY_COUNT

    # Once the disk copy is older than feed_refresh_seconds it is re-downloaded.
    clock.advance(3601)
    fetcher3 = StaticFetcher({OPENPHISH_PREFIX: FetchResponse(200, "https://fresh.example/x\n")})
    engine3 = ThreatIntelEngine(cfg, fetcher=fetcher3, cache_dir=str(cache_dir), now=clock)
    fresh = lookup(engine3, "fresh.example")
    assert [c["url"] for c in fetcher3.calls] == [OPENPHISH_FEED_URL]
    assert fresh.detections["openphish"] == {
        "in_feed": True,
        "matched_urls": ["https://fresh.example/x"],
        "feed_entries": 1,
        "malicious": 1,
    }
    assert json.loads(meta_file.read_text())["fetched_at"] == clock.t

    # A failed refresh falls back to the (stale) disk copy and reports the error.
    clock.advance(3601)
    fetcher4 = StaticFetcher({OPENPHISH_PREFIX: FetchResponse(503, "down")})
    engine4 = ThreatIntelEngine(cfg, fetcher=fetcher4, cache_dir=str(cache_dir), now=clock)
    stale = lookup(engine4, "fresh.example")
    assert stale.errors == {}
    assert stale.detections["openphish"]["in_feed"] is True
    assert engine4.feed_status()["openphish"]["error"] == "http 503"


def test_openphish_fetch_failure_without_cache_is_an_error(tmp_path):
    routes = clean_routes(**{OPENPHISH_PREFIX: FetchResponse(503, "unavailable")})
    engine, _ = make_engine(tmp_path, routes)
    result = lookup(engine, "benign.example")
    assert result.errors == {"openphish": "http 503"}
    assert "openphish" not in result.detections
    assert "openphish" not in result.sources_checked
    assert set(result.sources_checked) == {
        "virustotal",
        "urlscan",
        "google_safebrowsing",
        "phishtank",
        "urlhaus",
    }
    assert not (tmp_path / "intel_cache" / "openphish_feed.txt").exists()


def test_feed_status(tmp_path):
    clock = FakeClock()
    engine, _ = make_engine(tmp_path, clock=clock)
    assert engine.feed_status() == {
        "openphish": {"entries": 0, "fetched_at": None, "age_seconds": None, "error": None}
    }

    lookup(engine, "benign.example")
    clock.advance(120)
    status = engine.feed_status()["openphish"]
    assert status["entries"] == OPENPHISH_ENTRY_COUNT
    assert status["fetched_at"] == "2023-11-14T22:13:20+00:00"
    assert status["age_seconds"] == pytest.approx(120.0)
    assert status["error"] is None


# --------------------------------------------------------------------------- #
# Serialisation and HTTP layer
# --------------------------------------------------------------------------- #


def test_to_dict_is_json_serialisable(tmp_path):
    engine, _ = make_engine(tmp_path, hit_routes())
    result = lookup(engine, "evil.example")
    payload = result.to_dict()
    encoded = json.dumps(payload)
    decoded = json.loads(encoded)
    assert decoded["domain"] == "evil.example"
    assert decoded["is_malicious"] is True
    assert decoded["cached"] is False
    assert decoded["errors"] == {}
    assert set(decoded) >= {
        "domain",
        "sources_checked",
        "detections",
        "total_score",
        "is_malicious",
        "first_seen",
        "last_seen",
        "tags",
        "whois_info",
        "dns_records",
        "ssl_info",
        "timestamp",
        "errors",
        "cached",
    }
    assert decoded["timestamp"].endswith("+00:00")


def test_static_fetcher_longest_prefix_wins_and_records_calls():
    seen = []

    def dynamic(method, url, kwargs):
        seen.append((method, url, kwargs["params"]))
        return {"which": "dynamic"}

    fetcher = StaticFetcher(
        [
            ("GET https://api.test/", {"which": "short"}),
            ("GET", "https://api.test/v1/special", {"which": "long"}),
            ("*", "https://api.test/v1/any", dynamic),
        ]
    )

    async def run():
        long = await fetcher.request("GET", "https://api.test/v1/special?x=1")
        short = await fetcher.request("get", "https://api.test/v1/other", headers={"H": "1"})
        anym = await fetcher.request("POST", "https://api.test/v1/any", params={"k": "v"})
        return long.json(), short.json(), anym.json()

    long, short, anym = asyncio.run(run())
    assert long == {"which": "long"}
    assert short == {"which": "short"}
    assert anym == {"which": "dynamic"}
    assert seen == [("POST", "https://api.test/v1/any", {"k": "v"})]
    assert [c["method"] for c in fetcher.calls] == ["GET", "GET", "POST"]
    assert fetcher.calls[1]["headers"] == {"H": "1"}
    assert set(fetcher.calls[0]) == {
        "method",
        "url",
        "headers",
        "params",
        "data",
        "json",
        "timeout",
    }

    with pytest.raises(LookupError):
        asyncio.run(fetcher.request("DELETE", "https://api.test/v1/special"))
    assert len(fetcher.calls) == 4


def test_aiohttp_fetcher_reports_missing_dependency(monkeypatch):
    monkeypatch.setitem(sys.modules, "aiohttp", None)
    fetcher = AiohttpFetcher()
    with pytest.raises(RuntimeError, match="aiohttp"):
        asyncio.run(fetcher.request("GET", "https://example.invalid/"))
