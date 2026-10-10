#!/usr/bin/env python3
"""Tests for the Flask API (src/api)."""

import json
from types import SimpleNamespace

import pytest

from src.api.app import create_app
from src.api.auth import TokenAuth, UserStore, extract_bearer
from src.api.ratelimit import RateLimiter, parse_rule
from src.config.settings import Settings
from src.core.threat_intel import ThreatIntelResult
from src.models.database import Database


class FakeIntel:
    def __init__(self):
        self.calls = []

    def lookup_sync(self, domain, force_refresh=False):
        self.calls.append((domain, force_refresh))
        return ThreatIntelResult(
            domain=domain,
            sources_checked=["urlhaus"],
            detections={"urlhaus": {"listed": True, "malicious": 3}},
            total_score=70.0,
            is_malicious=True,
            tags=["malicious", "urlhaus"],
        )

    def enabled_sources(self):
        return ["urlhaus", "openphish"]


def fake_enrich(hostname, **kwargs):
    return {"domain": hostname, "dns": {"A": ["1.2.3.4"]}, "options": kwargs, "errors": {}}


def fake_resolver(domain):
    return ["9.9.9.9"] if domain in ("nbkk.com", "nbk-login.com", "novapayy.com", "novapay-login.com") else []


def make_settings(**api_overrides):
    settings = Settings()
    settings.api.secret_key = "unit-test-secret"
    settings.api.admin_password = "admin-pw"
    settings.api.analyst_password = "analyst-pw"
    settings.api.rate_limit = "1000/hour"
    settings.squat_watcher.tlds = ["com"]
    for key, value in api_overrides.items():
        setattr(settings.api, key, value)
    return settings


@pytest.fixture
def env():
    settings = make_settings()
    db = Database(":memory:")
    app = create_app(
        settings,
        db=db,
        testing=True,
        intel_engine=FakeIntel(),
        resolver=fake_resolver,
        enrich_fn=fake_enrich,
    )
    client = app.test_client()
    return SimpleNamespace(app=app, client=client, db=db, settings=settings)


def login(client, username="admin", password="admin-pw"):
    resp = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.get_json()
    return {"Authorization": f"Bearer {resp.get_json()['token']}"}


# --------------------------------------------------------------------------- #
# Auth primitives
# --------------------------------------------------------------------------- #


class TestAuthPrimitives:
    def test_token_roundtrip_and_expiry(self):
        clock = {"t": 1000.0}
        auth = TokenAuth("secret", ttl_seconds=60, now=lambda: clock["t"])
        token, expires = auth.issue("ali", "analyst")
        assert expires == 1060
        principal = auth.verify(token)
        assert principal.username == "ali" and principal.role == "analyst"
        clock["t"] = 1061
        assert auth.verify(token) is None

    def test_token_tamper_and_garbage(self):
        auth = TokenAuth("secret")
        token, _ = auth.issue("ali", "admin")
        payload, _, sig = token.rpartition(".")
        assert auth.verify(payload + "." + "0" * 64) is None
        assert auth.verify("not-a-token") is None
        assert auth.verify("") is None
        assert TokenAuth("other").verify(token) is None
        with pytest.raises(ValueError):
            TokenAuth("")

    def test_user_store(self):
        users = UserStore("a", "b")
        assert users.authenticate("admin", "a")["role"] == "admin"
        assert users.authenticate("analyst", "b")["role"] == "analyst"
        assert users.authenticate("admin", "wrong") is None
        assert users.authenticate("nobody", "x") is None
        users.add("viewer1", "pw", role="viewer")
        assert users.authenticate("viewer1", "pw")["role"] == "viewer"
        assert "viewer1" in users

    def test_extract_bearer(self):
        assert extract_bearer("Bearer abc") == "abc"
        assert extract_bearer("bearer abc") == "abc"
        assert extract_bearer("Basic abc") is None
        assert extract_bearer(None) is None


class TestRateLimiter:
    def test_parse_rule(self):
        assert parse_rule("100/hour") == (100, 3600)
        assert parse_rule("5/min") == (5, 60)
        assert parse_rule("") is None and parse_rule(None) is None and parse_rule("0/hour") is None
        with pytest.raises(ValueError):
            parse_rule("lots")

    def test_sliding_window(self):
        clock = {"t": 0.0}
        limiter = RateLimiter("2/minute", now=lambda: clock["t"])
        assert limiter.check("a") == (True, 1, 0)
        assert limiter.check("a") == (True, 0, 0)
        allowed, remaining, retry = limiter.check("a")
        assert allowed is False and remaining == 0 and retry >= 1
        assert limiter.check("b")[0] is True
        clock["t"] = 61
        assert limiter.check("a")[0] is True
        limiter.reset("a")
        assert limiter.check("a") == (True, 1, 0)
        assert RateLimiter(None).check("x") == (True, -1, 0)


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #


class TestSystem:
    def test_health_and_headers(self, env):
        resp = env.client.get("/api/v1/health")
        data = resp.get_json()
        assert resp.status_code == 200 and data["status"] == "healthy"
        assert data["version"] and data["database"] == "ok"
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert resp.headers["Cache-Control"] == "no-store"

    def test_index_serves_demo(self, env):
        resp = env.client.get("/")
        assert resp.status_code == 200 and b"BrandSentra" in resp.data

    def test_openapi_and_docs(self, env):
        spec = env.client.get("/api/v1/openapi.json").get_json()
        assert spec["openapi"].startswith("3.0")
        assert "/api/v1/scan/domain" in spec["paths"]
        assert "/api/v1/alerts/{alert_id}" in spec["paths"]
        assert env.client.get("/api/v1/docs").status_code == 200

    def test_404_and_405_are_json(self, env):
        assert env.client.get("/api/v1/nope").get_json()["code"] == 404
        assert env.client.delete("/api/v1/health").get_json()["code"] == 405

    def test_metrics(self, env):
        env.client.post("/api/v1/scan/domain", json={"domain": "novapay-login.com"})
        resp = env.client.get("/metrics")
        assert resp.status_code == 200
        text = resp.get_data(as_text=True)
        assert "brandsentra_total_domains 1" in text
        assert "brandsentra_engine_detections" in text

    def test_metrics_can_be_disabled(self):
        app = create_app(make_settings(enable_metrics=False), db=Database(":memory:"), testing=True)
        assert app.test_client().get("/metrics").status_code == 404

    def test_rate_limit(self):
        app = create_app(
            make_settings(rate_limit="2/minute"), db=Database(":memory:"), testing=True
        )
        client = app.test_client()
        assert client.get("/api/v1/stats").status_code == 200
        assert client.get("/api/v1/stats").headers["X-RateLimit-Remaining"] == "0"
        resp = client.get("/api/v1/stats")
        assert resp.status_code == 429 and resp.headers["Retry-After"]
        assert client.get("/api/v1/health").status_code == 200  # exempt

    def test_stats_and_certstream_status(self, env):
        env.db.set_state("certstream.monitor", {"status": "running", "total_certs": 5})
        stats = env.client.get("/api/v1/stats").get_json()
        assert stats["database"]["total_domains"] == 0
        assert stats["monitor"]["status"] == "running"
        status = env.client.get("/api/v1/certstream/status").get_json()
        assert status["status"] == "running" and status["last_heartbeat"]
        assert "novapay" in status["keywords"] or "brandsentra" in status["keywords"]
        env.db.add_certstream_event(
            {"domain": "novapay-x.com", "timestamp": "2026-01-01T00:00:00+00:00"}
        )
        assert env.client.get("/api/v1/certstream/events").get_json()["total"] == 1


class TestAuthEndpoints:
    def test_login_success_and_failure(self, env):
        resp = env.client.post(
            "/api/v1/auth/login", json={"username": "admin", "password": "admin-pw"}
        )
        data = resp.get_json()
        assert (
            data["success"] and data["token_type"] == "Bearer" and data["user"]["role"] == "admin"
        )
        assert (
            env.client.post(
                "/api/v1/auth/login", json={"username": "admin", "password": "x"}
            ).status_code
            == 401
        )
        assert (
            env.client.post(
                "/api/v1/auth/login", data="nope", content_type="application/json"
            ).status_code
            == 400
        )

    def test_me_and_roles(self, env):
        headers = login(env.client, "analyst", "analyst-pw")
        me = env.client.get("/api/v1/auth/me", headers=headers).get_json()
        assert me["username"] == "analyst" and me["role"] == "analyst"
        assert env.client.get("/api/v1/auth/me").status_code == 401
        assert env.client.get("/api/v1/config", headers=headers).status_code == 403
        admin = login(env.client)
        cfg = env.client.get("/api/v1/config", headers=admin).get_json()
        assert cfg["config"]["api"]["secret_key"] == "***"
        assert isinstance(cfg["warnings"], list)

    def test_api_key(self):
        settings = make_settings(api_key="k3y")
        app = create_app(settings, db=Database(":memory:"), testing=True)
        client = app.test_client()
        assert (
            client.get("/api/v1/auth/me", headers={"X-API-Key": "k3y"}).get_json()["role"]
            == "admin"
        )
        assert client.get("/api/v1/auth/me", headers={"X-API-Key": "nope"}).status_code == 401

    def test_auth_required_mode(self):
        app = create_app(make_settings(auth_required=True), db=Database(":memory:"), testing=True)
        client = app.test_client()
        assert (
            client.post("/api/v1/scan/domain", json={"domain": "nbk-login.com"}).status_code == 401
        )
        headers = login(client)
        assert (
            client.post(
                "/api/v1/scan/domain", json={"domain": "nbk-login.com"}, headers=headers
            ).status_code
            == 200
        )
        assert client.get("/api/v1/health").status_code == 200


class TestScanning:
    def test_scan_domain_persists(self, env):
        resp = env.client.post(
            "/api/v1/scan/domain", json={"domain": "https://novapay-login.xyz/verify"}
        )
        data = resp.get_json()
        assert resp.status_code == 200
        assert data["domain"] == "novapay-login.xyz"
        assert data["phishing"]["is_phishing"] is True
        assert data["phishing"]["risk_level"] in ("high", "critical")
        assert data["domain_squatting"][0]["target"] == "novapay.com"
        assert data["brand_alerts"][0]["brand"].startswith("NovaPay")
        assert data["allowlisted"] is False
        assert env.db.count_alerts() == 1
        assert env.db.get_scan_history()[0]["domain"] == "novapay-login.xyz"
        assert env.db.get_domain("novapay-login.xyz")["is_phishing"] is True

    def test_scan_with_intel_and_enrich(self, env):
        data = env.client.post(
            "/api/v1/scan/domain",
            json={"domain": "nbk-login.xyz", "intel": True, "enrich": True, "persist": False},
        ).get_json()
        assert data["intel"]["is_malicious"] is True
        assert data["enrichment"]["dns"]["A"] == ["1.2.3.4"]
        assert env.db.count_scans() == 0

    def test_scan_validation(self, env):
        assert env.client.post("/api/v1/scan/domain", json={}).status_code == 400
        assert env.client.post("/api/v1/scan/domain", json={"domain": "   "}).status_code == 400
        assert env.client.post("/api/v1/scan/domain", json=[1]).status_code == 400

    def test_allowlisted_scan_is_clean(self, env):
        headers = login(env.client)
        env.client.post(
            "/api/v1/allowlist", json={"domain": "nbk-login.xyz", "reason": "ours"}, headers=headers
        )
        data = env.client.post("/api/v1/scan/domain", json={"domain": "nbk-login.xyz"}).get_json()
        assert data["allowlisted"] is True and data["phishing"]["risk_level"] == "clean"
        assert data["brand_alerts"] == [] and data["domain_squatting"] == []

    def test_bulk(self, env):
        resp = env.client.post(
            "/api/v1/scan/bulk", json={"domains": ["nbk-login.xyz", "google.com", 42, " "]}
        )
        data = resp.get_json()
        assert data["total"] == 4
        assert data["results"][0]["is_phishing"] is True and data["results"][0]["brand_alerts"] == 1
        assert data["results"][1]["risk_level"] == "clean"
        assert data["results"][2]["error"] == "invalid domain"
        assert data["summary"]["phishing"] == 1
        assert env.client.post("/api/v1/scan/bulk", json={"domains": []}).status_code == 400
        too_many = ["a%d.com" % i for i in range(env.settings.api.max_bulk_domains + 1)]
        assert env.client.post("/api/v1/scan/bulk", json={"domains": too_many}).status_code == 400
        history = env.client.get("/api/v1/scans/history").get_json()
        assert history["total"] == 1 and history["scans"][0]["scan_type"] == "bulk"


class TestBrands:
    def test_brands_and_permutations(self, env):
        brands = env.client.get("/api/v1/brands").get_json()
        assert brands["total"] >= 25 and "alerts" in brands["brands"][0]
        simple = env.client.post(
            "/api/v1/brands/permutations", json={"brand": "nbk.com", "limit": 10}
        ).get_json()
        assert len(simple["permutations"]) == 10 and simple["total"] > 10
        detailed = env.client.post(
            "/api/v1/brands/permutations",
            json={"brand": "nbk.com", "tlds": ["com", "kw"], "limit": 50},
        ).get_json()
        assert detailed["permutations"][0]["technique"] == "tld_swap"
        assert detailed["techniques"]["tld_swap"] == 1
        assert env.client.post("/api/v1/brands/permutations", json={"brand": ""}).status_code == 400
        assert (
            env.client.post(
                "/api/v1/brands/permutations", json={"brand": "x.com", "tlds": "com"}
            ).status_code
            == 400
        )


class TestAlerts:
    def _seed(self, env):
        env.client.post("/api/v1/scan/domain", json={"domain": "nbk-login.xyz"})
        env.client.post("/api/v1/scan/domain", json={"domain": "kfh-verify.top"})
        return env.client.get("/api/v1/alerts").get_json()["alerts"]

    def test_list_get_patch(self, env):
        alerts = self._seed(env)
        assert len(alerts) == 2 and alerts[0]["brand"] and alerts[0]["type"]
        alert_id = alerts[0]["alert_id"]
        assert env.client.get("/api/v1/alerts?severity=critical").get_json()["total"] >= 1
        assert env.client.get("/api/v1/alerts?brand=Finance").get_json()["total"] == 1
        detail = env.client.get(f"/api/v1/alerts/{alert_id}").get_json()
        assert detail["history"] == []
        assert (
            env.client.patch(f"/api/v1/alerts/{alert_id}", json={"status": "resolved"}).status_code
            == 401
        )
        headers = login(env.client, "analyst", "analyst-pw")
        bad = env.client.patch(
            f"/api/v1/alerts/{alert_id}", json={"status": "bogus"}, headers=headers
        )
        assert bad.status_code == 400
        assert (
            env.client.patch(f"/api/v1/alerts/{alert_id}", json={}, headers=headers).status_code
            == 400
        )
        ok = env.client.patch(
            f"/api/v1/alerts/{alert_id}",
            json={"status": "investigating", "assignee": "ali"},
            headers=headers,
        ).get_json()
        assert ok["status"] == "investigating" and ok["assignee"] == "ali"
        assert ok["history"][0]["actor"] == "analyst"
        assert (
            env.client.patch(
                "/api/v1/alerts/missing", json={"status": "resolved"}, headers=headers
            ).status_code
            == 404
        )
        assert env.client.get("/api/v1/alerts/missing").status_code == 404

    def test_false_positive_allowlists(self, env):
        alerts = self._seed(env)
        headers = login(env.client)
        target = next(a for a in alerts if a["domain"] == "kfh-verify.top")
        env.client.patch(
            f"/api/v1/alerts/{target['alert_id']}",
            json={"status": "false_positive", "allowlist": True},
            headers=headers,
        )
        assert env.db.is_allowlisted("kfh-verify.top")
        rescan = env.client.post(
            "/api/v1/scan/domain", json={"domain": "kfh-verify.top"}
        ).get_json()
        assert rescan["allowlisted"] is True and rescan["brand_alerts"] == []

    def test_exports(self, env):
        self._seed(env)
        csv_resp = env.client.get("/api/v1/alerts/export?format=csv")
        assert csv_resp.mimetype == "text/csv"
        assert csv_resp.get_data(as_text=True).splitlines()[0].startswith("alert_id,")
        js = env.client.get("/api/v1/alerts/export").get_json()
        assert js["total"] == 2
        stix = env.client.get("/api/v1/alerts/export?format=stix&tlp=red").get_json()
        assert stix["type"] == "bundle"
        assert any(o["type"] == "indicator" for o in stix["objects"])
        assert env.client.get("/api/v1/alerts/export?format=xml").status_code == 400
        assert env.client.get("/api/v1/alerts/export?format=stix&tlp=pink").status_code == 400


class TestAllowlistIntelEnrich:
    def test_allowlist_crud(self, env):
        assert env.client.post("/api/v1/allowlist", json={"domain": "x.com"}).status_code == 401
        headers = login(env.client)
        assert (
            env.client.post("/api/v1/allowlist", json={"domain": "  "}, headers=headers).status_code
            == 400
        )
        assert (
            env.client.post(
                "/api/v1/allowlist", json={"domain": "Good.example"}, headers=headers
            ).status_code
            == 201
        )
        assert (
            env.client.post(
                "/api/v1/allowlist", json={"domain": "good.example"}, headers=headers
            ).status_code
            == 200
        )
        listed = env.client.get("/api/v1/allowlist").get_json()
        assert listed["total"] == 1 and listed["allowlist"][0]["added_by"] == "admin"
        assert env.client.delete("/api/v1/allowlist/good.example", headers=headers).get_json()[
            "removed"
        ]
        assert (
            env.client.delete("/api/v1/allowlist/good.example", headers=headers).status_code == 404
        )

    def test_intel(self, env):
        data = env.client.get("/api/v1/intel/https://EVIL.example/x?refresh=1").get_json()
        assert data["domain"] == "evil.example" and data["is_malicious"] is True
        assert data["enabled_sources"] == ["urlhaus", "openphish"]
        assert env.app.extensions["kcw"]._intel.calls == [("evil.example", True)]

    def test_enrich(self, env):
        data = env.client.get("/api/v1/enrich/nbk-login.com?tls=1&rdap=0").get_json()
        assert data["dns"]["A"] == ["1.2.3.4"]
        assert data["options"] == {"dns": True, "rdap": False, "tls": True, "whois": False}


class TestSquatsAndReports:
    def test_squat_check_and_sightings(self, env):
        assert env.client.post("/api/v1/squats/check", json={"brand": "novapay.com"}).status_code == 401
        headers = login(env.client)
        summary = env.client.post(
            "/api/v1/squats/check", json={"brand": "novapay.com", "limit": 300}, headers=headers
        ).get_json()
        assert summary["live"] == 2 and summary["new"] == 2
        sightings = env.client.get("/api/v1/squats/sightings?brand=novapay").get_json()
        assert sightings["total"] == 2 and sightings["watcher"]["live"] == 2
        updated = env.client.patch(
            "/api/v1/squats/sightings/novapayy.com", json={"status": "monitoring"}, headers=headers
        ).get_json()
        assert updated["status"] == "monitoring"
        assert (
            env.client.patch(
                "/api/v1/squats/sightings/novapayy.com", json={"status": "x"}, headers=headers
            ).status_code
            == 400
        )
        assert (
            env.client.patch(
                "/api/v1/squats/sightings/none.com", json={"status": "benign"}, headers=headers
            ).status_code
            == 404
        )
        assert (
            env.client.post("/api/v1/squats/check", json={"brand": ""}, headers=headers).status_code
            == 400
        )

    def test_reports_and_stix(self, env):
        env.client.post("/api/v1/scan/domain", json={"domain": "novapay-login.xyz"})
        summary = env.client.get("/api/v1/reports/summary?days=3").get_json()
        assert summary["period_days"] == 3 and summary["totals"]["total_domains"] == 1
        assert summary["engine"]["detections"] >= 1
        md = env.client.get("/api/v1/reports/summary?format=markdown")
        assert md.mimetype == "text/markdown" and b"# BrandSentra Report" in md.data
        bundle = env.client.get("/api/v1/export/stix?min_risk=40&tlp=green").get_json()
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        assert indicators and indicators[0]["pattern"] == "[domain-name:value = 'novapay-login.xyz']"
        assert env.client.get("/api/v1/export/stix?min_risk=abc").status_code == 400
        assert env.client.get("/api/v1/export/stix?tlp=pink").status_code == 400


def test_lazy_module_app(monkeypatch, tmp_path):
    import src.api.app as module

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("KCW_DB_PATH", str(tmp_path / "lazy.db"))
    module._app_instance = None
    app = module.app
    assert app is module.get_app()
    assert app.test_client().get("/api/v1/health").status_code == 200
    module._app_instance = None
    with pytest.raises(AttributeError):
        module.nothing_here
    assert json.loads(json.dumps({"ok": True}))["ok"]


def test_proxy_endpoint(env, monkeypatch):
    # Missing url param
    res = env.client.get("/api/v1/proxy")
    assert res.status_code == 400

    # Invalid url
    res = env.client.get("/api/v1/proxy?url=ftp://bad.com")
    assert res.status_code == 400

    # Local address SSRF prevention
    res = env.client.get("/api/v1/proxy?url=http://127.0.0.1:8000/secret")
    assert res.status_code == 403

    # OPTIONS preflight
    res = env.client.open("/api/v1/proxy", method="OPTIONS")
    assert res.status_code == 204
    assert res.headers.get("Access-Control-Allow-Origin") == "*"

    # Successful GET with mocked requests.get
    class FakeResponse:
        status_code = 200
        content = b'{"tree_size": 12345}'
        headers = {"Content-Type": "application/json"}

    import requests
    monkeypatch.setattr(requests, "get", lambda *args, **kwargs: FakeResponse())

    res = env.client.get("/api/v1/proxy?url=https://example-ct.org/ct/v1/get-sth")
    assert res.status_code == 200
    assert res.headers.get("Access-Control-Allow-Origin") == "*"
    assert b"12345" in res.data

