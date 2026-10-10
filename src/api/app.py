#!/usr/bin/env python3
"""
BrandSentra - REST API Server

Flask application exposing the detection engines, persisted alerts with a
triage lifecycle, allowlisting, threat-intel and RDAP/DNS enrichment,
typosquat sightings, reports and exports (CSV / STIX 2.1), Prometheus
metrics and an OpenAPI description.
"""

from __future__ import annotations

import logging
import os
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from functools import wraps
from types import SimpleNamespace
from typing import Any, Callable, Dict, Optional, Tuple

import requests
from flask import Blueprint, Flask, Response, g, jsonify, request, send_from_directory
from flask_cors import CORS

from src import __version__
from src.api.auth import Principal, TokenAuth, UserStore, extract_bearer
from src.api.openapi import SWAGGER_HTML, build_spec
from src.api.ratelimit import RateLimiter
from src.config.settings import Settings, load_config, to_dict, validate
from src.core.engine import build_engines, run_scan
from src.core.reports import alerts_to_csv, build_summary, render_markdown, render_prometheus
from src.core.stix_export import TLP_MARKINGS, build_stix_bundle
from src.models.database import ALERT_STATUSES, SIGHTING_STATUSES, Database
from src.utils.domain import normalize_domain

logger = logging.getLogger("brandsentra.api")

DEMO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "demo"))
RATE_LIMIT_EXEMPT = ("/api/v1/health", "/metrics", "/api/v1/openapi.json", "/api/v1/docs", "/api/v1/proxy")


class APIError(Exception):
    """Raised by handlers to produce a JSON error response."""

    def __init__(self, message: str, status: int = 400, **extra: Any):
        super().__init__(message)
        self.message = message
        self.status = status
        self.extra = extra


def _bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on", "y")


def _int(value: Any, default: int, lo: int = 0, hi: int = 10**9) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, number))


def _json() -> Dict[str, Any]:
    data = request.get_json(silent=True)
    if data is None:
        if request.data:
            raise APIError("Request body must be valid JSON")
        return {}
    if not isinstance(data, dict):
        raise APIError("JSON body must be an object")
    return data


def _state() -> SimpleNamespace:
    from flask import current_app

    return current_app.extensions["kcw"]


# --------------------------------------------------------------------------- #
# Authentication helpers
# --------------------------------------------------------------------------- #


def _authenticate() -> Optional[Principal]:
    state = _state()
    token = extract_bearer(request.headers.get("Authorization"))
    if token:
        principal = state.auth.verify(token)
        if principal:
            return principal
    api_key = request.headers.get("X-API-Key") or request.args.get("api_key")
    configured = state.config.api.api_key
    if api_key and configured:
        import hmac

        if hmac.compare_digest(api_key, configured):
            return Principal("api-key", "admin", "api_key")
    return None


def require_auth(*roles: str, always: bool = True) -> Callable:
    """
    Require an authenticated principal.

    ``always=False`` only enforces when ``api.auth_required`` is on (used for
    read endpoints so the demo keeps working out of the box).
    """

    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            state = _state()
            principal = _authenticate()
            g.principal = principal
            if principal is None:
                if always or state.config.api.auth_required:
                    raise APIError("Authentication required", 401)
                return fn(*args, **kwargs)
            if roles and not principal.has_role(*roles):
                raise APIError("Insufficient role", 403)
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def _actor() -> Optional[str]:
    principal = getattr(g, "principal", None)
    return principal.username if principal else None


# --------------------------------------------------------------------------- #
# Blueprint
# --------------------------------------------------------------------------- #

api = Blueprint("api", __name__, url_prefix="/api/v1")


@api.route("/health", methods=["GET"])
def health() -> Any:
    state = _state()
    db_ok = True
    try:
        state.db.get_state("certstream.monitor")
    except Exception:  # pragma: no cover - only on a broken database file
        db_ok = False
    monitor = state.db.get_state("certstream.monitor") or {}
    return jsonify(
        {
            "status": "healthy" if db_ok else "degraded",
            "version": __version__,
            "database": "ok" if db_ok else "error",
            "uptime_seconds": round(time.time() - state.started_at, 1),
            "monitor": monitor.get("status", "unknown"),
            "time": datetime.now(timezone.utc).isoformat(),
        }
    ), (200 if db_ok else 503)


@api.route("/auth/login", methods=["POST"])
def login() -> Any:
    state = _state()
    data = _json()
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    user = state.users.authenticate(username, password)
    if not user:
        raise APIError("Invalid credentials", 401)
    token, expires = state.auth.issue(user["username"], user["role"])
    return jsonify(
        {
            "success": True,
            "user": user,
            "token": token,
            "token_type": "Bearer",
            "expires_at": datetime.fromtimestamp(expires, tz=timezone.utc).isoformat(),
            "expires_in": state.auth.ttl,
        }
    )


@api.route("/auth/me", methods=["GET"])
@require_auth()
def me() -> Any:
    return jsonify(g.principal.to_dict())


# -- scanning ---------------------------------------------------------------- #


def _scan(
    domain: str, with_intel: bool, with_enrich: bool, persist: bool, source: str = "scan"
) -> Dict:
    state = _state()
    try:
        result = run_scan(
            state,
            domain,
            with_intel=with_intel,
            with_enrich=with_enrich,
            persist=persist,
            source=source,
            actor=_actor(),
        )
    except ValueError as exc:
        raise APIError(str(exc))
    # Compatibility fields used by the original demo UI
    for item in result["brand_alerts"]:
        item["brand"] = item["brand_name"]
        item["type"] = item["alert_type"]
    return result


@api.route("/scan/domain", methods=["POST"])
@require_auth(always=False)
def scan_domain() -> Any:
    data = _json()
    domain = str(data.get("domain", "")).strip()
    result = _scan(
        domain,
        with_intel=_bool(data.get("intel")),
        with_enrich=_bool(data.get("enrich")),
        persist=_bool(data.get("persist"), True),
    )
    return jsonify(result)


@api.route("/scan/bulk", methods=["POST"])
@require_auth(always=False)
def scan_bulk() -> Any:
    state = _state()
    data = _json()
    domains = data.get("domains")
    limit = state.config.api.max_bulk_domains
    if not isinstance(domains, list) or not domains:
        raise APIError("Provide a non-empty 'domains' list")
    if len(domains) > limit:
        raise APIError(f"Provide 1-{limit} domains", limit=limit)
    persist = _bool(data.get("persist"), True)
    results = []
    for raw in domains:
        if not isinstance(raw, str) or not raw.strip():
            results.append({"domain": raw, "error": "invalid domain"})
            continue
        hostname = normalize_domain(raw)
        if not hostname:
            results.append({"domain": raw, "error": "invalid domain"})
            continue
        verdict = state.detector.analyze(hostname)
        brand_alerts = state.brand_monitor.check_domain(hostname, source="bulk", record=persist)
        allowlisted = state.db.is_allowlisted(hostname)
        results.append(
            {
                "domain": hostname,
                "input": raw,
                "risk_score": 0.0 if allowlisted else verdict.risk_score,
                "risk_level": "clean" if allowlisted else verdict.risk_level,
                "is_phishing": False if allowlisted else verdict.is_phishing,
                "categories": verdict.categories,
                "matched_brands": verdict.matched_brands,
                "brand_alerts": len(brand_alerts),
                "allowlisted": allowlisted,
            }
        )
        if persist and not allowlisted:
            state.db.add_domain(
                hostname,
                verdict.risk_score,
                verdict.risk_level,
                verdict.is_phishing,
                verdict.categories,
                source="bulk",
            )
            for alert in brand_alerts:
                state.db.add_alert(alert, source="bulk", risk_score=verdict.risk_score)
    if persist:
        state.db.add_scan(
            "bulk",
            "bulk",
            {"count": len(results), "phishing": sum(1 for r in results if r.get("is_phishing"))},
            actor=_actor(),
        )
    summary = {
        "total": len(results),
        "phishing": sum(1 for r in results if r.get("is_phishing")),
        "by_level": {},
    }
    for r in results:
        lvl = r.get("risk_level")
        if lvl:
            summary["by_level"][lvl] = summary["by_level"].get(lvl, 0) + 1
    return jsonify({"results": results, "total": len(results), "summary": summary})


@api.route("/scans/history", methods=["GET"])
@require_auth(always=False)
def scan_history() -> Any:
    state = _state()
    rows = state.db.get_scan_history(
        limit=_int(request.args.get("limit"), 50, 1, 500), domain=request.args.get("domain")
    )
    return jsonify({"scans": rows, "total": len(rows)})


# -- brands ------------------------------------------------------------------ #


@api.route("/brands", methods=["GET"])
def get_brands() -> Any:
    state = _state()
    counts = state.db.alert_counts().get("by_brand", {})
    brands = []
    for b in state.brand_monitor.brands:
        item = b.to_dict()
        item["alerts"] = counts.get(b.name, 0)
        brands.append(item)
    return jsonify({"brands": brands, "total": len(brands)})


@api.route("/brands/permutations", methods=["POST"])
@require_auth(always=False)
def get_permutations() -> Any:
    state = _state()
    data = _json()
    brand = normalize_domain(str(data.get("brand", "")))
    if not brand:
        raise APIError("Brand domain required")
    limit = _int(data.get("limit"), 500, 1, 5000)
    tlds = data.get("tlds")
    if tlds is not None and not isinstance(tlds, list):
        raise APIError("'tlds' must be a list")
    if _bool(data.get("detailed"), False) or tlds:
        perms = state.analyzer.generate_permutations_detailed(
            brand,
            tlds=tlds or None,
            include_combos=_bool(data.get("include_combos"), True),
            max_results=limit,
        )
        techniques: Dict[str, int] = {}
        for p in perms:
            techniques[p["technique"]] = techniques.get(p["technique"], 0) + 1
        return jsonify(
            {"brand": brand, "permutations": perms, "total": len(perms), "techniques": techniques}
        )
    perms = state.analyzer.generate_permutations(brand)
    return jsonify({"brand": brand, "permutations": perms[:limit], "total": len(perms)})


# -- alerts ------------------------------------------------------------------ #


def _alert_filters() -> Dict[str, Any]:
    return {
        "status": request.args.get("status"),
        "severity": request.args.get("severity"),
        "brand": request.args.get("brand"),
        "domain": request.args.get("domain"),
        "since": request.args.get("since"),
        "alert_type": request.args.get("type"),
        "open_only": _bool(request.args.get("open_only")),
    }


@api.route("/alerts", methods=["GET"])
@require_auth(always=False)
def get_alerts() -> Any:
    state = _state()
    filters = _alert_filters()
    limit = _int(request.args.get("limit"), 50, 1, 500)
    offset = _int(request.args.get("offset"), 0, 0)
    alerts = state.db.get_alerts(
        limit=limit, offset=offset, order=request.args.get("order", "desc"), **filters
    )
    total = state.db.count_alerts(**filters)
    for a in alerts:
        a["brand"] = a.get("brand_name")
        a["type"] = a.get("alert_type")
        a["detected_at"] = a.get("created_at")
    return jsonify({"alerts": alerts, "total": total, "limit": limit, "offset": offset})


@api.route("/alerts/export", methods=["GET"])
@require_auth(always=False)
def export_alerts() -> Any:
    state = _state()
    fmt = (request.args.get("format") or "json").lower()
    filters = _alert_filters()
    limit = _int(request.args.get("limit"), 1000, 1, 10000)
    alerts = state.db.get_alerts(limit=limit, **filters)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    if fmt == "csv":
        return Response(
            alerts_to_csv(alerts),
            mimetype="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename=brandsentra-alerts-{stamp}.csv"
            },
        )
    if fmt == "stix":
        records = [
            {
                "domain": a["domain"],
                "risk_score": a.get("risk_score")
                or {"critical": 90, "high": 70, "medium": 50}.get(a["severity"], 30),
                "risk_level": a["severity"],
                "categories": [a["alert_type"]],
                "first_seen": a["created_at"],
                "last_seen": a.get("updated_at") or a["created_at"],
                "source": a.get("source") or "brand_monitor",
                "brand": a.get("brand_name"),
                "alert_type": a["alert_type"],
                "description": a.get("description"),
            }
            for a in alerts
            if a.get("domain")
        ]
        tlp = (request.args.get("tlp") or "amber").lower()
        if tlp not in TLP_MARKINGS:
            raise APIError("Invalid tlp; expected white, green, amber or red")
        return jsonify(build_stix_bundle(records, tlp=tlp))
    if fmt != "json":
        raise APIError("Invalid format; expected csv, json or stix")
    return jsonify(
        {
            "alerts": alerts,
            "total": len(alerts),
            "exported_at": datetime.now(timezone.utc).isoformat(),
        }
    )


@api.route("/alerts/<alert_id>", methods=["GET"])
@require_auth(always=False)
def get_alert(alert_id: str) -> Any:
    state = _state()
    alert = state.db.get_alert(alert_id)
    if not alert:
        raise APIError("Alert not found", 404)
    alert["history"] = state.db.get_alert_history(alert_id)
    return jsonify(alert)


@api.route("/alerts/<alert_id>", methods=["PATCH"])
@require_auth("admin", "analyst")
def update_alert(alert_id: str) -> Any:
    state = _state()
    data = _json()
    status = data.get("status")
    if status is not None and status not in ALERT_STATUSES:
        raise APIError(f"Invalid status; expected one of {', '.join(ALERT_STATUSES)}")
    if not any(k in data for k in ("status", "assignee", "notes")):
        raise APIError("Provide at least one of status, assignee, notes")
    updated = state.db.update_alert(
        alert_id,
        status=status,
        assignee=data.get("assignee"),
        notes=data.get("notes"),
        actor=_actor(),
    )
    if updated is None:
        raise APIError("Alert not found", 404)
    if status:
        state.brand_monitor.update_alert_status(alert_id, status, data.get("assignee"))
    if status == "false_positive" and _bool(data.get("allowlist")):
        state.add_allowlist(
            updated["domain"], reason=f"false positive {alert_id}", added_by=_actor() or ""
        )
    updated["history"] = state.db.get_alert_history(alert_id)
    return jsonify(updated)


# -- allowlist --------------------------------------------------------------- #


@api.route("/allowlist", methods=["GET"])
@require_auth(always=False)
def get_allowlist() -> Any:
    entries = _state().db.get_allowlist()
    return jsonify({"allowlist": entries, "total": len(entries)})


@api.route("/allowlist", methods=["POST"])
@require_auth("admin", "analyst")
def add_allowlist() -> Any:
    state = _state()
    data = _json()
    domain = normalize_domain(str(data.get("domain", "")))
    if not domain:
        raise APIError("Domain is required")
    created = state.add_allowlist(
        domain, reason=str(data.get("reason", "")), added_by=_actor() or ""
    )
    return jsonify({"domain": domain, "created": created}), (201 if created else 200)


@api.route("/allowlist/<path:domain>", methods=["DELETE"])
@require_auth("admin", "analyst")
def remove_allowlist(domain: str) -> Any:
    state = _state()
    hostname = normalize_domain(domain)
    if not state.remove_allowlist(hostname):
        raise APIError("Allowlist entry not found", 404)
    return jsonify({"domain": hostname, "removed": True})


# -- intel & enrichment ------------------------------------------------------ #


@api.route("/intel/<path:domain>", methods=["GET"])
@require_auth(always=False)
def intel_lookup(domain: str) -> Any:
    state = _state()
    hostname = normalize_domain(domain)
    if not hostname:
        raise APIError("Domain is required")
    result = state.intel().lookup_sync(hostname, force_refresh=_bool(request.args.get("refresh")))
    payload = result.to_dict()
    payload["enabled_sources"] = state.intel().enabled_sources()
    return jsonify(payload)


@api.route("/enrich/<path:domain>", methods=["GET"])
@require_auth(always=False)
def enrich(domain: str) -> Any:
    state = _state()
    hostname = normalize_domain(domain)
    if not hostname:
        raise APIError("Domain is required")
    result = state.enrich(
        hostname,
        dns=_bool(request.args.get("dns"), True),
        rdap=_bool(request.args.get("rdap"), True),
        tls=_bool(request.args.get("tls"), False),
        whois=_bool(request.args.get("whois"), False),
    )
    return jsonify(result)


# -- typosquat sightings ----------------------------------------------------- #


@api.route("/squats/sightings", methods=["GET"])
@require_auth(always=False)
def get_sightings() -> Any:
    state = _state()
    rows = state.db.get_sightings(
        brand=request.args.get("brand"),
        status=request.args.get("status"),
        since=request.args.get("since"),
        limit=_int(request.args.get("limit"), 100, 1, 1000),
        offset=_int(request.args.get("offset"), 0, 0),
    )
    return jsonify(
        {
            "sightings": rows,
            "total": len(rows),
            "watcher": state.db.get_state("squat_watcher.last_run"),
        }
    )


@api.route("/squats/sightings/<path:domain>", methods=["PATCH"])
@require_auth("admin", "analyst")
def update_sighting(domain: str) -> Any:
    state = _state()
    data = _json()
    status = data.get("status")
    if status not in SIGHTING_STATUSES:
        raise APIError(f"Invalid status; expected one of {', '.join(SIGHTING_STATUSES)}")
    row = state.db.update_sighting_status(normalize_domain(domain), status)
    if row is None:
        raise APIError("Sighting not found", 404)
    return jsonify(row)


@api.route("/squats/check", methods=["POST"])
@require_auth("admin", "analyst")
def check_squats() -> Any:
    state = _state()
    data = _json()
    brand = normalize_domain(str(data.get("brand", "")))
    if not brand:
        raise APIError("Brand domain required")
    limit = _int(data.get("limit"), 200, 1, 2000)
    tlds = data.get("tlds")
    if tlds is not None and not isinstance(tlds, list):
        raise APIError("'tlds' must be a list")
    watcher = state.make_watcher(tlds=tlds, limit=limit, brands=[brand])
    summary = watcher.run_once(brands=[brand])
    return jsonify(summary)


# -- stats, reports, exports ------------------------------------------------- #


@api.route("/stats", methods=["GET"])
def get_stats() -> Any:
    state = _state()
    stats = state.db.get_stats()
    return jsonify(
        {
            "database": stats,
            "brands": state.brand_monitor.get_stats(),
            "detections": state.detector.detection_count,
            "alerts": state.db.alert_counts(),
            "monitor": state.db.get_state("certstream.monitor"),
            "watcher": state.db.get_state("squat_watcher.last_run"),
            "notifications": state.notifier.stats if state.notifier else None,
            "uptime_seconds": round(time.time() - state.started_at, 1),
            "version": __version__,
            "time": datetime.now(timezone.utc).isoformat(),
        }
    )


@api.route("/reports/summary", methods=["GET"])
@require_auth(always=False)
def report_summary() -> Any:
    state = _state()
    days = _int(request.args.get("days"), 7, 1, 365)
    summary = build_summary(
        state.db,
        days=days,
        extra={
            "engine": {
                "detections": state.detector.detection_count,
                "brands": state.brand_monitor.get_stats(),
            }
        },
    )
    if (request.args.get("format") or "json").lower() == "markdown":
        return Response(render_markdown(summary), mimetype="text/markdown")
    return jsonify(summary)


@api.route("/export/stix", methods=["GET"])
@require_auth(always=False)
def export_stix() -> Any:
    state = _state()
    try:
        min_risk = float(request.args.get("min_risk", 40))
    except ValueError:
        raise APIError("min_risk must be a number")
    tlp = (request.args.get("tlp") or "amber").lower()
    if tlp not in TLP_MARKINGS:
        raise APIError("Invalid tlp; expected white, green, amber or red")
    limit = _int(request.args.get("limit"), 1000, 1, 10000)
    records = state.db.iter_indicator_records(min_risk=min_risk, limit=limit)
    return jsonify(build_stix_bundle(records, tlp=tlp))


# -- monitor & system -------------------------------------------------------- #


@api.route("/certstream/status", methods=["GET"])
def certstream_status() -> Any:
    state = _state()
    entry = state.db.get_state_entry("certstream.monitor")
    monitor = (entry or {}).get("value") or {}
    return jsonify(
        {
            "status": monitor.get("status", "unknown"),
            "stats": monitor,
            "last_heartbeat": (entry or {}).get("updated_at"),
            "keywords": state.config.certstream.keywords,
            "url": state.config.certstream.url,
            "events_stored": state.db.count_certstream_events(),
        }
    )


@api.route("/certstream/events", methods=["GET"])
@require_auth(always=False)
def certstream_events() -> Any:
    rows = _state().db.get_recent_certstream_events(
        limit=_int(request.args.get("limit"), 50, 1, 500)
    )
    return jsonify({"events": rows, "total": len(rows)})


@api.route("/config", methods=["GET"])
@require_auth("admin")
def get_config() -> Any:
    state = _state()
    return jsonify({"config": to_dict(state.config), "warnings": validate(state.config)})


@api.route("/openapi.json", methods=["GET"])
def openapi() -> Any:
    return jsonify(build_spec(request.host_url.rstrip("/") or "/"))


@api.route("/docs", methods=["GET"])
def docs() -> Any:
    return Response(SWAGGER_HTML, mimetype="text/html")


_PROXY_CACHE: Dict[str, Tuple[float, bytes, str, int]] = {}
_PROXY_CACHE_LOCK = threading.Lock()


@api.route("/proxy", methods=["GET", "POST", "OPTIONS"])
def proxy_request() -> Any:
    """CORS proxy for external threat-intelligence, RDAP and Certificate Transparency logs."""
    if request.method == "OPTIONS":
        resp = Response("", status=204)
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "*"
        return resp

    target_url = request.args.get("url", "").strip()
    if not target_url:
        raise APIError("Target URL parameter 'url' is required", status=400)

    parsed = urllib.parse.urlparse(target_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise APIError("Invalid target URL; must be http or https", status=400)

    host = (parsed.hostname or "").lower()
    if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        raise APIError("Access to local address is forbidden", status=403)

    now = time.time()
    if request.method == "GET":
        with _PROXY_CACHE_LOCK:
            entry = _PROXY_CACHE.get(target_url)
            if entry and entry[0] > now:
                resp = Response(entry[1], status=entry[3], content_type=entry[2])
                resp.headers["X-Cache"] = "HIT"
                resp.headers["Access-Control-Allow-Origin"] = "*"
                return resp

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36 BrandSentra/2.5.0"
        ),
    }
    if request.headers.get("Accept"):
        headers["Accept"] = request.headers.get("Accept")
    if request.content_type:
        headers["Content-Type"] = request.content_type

    try:
        if request.method == "POST":
            data = request.get_data()
            r = requests.post(target_url, data=data, headers=headers, timeout=15)
        else:
            r = requests.get(target_url, headers=headers, timeout=15)

        content_type = r.headers.get("Content-Type", "application/octet-stream")

        if request.method == "GET" and r.status_code == 200:
            ttl = 10.0
            if "/tile/data/" in target_url:
                ttl = 3600.0  # static data tiles are immutable
            elif "/checkpoint" in target_url or "/get-sth" in target_url:
                ttl = 5.0
            elif "crt.sh" in target_url or "urlhaus" in target_url:
                ttl = 60.0
            with _PROXY_CACHE_LOCK:
                if len(_PROXY_CACHE) > 2000:
                    _PROXY_CACHE.clear()
                _PROXY_CACHE[target_url] = (now + ttl, r.content, content_type, r.status_code)

        resp = Response(r.content, status=r.status_code, content_type=content_type)
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp
    except requests.exceptions.Timeout:
        return jsonify({"error": "Gateway timeout"}), 504
    except Exception as exc:
        return jsonify({"error": str(exc)}), 502



# --------------------------------------------------------------------------- #
# Application factory
# --------------------------------------------------------------------------- #


def create_app(
    config: Optional[Settings] = None,
    db: Optional[Database] = None,
    testing: bool = False,
    intel_engine: Any = None,
    resolver: Any = None,
    enrich_fn: Optional[Callable[..., Dict[str, Any]]] = None,
    notifier: Any = None,
) -> Flask:
    """Build a configured Flask application."""
    settings = config or load_config()
    for warning in validate(settings):
        logger.warning("config: %s", warning)

    app = Flask(__name__, static_folder=DEMO_DIR, static_url_path="/")
    app.config["TESTING"] = testing
    app.json.sort_keys = False  # type: ignore[attr-defined]
    CORS(app, origins=settings.api.cors_origins)

    state = build_engines(
        settings,
        db=db,
        intel_engine=intel_engine,
        resolver=resolver,
        enrich_fn=enrich_fn,
        notifier=notifier,
    )
    state.auth = TokenAuth(settings.api.secret_key, settings.api.token_ttl_seconds)
    state.users = UserStore(settings.api.admin_password, settings.api.analyst_password)
    state.limiter = RateLimiter(settings.api.rate_limit)
    app.extensions["kcw"] = state
    database = state.db
    detector = state.detector
    brand_monitor = state.brand_monitor
    dispatcher = state.notifier

    app.register_blueprint(api)

    @app.route("/")
    def index() -> Any:
        return send_from_directory(app.static_folder, "index.html")

    if settings.api.enable_metrics:

        @app.route("/metrics")
        def metrics() -> Any:
            text = render_prometheus(
                database.get_stats(),
                database.alert_counts(),
                database.get_state("certstream.monitor"),
                extra={
                    "engine_detections": detector.detection_count,
                    "brand_monitor_checked": brand_monitor.stats["checked"],
                    "notifications_sent": (dispatcher.stats.get("sent", 0) if dispatcher else 0),
                },
                uptime_seconds=time.time() - state.started_at,
            )
            return Response(text, mimetype="text/plain; version=0.0.4; charset=utf-8")

    @app.before_request
    def _rate_limit() -> Any:
        if not state.limiter.enabled or request.path in RATE_LIMIT_EXEMPT:
            return None
        if not request.path.startswith("/api/"):
            return None
        key = request.remote_addr or "unknown"
        if settings.api.trust_proxy:
            forwarded = request.headers.get("X-Forwarded-For", "")
            if forwarded:
                key = forwarded.split(",")[0].strip()
        allowed, remaining, retry = state.limiter.check(key)
        g.rate_remaining = remaining
        if not allowed:
            response = jsonify({"error": "Rate limit exceeded", "code": 429, "retry_after": retry})
            response.status_code = 429
            response.headers["Retry-After"] = str(retry)
            return response
        return None

    @app.after_request
    def _headers(response: Response) -> Response:
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-BrandSentra-Version", __version__)
        if request.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
            remaining = getattr(g, "rate_remaining", None)
            if remaining is not None and remaining >= 0:
                response.headers["X-RateLimit-Remaining"] = str(remaining)
                response.headers["X-RateLimit-Limit"] = str(state.limiter.limit)
        return response

    @app.errorhandler(APIError)
    def _api_error(exc: APIError) -> Any:
        payload = {"error": exc.message, "code": exc.status}
        payload.update(exc.extra)
        return jsonify(payload), exc.status

    @app.errorhandler(404)
    def _not_found(_: Any) -> Any:
        if request.path.startswith("/api/"):
            return jsonify({"error": "Not found", "code": 404}), 404
        return jsonify({"error": "Not found", "code": 404, "hint": "API lives under /api/v1"}), 404

    @app.errorhandler(405)
    def _method_not_allowed(_: Any) -> Any:
        return jsonify({"error": "Method not allowed", "code": 405}), 405

    @app.errorhandler(Exception)
    def _unhandled(exc: Exception) -> Any:
        if testing:
            raise exc
        logger.exception("Unhandled API error: %s", exc)
        return jsonify({"error": "Internal server error", "code": 500}), 500

    return app


_app_instance: Optional[Flask] = None


def get_app() -> Flask:
    """Return the process-wide application, creating it on first use."""
    global _app_instance
    if _app_instance is None:
        _app_instance = create_app()
    return _app_instance


def __getattr__(name: str) -> Any:  # PEP 562 lazy module attribute
    if name == "app":
        return get_app()
    raise AttributeError(name)


if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    application = get_app()
    cfg = application.extensions["kcw"].config
    application.run(host=cfg.api.host, port=cfg.api.port, debug=cfg.api.debug)
