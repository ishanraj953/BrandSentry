#!/usr/bin/env python3
"""
BrandSentra - Engine Wiring

One place that assembles the detection engines, storage, notifications and
helpers so the API, the CLI and the monitor all behave identically.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional

from src.config.settings import Settings
from src.core.brand_monitor import BrandAlert, BrandMonitor
from src.core.domain_analyzer import DomainAnalyzer
from src.core.phishing_detector import PhishingDetector, PhishingVerdict
from src.core.squat_watcher import Sighting, SquatWatcher
from src.models.database import Database
from src.notifications.dispatcher import Alert, NotificationDispatcher
from src.utils import network
from src.utils.domain import normalize_domain

logger = logging.getLogger("brandsentra.engine")


def build_engines(
    settings: Settings,
    db: Optional[Database] = None,
    intel_engine: Any = None,
    resolver: Any = None,
    enrich_fn: Optional[Callable[..., Dict[str, Any]]] = None,
    notifier: Any = None,
) -> SimpleNamespace:
    """
    Construct all engines for ``settings``.

    Returns a namespace with ``config, db, detector, analyzer, brand_monitor,
    notifier`` plus helper callables ``intel()``, ``enrich()``,
    ``add_allowlist()``, ``remove_allowlist()`` and ``make_watcher()``.
    """
    database = db or Database(settings.database.db_path)
    brand_monitor = BrandMonitor.from_settings(settings)
    analyzer = DomainAnalyzer(
        settings.domain_analysis, legitimate_domains=brand_monitor.protected_domains()
    )
    stored_allowlist = database.allowlist_domains()
    for entry in stored_allowlist:
        analyzer.add_allowlist(entry)
        brand_monitor.add_allowlist(entry)
    detector = PhishingDetector(settings, allowlist=stored_allowlist, brands=brand_monitor.brands)
    dispatcher = (
        notifier if notifier is not None else NotificationDispatcher(settings.notifications)
    )

    state = SimpleNamespace(
        config=settings,
        db=database,
        detector=detector,
        analyzer=analyzer,
        brand_monitor=brand_monitor,
        notifier=dispatcher,
        resolver=resolver,
        started_at=time.time(),
        _intel=intel_engine,
    )

    def intel() -> Any:
        if state._intel is None:
            from src.core.threat_intel import ThreatIntelEngine

            state._intel = ThreatIntelEngine(settings.threat_intel)
        return state._intel

    def enrich(hostname: str, **kwargs: Any) -> Dict[str, Any]:
        fn = enrich_fn or network.enrich_domain
        return fn(hostname, **kwargs)

    def add_allowlist(domain: str, reason: str = "", added_by: str = "") -> bool:
        domain = normalize_domain(domain)
        created = database.add_allowlist(domain, reason=reason, added_by=added_by)
        analyzer.add_allowlist(domain)
        brand_monitor.add_allowlist(domain)
        detector.allowlist.add(domain)
        return created

    def remove_allowlist(domain: str) -> bool:
        domain = normalize_domain(domain)
        removed = database.remove_allowlist(domain)
        analyzer.allowlist = [d for d in analyzer.allowlist if d != domain]
        brand_monitor.remove_allowlist(domain)
        detector.allowlist.discard(domain)
        return removed

    def make_watcher(
        tlds: Optional[List[str]] = None,
        limit: Optional[int] = None,
        brands: Optional[List[str]] = None,
        notify: bool = True,
    ) -> SquatWatcher:
        cfg = SimpleNamespace(**vars(settings.squat_watcher))
        if tlds:
            cfg.tlds = list(tlds)
        if limit:
            cfg.max_candidates_per_brand = int(limit)

        def on_new(sighting: Sighting) -> None:
            if notify and dispatcher is not None:
                dispatcher.dispatch(
                    sighting_alert(sighting, settings.squat_watcher.notify_severity)
                )

        return SquatWatcher(
            analyzer, cfg, db=database, resolver=state.resolver, brands=brands, on_new=on_new
        )

    state.intel = intel
    state.enrich = enrich
    state.add_allowlist = add_allowlist
    state.remove_allowlist = remove_allowlist
    state.make_watcher = make_watcher
    return state


# --------------------------------------------------------------------------- #
# Scanning pipeline shared by API and CLI
# --------------------------------------------------------------------------- #


def run_scan(
    state: SimpleNamespace,
    domain: str,
    with_intel: bool = False,
    with_enrich: bool = False,
    persist: bool = True,
    source: str = "scan",
    actor: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Run the full pipeline on one hostname.

    Raises ``ValueError`` for empty or oversized input.
    """
    hostname = normalize_domain(domain)
    if not hostname:
        raise ValueError("Domain is required")
    if len(hostname) > 253:
        raise ValueError("Domain too long")

    verdict: PhishingVerdict = state.detector.analyze(hostname)
    squats = state.analyzer.analyze(hostname)
    brand_alerts: List[BrandAlert] = state.brand_monitor.check_domain(
        hostname, source=source, record=persist
    )
    allowlisted = state.db.is_allowlisted(hostname)

    result: Dict[str, Any] = {
        "domain": hostname,
        "input": domain,
        "phishing": verdict.to_dict(),
        "domain_squatting": [r.to_dict() for r in squats],
        "brand_alerts": [a.to_dict() for a in brand_alerts],
        "allowlisted": allowlisted,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
    }
    if allowlisted:
        result["phishing"].update(
            {
                "is_phishing": False,
                "risk_level": "clean",
                "risk_score": 0.0,
                "recommendation": "Domain is allowlisted.",
            }
        )

    if with_intel:
        try:
            result["intel"] = state.intel().lookup_sync(hostname).to_dict()
        except Exception as exc:  # network failures must not break the scan
            result["intel"] = {"error": str(exc)}
    if with_enrich:
        try:
            result["enrichment"] = state.enrich(
                hostname, dns=True, rdap=True, tls=False, whois=False
            )
        except Exception as exc:
            result["enrichment"] = {"error": str(exc)}

    if persist:
        try:
            phishing = result["phishing"]
            state.db.add_domain(
                hostname,
                phishing["risk_score"],
                phishing["risk_level"],
                phishing["is_phishing"],
                verdict.categories,
                source=source,
                keywords=[i["keyword"] for i in verdict.indicators if i.get("keyword")],
            )
            state.db.add_scan(
                hostname,
                "domain",
                {k: v for k, v in result.items() if k != "enrichment"},
                risk_score=phishing["risk_score"],
                risk_level=phishing["risk_level"],
                actor=actor,
            )
            for alert in brand_alerts:
                state.db.add_alert(alert, source=source, risk_score=verdict.risk_score)
        except Exception as exc:  # pragma: no cover - storage problems are logged, not fatal
            logger.error("Failed to persist scan for %s: %s", hostname, exc)
    return result


# --------------------------------------------------------------------------- #
# Alert adapters
# --------------------------------------------------------------------------- #


def brand_alert_notification(alert: BrandAlert, source: str = "certstream") -> Alert:
    """Convert a :class:`BrandAlert` into a notification payload."""
    return Alert(
        title=f"Brand Alert: {alert.brand_name}",
        message=alert.description,
        severity=alert.severity,
        domain=alert.domain or alert.evidence.get("suspicious_domain", ""),
        alert_type=alert.alert_type,
        details={**alert.evidence, "alert_id": alert.alert_id, "source": source},
    )


def phishing_notification(verdict: PhishingVerdict, source: str = "certstream") -> Alert:
    """Notification for a high-risk domain without a specific brand alert."""
    return Alert(
        title=f"Phishing domain detected: {verdict.domain}",
        message=verdict.explanation or verdict.recommendation,
        severity=(
            verdict.risk_level if verdict.risk_level in ("critical", "high", "medium") else "low"
        ),
        domain=verdict.domain,
        alert_type="phishing_domain",
        details={
            "risk_score": verdict.risk_score,
            "categories": verdict.categories,
            "matched_brands": verdict.matched_brands,
            "source": source,
        },
    )


def sighting_alert(sighting: Sighting, severity: str = "high") -> Alert:
    """Notification for a newly live typosquat."""
    return Alert(
        title=f"New typosquat live: {sighting.domain}",
        message=(
            f"{sighting.domain} ({sighting.technique} of {sighting.brand}) now resolves to "
            f"{', '.join(sighting.ips) or 'unknown'}"
        ),
        severity=severity,
        domain=sighting.domain,
        alert_type="typosquat_sighting",
        details=sighting.to_dict(),
    )


__all__ = [
    "brand_alert_notification",
    "build_engines",
    "phishing_notification",
    "run_scan",
    "sighting_alert",
]
