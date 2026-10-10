#!/usr/bin/env python3
"""
BrandSentra - CertStream Monitor

Real-time Certificate Transparency log monitoring. Every certificate seen
by CertStream is matched against the configured keywords; matching
hostnames are scored, de-duplicated per certificate (a certificate with
``example.com`` and ``*.example.com`` yields one event) and handed to the
registered callbacks.

Short keywords only match whole tokens or the TLD
so noise is avoided. Statistics are persisted to
the database heartbeat so the API can show live monitor status even though
the monitor runs in another process.
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from src.core.constants import tld_risk
from src.utils.domain import parse_domain, shannon_entropy

try:  # pragma: no cover - optional runtime dependency
    import certstream
except ImportError:  # pragma: no cover
    certstream = None

logger = logging.getLogger("brandsentra.certstream")

STATE_KEY = "certstream.monitor"
_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")


@dataclass
class CertificateEvent:
    """Represents a parsed certificate transparency event."""

    domain: str
    all_domains: List[str]
    issuer: str
    fingerprint: str
    not_before: str
    not_after: str
    serial_number: str
    source: str
    timestamp: str
    matched_keywords: List[str]
    risk_score: float = 0.0
    is_wildcard: bool = False
    issuer_name: str = ""
    seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "all_domains": list(self.all_domains),
            "issuer": self.issuer,
            "issuer_name": self.issuer_name,
            "fingerprint": self.fingerprint,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "serial_number": self.serial_number,
            "source": self.source,
            "timestamp": self.timestamp,
            "matched_keywords": list(self.matched_keywords),
            "risk_score": self.risk_score,
            "is_wildcard": self.is_wildcard,
        }


class CertStreamMonitor:
    """Monitors Certificate Transparency logs via CertStream for keyword matches."""

    def __init__(self, config: Any, db: Any = None, now: Callable[[], float] = time.time):
        self.config = config
        self.db = db
        self._now = now
        self.keywords: List[str] = [k.lower().strip() for k in (config.keywords or []) if k]
        self.url: str = config.url
        self.retry_delay: int = int(config.retry_delay)
        self.max_delay: int = int(config.max_delay)
        self.heartbeat_interval: int = int(getattr(config, "heartbeat_interval", 100) or 100)
        self.persist_events: bool = bool(getattr(config, "persist_events", True))
        self.ignore_wildcards: bool = bool(getattr(config, "ignore_wildcards", False))
        self.min_keyword_length: int = int(getattr(config, "min_keyword_length", 3) or 3)
        self.callbacks: List[Callable[[CertificateEvent], None]] = []
        self.stats: Dict[str, Any] = {
            "status": "stopped",
            "total_certs": 0,
            "matched_certs": 0,
            "matched_domains": 0,
            "callback_errors": 0,
            "reconnects": 0,
            "errors": 0,
            "start_time": None,
            "last_event": None,
            "last_heartbeat": None,
            "keywords": len(self.keywords),
        }
        self._running = False

    # ------------------------------------------------------------------ #

    def add_callback(self, callback: Callable[[CertificateEvent], None]) -> None:
        """Register a callback for matched certificate events."""
        self.callbacks.append(callback)

    def match_keywords(self, domain: str) -> List[str]:
        """Keywords that match ``domain`` (token match for short keywords)."""
        lowered = domain.lower()
        parsed = parse_domain(lowered)
        target = f"{parsed.subdomain}.{parsed.label}".strip(".") if parsed.label else lowered
        tokens = set(t for t in _TOKEN_SPLIT.split(target) if t)
        hits: List[str] = []
        for kw in self.keywords:
            if len(kw) < self.min_keyword_length:
                if kw in tokens:
                    hits.append(kw)
            elif len(kw) <= 4:
                # short keywords must sit at a token edge ("novapaybank", "e-kestrel", "lkpay"),
                # never buried inside a long random label ("...jskuw", "kkunalsanga")
                if kw in tokens or any(
                    (t.startswith(kw) or t.endswith(kw)) and len(t) <= len(kw) + 8 for t in tokens
                ):
                    hits.append(kw)
            elif kw in target:
                hits.append(kw)
        return hits

    def _calculate_risk_score(
        self, domain: str, cert_data: Dict[str, Any], hits: List[str]
    ) -> float:
        """Heuristic risk score for a matched certificate hostname."""
        parsed = parse_domain(domain)
        label = parsed.label or domain.split(".")[0]
        score = min(len(hits) * 15.0, 40.0)
        risk = tld_risk(parsed.suffix)
        if risk == "high":
            score += 20
        elif risk == "medium":
            score += 10
        if shannon_entropy(label) > 3.5 and len(label) >= 10:
            score += 15
        if len(label) > 20:
            score += 10
        if label.count("-") >= 3:
            score += 15
        if re.search(r"\d{4,}", label):
            score += 10
        issuer = json.dumps(cert_data.get("leaf_cert", {}).get("issuer", {})).lower()
        if "let's encrypt" in issuer or "zerossl" in issuer:
            score += 5
        if parsed.depth >= 4:
            score += 10
        if parsed.hosting_platform:
            score += 10
        return min(score, 100.0)

    @staticmethod
    def _issuer_name(issuer: Any) -> str:
        if isinstance(issuer, dict):
            return str(issuer.get("O") or issuer.get("CN") or issuer.get("aggregated") or "")
        return str(issuer or "")

    # ------------------------------------------------------------------ #

    def process_certificate(
        self, data: Dict[str, Any], source: Optional[str] = None
    ) -> List[CertificateEvent]:
        """
        Match one certificate (the ``data`` part of a CertStream message).

        Returns the events emitted (already dispatched to callbacks).
        """
        leaf = data.get("leaf_cert", {}) or {}
        all_domains = [d for d in (leaf.get("all_domains") or []) if isinstance(d, str)]
        issuer = leaf.get("issuer", {}) or {}
        src_name = source or (data.get("source") or {}).get("name", "unknown")
        events: List[CertificateEvent] = []
        seen_hosts: set = set()

        for raw in all_domains:
            is_wildcard = raw.startswith("*.")
            if is_wildcard and self.ignore_wildcards:
                continue
            hostname = parse_domain(raw).hostname
            if not hostname or hostname in seen_hosts:
                continue
            hits = self.match_keywords(hostname)
            if not hits:
                continue
            seen_hosts.add(hostname)
            event = CertificateEvent(
                domain=hostname,
                all_domains=all_domains,
                issuer=json.dumps(issuer, ensure_ascii=False),
                fingerprint=leaf.get("fingerprint", "") or "",
                not_before=str(leaf.get("not_before", "") or ""),
                not_after=str(leaf.get("not_after", "") or ""),
                serial_number=str(leaf.get("serial_number", "") or ""),
                source=str(src_name),
                timestamp=datetime.now(timezone.utc).isoformat(),
                matched_keywords=hits,
                risk_score=self._calculate_risk_score(hostname, data, hits),
                is_wildcard=is_wildcard,
                issuer_name=self._issuer_name(issuer),
            )
            events.append(event)

        if events:
            self.stats["matched_certs"] += 1
            self.stats["matched_domains"] += len(events)
            self.stats["last_event"] = events[-1].timestamp
        for event in events:
            logger.info(
                "[MATCH] %s | Risk: %.0f | Keywords: %s",
                event.domain,
                event.risk_score,
                event.matched_keywords,
            )
            if self.db is not None and self.persist_events:
                try:
                    self.db.add_certstream_event(event)
                except Exception as exc:  # storage must not stop the stream
                    logger.error("Failed to persist certstream event: %s", exc)
            for callback in self.callbacks:
                try:
                    callback(event)
                except Exception as exc:
                    self.stats["callback_errors"] += 1
                    logger.error("Callback error for %s: %s", event.domain, exc)
        return events

    def _handle_message(self, message: Dict[str, Any], context: Any = None) -> None:
        """CertStream message hook."""
        if message.get("message_type") != "certificate_update":
            return
        self.stats["total_certs"] += 1
        try:
            self.process_certificate(message.get("data", {}) or {})
        except Exception as exc:
            self.stats["errors"] += 1
            logger.debug("Parse error: %s", exc)
        if self.heartbeat_interval and self.stats["total_certs"] % self.heartbeat_interval == 0:
            self.heartbeat()

    def heartbeat(self, status: Optional[str] = None) -> Dict[str, Any]:
        """Persist the current statistics for the API to display."""
        if status:
            self.stats["status"] = status
        tailer = getattr(self, "_tailer", None)
        if tailer is not None and tailer.logs:
            self.stats["ct"] = tailer.summary()
        self.stats["last_heartbeat"] = datetime.now(timezone.utc).isoformat()
        if self.db is not None:
            try:
                self.db.set_state(STATE_KEY, self.get_stats())
            except Exception as exc:
                logger.error("Failed to persist monitor heartbeat: %s", exc)
        return self.get_stats()

    # ------------------------------------------------------------------ #

    def start(self) -> None:
        """Start monitoring: direct CT log tailing by default, CertStream WebSocket on request."""
        source = str(getattr(self.config, "source", "ctlogs") or "ctlogs").lower()
        if source == "ctlogs":
            self.start_ct_logs()
            return
        if certstream is None:
            raise ImportError("certstream package not installed: pip install certstream")

        self._running = True
        self.stats["start_time"] = datetime.now(timezone.utc).isoformat()
        self.heartbeat("running")
        retry_delay = self.retry_delay
        logger.info("Starting CertStream monitor | Keywords: %d | %s", len(self.keywords), self.url)

        while self._running:
            connected_at = self._now()
            try:
                certstream.listen_for_events(self._handle_message, url=self.url)
            except Exception as exc:
                self.stats["errors"] += 1
                logger.warning("CertStream error: %s. Retry in %ss", exc, retry_delay)
            if not self._running:
                break
            if self._now() - connected_at > 300:
                retry_delay = self.retry_delay  # a long healthy session resets the backoff
            self.stats["reconnects"] += 1
            self.heartbeat("reconnecting")
            time.sleep(retry_delay)
            retry_delay = min(self.max_delay, retry_delay * 2)
        self.heartbeat("stopped")

    def build_ct_tailer(self, **overrides: Any) -> Any:
        """Create the direct CT log tailer wired to this monitor (no third-party feed)."""
        from src.core.ct_tailer import CTLogTailer

        cfg = self.config
        logs = [{"name": u, "url": u} for u in (getattr(cfg, "ct_logs", None) or [])]
        kwargs: Dict[str, Any] = dict(
            logs=logs or None,
            batch_size=int(getattr(cfg, "ct_batch_size", 256) or 256),
            poll_interval=float(getattr(cfg, "ct_poll_interval", 2.0) or 2.0),
            max_lag=int(getattr(cfg, "ct_max_lag", 5000) or 5000),
            log_list_url=getattr(cfg, "ct_log_list_url", None),
        )
        kwargs.update(overrides)
        self._tailer = CTLogTailer(self._handle_message, **kwargs)
        return self._tailer

    def start_ct_logs(self, iterations: Optional[int] = None) -> None:
        """Tail CT logs directly until :meth:`stop` (or for ``iterations`` polling rounds)."""
        tailer = getattr(self, "_tailer", None) or self.build_ct_tailer()
        self._running = True
        self.stats["start_time"] = datetime.now(timezone.utc).isoformat()
        self.stats["source"] = "ctlogs"
        tailer.discover()
        self.stats["ct_logs"] = [log["name"] for log in tailer.logs]
        self.heartbeat("running")
        logger.info(
            "Starting direct CT log tailer | Keywords: %d | Logs: %d",
            len(self.keywords),
            len(tailer.logs),
        )
        if not tailer.logs:
            logger.error("No CT log answered; check outbound HTTPS access")
            self.heartbeat("no-logs")
            return
        try:
            tailer.run(iterations=iterations)
        finally:
            self.stats["ct"] = tailer.summary()
            self.heartbeat("stopped" if not self._running else "running")

    def stop(self) -> None:
        """Stop the monitor."""
        self._running = False
        tailer = getattr(self, "_tailer", None)
        if tailer is not None:
            tailer.stop()
        self.heartbeat("stopped")
        logger.info("CertStream monitor stopped")

    def get_stats(self) -> Dict[str, Any]:
        """Return monitoring statistics."""
        return dict(self.stats)


__all__ = ["CertStreamMonitor", "CertificateEvent", "STATE_KEY"]
