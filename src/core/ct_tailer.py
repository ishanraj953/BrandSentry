"""
BrandSentra - Direct Certificate Transparency log tailer

Reads public CT logs straight from the log servers (RFC 6962 ``get-sth`` and
``get-entries``) so the monitor does not depend on any third-party streaming
service. Log URLs are discovered from Google's public log list when reachable
and fall back to a built-in list of current shards.

Each entry is parsed with :mod:`src.utils.x509` and delivered to a
:class:`~src.core.certstream_monitor.CertStreamMonitor` as a CertStream-shaped
message, so keyword matching, scoring, persistence and notifications are shared
with the WebSocket path.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional

from src.utils.x509 import (
    DERError,
    parse_data_tile,
    parse_leaf_input,
    tile_path,
    to_certstream_message,
)

logger = logging.getLogger("brandsentra.ctlogs")

LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"

# Longest lifetime a newly issued certificate may have (the CA/Browser Forum cap during 2026).
# Shards are keyed by certificate expiry date, so a certificate issued today lands in a shard up
# to one lifetime ahead and the tailer must read every shard that starts within that window.
MAX_CERT_LIFETIME_DAYS = 200

# Fallback shards (checked 2026-09). Logs that do not answer are skipped automatically.
FALLBACK_LOGS: List[Dict[str, str]] = [
    {"name": "Google Argon 2026h2", "url": "https://ct.googleapis.com/logs/us1/argon2026h2/"},
    {"name": "Google Argon 2027h1", "url": "https://ct.googleapis.com/logs/us1/argon2027h1/"},
    {"name": "Google Xenon 2026h2", "url": "https://ct.googleapis.com/logs/eu1/xenon2026h2/"},
    {"name": "Google Xenon 2027h1", "url": "https://ct.googleapis.com/logs/eu1/xenon2027h1/"},
    {"name": "Cloudflare Nimbus 2026", "url": "https://ct.cloudflare.com/logs/nimbus2026/"},
    {"name": "Cloudflare Nimbus 2027", "url": "https://ct.cloudflare.com/logs/nimbus2027/"},
    {"name": "Let's Encrypt Oak 2026h2", "url": "https://oak.ct.letsencrypt.org/2026h2/"},
    {"name": "Let's Encrypt Oak 2027h1", "url": "https://oak.ct.letsencrypt.org/2027h1/"},
    {"name": "DigiCert Wyvern 2026h2", "url": "https://wyvern.ct.digicert.com/2026h2/"},
    {"name": "DigiCert Sphinx 2026h2", "url": "https://sphinx.ct.digicert.com/2026h2/"},
    {"name": "Sectigo Sabre 2026h2", "url": "https://sabre2026h2.ct.sectigo.com/"},
    {"name": "Sectigo Mammoth 2026h2", "url": "https://mammoth2026h2.ct.sectigo.com/"},
]

Fetcher = Callable[[str, float], Any]
BytesFetcher = Callable[[str, float], bytes]

TILE_WIDTH = 256

# Static CT API (tiled) logs: monitoring prefixes. Probed like the others; unreachable ones are skipped.
FALLBACK_STATIC_LOGS: List[Dict[str, str]] = [
    {"name": "Geomys Tuscolo 2026h2", "url": "https://tuscolo2026h2.sunlight.geomys.org/"},
    {"name": "Geomys Tuscolo 2027h1", "url": "https://tuscolo2027h1.sunlight.geomys.org/"},
    {"name": "Let's Encrypt Sycamore 2026h2", "url": "https://sycamore.ct.letsencrypt.org/2026h2/"},
    {"name": "Let's Encrypt Willow 2026h2", "url": "https://willow.ct.letsencrypt.org/2026h2/"},
]


def _default_fetcher(url: str, timeout: float) -> Any:
    import requests

    resp = requests.get(url, timeout=timeout, headers={"User-Agent": "BrandSentra CT tailer"})
    if resp.status_code != 200:
        raise RuntimeError(f"HTTP {resp.status_code}")
    return resp.json()


def _default_bytes_fetcher(url: str, timeout: float) -> bytes:
    import requests

    resp = requests.get(url, timeout=timeout, headers={"User-Agent": "BrandSentra CT tailer"})
    if resp.status_code != 200:
        raise RuntimeError(f"HTTP {resp.status_code}")
    return resp.content


def parse_checkpoint(text: str) -> int:
    """Return the tree size from a Static CT API ``checkpoint`` (origin line, size, root hash...)."""
    lines = text.strip().split("\n")
    if len(lines) < 3:
        raise ValueError("malformed checkpoint")
    return int(lines[1].strip())


def _interval_accepts_new_certs(
    log: Dict[str, Any], now: datetime, lifetime_days: int = MAX_CERT_LIFETIME_DAYS
) -> bool:
    """
    True when ``log`` can still receive certificates issued around ``now``.

    A shard's temporal interval is the range of certificate *expiry* dates it accepts, not of
    issuance dates. A certificate issued today therefore lands in the shard that covers today
    plus its lifetime, which may be months ahead. Keep every shard that has not ended yet and
    that starts within the longest lifetime a new certificate can have.
    """
    interval = log.get("temporal_interval")
    if not interval:
        return True
    try:
        start = datetime.fromisoformat(interval["start_inclusive"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(interval["end_exclusive"].replace("Z", "+00:00"))
    except (KeyError, ValueError):
        return True
    return end > now and start < now + timedelta(days=lifetime_days)


def select_logs_from_list(
    log_list: Dict[str, Any],
    now: Optional[datetime] = None,
    lifetime_days: int = MAX_CERT_LIFETIME_DAYS,
) -> List[Dict[str, str]]:
    """
    Pick usable logs (RFC 6962 and Static CT API) that new certificates can land in: every
    shard that has not ended and starts within ``lifetime_days`` of ``now``.
    """
    now = now or datetime.now(timezone.utc)
    chosen: List[Dict[str, str]] = []
    for operator in log_list.get("operators", []):
        for kind, key, url_key in (
            ("rfc6962", "logs", "url"),
            ("static", "tiled_logs", "monitoring_url"),
        ):
            for log in operator.get(key, []):
                state = log.get("state") or {}
                if not ({"usable", "qualified"} & set(state.keys())):
                    continue
                if not _interval_accepts_new_certs(log, now, lifetime_days):
                    continue
                url = str(log.get(url_key) or "").rstrip("/") + "/"
                if not url.startswith("https://"):
                    continue
                op_name = str(operator.get("name", "log")).strip()
                desc = str(log.get("description", "")).strip().strip("'\"")
                if desc.lower().startswith(op_name.lower()):
                    desc = desc[len(op_name) :].strip(" -'\"")
                name = f"{op_name} {desc}".strip()
                chosen.append({"name": name, "url": url, "kind": kind})
    return chosen


class CTLogTailer:
    """Poll a set of CT logs and hand every certificate to a message handler."""

    def __init__(
        self,
        handler: Callable[[Dict[str, Any]], None],
        logs: Optional[Iterable[Dict[str, str]]] = None,
        fetcher: Fetcher = _default_fetcher,
        bytes_fetcher: BytesFetcher = _default_bytes_fetcher,
        batch_size: int = 256,
        poll_interval: float = 2.0,
        max_lag: int = 5000,
        log_list_url: Optional[str] = LOG_LIST_URL,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], float] = time.time,
    ):
        self.handler = handler
        self.fetch = fetcher
        self.fetch_bytes = bytes_fetcher
        self.batch_size = max(1, int(batch_size))
        self.poll_interval = float(poll_interval)
        self.max_lag = int(max_lag)
        self.log_list_url = log_list_url
        self._sleep = sleep
        self._now = now
        self.configured_logs = [dict(item) for item in logs] if logs else []
        self.logs: List[Dict[str, Any]] = []
        self.stats: Dict[str, Any] = {
            "entries": 0,
            "skipped": 0,
            "parse_errors": 0,
            "requests": 0,
            "errors": 0,
        }
        self._running = False

    # ------------------------------------------------------------------ #

    def discover(self) -> List[Dict[str, Any]]:
        """Resolve the list of logs to tail (configured > log list > fallback) and probe them."""
        candidates = list(self.configured_logs)
        if not candidates and self.log_list_url:
            try:
                candidates = select_logs_from_list(self.fetch(self.log_list_url, 15))
                logger.info(
                    "Discovered %d usable CT logs from %s", len(candidates), self.log_list_url
                )
            except Exception as exc:  # offline or blocked: fall back
                logger.warning("CT log list unavailable (%s); using built-in shards", exc)
        if not candidates:
            candidates = [dict(item) for item in FALLBACK_LOGS] + [
                dict(item, kind="static") for item in FALLBACK_STATIC_LOGS
            ]
        self.logs = []
        for cand in candidates:
            state = {
                "name": cand["name"],
                "url": cand["url"],
                "kind": cand.get("kind", "rfc6962"),
                "tree_size": 0,
                "cursor": None,
                "entries": 0,
                "skipped": 0,
                "errors": 0,
                "backoff": 0.0,
                "next_at": 0.0,
                "status": "probing",
            }
            try:
                state["tree_size"] = self._tree_size(state)
                state["cursor"] = max(0, state["tree_size"] - self.batch_size)
                state["status"] = "live"
                self.logs.append(state)
            except Exception as exc:
                logger.info("CT log %s unreachable: %s", cand["name"], exc)
        logger.info("Tailing %d CT logs", len(self.logs))
        return self.logs

    def _tree_size(self, log: Dict[str, Any]) -> int:
        self.stats["requests"] += 1
        if log.get("kind") == "static":
            return parse_checkpoint(self.fetch_bytes(log["url"] + "checkpoint", 10).decode("utf-8"))
        sth = self.fetch(log["url"] + "ct/v1/get-sth", 10)
        return int(sth.get("tree_size", 0))

    def _fetch_entries(self, log: Dict[str, Any]) -> List[Any]:
        """Return the next batch as ``(index, parsed_or_None, error)`` tuples."""
        out: List[Any] = []
        self.stats["requests"] += 1
        if log.get("kind") == "static":
            tile = log["cursor"] // TILE_WIDTH
            start = tile * TILE_WIDTH
            width = min(TILE_WIDTH, log["tree_size"] - start)
            suffix = "" if width == TILE_WIDTH else f".p/{width}"
            data = self.fetch_bytes(f"{log['url']}tile/data/{tile_path(tile)}{suffix}", 20)
            try:
                leaves = parse_data_tile(data)
            except DERError as exc:
                logger.debug("%s tile %d: %s", log["name"], tile, exc)
                leaves = []
            for offset, parsed in enumerate(leaves):
                index = start + offset
                if index >= log["cursor"]:
                    out.append((index, parsed, None))
            if not leaves:  # unreadable tile: step past it so we do not spin on it
                out.append((start + width - 1, None, "unreadable tile"))
            return out
        end = min(log["cursor"] + self.batch_size, log["tree_size"]) - 1
        payload = self.fetch(f"{log['url']}ct/v1/get-entries?start={log['cursor']}&end={end}", 20)
        for offset, entry in enumerate(payload.get("entries") or []):
            index = log["cursor"] + offset
            try:
                out.append((index, parse_leaf_input(entry.get("leaf_input", "")), None))
            except (DERError, ValueError, TypeError) as exc:
                out.append((index, None, str(exc)))
        return out

    def poll_log(self, log: Dict[str, Any]) -> int:
        """Fetch one batch from ``log``; returns the number of entries processed."""
        if self._now() < log["next_at"]:
            return 0
        try:
            log["tree_size"] = self._tree_size(log)
            if log["cursor"] is None:
                log["cursor"] = max(0, log["tree_size"] - self.batch_size)
            if log["tree_size"] - log["cursor"] > self.max_lag:
                skipped = log["tree_size"] - self.batch_size - log["cursor"]
                log["skipped"] += skipped
                self.stats["skipped"] += skipped
                log["cursor"] = log["tree_size"] - self.batch_size
            if log["cursor"] >= log["tree_size"]:
                log["next_at"] = self._now() + self.poll_interval
                return 0
            entries = self._fetch_entries(log)
            for index, parsed, error in entries:
                if parsed is None:
                    self.stats["parse_errors"] += 1
                    logger.debug("%s#%d parse error: %s", log["name"], index, error)
                    continue
                try:
                    self.handler(to_certstream_message(parsed, log["name"], index))
                except Exception as exc:  # handler bugs must not stop the tail
                    logger.error("handler error for %s#%d: %s", log["name"], index, exc)
            processed = len(entries)
            if entries:
                log["cursor"] = entries[-1][0] + 1
            log["entries"] += processed
            self.stats["entries"] += processed
            log["backoff"] = 0.0
            log["status"] = "live"
            # keep a polite pace even when we are behind: at most ~2 requests/second per log
            log["next_at"] = self._now() + (
                min(0.5, self.poll_interval) if processed >= self.batch_size else self.poll_interval
            )
            return processed
        except Exception as exc:
            log["errors"] += 1
            self.stats["errors"] += 1
            rate_limited = "429" in str(exc)
            floor = 20.0 if rate_limited else 2.0
            log["backoff"] = min(300.0, max(floor, (log["backoff"] or floor / 2) * 2))
            log["next_at"] = self._now() + log["backoff"]
            log["status"] = "rate-limited" if rate_limited else f"error: {exc}"
            level = logging.INFO if rate_limited else logging.WARNING
            logger.log(level, "CT log %s: %s (retry in %.0fs)", log["name"], exc, log["backoff"])
            return 0

    def poll_once(self) -> int:
        """Poll every log once; returns total entries processed."""
        return sum(self.poll_log(log) for log in self.logs)

    def run(self, iterations: Optional[int] = None) -> None:
        """Tail forever (or for ``iterations`` rounds) with a small idle sleep."""
        self._running = True
        if not self.logs:
            self.discover()
        rounds = 0
        while self._running and (iterations is None or rounds < iterations):
            processed = self.poll_once()
            rounds += 1
            if not processed:
                self._sleep(self.poll_interval)

    def stop(self) -> None:
        self._running = False

    def summary(self) -> Dict[str, Any]:
        seen = self.stats["entries"] + self.stats["skipped"]
        return {
            "logs": [
                {
                    k: v
                    for k, v in log.items()
                    if k
                    in (
                        "name",
                        "url",
                        "kind",
                        "tree_size",
                        "cursor",
                        "entries",
                        "skipped",
                        "errors",
                        "status",
                    )
                }
                for log in self.logs
            ],
            "coverage": round(100.0 * self.stats["entries"] / seen, 1) if seen else 100.0,
            **self.stats,
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"CTLogTailer({json.dumps(self.summary())})"


__all__ = [
    "CTLogTailer",
    "FALLBACK_LOGS",
    "FALLBACK_STATIC_LOGS",
    "LOG_LIST_URL",
    "parse_checkpoint",
    "select_logs_from_list",
]
