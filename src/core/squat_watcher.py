#!/usr/bin/env python3
"""
BrandSentra - Proactive Typosquat Watcher

Instead of waiting for a look-alike domain to show up in Certificate
Transparency logs, the watcher generates every plausible squatting
permutation of each protected brand (typos, homoglyphs, combo-squats, TLD
swaps ...), resolves them in parallel and records the ones that are live.

* A permutation that resolves for the first time is a **new sighting** and
  triggers the ``on_new`` callback (wired to the notification dispatcher by
  the CLI and API).
* Sightings are persisted in the database with first/last seen timestamps,
  the resolved IPs and a triage status (``new``, ``monitoring``,
  ``takedown_requested``, ``resolved``, ``benign``).

The resolver is injectable so the watcher can be unit-tested offline.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional

from src.core.domain_analyzer import DomainAnalyzer

logger = logging.getLogger("brandsentra.squat_watcher")

Resolver = Callable[[str], List[str]]

STATE_KEY = "squat_watcher.last_run"


@dataclass
class Sighting:
    """A live squatting candidate."""

    domain: str
    brand: str
    technique: str
    ips: List[str]
    is_new: bool
    first_seen: str
    last_seen: str
    seen_count: int = 1
    status: str = "new"
    tld: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def make_resolver(timeout: float = 3.0) -> Resolver:
    """
    Build a resolver returning the A/AAAA addresses of a hostname.

    Uses dnspython when installed (honouring ``timeout``), otherwise the
    system resolver via :func:`socket.getaddrinfo`. Unresolvable names
    return an empty list; transient errors are logged and also return ``[]``.
    """
    try:
        import dns.resolver  # type: ignore

        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        resolver.timeout = timeout

        def _dns(domain: str) -> List[str]:
            ips: List[str] = []
            for rtype in ("A", "AAAA"):
                try:
                    answers = resolver.resolve(domain, rtype)
                    ips.extend(str(r) for r in answers)
                except (
                    dns.resolver.NXDOMAIN,
                    dns.resolver.NoAnswer,
                    dns.resolver.NoNameservers,
                ):
                    continue
                except Exception as exc:  # pragma: no cover - network dependent
                    logger.debug("DNS %s %s failed: %s", domain, rtype, exc)
            return sorted(set(ips))

        return _dns
    except ImportError:  # pragma: no cover - dnspython is a declared dependency

        def _socket(domain: str) -> List[str]:
            try:
                infos = socket.getaddrinfo(domain, None)
            except socket.gaierror:
                return []
            except Exception as exc:
                logger.debug("getaddrinfo %s failed: %s", domain, exc)
                return []
            return sorted({info[4][0] for info in infos})

        return _socket


class SquatWatcher:
    """Generates, resolves and tracks squatting permutations of protected brands."""

    def __init__(
        self,
        analyzer: DomainAnalyzer,
        config: Any = None,
        db: Any = None,
        resolver: Optional[Resolver] = None,
        brands: Optional[Iterable[str]] = None,
        on_new: Optional[Callable[[Sighting], None]] = None,
        now: Callable[[], float] = time.time,
    ):
        self.analyzer = analyzer
        self.config = config
        self.db = db
        self._now = now
        self.on_new = on_new
        self.tlds: List[str] = list(getattr(config, "tlds", None) or [])
        self.include_combos: bool = bool(getattr(config, "include_combos", True))
        self.max_workers: int = int(getattr(config, "max_workers", 32) or 32)
        self.dns_timeout: float = float(getattr(config, "dns_timeout", 3.0) or 3.0)
        self.max_candidates: int = int(getattr(config, "max_candidates_per_brand", 1500) or 1500)
        self.interval: int = int(getattr(config, "interval_seconds", 21600) or 21600)
        configured = list(brands or getattr(config, "brands", None) or [])
        self.brands: List[str] = configured or list(analyzer.protected_brands)
        self.resolver: Resolver = resolver or make_resolver(self.dns_timeout)
        self._stop = threading.Event()
        self.stats: Dict[str, Any] = {"runs": 0, "candidates": 0, "live": 0, "new": 0}

    # ------------------------------------------------------------------ #

    def candidates(self, brand: str) -> List[Dict[str, str]]:
        """Permutation candidates for ``brand`` minus its own legitimate domains."""
        perms = self.analyzer.generate_permutations_detailed(
            brand,
            tlds=self.tlds or None,
            include_combos=self.include_combos,
            max_results=self.max_candidates,
        )
        return [p for p in perms if not self.analyzer.is_legitimate(p["domain"])]

    def resolve_many(self, domains: Iterable[str]) -> Dict[str, List[str]]:
        """Resolve many hostnames concurrently; returns ``{domain: [ips]}``."""
        domains = list(dict.fromkeys(domains))
        results: Dict[str, List[str]] = {}
        if not domains:
            return results

        def _one(domain: str) -> None:
            try:
                results[domain] = list(self.resolver(domain) or [])
            except Exception as exc:
                logger.debug("Resolver error for %s: %s", domain, exc)
                results[domain] = []

        workers = max(1, min(self.max_workers, len(domains)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(_one, domains))
        return results

    def check_brand(self, brand: str) -> List[Sighting]:
        """Generate, resolve and record sightings for one brand."""
        candidates = self.candidates(brand)
        by_domain = {c["domain"]: c for c in candidates}
        resolved = self.resolve_many(by_domain)
        self.stats["candidates"] += len(candidates)

        sightings: List[Sighting] = []
        for domain, ips in resolved.items():
            if not ips:
                continue
            meta = by_domain[domain]
            sighting = self._record(
                domain, brand, meta.get("technique", ""), ips, meta.get("tld", "")
            )
            sightings.append(sighting)
            if sighting.is_new:
                self.stats["new"] += 1
                if self.on_new:
                    try:
                        self.on_new(sighting)
                    except Exception as exc:  # callbacks must never break the run
                        logger.error("on_new callback failed for %s: %s", domain, exc)
        self.stats["live"] += len(sightings)
        sightings.sort(key=lambda s: (not s.is_new, s.domain))
        return sightings

    def _record(
        self, domain: str, brand: str, technique: str, ips: List[str], tld: str
    ) -> Sighting:
        now_iso = datetime.now(timezone.utc).isoformat()
        if self.db is None:
            return Sighting(domain, brand, technique, ips, True, now_iso, now_iso, 1, "new", tld)
        is_new, row = self.db.upsert_sighting(domain, brand, technique, ips)
        return Sighting(
            domain=domain,
            brand=brand,
            technique=technique,
            ips=ips,
            is_new=is_new,
            first_seen=row.get("first_seen", now_iso),
            last_seen=row.get("last_seen", now_iso),
            seen_count=int(row.get("seen_count", 1)),
            status=row.get("status", "new"),
            tld=tld,
        )

    def run_once(self, brands: Optional[Iterable[str]] = None) -> Dict[str, Any]:
        """Check every brand once and return a run summary."""
        started = self._now()
        started_iso = datetime.now(timezone.utc).isoformat()
        targets = list(brands) if brands else list(self.brands)
        all_sightings: List[Sighting] = []
        errors: Dict[str, str] = {}
        for brand in targets:
            if self._stop.is_set():
                break
            try:
                all_sightings.extend(self.check_brand(brand))
            except Exception as exc:
                logger.error("Squat check failed for %s: %s", brand, exc)
                errors[brand] = str(exc)
        self.stats["runs"] += 1
        summary = {
            "started_at": started_iso,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": round(self._now() - started, 3),
            "brands": len(targets),
            "candidates": self.stats["candidates"],
            "live": len(all_sightings),
            "new": sum(1 for s in all_sightings if s.is_new),
            "errors": errors,
            "sightings": [s.to_dict() for s in all_sightings],
        }
        if self.db is not None:
            state = {k: v for k, v in summary.items() if k != "sightings"}
            state["new_domains"] = [s.domain for s in all_sightings if s.is_new][:50]
            self.db.set_state(STATE_KEY, state)
        logger.info(
            "Squat watcher run: %d brands, %d live, %d new (%.1fs)",
            summary["brands"],
            summary["live"],
            summary["new"],
            summary["duration_seconds"],
        )
        return summary

    def run_forever(
        self,
        interval: Optional[int] = None,
        max_runs: Optional[int] = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> int:
        """Run repeatedly until :meth:`stop` is called; returns the run count."""
        wait = int(interval or self.interval)
        runs = 0
        self._stop.clear()
        while not self._stop.is_set():
            self.run_once()
            runs += 1
            if max_runs is not None and runs >= max_runs:
                break
            if self._stop.wait(0) if wait <= 0 else False:
                break
            sleep(wait)
        return runs

    def stop(self) -> None:
        self._stop.set()


__all__ = ["Resolver", "STATE_KEY", "Sighting", "SquatWatcher", "make_resolver"]
