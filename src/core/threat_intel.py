#!/usr/bin/env python3
"""
BrandSentra - Threat Intelligence Integration

Aggregates reputation data about a domain from several public and commercial
sources (VirusTotal, urlscan.io, Google Safe Browsing, PhishTank, OpenPhish and
URLhaus) into one weighted verdict.

Design notes:

* Every network call goes through the small :class:`Fetcher` protocol, so the
  engine can be exercised fully offline with :class:`StaticFetcher`.
* Sources run concurrently. A failing source is recorded in
  ``ThreatIntelResult.errors`` and never prevents the others from reporting.
* Results are cached in memory for ``cache_ttl_seconds``. The OpenPhish feed
  is kept in memory and mirrored to disk so a restart does not re-download it.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import copy
import json as _json
import logging
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Protocol, Tuple, Union

from src import __version__
from src.utils.domain import normalize_domain, parse_domain

logger = logging.getLogger("brandsentra.threat_intel")

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

#: Evaluation order of the sources (also the order of ``enabled_sources()``).
SOURCE_ORDER: Tuple[str, ...] = (
    "virustotal",
    "urlscan",
    "google_safebrowsing",
    "phishtank",
    "openphish",
    "urlhaus",
)

#: Maximum contribution of each source to the 0-100 aggregate score.
SOURCE_WEIGHTS: Dict[str, float] = {
    "virustotal": 35.0,
    "google_safebrowsing": 25.0,
    "phishtank": 25.0,
    "openphish": 20.0,
    "urlhaus": 20.0,
    "urlscan": 15.0,
}

#: Number of "malicious" hits at which a source reaches its full weight.
SOURCE_THRESHOLDS: Dict[str, float] = {"virustotal": 5.0, "urlhaus": 5.0}
DEFAULT_WEIGHT = 10.0
DEFAULT_THRESHOLD = 1.0

#: Score floor applied when a curated phishing/malware list contains the domain.
AUTHORITATIVE_FLOOR = 70.0
#: Aggregate score at or above which a domain is considered malicious.
MALICIOUS_THRESHOLD = 50.0

VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/domains/{domain}"
URLSCAN_URL = "https://urlscan.io/api/v1/search/?q=domain:{domain}"
SAFEBROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
PHISHTANK_URL = "https://checkurl.phishtank.com/checkurl/"
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
URLHAUS_HOST_URL = "https://urlhaus-api.abuse.ch/v1/host/"

SAFEBROWSING_THREAT_TYPES: Tuple[str, ...] = (
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
)

OPENPHISH_FEED_FILE = "openphish_feed.txt"
OPENPHISH_META_FILE = "openphish_meta.json"
OPENPHISH_MAX_MATCHES = 5
VT_MAX_CATEGORY_TAGS = 3

DEFAULT_CACHE_DIR = "data/intel_cache"
DEFAULT_CACHE_TTL = 3600.0
DEFAULT_FEED_REFRESH = 3600.0
DEFAULT_TIMEOUT = 10.0


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _epoch_to_iso(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_bool(value: Any) -> bool:
    """Interpret API booleans, including PhishTank's ``"y"``/``"n"`` strings."""
    if isinstance(value, str):
        return value.strip().lower() in {"y", "yes", "true", "1"}
    return bool(value)


def _describe_error(exc: BaseException) -> str:
    text = str(exc).strip()
    return text or exc.__class__.__name__


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


@dataclass
class ThreatIntelResult:
    """Consolidated threat intelligence verdict for one domain.

    Attributes:
        domain: Normalised hostname that was looked up.
        sources_checked: Sources that answered successfully.
        detections: Per-source normalised result, keyed by source name.
        total_score: Weighted aggregate score in the range 0-100.
        is_malicious: ``True`` when ``total_score`` reaches the malicious threshold.
        first_seen: Earliest sighting reported by a source, when available.
        last_seen: Latest sighting reported by a source, when available.
        tags: Short labels summarising the findings (``malicious``, ``known_phish`` ...).
        whois_info: Optional WHOIS enrichment (not populated by this module).
        dns_records: Optional DNS enrichment (not populated by this module).
        ssl_info: Optional TLS enrichment (not populated by this module).
        timestamp: UTC ISO-8601 time the result was produced.
        errors: Source name (or ``"input"``) mapped to the failure message.
        cached: ``True`` when the result was served from the in-memory cache.
    """

    domain: str
    sources_checked: List[str]
    detections: Dict[str, Dict]
    total_score: float
    is_malicious: bool
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    whois_info: Optional[Dict] = None
    dns_records: Optional[Dict] = None
    ssl_info: Optional[Dict] = None
    timestamp: str = field(default_factory=_utc_now_iso)
    errors: Dict[str, str] = field(default_factory=dict)
    cached: bool = False

    def to_dict(self) -> Dict:
        """Return a JSON-serialisable dictionary of the result."""
        return asdict(self)


class ThreatIntelSourceError(Exception):
    """Raised by a source check when the upstream service gives an unusable answer."""


# --------------------------------------------------------------------------- #
# HTTP layer
# --------------------------------------------------------------------------- #


@dataclass
class FetchResponse:
    """Minimal HTTP response used by every :class:`Fetcher`.

    Attributes:
        status: HTTP status code.
        text: Decoded response body.
        headers: Response headers.
    """

    status: int
    text: str = ""
    headers: Dict[str, str] = field(default_factory=dict)

    def json(self) -> Any:
        """Decode the body as JSON."""
        return _json.loads(self.text)


class Fetcher(Protocol):
    """Asynchronous HTTP client interface consumed by :class:`ThreatIntelEngine`."""

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Any] = None,
        timeout: float = 10,
    ) -> FetchResponse:
        """Perform one HTTP request and return the response."""
        ...


class AiohttpFetcher:
    """Default :class:`Fetcher` backed by ``aiohttp``.

    ``aiohttp`` is imported lazily inside :meth:`request`, so the module can be
    imported (and tested) on machines that do not have it installed.
    """

    def __init__(self, user_agent: Optional[str] = None) -> None:
        """Create the fetcher.

        Args:
            user_agent: ``User-Agent`` header sent with every request.
        """
        self.user_agent = user_agent or f"BrandSentra/{__version__}"

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Any] = None,
        timeout: float = 10,
    ) -> FetchResponse:
        """Perform one HTTP request with a fresh ``aiohttp`` session.

        Raises:
            RuntimeError: When ``aiohttp`` is not installed.
        """
        try:
            import aiohttp
        except ImportError as exc:  # pragma: no cover - exercised via sys.modules patching
            raise RuntimeError(
                "aiohttp is required for live threat-intelligence lookups; "
                "install it with 'pip install aiohttp' or inject a custom Fetcher"
            ) from exc

        merged_headers = {"User-Agent": self.user_agent}
        merged_headers.update(headers or {})
        client_timeout = aiohttp.ClientTimeout(total=timeout)
        async with aiohttp.ClientSession(timeout=client_timeout) as session:
            async with session.request(
                method.upper(),
                url,
                headers=merged_headers,
                params=params,
                data=data,
                json=json,
            ) as resp:
                text = await resp.text()
                return FetchResponse(
                    status=resp.status,
                    text=text,
                    headers={k: v for k, v in resp.headers.items()},
                )


RouteKey = Union[str, Tuple[str, str]]
RouteValue = Union[
    FetchResponse,
    BaseException,
    Callable[..., Any],
    Dict[str, Any],
    List[Any],
    str,
]


def json_response(payload: Any, status: int = 200) -> FetchResponse:
    """Build a :class:`FetchResponse` carrying ``payload`` encoded as JSON."""
    return FetchResponse(
        status=status,
        text=_json.dumps(payload),
        headers={"Content-Type": "application/json"},
    )


class StaticFetcher:
    """Offline :class:`Fetcher` that answers from a routing table.

    Routes match on HTTP method plus URL prefix; when several prefixes match,
    the longest wins. A method of ``"*"`` matches any method.

    Routes are given either as a mapping or as a list. Mapping keys are
    ``"METHOD https://prefix"`` strings or ``(method, prefix)`` tuples; list
    items are ``(key, value)`` or ``(method, prefix, value)`` tuples.

    A route value may be:

    * a :class:`FetchResponse`, returned as is;
    * an exception instance, raised;
    * a callable ``fn(method, url, kwargs) -> value`` evaluated per request,
      where ``kwargs`` holds ``headers``, ``params``, ``data``, ``json`` and
      ``timeout``;
    * a ``dict`` or ``list``, returned as a 200 JSON response;
    * a ``str``, returned as a 200 text response.

    Every request is appended to :attr:`calls` as a dict with the keys
    ``method``, ``url``, ``headers``, ``params``, ``data``, ``json`` and
    ``timeout``.
    """

    def __init__(
        self,
        routes: Union[Dict[RouteKey, RouteValue], List[Tuple[Any, ...]], None] = None,
    ) -> None:
        """Create the fetcher from an optional routing table."""
        self._routes: List[Tuple[str, str, Any]] = []
        self.calls: List[Dict[str, Any]] = []
        items = routes.items() if isinstance(routes, dict) else (routes or [])
        for item in items:
            if len(item) == 3:
                method, prefix, value = item
                self.add_route(method, prefix, value)
            elif len(item) == 2:
                method, prefix = self._split_key(item[0])
                self.add_route(method, prefix, item[1])
            else:
                raise ValueError(f"unsupported route definition: {item!r}")

    @staticmethod
    def _split_key(key: RouteKey) -> Tuple[str, str]:
        if isinstance(key, tuple):
            method, prefix = key
            return str(method), str(prefix)
        parts = str(key).split(None, 1)
        if len(parts) == 2:
            return parts[0], parts[1]
        return "*", parts[0] if parts else ""

    def add_route(self, method: str, prefix: str, value: RouteValue) -> None:
        """Register ``value`` for requests whose URL starts with ``prefix``."""
        self._routes.append((method.upper(), prefix, value))

    def _match(self, method: str, url: str) -> Tuple[bool, Any]:
        best: Optional[Tuple[str, str, Any]] = None
        for route in self._routes:
            route_method, prefix, _ = route
            if route_method not in ("*", method.upper()):
                continue
            if not url.startswith(prefix):
                continue
            if best is None or len(prefix) > len(best[1]):
                best = route
        if best is None:
            return False, None
        return True, best[2]

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Any] = None,
        timeout: float = 10,
    ) -> FetchResponse:
        """Record the call and answer it from the routing table.

        Raises:
            LookupError: When no route matches the request.
        """
        call: Dict[str, Any] = {
            "method": method.upper(),
            "url": url,
            "headers": dict(headers or {}),
            "params": dict(params or {}),
            "data": dict(data) if isinstance(data, dict) else data,
            "json": copy.deepcopy(json),
            "timeout": timeout,
        }
        self.calls.append(call)
        found, value = self._match(method, url)
        if not found:
            raise LookupError(f"StaticFetcher has no route for {call['method']} {url}")
        return self._materialise(value, call)

    @staticmethod
    def _materialise(value: Any, call: Dict[str, Any]) -> FetchResponse:
        if isinstance(value, type) and issubclass(value, BaseException):
            raise value(f"{call['method']} {call['url']}")
        if callable(value) and not isinstance(value, (FetchResponse, BaseException)):
            kwargs = {k: call[k] for k in ("headers", "params", "data", "json", "timeout")}
            value = value(call["method"], call["url"], kwargs)
        if isinstance(value, BaseException):
            raise value
        if isinstance(value, FetchResponse):
            return value
        if isinstance(value, (dict, list)):
            return json_response(value)
        if isinstance(value, str):
            return FetchResponse(status=200, text=value)
        raise TypeError(f"unsupported StaticFetcher route value: {value!r}")


# --------------------------------------------------------------------------- #
# OpenPhish feed state
# --------------------------------------------------------------------------- #


@dataclass
class _OpenPhishFeed:
    urls: List[str] = field(default_factory=list)
    by_host: Dict[str, List[str]] = field(default_factory=dict)
    by_registrable: Dict[str, List[str]] = field(default_factory=dict)
    fetched_at: Optional[float] = None
    error: Optional[str] = None

    @property
    def loaded(self) -> bool:
        return bool(self.urls)

    @classmethod
    def from_lines(cls, lines: List[str], fetched_at: Optional[float]) -> "_OpenPhishFeed":
        feed = cls(fetched_at=fetched_at)
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            host = normalize_domain(line)
            if not host:
                continue
            feed.urls.append(line)
            feed.by_host.setdefault(host, []).append(line)
            registrable = parse_domain(host).registrable or host
            feed.by_registrable.setdefault(registrable, []).append(line)
        return feed

    def matches(self, hostname: str) -> List[str]:
        """Feed URLs whose host equals ``hostname`` or shares its registrable domain."""
        registrable = parse_domain(hostname).registrable or hostname
        seen: set = set()
        out: List[str] = []
        for url in self.by_host.get(hostname, []) + self.by_registrable.get(registrable, []):
            if url not in seen:
                seen.add(url)
                out.append(url)
        return out


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #


class ThreatIntelEngine:
    """Aggregates threat intelligence about a domain from multiple sources.

    Args:
        config: Dataclass-like settings object. Every attribute is read with
            ``getattr(config, name, default)`` so older configurations keep
            working. Recognised attributes: ``virustotal_api_key``,
            ``urlscan_api_key``, ``phishtank_api_key``,
            ``google_safebrowsing_key``, ``openphish_enabled``,
            ``urlhaus_enabled``, ``cache_ttl_seconds``,
            ``feed_refresh_seconds``, ``request_timeout`` and ``cache_dir``.
        fetcher: HTTP client. Defaults to :class:`AiohttpFetcher`.
        cache_dir: Directory for the persisted OpenPhish feed. Overrides
            ``config.cache_dir``.
        now: Clock returning seconds since the epoch; injectable for tests.
    """

    def __init__(
        self,
        config: Any,
        fetcher: Optional[Fetcher] = None,
        cache_dir: Optional[str] = None,
        now: Callable[[], float] = time.time,
    ) -> None:
        self.config = config
        self.fetcher: Fetcher = fetcher if fetcher is not None else AiohttpFetcher()
        self._now = now
        self.cache_dir = Path(cache_dir or str(self._cfg("cache_dir", DEFAULT_CACHE_DIR)))
        self.cache_ttl = float(self._cfg("cache_ttl_seconds", DEFAULT_CACHE_TTL))
        self.feed_refresh = float(self._cfg("feed_refresh_seconds", DEFAULT_FEED_REFRESH))
        self.timeout = float(self._cfg("request_timeout", DEFAULT_TIMEOUT))

        self._cache: Dict[str, Tuple[float, ThreatIntelResult]] = {}
        self._feed = _OpenPhishFeed()
        self._feed_lock = threading.Lock()
        self._checks: Dict[str, Callable[[str], Awaitable[Dict[str, Any]]]] = {
            "virustotal": self._check_virustotal,
            "urlscan": self._check_urlscan,
            "google_safebrowsing": self._check_google_safebrowsing,
            "phishtank": self._check_phishtank,
            "openphish": self._check_openphish,
            "urlhaus": self._check_urlhaus,
        }
        self._load_feed_from_disk()

    # ------------------------------------------------------------------ #
    # Configuration
    # ------------------------------------------------------------------ #

    def _cfg(self, name: str, default: Any) -> Any:
        value = getattr(self.config, name, default)
        return default if value is None else value

    def enabled_sources(self) -> List[str]:
        """Return the names of the sources the current configuration enables.

        Keyed services are enabled by a non-empty key; PhishTank likewise
        requires an application key so anonymous rate limits are never hit.
        OpenPhish and URLhaus are toggled by ``openphish_enabled`` and
        ``urlhaus_enabled`` and default to on.
        """
        flags = {
            "virustotal": bool(self._cfg("virustotal_api_key", "")),
            "urlscan": bool(self._cfg("urlscan_api_key", "")),
            "google_safebrowsing": bool(self._cfg("google_safebrowsing_key", "")),
            "phishtank": bool(self._cfg("phishtank_api_key", "")),
            "openphish": bool(self._cfg("openphish_enabled", True)),
            "urlhaus": bool(self._cfg("urlhaus_enabled", True)),
        }
        return [name for name in SOURCE_ORDER if flags[name]]

    # ------------------------------------------------------------------ #
    # Public lookup API
    # ------------------------------------------------------------------ #

    async def lookup(self, domain: str, force_refresh: bool = False) -> ThreatIntelResult:
        """Run every enabled source against ``domain`` and aggregate the verdict.

        Args:
            domain: Hostname or URL; it is normalised with ``normalize_domain``.
            force_refresh: Bypass (and overwrite) the in-memory cache.

        Returns:
            The aggregated :class:`ThreatIntelResult`.
        """
        host = normalize_domain(domain)
        if not host:
            return ThreatIntelResult(
                domain=host,
                sources_checked=[],
                detections={},
                total_score=0.0,
                is_malicious=False,
                errors={"input": "empty domain"},
            )

        if not force_refresh:
            hit = self._cache_get(host)
            if hit is not None:
                return hit

        result = ThreatIntelResult(
            domain=host,
            sources_checked=[],
            detections={},
            total_score=0.0,
            is_malicious=False,
        )
        sources = self.enabled_sources()
        outcomes = await asyncio.gather(*(self._run_source(name, host) for name in sources))
        for name, detection, error in outcomes:
            if error is not None:
                result.errors[name] = error
            else:
                result.sources_checked.append(name)
                result.detections[name] = detection or {}

        self._finalise(result)
        self._cache_put(host, result)
        return result

    def lookup_sync(self, domain: str, force_refresh: bool = False) -> ThreatIntelResult:
        """Blocking wrapper around :meth:`lookup`.

        Works both from plain synchronous code and from inside a running event
        loop (in which case the lookup runs on a helper thread with its own
        loop, blocking the caller until it completes).
        """
        coro = self.lookup(domain, force_refresh=force_refresh)
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result()

    def clear_cache(self) -> None:
        """Drop every cached lookup result (the OpenPhish feed is kept)."""
        self._cache.clear()

    def feed_status(self) -> Dict:
        """Describe the state of the locally held threat feeds."""
        feed = self._feed
        age = None if feed.fetched_at is None else max(0.0, float(self._now()) - feed.fetched_at)
        return {
            "openphish": {
                "entries": len(feed.urls),
                "fetched_at": _epoch_to_iso(feed.fetched_at),
                "age_seconds": age,
                "error": feed.error,
            }
        }

    # ------------------------------------------------------------------ #
    # Caching
    # ------------------------------------------------------------------ #

    def _cache_get(self, host: str) -> Optional[ThreatIntelResult]:
        if self.cache_ttl <= 0:
            return None
        entry = self._cache.get(host)
        if entry is None:
            return None
        stored_at, result = entry
        if float(self._now()) - stored_at >= self.cache_ttl:
            self._cache.pop(host, None)
            return None
        hit = copy.deepcopy(result)
        hit.cached = True
        return hit

    def _cache_put(self, host: str, result: ThreatIntelResult) -> None:
        if self.cache_ttl <= 0:
            return
        self._cache[host] = (float(self._now()), copy.deepcopy(result))

    # ------------------------------------------------------------------ #
    # Source execution
    # ------------------------------------------------------------------ #

    async def _run_source(
        self, name: str, host: str
    ) -> Tuple[str, Optional[Dict[str, Any]], Optional[str]]:
        check = self._checks[name]
        try:
            detection = await check(host)
            return name, detection, None
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("%s lookup failed for %s: %s", name, host, exc)
            return name, None, _describe_error(exc)

    async def _request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Any] = None,
    ) -> FetchResponse:
        return await self.fetcher.request(
            method,
            url,
            headers=headers,
            params=params,
            data=data,
            json=json,
            timeout=self.timeout,
        )

    @staticmethod
    def _require_ok(resp: FetchResponse) -> None:
        if resp.status != 200:
            raise ThreatIntelSourceError(f"http {resp.status}")

    async def _check_virustotal(self, domain: str) -> Dict[str, Any]:
        """Query VirusTotal API v3 for the domain object."""
        resp = await self._request(
            "GET",
            VIRUSTOTAL_URL.format(domain=domain),
            headers={"x-apikey": str(self._cfg("virustotal_api_key", ""))},
        )
        self._require_ok(resp)
        attrs = _as_dict(_as_dict(_as_dict(resp.json()).get("data")).get("attributes"))
        stats = _as_dict(attrs.get("last_analysis_stats"))
        categories: List[str] = []
        for value in _as_dict(attrs.get("categories")).values():
            text = str(value).strip()
            if text and text not in categories:
                categories.append(text)
        return {
            "malicious": _as_int(stats.get("malicious")),
            "suspicious": _as_int(stats.get("suspicious")),
            "harmless": _as_int(stats.get("harmless")),
            "undetected": _as_int(stats.get("undetected")),
            "reputation": _as_int(attrs.get("reputation")),
            "categories": categories,
            "last_analysis_date": attrs.get("last_analysis_date"),
        }

    async def _check_urlscan(self, domain: str) -> Dict[str, Any]:
        """Search urlscan.io for previous scans of the domain."""
        resp = await self._request(
            "GET",
            URLSCAN_URL.format(domain=domain),
            headers={"API-Key": str(self._cfg("urlscan_api_key", ""))},
        )
        self._require_ok(resp)
        raw_results = _as_dict(resp.json()).get("results") or []
        results = [_as_dict(item) for item in raw_results]
        malicious = sum(
            1
            for item in results
            if _as_dict(_as_dict(item.get("verdicts")).get("overall")).get("malicious")
        )
        last_scan = results[0].get("result") if results else None
        return {
            "total_scans": len(results),
            "malicious": malicious,
            "last_scan": last_scan or None,
        }

    async def _check_google_safebrowsing(self, domain: str) -> Dict[str, Any]:
        """Query the Google Safe Browsing v4 Lookup API."""
        body = {
            "client": {"clientId": "brandsentra", "clientVersion": __version__},
            "threatInfo": {
                "threatTypes": list(SAFEBROWSING_THREAT_TYPES),
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": f"http://{domain}/"},
                    {"url": f"https://{domain}/"},
                ],
            },
        }
        resp = await self._request(
            "POST",
            SAFEBROWSING_URL,
            params={"key": str(self._cfg("google_safebrowsing_key", ""))},
            json=body,
        )
        self._require_ok(resp)
        matches = _as_dict(resp.json()).get("matches") or []
        threats = sorted(
            {
                str(_as_dict(match).get("threatType"))
                for match in matches
                if _as_dict(match).get("threatType")
            }
        )
        return {"threats": threats, "malicious": len(threats)}

    async def _check_phishtank(self, domain: str) -> Dict[str, Any]:
        """Check the PhishTank database."""
        form: Dict[str, Any] = {"url": f"http://{domain}/", "format": "json"}
        app_key = str(self._cfg("phishtank_api_key", ""))
        if app_key:
            form["app_key"] = app_key
        resp = await self._request(
            "POST",
            PHISHTANK_URL,
            headers={"User-Agent": "phishtank/brandsentra"},
            data=form,
        )
        self._require_ok(resp)
        results = _as_dict(_as_dict(resp.json()).get("results"))
        in_database = _as_bool(results.get("in_database"))
        verified = _as_bool(results.get("verified"))
        valid = _as_bool(results.get("valid"))
        return {
            "in_database": in_database,
            "verified": verified,
            "valid": valid,
            "phish_id": results.get("phish_id"),
            "phish_detail_page": results.get("phish_detail_page"),
            "malicious": 1 if (in_database and valid) else 0,
        }

    async def _check_openphish(self, domain: str) -> Dict[str, Any]:
        """Match the domain against the OpenPhish community feed."""
        feed = await self._ensure_openphish_feed()
        matched = feed.matches(domain)[:OPENPHISH_MAX_MATCHES]
        return {
            "in_feed": bool(matched),
            "matched_urls": matched,
            "feed_entries": len(feed.urls),
            "malicious": 1 if matched else 0,
        }

    async def _check_urlhaus(self, domain: str) -> Dict[str, Any]:
        """Query the abuse.ch URLhaus host endpoint."""
        resp = await self._request("POST", URLHAUS_HOST_URL, data={"host": domain})
        self._require_ok(resp)
        payload = _as_dict(resp.json())
        status = payload.get("query_status")
        if status == "ok":
            url_count = _as_int(payload.get("url_count"))
            return {
                "listed": True,
                "url_count": url_count,
                "blacklists": _as_dict(payload.get("blacklists")),
                "firstseen": payload.get("firstseen"),
                "malicious": min(url_count, 5) or 1,
            }
        if status == "no_results":
            return {"listed": False, "url_count": 0, "malicious": 0}
        raise ThreatIntelSourceError(f"unexpected query_status {status!r}")

    # ------------------------------------------------------------------ #
    # OpenPhish feed management
    # ------------------------------------------------------------------ #

    def _feed_is_stale(self) -> bool:
        fetched_at = self._feed.fetched_at
        if fetched_at is None:
            return True
        return float(self._now()) - fetched_at >= self.feed_refresh

    async def _ensure_openphish_feed(self) -> _OpenPhishFeed:
        if not self._feed_is_stale():
            return self._feed
        try:
            lines = await self._download_openphish()
        except Exception as exc:
            message = _describe_error(exc)
            if self._feed.loaded:
                logger.warning("OpenPhish refresh failed (%s); using cached feed", message)
                self._feed.error = message
                return self._feed
            self._feed.error = message
            raise
        self._replace_feed(lines, fetched_at=float(self._now()), persist=True)
        return self._feed

    async def _download_openphish(self) -> List[str]:
        resp = await self._request("GET", OPENPHISH_FEED_URL)
        self._require_ok(resp)
        return resp.text.splitlines()

    def _replace_feed(self, lines: List[str], fetched_at: Optional[float], persist: bool) -> None:
        feed = _OpenPhishFeed.from_lines(lines, fetched_at)
        with self._feed_lock:
            self._feed = feed
            if persist:
                self._persist_feed(feed)
        logger.info("OpenPhish feed loaded with %d entries", len(feed.urls))

    def _persist_feed(self, feed: _OpenPhishFeed) -> None:
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            self._atomic_write(self.cache_dir / OPENPHISH_FEED_FILE, "\n".join(feed.urls) + "\n")
            meta = {"fetched_at": feed.fetched_at, "entries": len(feed.urls)}
            self._atomic_write(self.cache_dir / OPENPHISH_META_FILE, _json.dumps(meta))
        except OSError as exc:
            logger.warning("Could not persist OpenPhish feed to %s: %s", self.cache_dir, exc)

    @staticmethod
    def _atomic_write(path: Path, content: str) -> None:
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(content, encoding="utf-8")
        os.replace(tmp, path)

    def _load_feed_from_disk(self) -> None:
        feed_path = self.cache_dir / OPENPHISH_FEED_FILE
        meta_path = self.cache_dir / OPENPHISH_META_FILE
        if not feed_path.is_file():
            return
        fetched_at: Optional[float] = None
        try:
            if meta_path.is_file():
                meta = _as_dict(_json.loads(meta_path.read_text(encoding="utf-8")))
                raw = meta.get("fetched_at")
                fetched_at = float(raw) if raw is not None else None
            lines = feed_path.read_text(encoding="utf-8").splitlines()
        except (OSError, ValueError, TypeError) as exc:
            logger.warning("Ignoring unreadable OpenPhish cache in %s: %s", self.cache_dir, exc)
            return
        self._replace_feed(lines, fetched_at=fetched_at, persist=False)

    # ------------------------------------------------------------------ #
    # Scoring
    # ------------------------------------------------------------------ #

    def _finalise(self, result: ThreatIntelResult) -> None:
        detections = result.detections
        score = 0.0
        for name, detection in detections.items():
            weight = SOURCE_WEIGHTS.get(name, DEFAULT_WEIGHT)
            threshold = SOURCE_THRESHOLDS.get(name, DEFAULT_THRESHOLD)
            try:
                malicious = float(detection.get("malicious", 0) or 0)
            except (TypeError, ValueError):
                malicious = 0.0
            if malicious > 0:
                score += weight * min(malicious / threshold, 1.0)
        score = min(score, 100.0)

        openphish = _as_dict(detections.get("openphish"))
        phishtank = _as_dict(detections.get("phishtank"))
        safebrowsing = _as_dict(detections.get("google_safebrowsing"))
        urlhaus = _as_dict(detections.get("urlhaus"))
        authoritative = (
            bool(openphish.get("in_feed"))
            or bool(phishtank.get("malicious"))
            or bool(safebrowsing.get("threats"))
            or bool(urlhaus.get("listed"))
        )
        if authoritative:
            score = max(score, AUTHORITATIVE_FLOOR)

        result.total_score = round(score, 2)
        result.is_malicious = result.total_score >= MALICIOUS_THRESHOLD
        result.tags = self._build_tags(result)
        if urlhaus.get("firstseen"):
            result.first_seen = str(urlhaus["firstseen"])

    @staticmethod
    def _build_tags(result: ThreatIntelResult) -> List[str]:
        detections = result.detections
        tags: List[str] = []

        def add(tag: str) -> None:
            if tag not in tags:
                tags.append(tag)

        if result.is_malicious:
            add("malicious")
        openphish = _as_dict(detections.get("openphish"))
        phishtank = _as_dict(detections.get("phishtank"))
        if openphish.get("in_feed") or phishtank.get("malicious"):
            add("known_phish")
        for threat in _as_dict(detections.get("google_safebrowsing")).get("threats") or []:
            add(f"safebrowsing:{str(threat).lower()}")
        if _as_dict(detections.get("urlhaus")).get("listed"):
            add("urlhaus")
        categories = _as_dict(detections.get("virustotal")).get("categories") or []
        for category in list(categories)[:VT_MAX_CATEGORY_TAGS]:
            add(f"vt:{str(category).lower()}")
        if result.sources_checked and result.total_score == 0:
            add("clean")
        return tags


__all__ = [
    "AUTHORITATIVE_FLOOR",
    "AiohttpFetcher",
    "FetchResponse",
    "Fetcher",
    "MALICIOUS_THRESHOLD",
    "OPENPHISH_FEED_URL",
    "SOURCE_ORDER",
    "SOURCE_THRESHOLDS",
    "SOURCE_WEIGHTS",
    "StaticFetcher",
    "ThreatIntelEngine",
    "ThreatIntelResult",
    "ThreatIntelSourceError",
    "json_response",
]
