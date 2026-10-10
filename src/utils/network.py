#!/usr/bin/env python3
"""
BrandSentra - DNS, RDAP, WHOIS & TLS Utilities

Best-effort enrichment helpers. Every function swallows network errors and
returns ``None`` / empty structures so callers can enrich opportunistically
without wrapping each lookup in try/except. :func:`enrich_domain` bundles
them with per-step error reporting for the API and CLI.
"""

from __future__ import annotations

import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.utils.domain import parse_domain

logger = logging.getLogger("brandsentra.utils")

RDAP_BOOTSTRAP = "https://rdap.org/domain/{domain}"
DEFAULT_TIMEOUT = 6.0


def dns_resolve(domain: str, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, List[str]]:
    """Resolve common record types for a domain."""
    results: Dict[str, List[str]] = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "CNAME": [],
    }
    try:
        import dns.resolver  # type: ignore

        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        for rtype in results.keys():
            try:
                answers = resolver.resolve(domain, rtype)
                results[rtype] = [str(r).rstrip(".") for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                pass
            except Exception as exc:  # timeouts, SERVFAIL ...
                logger.debug("DNS %s %s failed: %s", domain, rtype, exc)
    except ImportError:  # pragma: no cover - dnspython is a declared dependency
        try:
            results["A"] = sorted(
                {i[4][0] for i in socket.getaddrinfo(domain, None, socket.AF_INET)}
            )
        except socket.gaierror:
            pass
    return results


def resolve_ips(domain: str, timeout: float = DEFAULT_TIMEOUT) -> List[str]:
    """A and AAAA addresses only."""
    records = dns_resolve(domain, timeout)
    return sorted(set(records.get("A", []) + records.get("AAAA", [])))


def whois_lookup(domain: str) -> Optional[Dict[str, Any]]:
    """Perform a WHOIS lookup (requires ``python-whois``)."""
    try:
        import whois  # type: ignore

        w = whois.whois(domain)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers,
            "status": w.status,
            "country": getattr(w, "country", None),
        }
    except Exception as exc:
        logger.debug("WHOIS lookup failed for %s: %s", domain, exc)
        return None


def reverse_ip_lookup(ip: str) -> List[str]:
    """Reverse-resolve an IP address."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return [hostname]
    except (socket.herror, socket.gaierror, OSError):
        return []


def _parse_rdap_datetime(value: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def parse_rdap(data: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise an RDAP domain object into a compact dict."""
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", []) or []}
    registrar = None
    abuse_email = None
    for entity in data.get("entities", []) or []:
        roles = entity.get("roles", []) or []
        vcard = entity.get("vcardArray", [None, []]) or [None, []]
        entries = vcard[1] if len(vcard) > 1 and isinstance(vcard[1], list) else []
        name = next((e[3] for e in entries if isinstance(e, list) and e and e[0] == "fn"), None)
        if "registrar" in roles and not registrar:
            registrar = name
        for sub in entity.get("entities", []) or []:
            if "abuse" in (sub.get("roles", []) or []):
                sub_vcard = sub.get("vcardArray", [None, []]) or [None, []]
                sub_entries = sub_vcard[1] if len(sub_vcard) > 1 else []
                abuse_email = next(
                    (e[3] for e in sub_entries if isinstance(e, list) and e and e[0] == "email"),
                    abuse_email,
                )
    created = events.get("registration")
    created_dt = _parse_rdap_datetime(created) if created else None
    age_days = None
    if created_dt:
        age_days = (datetime.now(timezone.utc) - created_dt.astimezone(timezone.utc)).days
    return {
        "handle": data.get("handle"),
        "ldh_name": data.get("ldhName"),
        "registrar": registrar,
        "abuse_email": abuse_email,
        "status": data.get("status", []),
        "nameservers": [ns.get("ldhName", "").lower() for ns in data.get("nameservers", []) or []],
        "created": created,
        "expires": events.get("expiration"),
        "last_changed": events.get("last changed"),
        "age_days": age_days,
        "dnssec": bool((data.get("secureDNS") or {}).get("delegationSigned")),
    }


def rdap_lookup(
    domain: str, timeout: float = DEFAULT_TIMEOUT, session: Any = None
) -> Optional[Dict[str, Any]]:
    """
    Registration data via RDAP (the JSON successor of WHOIS).

    Queries the IANA-backed ``rdap.org`` redirector for the registrable
    domain. Returns ``None`` when the registry has no RDAP service or the
    request fails.
    """
    parsed = parse_domain(domain)
    target = parsed.registrable or parsed.hostname
    if not target:
        return None
    try:
        import requests

        http = session or requests
        resp = http.get(
            RDAP_BOOTSTRAP.format(domain=target),
            timeout=timeout,
            headers={"Accept": "application/rdap+json, application/json"},
            allow_redirects=True,
        )
        if resp.status_code == 404:
            return {"ldh_name": target, "registered": False}
        if resp.status_code != 200:
            logger.debug("RDAP %s returned %s", target, resp.status_code)
            return None
        info = parse_rdap(resp.json())
        info["registered"] = True
        info.setdefault("ldh_name", target)
        return info
    except Exception as exc:
        logger.debug("RDAP lookup failed for %s: %s", target, exc)
        return None


def check_ssl_certificate(
    domain: str, port: int = 443, timeout: float = DEFAULT_TIMEOUT
) -> Optional[Dict[str, Any]]:
    """Retrieve the leaf TLS certificate presented by ``domain``."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # nosec B502 - we inspect, not trust, the certificate
        with socket.create_connection((domain, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=domain) as s:
                cert = s.getpeercert(binary_form=False) or {}
                if not cert:
                    der = s.getpeercert(binary_form=True)
                    return _parse_der_certificate(der) if der else None
                return _normalise_cert(cert)
    except Exception as exc:
        logger.debug("SSL check failed for %s: %s", domain, exc)
        return None


def _normalise_cert(cert: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "subject": dict(x[0] for x in cert.get("subject", ())),
        "issuer": dict(x[0] for x in cert.get("issuer", ())),
        "serial_number": cert.get("serialNumber"),
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
        "san": [entry[1] for entry in cert.get("subjectAltName", ())],
    }


def _parse_der_certificate(der: bytes) -> Optional[Dict[str, Any]]:
    try:
        from cryptography import x509  # type: ignore
        from cryptography.hazmat.primitives import hashes  # type: ignore

        cert = x509.load_der_x509_certificate(der)
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            names = san.get_values_for_type(x509.DNSName)
        except Exception:
            names = []
        return {
            "subject": {a.oid._name: a.value for a in cert.subject},
            "issuer": {a.oid._name: a.value for a in cert.issuer},
            "serial_number": format(cert.serial_number, "x"),
            "not_before": (
                cert.not_valid_before_utc.isoformat()
                if hasattr(cert, "not_valid_before_utc")
                else cert.not_valid_before.isoformat()
            ),
            "not_after": (
                cert.not_valid_after_utc.isoformat()
                if hasattr(cert, "not_valid_after_utc")
                else cert.not_valid_after.isoformat()
            ),
            "san": list(names),
            "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        }
    except Exception as exc:  # pragma: no cover - optional dependency path
        logger.debug("DER parse failed: %s", exc)
        return None


def enrich_domain(
    domain: str,
    dns: bool = True,
    rdap: bool = True,
    tls: bool = True,
    whois: bool = False,
    timeout: float = DEFAULT_TIMEOUT,
    lookups: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Run the enabled lookups and collect results plus per-step errors.

    ``lookups`` lets tests (or callers with custom resolvers) override the
    functions used for each step: keys ``dns``, ``rdap``, ``tls``, ``whois``.
    """
    funcs = {
        "dns": lambda d: dns_resolve(d, timeout),
        "rdap": lambda d: rdap_lookup(d, timeout),
        "tls": lambda d: check_ssl_certificate(d, timeout=timeout),
        "whois": whois_lookup,
    }
    funcs.update(lookups or {})
    parsed = parse_domain(domain)
    result: Dict[str, Any] = {
        "domain": parsed.hostname,
        "registrable": parsed.registrable,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "errors": {},
    }
    for name, enabled in (("dns", dns), ("rdap", rdap), ("tls", tls), ("whois", whois)):
        if not enabled:
            continue
        try:
            result[name] = funcs[name](parsed.hostname)
        except Exception as exc:
            result[name] = None
            result["errors"][name] = str(exc)
    dns_data = result.get("dns") or {}
    result["resolves"] = bool(dns_data.get("A") or dns_data.get("AAAA")) if dns else None
    return result


__all__ = [
    "check_ssl_certificate",
    "dns_resolve",
    "enrich_domain",
    "parse_rdap",
    "rdap_lookup",
    "resolve_ips",
    "reverse_ip_lookup",
    "whois_lookup",
]
