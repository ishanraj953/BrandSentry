#!/usr/bin/env python3
"""
BrandSentra - STIX 2.1 Export
Serialises phishing / brand-impersonation domain indicators as a STIX 2.1
bundle that SIEM and TIP platforms (MISP, OpenCTI, Splunk ES, Microsoft
Sentinel, ...) can ingest directly.

Only the Python standard library is used. All identifiers are derived with
UUIDv5 from a fixed namespace so repeated exports of the same data produce
the same STIX ids and can be safely re-imported / updated downstream.
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from src import __version__

logger = logging.getLogger("brandsentra.stix_export")

__all__ = [
    "TLP_MARKINGS",
    "KCW_NAMESPACE",
    "BRANDSENTRA_NAMESPACE",
    "stix_timestamp",
    "escape_pattern_value",
    "make_indicator",
    "build_stix_bundle",
    "bundle_to_json",
]

# Canonical TLP v1 marking-definition ids from the STIX 2.1 specification.
TLP_MARKINGS: Dict[str, str] = {
    "white": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "red": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}

# Creation timestamp mandated by the specification for the canonical TLP objects.
_TLP_CREATED = "2017-01-20T00:00:00.000Z"

# Fixed UUIDv5 namespace for every BrandSentra-generated STIX identifier.
KCW_NAMESPACE: uuid.UUID = uuid.UUID("6f1c9a4e-2b7d-5e83-9c05-4d8a1f3b7e62")
BRANDSENTRA_NAMESPACE: uuid.UUID = KCW_NAMESPACE

_DEFAULT_RISK_SCORE = 50.0
_BASE_LABELS = ("phishing", "brandsentra")


def stix_timestamp(dt: datetime) -> str:
    """Format a datetime as a STIX 2.1 timestamp with millisecond precision.

    Naive datetimes are assumed to already be in UTC; aware datetimes are
    converted to UTC before formatting.

    Args:
        dt: The datetime to format.

    Returns:
        A string of the form ``YYYY-MM-DDTHH:MM:SS.mmmZ``.
    """
    dt_utc = _to_utc(dt)
    millis = dt_utc.microsecond // 1000
    return dt_utc.strftime("%Y-%m-%dT%H:%M:%S") + f".{millis:03d}Z"


def escape_pattern_value(value: str) -> str:
    """Escape a string literal for use inside a STIX pattern.

    STIX patterning uses single-quoted string literals in which backslash and
    single quote must be escaped with a backslash.

    Args:
        value: The raw string value.

    Returns:
        The escaped string, safe to embed between single quotes in a pattern.
    """
    return value.replace("\\", "\\\\").replace("'", "\\'")


def make_indicator(
    record: Dict[str, Any],
    *,
    identity_id: str,
    marking_id: str,
    now: datetime,
) -> Dict[str, Any]:
    """Build a STIX 2.1 ``indicator`` object from a detection record.

    Only the ``domain`` key is required. Other keys (``risk_score``,
    ``risk_level``, ``categories``, ``first_seen``, ``last_seen``, ``source``,
    ``brand``, ``alert_type``, ``description``, ``matched_keywords``) are
    optional and interpreted leniently.

    Args:
        record: Detection record describing a suspicious domain.
        identity_id: STIX id of the producing ``identity`` object.
        marking_id: STIX id of the ``marking-definition`` to apply.
        now: Reference time used when the record carries no usable timestamps.

    Returns:
        A dictionary representing a STIX 2.1 indicator.

    Raises:
        ValueError: If the record has no usable ``domain``.
    """
    domain = _normalise_domain(record.get("domain"))
    if not domain:
        raise ValueError("record has no usable 'domain'")

    risk_score = _coerce_score(record.get("risk_score"))
    risk_level = _coerce_text(record.get("risk_level")).lower() or _derive_risk_level(risk_score)
    categories = _coerce_str_list(record.get("categories"))
    source = _coerce_text(record.get("source"))
    brand = _coerce_text(record.get("brand"))
    alert_type = _coerce_text(record.get("alert_type"))
    matched_keywords = _coerce_str_list(record.get("matched_keywords"))

    now_utc = _to_utc(now)
    created_dt = _parse_timestamp(record.get("first_seen")) or now_utc
    modified_dt = _parse_timestamp(record.get("last_seen")) or now_utc
    if modified_dt < created_dt:
        modified_dt = created_dt
    created = stix_timestamp(created_dt)
    modified = stix_timestamp(modified_dt)

    if brand:
        name = f"Brand impersonation of {brand}: {domain}"
    else:
        name = f"Suspected phishing domain: {domain}"

    description = _coerce_text(record.get("description")) or _synthesise_description(
        domain, risk_level, risk_score, categories, source, brand
    )

    label_set = set(categories)
    label_set.update(_BASE_LABELS)
    label_set.add(risk_level)
    if brand:
        label_set.add("brand-impersonation")
    labels = sorted(label_set)

    indicator_types = ["malicious-activity"] if risk_score >= 50 else ["anomalous-activity"]
    confidence = max(0, min(100, int(round(risk_score))))

    indicator: Dict[str, Any] = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": _indicator_id(domain),
        "created": created,
        "modified": modified,
        "created_by_ref": identity_id,
        "name": name,
        "description": description,
        "indicator_types": indicator_types,
        "pattern": f"[domain-name:value = '{escape_pattern_value(domain)}']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": created,
        "labels": labels,
        "confidence": confidence,
        "object_marking_refs": [marking_id],
    }

    if source:
        indicator["external_references"] = [
            {
                "source_name": source,
                "description": f"Detected by the BrandSentra '{source}' module",
            }
        ]

    indicator["x_brandsentra_risk_score"] = risk_score
    indicator["x_brandsentra_risk_level"] = risk_level
    if brand:
        indicator["x_brandsentra_brand"] = brand
    if alert_type:
        indicator["x_brandsentra_alert_type"] = alert_type
    if matched_keywords:
        indicator["x_brandsentra_matched_keywords"] = matched_keywords

    return indicator


def build_stix_bundle(
    records: Iterable[Dict[str, Any]],
    *,
    producer_name: str = "BrandSentra",
    tlp: str = "amber",
    now: Optional[datetime] = None,
    deterministic: bool = True,
) -> Dict[str, Any]:
    """Build a complete STIX 2.1 bundle from an iterable of detection records.

    The bundle contains the producer ``identity``, the canonical TLP
    ``marking-definition`` and one ``indicator`` per unique domain. Records
    are de-duplicated by domain (the highest ``risk_score`` wins) and records
    without a usable domain are skipped.

    Args:
        records: Any iterable (list, generator, ...) of detection records.
        producer_name: Name of the organisation producing the bundle.
        tlp: TLP colour: ``white``, ``green``, ``amber`` or ``red``.
        now: Reference time for the identity and for records without
            timestamps. Defaults to the current UTC time.
        deterministic: When ``True`` the bundle id is a UUIDv5 derived from the
            contained indicator ids; otherwise a random UUIDv4 is used.

    Returns:
        A dictionary representing a STIX 2.1 bundle.

    Raises:
        ValueError: If ``tlp`` is not a known TLP colour.
    """
    colour = _normalise_tlp(tlp)
    marking_id = TLP_MARKINGS[colour]
    now_utc = _to_utc(now) if now is not None else datetime.now(timezone.utc)

    identity_id = _identity_id(producer_name)
    identity = _make_identity(producer_name, identity_id, now_utc)
    marking = _make_tlp_marking(colour, marking_id)

    indicators: List[Dict[str, Any]] = [
        make_indicator(record, identity_id=identity_id, marking_id=marking_id, now=now_utc)
        for record in _dedupe_records(records)
    ]

    if deterministic:
        bundle_uuid = uuid.uuid5(KCW_NAMESPACE, ",".join(sorted(ind["id"] for ind in indicators)))
    else:
        bundle_uuid = uuid.uuid4()

    return {
        "type": "bundle",
        "id": f"bundle--{bundle_uuid}",
        "objects": [identity, marking, *indicators],
    }


def bundle_to_json(bundle: Dict[str, Any], indent: Optional[int] = 2) -> str:
    """Serialise a STIX bundle to a JSON string.

    Insertion order of keys is preserved and non-ASCII characters are emitted
    verbatim (``ensure_ascii=False``).

    Args:
        bundle: The bundle dictionary produced by :func:`build_stix_bundle`.
        indent: Indentation level passed to :func:`json.dumps`; ``None`` for
            the most compact output.

    Returns:
        The JSON representation of the bundle.
    """
    return json.dumps(bundle, indent=indent, ensure_ascii=False)


# --------------------------------------------------------------------------- #
# Internal helpers
# --------------------------------------------------------------------------- #


def _to_utc(dt: datetime) -> datetime:
    """Return ``dt`` as an aware UTC datetime (naive values are assumed UTC)."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _normalise_domain(value: Any) -> str:
    """Normalise a domain value to a stripped, lower-case string."""
    if value is None:
        return ""
    return str(value).strip().lower()


def _normalise_tlp(tlp: Any) -> str:
    """Validate and normalise a TLP colour, accepting an optional ``TLP:`` prefix."""
    colour = str(tlp or "").strip().lower()
    if colour.startswith("tlp:"):
        colour = colour[4:]
    if colour not in TLP_MARKINGS:
        valid = ", ".join(sorted(TLP_MARKINGS))
        raise ValueError(f"Unknown TLP colour {tlp!r}; expected one of: {valid}")
    return colour


def _coerce_text(value: Any) -> str:
    """Return ``value`` as a stripped string, or ``""`` when absent."""
    if value is None:
        return ""
    return str(value).strip()


def _coerce_score(value: Any) -> float:
    """Return ``value`` as a float risk score, falling back to the default."""
    if value is None or isinstance(value, bool):
        return _DEFAULT_RISK_SCORE
    try:
        score = float(value)
    except (TypeError, ValueError):
        return _DEFAULT_RISK_SCORE
    if score != score:  # NaN guard
        return _DEFAULT_RISK_SCORE
    return score


def _coerce_str_list(value: Any) -> List[str]:
    """Return ``value`` as a list of unique, non-empty strings (order preserved)."""
    if value is None:
        return []
    if isinstance(value, str):
        items: Iterable[Any] = [value]
    elif isinstance(value, (list, tuple, set, frozenset)):
        items = value
    else:
        items = [value]
    seen: Dict[str, None] = {}
    for item in items:
        text = _coerce_text(item)
        if text:
            seen.setdefault(text, None)
    return list(seen)


def _derive_risk_level(score: float) -> str:
    """Map a numeric risk score onto the BrandSentra risk level scale."""
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "clean"


def _parse_timestamp(value: Any) -> Optional[datetime]:
    """Parse a datetime or ISO-8601 string into an aware UTC datetime.

    Returns ``None`` when the value is missing or cannot be parsed.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return _to_utc(value)
    text = str(value).strip()
    if not text:
        return None
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        try:
            parsed = datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            logger.debug("Unparseable timestamp %r; falling back to 'now'", value)
            return None
    return _to_utc(parsed)


def _synthesise_description(
    domain: str,
    risk_level: str,
    risk_score: float,
    categories: List[str],
    source: str,
    brand: str,
) -> str:
    """Compose a human-readable description when the record provides none."""
    parts = [
        f"Domain {domain} was flagged by BrandSentra with {risk_level} risk "
        f"(score {risk_score:.1f}/100)."
    ]
    if brand:
        parts.append(f"It appears to impersonate {brand}.")
    if categories:
        parts.append("Categories: " + ", ".join(categories) + ".")
    if source:
        parts.append(f"Source: {source}.")
    return " ".join(parts)


def _indicator_id(domain: str) -> str:
    """Return the deterministic STIX id for a domain indicator."""
    return f"indicator--{uuid.uuid5(KCW_NAMESPACE, f'indicator:{domain}')}"


def _identity_id(producer_name: str) -> str:
    """Return the deterministic STIX id for a producer identity."""
    return f"identity--{uuid.uuid5(KCW_NAMESPACE, f'identity:{producer_name}')}"


def _make_identity(producer_name: str, identity_id: str, now: datetime) -> Dict[str, Any]:
    """Build the producer ``identity`` object."""
    timestamp = stix_timestamp(now)
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": timestamp,
        "modified": timestamp,
        "name": producer_name,
        "description": (
            f"{producer_name} - phishing detection and brand protection indicators "
            f"generated by BrandSentra v{__version__}."
        ),
        "identity_class": "organization",
        "sectors": ["technology"],
    }


def _make_tlp_marking(colour: str, marking_id: str) -> Dict[str, Any]:
    """Build the canonical TLP ``marking-definition`` object for ``colour``."""
    return {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": marking_id,
        "created": _TLP_CREATED,
        "definition_type": "tlp",
        "name": f"TLP:{colour.upper()}",
        "definition": {"tlp": colour},
    }


def _dedupe_records(records: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """De-duplicate records by normalised domain, keeping the highest risk score.

    Records that are not dictionaries or have no usable domain are skipped.
    First-seen order of domains is preserved.
    """
    best: Dict[str, Dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict):
            logger.debug("Skipping non-dict record: %r", record)
            continue
        domain = _normalise_domain(record.get("domain"))
        if not domain:
            logger.debug("Skipping record without a usable domain: %r", record)
            continue
        current = best.get(domain)
        if current is None or _coerce_score(record.get("risk_score")) > _coerce_score(
            current.get("risk_score")
        ):
            best[domain] = record
    return list(best.values())
