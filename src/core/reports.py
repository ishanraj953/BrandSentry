#!/usr/bin/env python3
"""
BrandSentra - Reporting & Exports

Builds operational summaries from the database and renders them as JSON
friendly dicts, Markdown (for the CLI / e-mail digests), CSV and the
Prometheus text exposition format used by ``/metrics``.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from src import __version__

ALERT_CSV_FIELDS = [
    "alert_id",
    "created_at",
    "severity",
    "status",
    "alert_type",
    "brand_name",
    "domain",
    "description",
    "assignee",
    "risk_score",
    "source",
]

INDICATOR_CSV_FIELDS = [
    "domain",
    "risk_score",
    "risk_level",
    "categories",
    "first_seen",
    "last_seen",
    "source",
    "brand",
    "alert_type",
]


def build_summary(db: Any, days: int = 7, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Assemble a dashboard/report summary for the last ``days`` days."""
    days = max(1, int(days))
    summary: Dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "version": __version__,
        "period_days": days,
        "totals": db.get_stats(),
        "alerts": db.alert_counts(days),
        "alerts_all_time": db.alert_counts(None),
        "timeseries": db.daily_timeseries(days),
        "top_domains": db.get_top_domains(limit=10),
        "recent_alerts": db.get_alerts(limit=10, open_only=True),
        "new_sightings": db.get_sightings(status="new", limit=10),
        "monitor": db.get_state("certstream.monitor"),
        "watcher": db.get_state("squat_watcher.last_run"),
    }
    if extra:
        summary.update(extra)
    return summary


def render_markdown(summary: Dict[str, Any]) -> str:
    """Render a :func:`build_summary` dict as a Markdown report."""
    totals = summary.get("totals", {})
    alerts = summary.get("alerts", {})
    lines: List[str] = [
        f"# BrandSentra Report ({summary.get('period_days', 7)} days)",
        "",
        f"_Generated {summary.get('generated_at', '')} by BrandSentra v{summary.get('version', '')}_",
        "",
        "## Totals",
        "",
        "| Metric | Value |",
        "|---|---:|",
    ]
    for key in (
        "total_domains",
        "phishing_detected",
        "critical_threats",
        "open_alerts",
        "total_alerts",
        "total_scans",
        "certstream_events",
        "squat_sightings",
        "new_sightings",
        "allowlist_entries",
    ):
        if key in totals:
            lines.append(f"| {key.replace('_', ' ').title()} | {totals[key]} |")

    lines += ["", f"## Alerts (last {summary.get('period_days', 7)} days)", ""]
    lines.append(f"- Total: **{alerts.get('total', 0)}**, open: **{alerts.get('open', 0)}**")
    for section, title in (
        ("by_severity", "By severity"),
        ("by_brand", "By brand"),
        ("by_type", "By type"),
    ):
        data = alerts.get(section) or {}
        if data:
            rendered = ", ".join(f"{k}: {v}" for k, v in list(data.items())[:8])
            lines.append(f"- {title}: {rendered}")

    series = summary.get("timeseries") or []
    if series:
        lines += [
            "",
            "## Daily activity",
            "",
            "| Date | Domains | Phishing | Alerts | Scans | Sightings |",
            "|---|---:|---:|---:|---:|---:|",
        ]
        for row in series:
            lines.append(
                f"| {row['date']} | {row.get('domains', 0)} | {row.get('phishing', 0)} | "
                f"{row.get('alerts', 0)} | {row.get('scans', 0)} | {row.get('sightings', 0)} |"
            )

    top = summary.get("top_domains") or []
    if top:
        lines += [
            "",
            "## Highest-risk domains",
            "",
            "| Domain | Score | Level | Last seen |",
            "|---|---:|---|---|",
        ]
        for d in top:
            lines.append(
                f"| `{d['domain']}` | {d.get('risk_score', 0):.0f} | {d.get('risk_level', '')} | {d.get('last_seen', '')[:19]} |"
            )

    recent = summary.get("recent_alerts") or []
    if recent:
        lines += ["", "## Open alerts", ""]
        for a in recent:
            lines.append(
                f"- **[{a.get('severity', '').upper()}]** `{a.get('domain', '')}` — {a.get('brand_name') or a.get('alert_type')} "
                f"({a.get('alert_type')}, {a.get('created_at', '')[:19]})"
            )

    sightings = summary.get("new_sightings") or []
    if sightings:
        lines += ["", "## New typosquat sightings", ""]
        for s in sightings:
            ips = ", ".join(s.get("ips") or []) or "-"
            lines.append(f"- `{s['domain']}` → {s.get('brand')} ({s.get('technique')}) IPs: {ips}")

    monitor = summary.get("monitor")
    if monitor:
        lines += ["", "## CertStream monitor", ""]
        for key in ("status", "total_certs", "matched_certs", "last_event", "start_time"):
            if key in monitor:
                lines.append(f"- {key.replace('_', ' ').title()}: {monitor[key]}")

    watcher = summary.get("watcher")
    if watcher:
        lines += ["", "## Squat watcher", ""]
        for key in ("finished_at", "brands", "candidates", "live", "new", "duration_seconds"):
            if key in watcher:
                lines.append(f"- {key.replace('_', ' ').title()}: {watcher[key]}")

    return "\n".join(lines) + "\n"


def rows_to_csv(rows: Iterable[Dict[str, Any]], fields: List[str]) -> str:
    """Serialise dict rows to CSV text with a fixed column order."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for row in rows:
        clean = {}
        for key in fields:
            value = row.get(key, "")
            if isinstance(value, (list, tuple, set)):
                value = "|".join(str(v) for v in value)
            elif isinstance(value, dict):
                value = ";".join(f"{k}={v}" for k, v in value.items())
            clean[key] = "" if value is None else value
        writer.writerow(clean)
    return buf.getvalue()


def alerts_to_csv(alerts: Iterable[Dict[str, Any]]) -> str:
    return rows_to_csv(alerts, ALERT_CSV_FIELDS)


def indicators_to_csv(records: Iterable[Dict[str, Any]]) -> str:
    return rows_to_csv(records, INDICATOR_CSV_FIELDS)


def _metric_name(name: str) -> str:
    return "".join(c if c.isalnum() or c == "_" else "_" for c in name)


def render_prometheus(
    stats: Dict[str, Any],
    alert_counts: Optional[Dict[str, Any]] = None,
    monitor_state: Optional[Dict[str, Any]] = None,
    extra: Optional[Dict[str, float]] = None,
    uptime_seconds: Optional[float] = None,
) -> str:
    """Render gauges in the Prometheus text exposition format."""
    lines: List[str] = []

    def gauge(
        name: str, value: Any, help_text: str, labels: Optional[Dict[str, str]] = None
    ) -> None:
        metric = _metric_name(f"brandsentra_{name}")
        if not any(line.startswith(f"# HELP {metric} ") for line in lines):
            lines.append(f"# HELP {metric} {help_text}")
            lines.append(f"# TYPE {metric} gauge")
        label_text = ""
        if labels:
            rendered = ",".join(
                f'{k}="{str(v).replace(chr(34), chr(39))}"' for k, v in labels.items()
            )
            label_text = "{" + rendered + "}"
        try:
            number = float(value)
        except (TypeError, ValueError):
            return
        lines.append(f"{metric}{label_text} {number:g}")

    gauge("info", 1, "Build information", {"version": __version__})
    if uptime_seconds is not None:
        gauge("uptime_seconds", uptime_seconds, "API process uptime in seconds")
    for key, value in stats.items():
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            gauge(key, value, f"Database counter {key}")
    if alert_counts:
        for sev, count in (alert_counts.get("by_severity") or {}).items():
            gauge("alerts_by_severity", count, "Alerts by severity", {"severity": sev})
        for status, count in (alert_counts.get("by_status") or {}).items():
            gauge("alerts_by_status", count, "Alerts by status", {"status": status})
        for brand, count in list((alert_counts.get("by_brand") or {}).items())[:50]:
            gauge("alerts_by_brand", count, "Alerts by brand", {"brand": brand})
    if monitor_state:
        for key in ("total_certs", "matched_certs", "reconnects", "errors"):
            if key in monitor_state:
                gauge(f"certstream_{key}", monitor_state[key], f"CertStream monitor {key}")
        gauge(
            "certstream_running",
            1 if monitor_state.get("status") == "running" else 0,
            "CertStream monitor running",
        )
    for key, value in (extra or {}).items():
        gauge(key, value, f"Runtime gauge {key}")
    return "\n".join(lines) + "\n"


__all__ = [
    "ALERT_CSV_FIELDS",
    "INDICATOR_CSV_FIELDS",
    "alerts_to_csv",
    "build_summary",
    "indicators_to_csv",
    "render_markdown",
    "render_prometheus",
    "rows_to_csv",
]
