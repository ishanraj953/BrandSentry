#!/usr/bin/env python3
"""
BrandSentra - Digital Risk Protection & Brand Intelligence Suite
Command line entry point.

Usage:
    python main.py monitor                      Start CertStream monitoring
    python main.py api | demo                   Start the API server + dashboard
    python main.py scan <domain> [--json]       Analyse one domain
    python main.py bulk <file|-> [--csv out]    Analyse many domains
    python main.py permutations <brand>         Generate squatting permutations
    python main.py watch-squats [--once]        Resolve permutations of protected brands
    python main.py report [--days 7]            Print an activity report
    python main.py allowlist list|add|remove    Manage the allowlist
    python main.py export-stix [--out file]     Export indicators as STIX 2.1
    python main.py config [--check]             Show effective configuration
    python main.py test-notify                  Send a test alert to every channel
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional

from src import __version__
from src.config.settings import Settings, load_config, to_dict, validate
from src.core.engine import (
    brand_alert_notification,
    build_engines,
    phishing_notification,
    run_scan,
)
from src.core.reports import build_summary, render_markdown, rows_to_csv
from src.core.stix_export import build_stix_bundle, bundle_to_json
from src.models.database import Database

logger = logging.getLogger("brandsentra")

BANNER = rf"""
 ____                       _ ____             _             
| __ ) _ __ __ _ _ __   __| / ___|  ___ _ __ | |_ _ __ __ _ 
|  _ \| '__/ _` | '_ \ / _` \___ \ / _ \ '_ \| __| '__/ _` |
| |_) | | | (_| | | | | (_| |___) |  __/ | | | |_| | | (_| |
|____/|_|  \__,_|_| |_|\__,_|____/ \___|_| |_|\__|_|  \__,_|
                                                        v{__version__}
    Digital Risk Protection & Brand Intelligence Suite
    BrandSentra Team
"""

LEVEL_ICONS = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "clean": "🟢"}


def _print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False, default=str))


def _engines(config: Settings, **kwargs: Any):
    return build_engines(config, db=Database(config.database.db_path), **kwargs)


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #


def cmd_monitor(config: Settings, args: argparse.Namespace) -> int:
    """Start CertStream real-time monitoring (or replay a capture file)."""
    from src.core.certstream_monitor import CertStreamMonitor

    state = _engines(config)
    db = state.db
    notify = not args.no_notify

    def on_cert_event(event: Any) -> None:
        context = {
            "issuer": event.issuer_name,
            "is_wildcard": event.is_wildcard,
            "source": "certstream",
        }
        verdict = state.detector.analyze(event.domain, context)
        db.add_domain(
            event.domain,
            verdict.risk_score,
            verdict.risk_level,
            verdict.is_phishing,
            verdict.categories,
            source="certstream",
            keywords=event.matched_keywords,
        )
        brand_alerts = state.brand_monitor.check_domain(event.domain, source="certstream")
        for alert in brand_alerts:
            db.add_alert(alert, source="certstream", risk_score=verdict.risk_score)
            if notify:
                state.notifier.dispatch(brand_alert_notification(alert))
        if verdict.risk_level in ("critical", "high"):
            logger.warning(
                "🚨 %s RISK: %s | Score: %.0f | %s",
                verdict.risk_level.upper(),
                event.domain,
                verdict.risk_score,
                verdict.explanation,
            )
            if notify and not brand_alerts:
                state.notifier.dispatch(phishing_notification(verdict))

    if getattr(args, "source", None):
        config.certstream.source = args.source
    monitor = CertStreamMonitor(config.certstream, db=db)
    monitor.add_callback(on_cert_event)

    if args.replay:
        count = 0
        with open(args.replay, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    message = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if "message_type" not in message:
                    message = {"message_type": "certificate_update", "data": message}
                monitor._handle_message(message)
                count += 1
        stats = monitor.heartbeat("replayed")
        print(
            f"Replayed {count} messages: {stats['matched_certs']} matching certificates, "
            f"{stats['matched_domains']} domains, {db.count_alerts()} alerts in database"
        )
        return 0

    logger.info("Starting live CT monitor (source=%s)...", config.certstream.source)
    try:
        monitor.start()
    except KeyboardInterrupt:
        monitor.stop()
        print("\nMonitor stopped.")
    return 0


def cmd_api(config: Settings, args: argparse.Namespace) -> int:
    """Start the API server (with the dashboard at /)."""
    from src.api.app import create_app

    if args.host:
        config.api.host = args.host
    if args.port:
        config.api.port = args.port
    elif "PORT" in os.environ:
        try:
            config.api.port = int(os.environ["PORT"])
        except ValueError:
            pass
    if args.debug or args.command == "demo":
        config.api.debug = True
    app = create_app(config)
    for warning in validate(config):
        logger.warning("config: %s", warning)
    logger.info("Starting API server on %s:%s", config.api.host, config.api.port)
    logger.info("Dashboard: http://localhost:%s/  API docs: /api/v1/docs", config.api.port)
    app.run(host=config.api.host, port=config.api.port, debug=config.api.debug)
    return 0


def _print_scan(result: Dict[str, Any]) -> None:
    phishing = result["phishing"]
    icon = LEVEL_ICONS.get(phishing["risk_level"], "")
    print(f"\n{'=' * 64}")
    print(f"  Scanning: {result['domain']}")
    print(f"{'=' * 64}\n")
    parsed = phishing.get("parsed", {})
    print(
        f"  Registrable: {parsed.get('registrable')}   Suffix: {parsed.get('suffix')}"
        f"   IDN: {'yes' if parsed.get('is_idn') else 'no'}"
    )
    if parsed.get("unicode_hostname") and parsed.get("unicode_hostname") != result["domain"]:
        print(f"  Unicode:     {parsed['unicode_hostname']}")
    print()
    print("  Phishing Detection:")
    print(f"    Risk Score:  {phishing['risk_score']:.1f}/100 {icon}")
    print(f"    Risk Level:  {phishing['risk_level'].upper()}")
    print(f"    Is Phishing: {'YES' if phishing['is_phishing'] else 'No'}")
    print(f"    Categories:  {', '.join(phishing['categories']) or 'None'}")
    if phishing.get("matched_brands"):
        print(f"    Brands:      {', '.join(phishing['matched_brands'])}")
    if result.get("allowlisted"):
        print("    Allowlisted: yes")
    print()
    if phishing["indicators"]:
        print(f"  Indicators ({len(phishing['indicators'])}):")
        for ind in phishing["indicators"]:
            print(f"    • {ind['type']}: {ind['detail']} (+{ind['weight']:g})")
        print()
    if result["domain_squatting"]:
        print("  Domain Squatting Analysis:")
        for r in result["domain_squatting"]:
            print(f"    Target:     {r['target']}")
            print(f"    Attacks:    {', '.join(r['attack_types'])}")
            print(f"    Similarity: {r['similarity']:.1%}   Confidence: {r['confidence']:.0%}")
            print(f"    Risk:       {r['risk_level'].upper()}")
            print()
    if result["brand_alerts"]:
        print(f"  Brand Alerts ({len(result['brand_alerts'])}):")
        for a in result["brand_alerts"]:
            print(f"    [{a['severity'].upper()}] {a['brand_name']}: {a['description']}")
        print()
    if "intel" in result:
        intel = result["intel"]
        if "error" in intel:
            print(f"  Threat Intel: error - {intel['error']}\n")
        else:
            print("  Threat Intelligence:")
            print(
                f"    Score:     {intel.get('total_score', 0):.0f}/100   "
                f"Malicious: {'YES' if intel.get('is_malicious') else 'no'}"
            )
            print(
                f"    Sources:   {', '.join(intel.get('sources_checked') or []) or 'none configured'}"
            )
            if intel.get("tags"):
                print(f"    Tags:      {', '.join(intel['tags'])}")
            if intel.get("errors"):
                print(f"    Errors:    {intel['errors']}")
            print()
    if "enrichment" in result:
        enr = result["enrichment"]
        print("  Enrichment:")
        dns = enr.get("dns") or {}
        print(
            f"    Resolves:  {'yes' if enr.get('resolves') else 'no'}"
            f"   A: {', '.join(dns.get('A') or []) or '-'}"
        )
        rdap = enr.get("rdap") or {}
        if rdap:
            print(
                f"    Registrar: {rdap.get('registrar') or '-'}   Created: {rdap.get('created') or '-'}"
                f"   Age: {rdap.get('age_days', '-')} days"
            )
        if enr.get("errors"):
            print(f"    Errors:    {enr['errors']}")
        print()
    print(f"  Recommendation: {phishing['recommendation']}")
    print(f"\n{'=' * 64}\n")


def cmd_scan(config: Settings, args: argparse.Namespace) -> int:
    """Scan a single domain."""
    state = _engines(config)
    try:
        result = run_scan(
            state,
            args.domain,
            with_intel=args.intel,
            with_enrich=args.enrich,
            persist=not args.no_persist,
            source="cli",
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        _print_json(result)
    else:
        _print_scan(result)
    return 1 if result["phishing"]["is_phishing"] and args.fail_on_phishing else 0


def _read_domains(path: str) -> List[str]:
    handle = sys.stdin if path == "-" else open(path, "r", encoding="utf-8")
    try:
        domains = []
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            domains.append(line.split(",")[0].strip())
        return domains
    finally:
        if handle is not sys.stdin:
            handle.close()


def cmd_bulk(config: Settings, args: argparse.Namespace) -> int:
    """Scan many domains from a file (one per line) or stdin."""
    state = _engines(config)
    domains = _read_domains(args.file)
    if not domains:
        print("error: no domains to scan", file=sys.stderr)
        return 2
    rows = []
    for domain in domains:
        try:
            result = run_scan(state, domain, persist=not args.no_persist, source="bulk")
        except ValueError:
            rows.append({"domain": domain, "error": "invalid"})
            continue
        phishing = result["phishing"]
        rows.append(
            {
                "domain": result["domain"],
                "risk_score": phishing["risk_score"],
                "risk_level": phishing["risk_level"],
                "is_phishing": phishing["is_phishing"],
                "categories": phishing["categories"],
                "matched_brands": phishing["matched_brands"],
                "brand_alerts": len(result["brand_alerts"]),
                "allowlisted": result["allowlisted"],
            }
        )
    rows.sort(key=lambda r: -float(r.get("risk_score", -1) or 0))
    if args.csv:
        fields = [
            "domain",
            "risk_score",
            "risk_level",
            "is_phishing",
            "categories",
            "matched_brands",
            "brand_alerts",
            "allowlisted",
            "error",
        ]
        text = rows_to_csv(rows, fields)
        if args.csv == "-":
            print(text, end="")
        else:
            with open(args.csv, "w", encoding="utf-8") as fh:
                fh.write(text)
            print(f"Wrote {len(rows)} rows to {args.csv}")
    elif args.json:
        _print_json({"results": rows, "total": len(rows)})
    else:
        print(f"\n{'Domain':45} {'Score':>6}  {'Level':9} Brands")
        print("-" * 80)
        for r in rows:
            if "error" in r:
                print(f"{r['domain']:45} {'':>6}  {'invalid':9}")
                continue
            icon = LEVEL_ICONS.get(r["risk_level"], "")
            print(
                f"{r['domain']:45} {r['risk_score']:6.1f}  {icon} {r['risk_level']:7} {', '.join(r['matched_brands'])}"
            )
        phishing = sum(1 for r in rows if r.get("is_phishing"))
        print("-" * 80)
        print(f"{len(rows)} domains scanned, {phishing} flagged as phishing\n")
    return 0


def cmd_permutations(config: Settings, args: argparse.Namespace) -> int:
    """Generate squatting permutations, optionally resolving them."""
    state = _engines(config)
    tlds = args.tlds or None
    perms = state.analyzer.generate_permutations_detailed(
        args.brand, tlds=tlds, include_combos=not args.no_combos, max_results=args.limit
    )
    live: Dict[str, List[str]] = {}
    if args.resolve:
        watcher = state.make_watcher(tlds=tlds, limit=args.limit, brands=[args.brand], notify=False)
        live = {
            d: ips for d, ips in watcher.resolve_many(p["domain"] for p in perms).items() if ips
        }
        for p in perms:
            p["ips"] = live.get(p["domain"], [])
    if args.json:
        _print_json(
            {"brand": args.brand, "total": len(perms), "live": len(live), "permutations": perms}
        )
        return 0
    print(
        f"\n{len(perms)} permutations of {args.brand}"
        + (f", {len(live)} resolving" if args.resolve else "")
    )
    print("-" * 64)
    for p in perms:
        if args.resolve and args.live_only and not p.get("ips"):
            continue
        suffix = f"  -> {', '.join(p['ips'])}" if p.get("ips") else ""
        print(f"  {p['domain']:40} {p['technique']}{suffix}")
    print()
    return 0


def cmd_watch_squats(config: Settings, args: argparse.Namespace) -> int:
    """Resolve permutations of every protected brand and record live ones."""
    state = _engines(config)
    watcher = state.make_watcher(
        tlds=args.tlds or None, brands=args.brand or None, notify=not args.no_notify
    )
    if args.once or args.json:
        summary = watcher.run_once()
        if args.json:
            _print_json(summary)
        else:
            print(
                f"\nChecked {summary['brands']} brands, {summary['candidates']} candidates: "
                f"{summary['live']} live, {summary['new']} new ({summary['duration_seconds']}s)"
            )
            for s in summary["sightings"]:
                flag = "NEW " if s["is_new"] else "    "
                print(
                    f"  {flag}{s['domain']:40} {s['brand']:22} {s['technique']:16} {', '.join(s['ips'])}"
                )
            print()
        return 0
    logger.info(
        "Squat watcher running every %ss (Ctrl+C to stop)", args.interval or watcher.interval
    )
    try:
        watcher.run_forever(interval=args.interval)
    except KeyboardInterrupt:
        watcher.stop()
        print("\nWatcher stopped.")
    return 0


def cmd_report(config: Settings, args: argparse.Namespace) -> int:
    """Print an activity report."""
    db = Database(config.database.db_path)
    summary = build_summary(db, days=args.days)
    text = json.dumps(summary, indent=2, default=str) if args.json else render_markdown(summary)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"Report written to {args.out}")
    else:
        print(text)
    return 0


def cmd_allowlist(config: Settings, args: argparse.Namespace) -> int:
    """Manage the allowlist."""
    state = _engines(config)
    if args.action == "list":
        entries = state.db.get_allowlist()
        if args.json:
            _print_json(entries)
        elif not entries:
            print("Allowlist is empty.")
        else:
            for e in entries:
                print(f"  {e['domain']:40} {e.get('reason', '')}  ({e.get('created_at', '')[:19]})")
        return 0
    if args.action == "add":
        created = state.add_allowlist(args.domain, reason=args.reason or "", added_by="cli")
        print(f"{'Added' if created else 'Already present'}: {args.domain}")
        return 0
    if args.action == "remove":
        removed = state.remove_allowlist(args.domain)
        print(f"{'Removed' if removed else 'Not found'}: {args.domain}")
        return 0 if removed else 1
    return 2


def cmd_export_stix(config: Settings, args: argparse.Namespace) -> int:
    """Export indicators as a STIX 2.1 bundle."""
    db = Database(config.database.db_path)
    bundle = build_stix_bundle(
        db.iter_indicator_records(min_risk=args.min_risk, limit=args.limit), tlp=args.tlp
    )
    text = bundle_to_json(bundle)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        count = sum(1 for o in bundle["objects"] if o["type"] == "indicator")
        print(f"Wrote {count} indicators to {args.out}")
    else:
        print(text)
    return 0


def cmd_config(config: Settings, args: argparse.Namespace) -> int:
    """Show the effective configuration and validation warnings."""
    warnings = validate(config)
    if args.json:
        _print_json(
            {"config_path": config.config_path, "config": to_dict(config), "warnings": warnings}
        )
    else:
        print(f"Config file: {config.config_path or '(defaults)'}")
        if not args.check:
            print(json.dumps(to_dict(config), indent=2, default=str))
        if warnings:
            print("\nWarnings:")
            for w in warnings:
                print(f"  - {w}")
        else:
            print("\nNo configuration warnings.")
    return 1 if (args.check and warnings) else 0


def cmd_test_notify(config: Settings, args: argparse.Namespace) -> int:
    """Send a synthetic alert through every configured channel."""
    state = _engines(config)
    channels = state.notifier.channels
    if not channels:
        print("No notification channels are enabled.")
        return 1
    results = state.notifier.test_channels()
    for name, ok in results.items():
        print(f"  {name:10} {'OK' if ok else 'FAILED'}")
    return 0 if all(results.values()) else 1


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="brandsentra", description="BrandSentra - Digital Risk Protection & Brand Intelligence Suite"
    )
    parser.add_argument("-c", "--config", help="path to a YAML config file")
    parser.add_argument("--log-level", help="override log level (DEBUG, INFO, WARNING ...)")
    parser.add_argument("--no-banner", action="store_true", help="do not print the banner")
    parser.add_argument("--version", action="version", version=f"BrandSentra {__version__}")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("monitor", help="Start live Certificate Transparency monitoring")
    p.add_argument("--no-notify", action="store_true", help="do not send notifications")
    p.add_argument(
        "--source",
        choices=("ctlogs", "certstream"),
        help="ctlogs = read CT logs directly (default, no third party); certstream = WebSocket",
    )
    p.add_argument(
        "--replay", metavar="FILE", help="replay a JSON-lines capture instead of connecting"
    )

    for name, help_text in (("api", "Start API server"), ("demo", "Start API with demo dashboard")):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--host")
        p.add_argument("--port", type=int)
        p.add_argument("--debug", action="store_true")

    p = sub.add_parser("scan", help="Scan a domain")
    p.add_argument("domain", help="domain, hostname or URL to scan")
    p.add_argument("--json", action="store_true", help="print JSON")
    p.add_argument("--intel", action="store_true", help="query threat-intelligence sources")
    p.add_argument("--enrich", action="store_true", help="DNS and RDAP enrichment")
    p.add_argument("--no-persist", action="store_true", help="do not store the scan")
    p.add_argument(
        "--fail-on-phishing", action="store_true", help="exit 1 when phishing is detected"
    )

    p = sub.add_parser("bulk", help="Scan domains from a file or stdin (-)")
    p.add_argument("file")
    p.add_argument("--json", action="store_true")
    p.add_argument("--csv", metavar="OUT", help="write CSV to OUT (or - for stdout)")
    p.add_argument("--no-persist", action="store_true")

    p = sub.add_parser("permutations", help="Generate squatting permutations of a brand")
    p.add_argument("brand")
    p.add_argument("--tlds", nargs="*", help="suffixes to combine with (default: the brand's own)")
    p.add_argument("--limit", type=int, default=500)
    p.add_argument("--no-combos", action="store_true")
    p.add_argument("--resolve", action="store_true", help="resolve candidates via DNS")
    p.add_argument(
        "--live-only", action="store_true", help="with --resolve, print only resolving names"
    )
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("watch-squats", help="Resolve permutations of protected brands")
    p.add_argument("--once", action="store_true", help="run a single pass and exit")
    p.add_argument("--interval", type=int, help="seconds between passes")
    p.add_argument("--brand", action="append", help="limit to this brand domain (repeatable)")
    p.add_argument("--tlds", nargs="*")
    p.add_argument("--no-notify", action="store_true")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("report", help="Print an activity report")
    p.add_argument("--days", type=int, default=7)
    p.add_argument("--json", action="store_true")
    p.add_argument("--out", help="write to a file")

    p = sub.add_parser("allowlist", help="Manage the allowlist")
    p.add_argument("action", choices=["list", "add", "remove"])
    p.add_argument("domain", nargs="?")
    p.add_argument("--reason")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("export-stix", help="Export indicators as a STIX 2.1 bundle")
    p.add_argument("--min-risk", type=float, default=40.0)
    p.add_argument("--limit", type=int, default=5000)
    p.add_argument("--tlp", default="amber", choices=["white", "green", "amber", "red"])
    p.add_argument("--out")

    p = sub.add_parser("config", help="Show effective configuration")
    p.add_argument("--json", action="store_true")
    p.add_argument("--check", action="store_true", help="only print warnings; exit 1 if any")

    sub.add_parser("test-notify", help="Send a test alert to every configured channel")
    sub.add_parser("version", help="Print the version")
    return parser


COMMANDS = {
    "monitor": cmd_monitor,
    "api": cmd_api,
    "demo": cmd_api,
    "scan": cmd_scan,
    "bulk": cmd_bulk,
    "permutations": cmd_permutations,
    "watch-squats": cmd_watch_squats,
    "report": cmd_report,
    "allowlist": cmd_allowlist,
    "export-stix": cmd_export_stix,
    "config": cmd_config,
    "test-notify": cmd_test_notify,
}


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "version":
        print(f"BrandSentra {__version__}")
        return 0
    if not args.command:
        print(BANNER)
        parser.print_help()
        return 0

    config = load_config(args.config)
    level = (args.log_level or config.log_level or "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    quiet = (
        getattr(args, "json", False)
        or args.no_banner
        or args.command
        in (
            "allowlist",
            "export-stix",
            "report",
            "config",
            "bulk",
        )
    )
    if not quiet:
        print(BANNER)

    if args.command == "allowlist" and args.action in ("add", "remove") and not args.domain:
        parser.error("allowlist add/remove requires a domain")

    handler = COMMANDS[args.command]
    return int(handler(config, args) or 0)


if __name__ == "__main__":
    sys.exit(main())
