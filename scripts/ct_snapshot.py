#!/usr/bin/env python3
"""
Tail Certificate Transparency logs for a while and publish the keyword matches as a
static JSON relay feed (``demo/feed/latest.json`` + a daily archive).

GitHub Actions runs this on a schedule so the GitHub Pages console can load real
matches from its own origin even when a browser cannot read the CT logs directly
(cross-origin restrictions). No third-party feed is involved: it is the same
dependency-free tailer and engine that power ``main.py monitor``.

Usage:
    python scripts/ct_snapshot.py --seconds 1500 --out demo/feed
    python scripts/ct_snapshot.py --seconds 30 --logs http://127.0.0.1:8899/   # local test log
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.config.settings import CertStreamConfig, Settings  # noqa: E402
from src.core.brand_monitor import BrandMonitor  # noqa: E402
from src.core.certstream_monitor import CertStreamMonitor  # noqa: E402
from src.core.phishing_detector import PhishingDetector  # noqa: E402

MAX_LATEST = 600
ARCHIVE_DAYS = 14
DISCLAIMER = (
    "Observations of public Certificate Transparency data: a hostname in a publicly logged "
    "certificate matched a watch keyword. Scores are automated heuristics, not accusations; "
    "verify independently before acting. See DISCLAIMER.md."
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def run_snapshot(
    seconds: float,
    out_dir: Path,
    logs: Optional[List[str]] = None,
    settings: Optional[Settings] = None,
    monitor: Optional[CertStreamMonitor] = None,
    now: Any = utcnow,
    sleep: Any = time.sleep,
    tailer_kwargs: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Tail logs for ``seconds`` and write the relay feed. Returns the summary written."""
    settings = settings or Settings()
    cfg: CertStreamConfig = settings.certstream
    if logs:
        cfg.ct_logs = list(logs)
    monitor = monitor or CertStreamMonitor(cfg, db=None)
    detector = PhishingDetector()
    brands = BrandMonitor(dedupe_window_seconds=0)
    matches: List[Dict[str, Any]] = []
    alerts: List[Dict[str, Any]] = []
    seen: set = set()

    def on_event(event: Any) -> None:
        # the same certificate is usually submitted to several logs: one row per hostname
        if event.domain in seen:
            return
        seen.add(event.domain)
        verdict = detector.analyze(
            event.domain, {"issuer": event.issuer_name, "is_wildcard": event.is_wildcard}
        )
        row = {
            "domain": event.domain,
            "ts": event.timestamp,
            "keywords": list(event.matched_keywords),
            "issuer": event.issuer_name,
            "score": round(verdict.risk_score, 1),
            "level": verdict.risk_level,
            "brands": list(verdict.matched_brands),
            "categories": list(verdict.categories),
            "log": event.source,
            "not_before": event.not_before,
            "wildcard": event.is_wildcard,
        }
        matches.append(row)
        for alert in brands.check_domain(event.domain, source="relay"):
            alerts.append(alert.to_dict() if hasattr(alert, "to_dict") else dict(vars(alert)))

    monitor.add_callback(on_event)
    kwargs = dict(tailer_kwargs or {})
    tailer = monitor.build_ct_tailer(**kwargs)
    started = now()
    tailer.discover()
    tailer._running = True  # noqa: SLF001 - drive the loop with our own deadline
    deadline = started + timedelta(seconds=seconds)
    while tailer.logs and now() < deadline:
        processed = tailer.poll_once()
        if not processed:
            sleep(min(tailer.poll_interval or 1.0, 2.0))
    tailer.stop()
    finished = now()
    summary = tailer.summary()
    latest = {
        "generated_at": finished.isoformat(),
        "started_at": started.isoformat(),
        "window_seconds": round((finished - started).total_seconds()),
        "keywords": len(monitor.keywords),
        "logs": summary["logs"],
        "coverage": summary["coverage"],
        "entries": summary["entries"],
        "matches": matches[-MAX_LATEST:],
        "alert_candidates": len(alerts),
        "engine": "python",
        "kind": "observations",
        "notice": DISCLAIMER,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "latest.json").write_text(json.dumps(latest, ensure_ascii=False, indent=0))
    _archive(out_dir / "archive", finished, matches, now)
    return latest


def _archive(
    archive_dir: Path, finished: datetime, matches: List[Dict[str, Any]], now: Any
) -> None:
    archive_dir.mkdir(parents=True, exist_ok=True)
    day_file = archive_dir / f"{finished.date().isoformat()}.json"
    existing: List[Dict[str, Any]] = []
    if day_file.exists():
        try:
            existing = json.loads(day_file.read_text(encoding="utf-8")).get("matches", [])
        except (ValueError, AttributeError):
            existing = []
    known = {(m.get("domain"), m.get("ts")) for m in existing}
    for m in matches:
        if (m["domain"], m["ts"]) not in known:
            existing.append(m)
            known.add((m["domain"], m["ts"]))
    day_file.write_text(
        json.dumps(
            {"date": finished.date().isoformat(), "notice": DISCLAIMER, "matches": existing},
            ensure_ascii=False,
        )
    )
    cutoff = (now() - timedelta(days=ARCHIVE_DAYS)).date().isoformat()
    for old in archive_dir.glob("*.json"):
        if old.stem < cutoff:
            old.unlink()
    index = sorted(p.stem for p in archive_dir.glob("*.json"))
    (archive_dir / "index.json").write_text(json.dumps(index))


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seconds", type=float, default=1500, help="how long to tail (default 25 min)")
    ap.add_argument("--out", default=str(ROOT / "demo" / "feed"), help="output directory")
    ap.add_argument(
        "--logs", nargs="*", help="explicit CT log URLs (append ' static' for tiled logs)"
    )
    args = ap.parse_args(argv)
    logs = None
    if args.logs:
        logs = [u if not u.endswith(" static") else u for u in args.logs]
    result = run_snapshot(args.seconds, Path(args.out), logs=logs)
    print(
        f"tailed {len(result['logs'])} log(s) for {result['window_seconds']}s: "
        f"{result['entries']} entries, {len(result['matches'])} matches, "
        f"{result['alert_candidates']} alert candidates"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
