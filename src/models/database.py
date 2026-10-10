#!/usr/bin/env python3
"""
BrandSentra - Database Layer

SQLite-backed storage for detected domains, alerts and their lifecycle,
scan history, CertStream events, the allowlist, typosquat sightings and
small key/value state shared between the API and monitor processes.

The class is safe to share between threads: every operation opens its own
short-lived connection (WAL mode) and writes are serialised with a lock.
``":memory:"`` is supported for tests by pinning a single connection.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import asdict, is_dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

SCHEMA_VERSION = 2

ALERT_STATUSES = ("open", "investigating", "resolved", "false_positive")
CLOSED_STATUSES = ("resolved", "false_positive")
SIGHTING_STATUSES = ("new", "monitoring", "takedown_requested", "resolved", "benign")


def utc_now_iso() -> str:
    """Current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _since_iso(days: Optional[int]) -> Optional[str]:
    if not days:
        return None
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def _to_dict(obj: Any) -> Dict[str, Any]:
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return dict(obj)
    if is_dataclass(obj):
        return asdict(obj)
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    return dict(vars(obj))


def _loads(value: Any, default: Any) -> Any:
    if value in (None, ""):
        return default
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


class Database:
    """SQLite database manager for BrandSentra."""

    def __init__(self, db_path: str = "data/brandsentra.db"):
        self.db_path = db_path
        self._lock = threading.RLock()
        self._memory_conn: Optional[sqlite3.Connection] = None
        if db_path != ":memory:":
            directory = os.path.dirname(db_path)
            if directory:
                os.makedirs(directory, exist_ok=True)
        else:
            self._memory_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._memory_conn.row_factory = sqlite3.Row
        self._init_db()

    # ------------------------------------------------------------------ #
    # Connection handling
    # ------------------------------------------------------------------ #

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Yield a connection; commits on success, rolls back on error."""
        with self._lock:
            if self._memory_conn is not None:
                conn = self._memory_conn
                try:
                    yield conn
                    conn.commit()
                except Exception:
                    conn.rollback()
                    raise
                return
            conn = sqlite3.connect(self.db_path, timeout=30)
            conn.row_factory = sqlite3.Row
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA foreign_keys=ON")
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS domains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    risk_score REAL DEFAULT 0,
                    risk_level TEXT DEFAULT 'clean',
                    is_phishing INTEGER DEFAULT 0,
                    categories TEXT DEFAULT '[]',
                    source TEXT DEFAULT '',
                    matched_keywords TEXT DEFAULT '[]',
                    seen_count INTEGER DEFAULT 1,
                    UNIQUE(domain)
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT UNIQUE NOT NULL,
                    brand_name TEXT,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    description TEXT,
                    evidence TEXT DEFAULT '{}',
                    status TEXT DEFAULT 'open',
                    created_at TEXT NOT NULL,
                    updated_at TEXT,
                    assignee TEXT,
                    notes TEXT DEFAULT '',
                    source TEXT DEFAULT '',
                    risk_score REAL DEFAULT 0,
                    resolved_at TEXT
                );

                CREATE TABLE IF NOT EXISTS alert_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT NOT NULL,
                    changed_at TEXT NOT NULL,
                    actor TEXT,
                    field TEXT NOT NULL,
                    old_value TEXT,
                    new_value TEXT
                );

                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    result TEXT NOT NULL,
                    risk_score REAL,
                    risk_level TEXT,
                    actor TEXT,
                    scanned_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS certstream_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    all_domains TEXT,
                    issuer TEXT,
                    fingerprint TEXT,
                    risk_score REAL DEFAULT 0,
                    matched_keywords TEXT,
                    source TEXT,
                    timestamp TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS allowlist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT UNIQUE NOT NULL,
                    reason TEXT DEFAULT '',
                    added_by TEXT DEFAULT '',
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS squat_sightings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT UNIQUE NOT NULL,
                    brand TEXT NOT NULL,
                    technique TEXT,
                    ips TEXT DEFAULT '[]',
                    source TEXT DEFAULT 'squat_watcher',
                    status TEXT DEFAULT 'new',
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    seen_count INTEGER DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS state (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_domains_risk ON domains(risk_score DESC);
                CREATE INDEX IF NOT EXISTS idx_domains_last_seen ON domains(last_seen DESC);
                CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
                CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
                CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_alerts_domain ON alerts(domain);
                CREATE INDEX IF NOT EXISTS idx_history_alert ON alert_history(alert_id);
                CREATE INDEX IF NOT EXISTS idx_scans_time ON scan_history(scanned_at DESC);
                CREATE INDEX IF NOT EXISTS idx_scans_domain ON scan_history(domain);
                CREATE INDEX IF NOT EXISTS idx_cert_time ON certstream_events(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_sightings_brand ON squat_sightings(brand);
                CREATE INDEX IF NOT EXISTS idx_sightings_status ON squat_sightings(status);
                """)
            self._migrate(conn)

    def _migrate(self, conn: sqlite3.Connection) -> None:
        """Bring databases created by older releases up to the current schema."""
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version >= SCHEMA_VERSION:
            return
        additions = {
            "alerts": {
                "notes": "TEXT DEFAULT ''",
                "source": "TEXT DEFAULT ''",
                "risk_score": "REAL DEFAULT 0",
                "resolved_at": "TEXT",
            },
            "domains": {"seen_count": "INTEGER DEFAULT 1"},
            "scan_history": {
                "risk_score": "REAL",
                "risk_level": "TEXT",
                "actor": "TEXT",
            },
            "certstream_events": {"source": "TEXT"},
        }
        for table, columns in additions.items():
            existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
            for column, ddl in columns.items():
                if column not in existing:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    # ------------------------------------------------------------------ #
    # Domains
    # ------------------------------------------------------------------ #

    def add_domain(
        self,
        domain: str,
        risk_score: float,
        risk_level: str,
        is_phishing: bool,
        categories: List[str],
        source: str = "",
        keywords: Optional[List[str]] = None,
    ) -> None:
        """Insert or refresh a detected domain."""
        now = utc_now_iso()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO domains (domain, first_seen, last_seen, risk_score, risk_level,
                                     is_phishing, categories, source, matched_keywords, seen_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                ON CONFLICT(domain) DO UPDATE SET
                    last_seen=excluded.last_seen,
                    risk_score=excluded.risk_score,
                    risk_level=excluded.risk_level,
                    is_phishing=excluded.is_phishing,
                    categories=excluded.categories,
                    matched_keywords=excluded.matched_keywords,
                    seen_count=domains.seen_count + 1
                """,
                (
                    domain.lower(),
                    now,
                    now,
                    float(risk_score),
                    risk_level,
                    int(bool(is_phishing)),
                    json.dumps(list(categories or [])),
                    source,
                    json.dumps(list(keywords or [])),
                ),
            )

    def get_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM domains WHERE domain = ?", (domain.lower(),)
            ).fetchone()
        return self._domain_row(row) if row else None

    def get_recent_domains(
        self, limit: int = 50, min_risk: Optional[float] = None, since: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        clauses, params = [], []
        if min_risk is not None:
            clauses.append("risk_score >= ?")
            params.append(float(min_risk))
        if since:
            clauses.append("last_seen >= ?")
            params.append(since)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM domains {where} ORDER BY last_seen DESC LIMIT ?",
                (*params, int(limit)),
            ).fetchall()
        return [self._domain_row(r) for r in rows]

    def get_top_domains(self, limit: int = 20, min_risk: float = 40.0) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM domains WHERE risk_score >= ? ORDER BY risk_score DESC, "
                "last_seen DESC LIMIT ?",
                (float(min_risk), int(limit)),
            ).fetchall()
        return [self._domain_row(r) for r in rows]

    def count_domains(self, since: Optional[str] = None, phishing_only: bool = False) -> int:
        clauses, params = [], []
        if since:
            clauses.append("last_seen >= ?")
            params.append(since)
        if phishing_only:
            clauses.append("is_phishing = 1")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._connect() as conn:
            return conn.execute(f"SELECT COUNT(*) FROM domains {where}", params).fetchone()[0]

    @staticmethod
    def _domain_row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        d["categories"] = _loads(d.get("categories"), [])
        d["matched_keywords"] = _loads(d.get("matched_keywords"), [])
        d["is_phishing"] = bool(d.get("is_phishing"))
        return d

    # ------------------------------------------------------------------ #
    # Alerts
    # ------------------------------------------------------------------ #

    def add_alert(self, alert: Any, source: str = "", risk_score: Optional[float] = None) -> bool:
        """
        Persist an alert (dict, dataclass or object with matching attributes).

        Returns ``True`` when a new row was inserted, ``False`` if ``alert_id``
        already existed.
        """
        data = _to_dict(alert)
        alert_id = data.get("alert_id")
        if not alert_id:
            raise ValueError("alert requires an alert_id")
        evidence = data.get("evidence") or {}
        domain = data.get("domain") or evidence.get("suspicious_domain") or ""
        created = data.get("detected_at") or data.get("created_at") or utc_now_iso()
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT OR IGNORE INTO alerts
                    (alert_id, brand_name, alert_type, severity, domain, description, evidence,
                     status, created_at, updated_at, assignee, notes, source, risk_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert_id,
                    data.get("brand_name") or data.get("brand"),
                    data.get("alert_type") or data.get("type") or "unknown",
                    data.get("severity") or "medium",
                    str(domain).lower(),
                    data.get("description") or data.get("message") or "",
                    json.dumps(evidence, default=str),
                    data.get("status") or "open",
                    created,
                    created,
                    data.get("assignee"),
                    data.get("notes") or "",
                    source or data.get("source") or "",
                    float(risk_score if risk_score is not None else data.get("risk_score") or 0),
                ),
            )
            return cur.rowcount == 1

    def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
        return self._alert_row(row) if row else None

    def _alert_filters(
        self,
        status: Optional[str],
        severity: Optional[str],
        brand: Optional[str],
        domain: Optional[str],
        since: Optional[str],
        alert_type: Optional[str] = None,
        open_only: bool = False,
    ) -> Tuple[str, List[Any]]:
        clauses: List[str] = []
        params: List[Any] = []
        if status:
            statuses = [s.strip() for s in status.split(",") if s.strip()]
            clauses.append(f"status IN ({','.join('?' * len(statuses))})")
            params.extend(statuses)
        if open_only:
            clauses.append("status NOT IN ('resolved', 'false_positive')")
        if severity:
            sevs = [s.strip() for s in severity.split(",") if s.strip()]
            clauses.append(f"severity IN ({','.join('?' * len(sevs))})")
            params.extend(sevs)
        if brand:
            clauses.append("brand_name LIKE ?")
            params.append(f"%{brand}%")
        if domain:
            clauses.append("domain LIKE ?")
            params.append(f"%{domain.lower()}%")
        if alert_type:
            clauses.append("alert_type = ?")
            params.append(alert_type)
        if since:
            clauses.append("created_at >= ?")
            params.append(since)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return where, params

    def get_alerts(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        brand: Optional[str] = None,
        domain: Optional[str] = None,
        since: Optional[str] = None,
        alert_type: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
        order: str = "desc",
        open_only: bool = False,
    ) -> List[Dict[str, Any]]:
        where, params = self._alert_filters(
            status, severity, brand, domain, since, alert_type, open_only
        )
        direction = "ASC" if str(order).lower() == "asc" else "DESC"
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM alerts {where} ORDER BY created_at {direction}, id {direction} "
                "LIMIT ? OFFSET ?",
                (*params, int(limit), int(offset)),
            ).fetchall()
        return [self._alert_row(r) for r in rows]

    def count_alerts(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        brand: Optional[str] = None,
        domain: Optional[str] = None,
        since: Optional[str] = None,
        alert_type: Optional[str] = None,
        open_only: bool = False,
    ) -> int:
        where, params = self._alert_filters(
            status, severity, brand, domain, since, alert_type, open_only
        )
        with self._connect() as conn:
            return conn.execute(f"SELECT COUNT(*) FROM alerts {where}", params).fetchone()[0]

    def update_alert(
        self,
        alert_id: str,
        status: Optional[str] = None,
        assignee: Optional[str] = None,
        notes: Optional[str] = None,
        actor: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Update lifecycle fields of an alert and record the change history."""
        if status is not None and status not in ALERT_STATUSES:
            raise ValueError(f"invalid status {status!r}; expected one of {ALERT_STATUSES}")
        current = self.get_alert(alert_id)
        if current is None:
            return None
        now = utc_now_iso()
        changes: List[Tuple[str, Any, Any]] = []
        updates: Dict[str, Any] = {"updated_at": now}
        if status is not None and status != current["status"]:
            changes.append(("status", current["status"], status))
            updates["status"] = status
            updates["resolved_at"] = now if status in CLOSED_STATUSES else None
        if assignee is not None and assignee != current.get("assignee"):
            changes.append(("assignee", current.get("assignee"), assignee))
            updates["assignee"] = assignee
        if notes is not None and notes != current.get("notes"):
            changes.append(("notes", current.get("notes"), notes))
            updates["notes"] = notes
        if not changes:
            return current
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        with self._connect() as conn:
            conn.execute(
                f"UPDATE alerts SET {set_clause} WHERE alert_id = ?",
                (*updates.values(), alert_id),
            )
            conn.executemany(
                "INSERT INTO alert_history (alert_id, changed_at, actor, field, old_value, "
                "new_value) VALUES (?, ?, ?, ?, ?, ?)",
                [
                    (alert_id, now, actor, fld, json.dumps(old), json.dumps(new))
                    for fld, old, new in changes
                ],
            )
        return self.get_alert(alert_id)

    def get_alert_history(self, alert_id: str) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM alert_history WHERE alert_id = ? ORDER BY id ASC", (alert_id,)
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["old_value"] = _loads(d.get("old_value"), d.get("old_value"))
            d["new_value"] = _loads(d.get("new_value"), d.get("new_value"))
            out.append(d)
        return out

    def alert_counts(self, days: Optional[int] = None) -> Dict[str, Any]:
        since = _since_iso(days)
        where = "WHERE created_at >= ?" if since else ""
        params = [since] if since else []
        with self._connect() as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM alerts {where}", params).fetchone()[0]
            open_where = f"{where} {'AND' if where else 'WHERE'} status NOT IN ('resolved', 'false_positive')"
            open_count = conn.execute(
                f"SELECT COUNT(*) FROM alerts {open_where}", params
            ).fetchone()[0]

            def group(col: str) -> Dict[str, int]:
                rows = conn.execute(
                    f"SELECT {col} AS k, COUNT(*) AS c FROM alerts {where} GROUP BY {col} "
                    "ORDER BY c DESC",
                    params,
                ).fetchall()
                return {str(r["k"]): r["c"] for r in rows if r["k"] is not None}

            return {
                "total": total,
                "open": open_count,
                "by_severity": group("severity"),
                "by_status": group("status"),
                "by_brand": group("brand_name"),
                "by_type": group("alert_type"),
            }

    @staticmethod
    def _alert_row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        d["evidence"] = _loads(d.get("evidence"), {})
        return d

    # ------------------------------------------------------------------ #
    # Scan history
    # ------------------------------------------------------------------ #

    def add_scan(
        self,
        domain: str,
        scan_type: str,
        result: Any,
        risk_score: Optional[float] = None,
        risk_level: Optional[str] = None,
        actor: Optional[str] = None,
    ) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO scan_history (domain, scan_type, result, risk_score, risk_level, "
                "actor, scanned_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    domain.lower(),
                    scan_type,
                    json.dumps(result, default=str),
                    risk_score,
                    risk_level,
                    actor,
                    utc_now_iso(),
                ),
            )
            return int(cur.lastrowid or 0)

    def get_scan_history(
        self, limit: int = 50, domain: Optional[str] = None, since: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        clauses, params = [], []
        if domain:
            clauses.append("domain LIKE ?")
            params.append(f"%{domain.lower()}%")
        if since:
            clauses.append("scanned_at >= ?")
            params.append(since)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM scan_history {where} ORDER BY scanned_at DESC, id DESC LIMIT ?",
                (*params, int(limit)),
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["result"] = _loads(d.get("result"), {})
            out.append(d)
        return out

    def count_scans(self, since: Optional[str] = None) -> int:
        where = "WHERE scanned_at >= ?" if since else ""
        params = [since] if since else []
        with self._connect() as conn:
            return conn.execute(f"SELECT COUNT(*) FROM scan_history {where}", params).fetchone()[0]

    # ------------------------------------------------------------------ #
    # CertStream events
    # ------------------------------------------------------------------ #

    def add_certstream_event(self, event: Any) -> int:
        data = _to_dict(event)
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO certstream_events (domain, all_domains, issuer, fingerprint, "
                "risk_score, matched_keywords, source, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(data.get("domain", "")).lower(),
                    json.dumps(data.get("all_domains") or []),
                    (
                        data.get("issuer")
                        if isinstance(data.get("issuer"), str)
                        else json.dumps(data.get("issuer") or {})
                    ),
                    data.get("fingerprint"),
                    float(data.get("risk_score") or 0),
                    json.dumps(data.get("matched_keywords") or []),
                    data.get("source"),
                    data.get("timestamp") or utc_now_iso(),
                ),
            )
            return int(cur.lastrowid or 0)

    def get_recent_certstream_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM certstream_events ORDER BY timestamp DESC, id DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["all_domains"] = _loads(d.get("all_domains"), [])
            d["matched_keywords"] = _loads(d.get("matched_keywords"), [])
            out.append(d)
        return out

    def count_certstream_events(self, since: Optional[str] = None) -> int:
        where = "WHERE timestamp >= ?" if since else ""
        params = [since] if since else []
        with self._connect() as conn:
            return conn.execute(
                f"SELECT COUNT(*) FROM certstream_events {where}", params
            ).fetchone()[0]

    # ------------------------------------------------------------------ #
    # Allowlist
    # ------------------------------------------------------------------ #

    def add_allowlist(self, domain: str, reason: str = "", added_by: str = "") -> bool:
        domain = domain.strip().lower().lstrip("*.")
        if not domain:
            raise ValueError("domain is required")
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT OR IGNORE INTO allowlist (domain, reason, added_by, created_at) "
                "VALUES (?, ?, ?, ?)",
                (domain, reason, added_by, utc_now_iso()),
            )
            return cur.rowcount == 1

    def remove_allowlist(self, domain: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM allowlist WHERE domain = ?", (domain.strip().lower(),))
            return cur.rowcount > 0

    def get_allowlist(self) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM allowlist ORDER BY domain ASC").fetchall()
        return [dict(r) for r in rows]

    def allowlist_domains(self) -> List[str]:
        return [row["domain"] for row in self.get_allowlist()]

    def is_allowlisted(self, domain: str) -> bool:
        """True when ``domain`` or one of its parents is allowlisted."""
        domain = domain.strip().lower()
        if not domain:
            return False
        parts = domain.split(".")
        candidates = [".".join(parts[i:]) for i in range(len(parts))]
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT 1 FROM allowlist WHERE domain IN ({','.join('?' * len(candidates))}) "
                "LIMIT 1",
                candidates,
            ).fetchone()
        return row is not None

    # ------------------------------------------------------------------ #
    # Typosquat sightings
    # ------------------------------------------------------------------ #

    def upsert_sighting(
        self,
        domain: str,
        brand: str,
        technique: str = "",
        ips: Optional[List[str]] = None,
        source: str = "squat_watcher",
    ) -> Tuple[bool, Dict[str, Any]]:
        """Record a live typosquat; returns ``(is_new, row)``."""
        domain = domain.strip().lower()
        now = utc_now_iso()
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT id FROM squat_sightings WHERE domain = ?", (domain,)
            ).fetchone()
            if existing:
                conn.execute(
                    "UPDATE squat_sightings SET last_seen = ?, ips = ?, seen_count = seen_count + 1 "
                    "WHERE domain = ?",
                    (now, json.dumps(sorted(set(ips or []))), domain),
                )
                is_new = False
            else:
                conn.execute(
                    "INSERT INTO squat_sightings (domain, brand, technique, ips, source, status, "
                    "first_seen, last_seen, seen_count) VALUES (?, ?, ?, ?, ?, 'new', ?, ?, 1)",
                    (
                        domain,
                        brand,
                        technique,
                        json.dumps(sorted(set(ips or []))),
                        source,
                        now,
                        now,
                    ),
                )
                is_new = True
            row = conn.execute(
                "SELECT * FROM squat_sightings WHERE domain = ?", (domain,)
            ).fetchone()
        return is_new, self._sighting_row(row)

    def get_sighting(self, domain: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM squat_sightings WHERE domain = ?", (domain.strip().lower(),)
            ).fetchone()
        return self._sighting_row(row) if row else None

    def get_sightings(
        self,
        brand: Optional[str] = None,
        status: Optional[str] = None,
        since: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        clauses, params = [], []
        if brand:
            clauses.append("brand LIKE ?")
            params.append(f"%{brand}%")
        if status:
            clauses.append("status = ?")
            params.append(status)
        if since:
            clauses.append("last_seen >= ?")
            params.append(since)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM squat_sightings {where} ORDER BY first_seen DESC, id DESC "
                "LIMIT ? OFFSET ?",
                (*params, int(limit), int(offset)),
            ).fetchall()
        return [self._sighting_row(r) for r in rows]

    def count_sightings(self, status: Optional[str] = None, since: Optional[str] = None) -> int:
        clauses, params = [], []
        if status:
            clauses.append("status = ?")
            params.append(status)
        if since:
            clauses.append("first_seen >= ?")
            params.append(since)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._connect() as conn:
            return conn.execute(f"SELECT COUNT(*) FROM squat_sightings {where}", params).fetchone()[
                0
            ]

    def update_sighting_status(self, domain: str, status: str) -> Optional[Dict[str, Any]]:
        if status not in SIGHTING_STATUSES:
            raise ValueError(f"invalid status {status!r}; expected one of {SIGHTING_STATUSES}")
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE squat_sightings SET status = ? WHERE domain = ?",
                (status, domain.strip().lower()),
            )
            if cur.rowcount == 0:
                return None
        return self.get_sighting(domain)

    @staticmethod
    def _sighting_row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        d["ips"] = _loads(d.get("ips"), [])
        return d

    # ------------------------------------------------------------------ #
    # Key / value state
    # ------------------------------------------------------------------ #

    def set_state(self, key: str, value: Any) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO state (key, value, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                (key, json.dumps(value, default=str), utc_now_iso()),
            )

    def get_state(self, key: str, default: Any = None) -> Any:
        with self._connect() as conn:
            row = conn.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
        if row is None:
            return default
        return _loads(row["value"], default)

    def get_state_entry(self, key: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT key, value, updated_at FROM state WHERE key = ?", (key,)
            ).fetchone()
        if row is None:
            return None
        return {
            "key": row["key"],
            "value": _loads(row["value"], None),
            "updated_at": row["updated_at"],
        }

    def get_all_state(self) -> Dict[str, Any]:
        with self._connect() as conn:
            rows = conn.execute("SELECT key, value FROM state").fetchall()
        return {r["key"]: _loads(r["value"], None) for r in rows}

    # ------------------------------------------------------------------ #
    # Reporting
    # ------------------------------------------------------------------ #

    def get_stats(self) -> Dict[str, Any]:
        with self._connect() as conn:
            q = conn.execute
            stats = {
                "total_domains": q("SELECT COUNT(*) FROM domains").fetchone()[0],
                "phishing_detected": q(
                    "SELECT COUNT(*) FROM domains WHERE is_phishing=1"
                ).fetchone()[0],
                "critical_threats": q(
                    "SELECT COUNT(*) FROM domains WHERE risk_level='critical'"
                ).fetchone()[0],
                "high_threats": q(
                    "SELECT COUNT(*) FROM domains WHERE risk_level='high'"
                ).fetchone()[0],
                "total_alerts": q("SELECT COUNT(*) FROM alerts").fetchone()[0],
                "open_alerts": q(
                    "SELECT COUNT(*) FROM alerts WHERE status NOT IN ('resolved','false_positive')"
                ).fetchone()[0],
                "total_scans": q("SELECT COUNT(*) FROM scan_history").fetchone()[0],
                "certstream_events": q("SELECT COUNT(*) FROM certstream_events").fetchone()[0],
                "allowlist_entries": q("SELECT COUNT(*) FROM allowlist").fetchone()[0],
                "squat_sightings": q("SELECT COUNT(*) FROM squat_sightings").fetchone()[0],
                "new_sightings": q(
                    "SELECT COUNT(*) FROM squat_sightings WHERE status='new'"
                ).fetchone()[0],
            }
            last = q("SELECT MAX(last_seen) FROM domains").fetchone()[0]
            stats["last_domain_seen"] = last
        return stats

    def daily_timeseries(self, days: int = 7) -> List[Dict[str, Any]]:
        """Per-day counts of domains, phishing domains, alerts and scans."""
        days = max(1, int(days))
        start = datetime.now(timezone.utc).date() - timedelta(days=days - 1)
        buckets: Dict[str, Dict[str, int]] = {
            (start + timedelta(days=i)).isoformat(): {
                "domains": 0,
                "phishing": 0,
                "alerts": 0,
                "critical_alerts": 0,
                "scans": 0,
                "sightings": 0,
            }
            for i in range(days)
        }
        since = start.isoformat()
        with self._connect() as conn:
            for row in conn.execute(
                "SELECT substr(last_seen,1,10) AS d, COUNT(*) AS c, SUM(is_phishing) AS p "
                "FROM domains WHERE last_seen >= ? GROUP BY d",
                (since,),
            ):
                if row["d"] in buckets:
                    buckets[row["d"]]["domains"] = row["c"]
                    buckets[row["d"]]["phishing"] = int(row["p"] or 0)
            for row in conn.execute(
                "SELECT substr(created_at,1,10) AS d, COUNT(*) AS c, "
                "SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) AS crit "
                "FROM alerts WHERE created_at >= ? GROUP BY d",
                (since,),
            ):
                if row["d"] in buckets:
                    buckets[row["d"]]["alerts"] = row["c"]
                    buckets[row["d"]]["critical_alerts"] = int(row["crit"] or 0)
            for row in conn.execute(
                "SELECT substr(scanned_at,1,10) AS d, COUNT(*) AS c FROM scan_history "
                "WHERE scanned_at >= ? GROUP BY d",
                (since,),
            ):
                if row["d"] in buckets:
                    buckets[row["d"]]["scans"] = row["c"]
            for row in conn.execute(
                "SELECT substr(first_seen,1,10) AS d, COUNT(*) AS c FROM squat_sightings "
                "WHERE first_seen >= ? GROUP BY d",
                (since,),
            ):
                if row["d"] in buckets:
                    buckets[row["d"]]["sightings"] = row["c"]
        return [{"date": d, **counts} for d, counts in buckets.items()]

    def iter_indicator_records(
        self, min_risk: float = 40.0, limit: int = 5000, include_alerts: bool = True
    ) -> Iterable[Dict[str, Any]]:
        """Yield indicator dicts (for STIX/CSV export) from domains and alerts."""
        seen = set()
        for d in self.get_top_domains(limit=limit, min_risk=min_risk):
            seen.add(d["domain"])
            yield {
                "domain": d["domain"],
                "risk_score": d["risk_score"],
                "risk_level": d["risk_level"],
                "categories": d["categories"],
                "first_seen": d["first_seen"],
                "last_seen": d["last_seen"],
                "source": d.get("source") or "brandsentra",
                "matched_keywords": d.get("matched_keywords") or [],
            }
        if not include_alerts:
            return
        for a in self.get_alerts(limit=limit, open_only=True):
            if a["domain"] in seen or not a["domain"]:
                continue
            seen.add(a["domain"])
            severity_score = {"critical": 90, "high": 70, "medium": 50, "low": 30}
            yield {
                "domain": a["domain"],
                "risk_score": a.get("risk_score") or severity_score.get(a["severity"], 50),
                "risk_level": a["severity"],
                "categories": [a["alert_type"]],
                "first_seen": a["created_at"],
                "last_seen": a.get("updated_at") or a["created_at"],
                "source": a.get("source") or "brand_monitor",
                "brand": a.get("brand_name"),
                "alert_type": a["alert_type"],
                "description": a.get("description"),
            }

    # ------------------------------------------------------------------ #
    # Maintenance
    # ------------------------------------------------------------------ #

    def purge_older_than(self, days: int) -> Dict[str, int]:
        """Delete closed alerts, scans and events older than ``days``."""
        cutoff = _since_iso(days)
        if not cutoff:
            return {}
        with self._connect() as conn:
            removed = {
                "alerts": conn.execute(
                    "DELETE FROM alerts WHERE created_at < ? AND status IN ('resolved','false_positive')",
                    (cutoff,),
                ).rowcount,
                "scan_history": conn.execute(
                    "DELETE FROM scan_history WHERE scanned_at < ?", (cutoff,)
                ).rowcount,
                "certstream_events": conn.execute(
                    "DELETE FROM certstream_events WHERE timestamp < ?", (cutoff,)
                ).rowcount,
                "domains": conn.execute(
                    "DELETE FROM domains WHERE last_seen < ? AND is_phishing = 0", (cutoff,)
                ).rowcount,
            }
        return removed

    def vacuum(self) -> None:
        if self._memory_conn is not None:
            return
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("VACUUM")
        finally:
            conn.close()

    def close(self) -> None:
        if self._memory_conn is not None:
            self._memory_conn.close()
            self._memory_conn = None


__all__ = [
    "ALERT_STATUSES",
    "CLOSED_STATUSES",
    "Database",
    "SCHEMA_VERSION",
    "SIGHTING_STATUSES",
    "utc_now_iso",
]
