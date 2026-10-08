"""Reliable SQLite Database Engine with WAL Mode for BB-SUITE.

Configured with WAL (Write-Ahead Logging), busy_timeout, foreign keys,
safe transactions, and confidence taxonomy indexing.
"""
from __future__ import annotations
from contextlib import contextmanager
from datetime import datetime
import json
import os
import sqlite3
import sys
from typing import Any, Dict, Generator, List, Optional

DB_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', 'reports', 'bbsuite.db')
)
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)


def get_conn() -> sqlite3.Connection:
    """Create a high-reliability SQLite connection with WAL journal mode and busy timeouts."""
    conn = sqlite3.connect(DB_PATH, timeout=15.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
    except Exception:
        pass
    return conn


@contextmanager
def get_db() -> Generator[sqlite3.Cursor, None, None]:
    """Context manager for safe transactional execution."""
    conn = get_conn()
    cur = conn.cursor()
    try:
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """Initialize database tables, indices, and schema migrations."""
    with get_db() as cur:
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS targets (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                url        TEXT NOT NULL UNIQUE,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS scans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id   INTEGER REFERENCES targets(id) ON DELETE CASCADE,
                started_at  TEXT,
                finished_at TEXT,
                duration_s  REAL DEFAULT 0,
                tool_count  INTEGER DEFAULT 0,
                sev_counts  TEXT DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS findings (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id        INTEGER REFERENCES scans(id) ON DELETE CASCADE,
                tool           TEXT,
                severity       TEXT,
                confidence     TEXT DEFAULT 'possible',
                title          TEXT,
                detail         TEXT,
                recommendation TEXT,
                created_at     TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS assets (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id    INTEGER REFERENCES targets(id) ON DELETE CASCADE,
                asset_type   TEXT,
                value        TEXT,
                extra        TEXT DEFAULT '{}',
                discovered_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(target_id, asset_type, value)
            );

            CREATE INDEX IF NOT EXISTS idx_findings_scan    ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_findings_sev     ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_findings_conf    ON findings(confidence);
            CREATE INDEX IF NOT EXISTS idx_assets_target    ON assets(target_id);
            CREATE INDEX IF NOT EXISTS idx_scants_started   ON scans(started_at);
        """)

        # Migration: ensure confidence column exists if upgrading from v2/v3.0
        cur.execute("PRAGMA table_info(findings);")
        columns = [row["name"] for row in cur.fetchall()]
        if "confidence" not in columns:
            try:
                cur.execute("ALTER TABLE findings ADD COLUMN confidence TEXT DEFAULT 'possible';")
            except Exception:
                pass


def upsert_target(url: str) -> int:
    with get_db() as cur:
        cur.execute("INSERT OR IGNORE INTO targets(url) VALUES(?)", (url,))
        cur.execute("SELECT id FROM targets WHERE url=?", (url,))
        row = cur.fetchone()
        return int(row['id'])


def create_scan(target_id: int, started_at: str) -> int:
    with get_db() as cur:
        cur.execute("INSERT INTO scans(target_id, started_at) VALUES(?,?)", (target_id, started_at))
        return int(cur.lastrowid)


def finish_scan(scan_id: int, duration_s: float, tool_count: int, sev_counts: Dict[str, Any]) -> None:
    with get_db() as cur:
        cur.execute(
            "UPDATE scans SET finished_at=?, duration_s=?, tool_count=?, sev_counts=? WHERE id=?",
            (datetime.now().isoformat(), duration_s, tool_count, json.dumps(sev_counts), scan_id)
        )


def save_findings(scan_id: int, tool: str, findings: List[Dict[str, Any]]) -> None:
    with get_db() as cur:
        for fnd in findings:
            if str(fnd.get('severity', '')).lower() == 'pass':
                continue
            cur.execute(
                """INSERT INTO findings(scan_id, tool, severity, confidence, title, detail, recommendation)
                   VALUES(?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    tool,
                    fnd.get('severity', 'info'),
                    fnd.get('confidence', 'possible'),
                    fnd.get('title', ''),
                    fnd.get('detail', ''),
                    fnd.get('recommendation', ''),
                )
            )


def save_asset(target_id: int, asset_type: str, value: str, extra: Optional[Dict[str, Any]] = None) -> None:
    try:
        with get_db() as cur:
            cur.execute(
                "INSERT OR IGNORE INTO assets(target_id, asset_type, value, extra) VALUES(?,?,?,?)",
                (target_id, asset_type, value, json.dumps(extra or {}))
            )
    except Exception:
        pass


def get_scan_history(limit: int = 20) -> List[Dict[str, Any]]:
    with get_db() as cur:
        cur.execute("""
            SELECT s.id, t.url, s.started_at, s.finished_at, s.duration_s,
                   s.tool_count, s.sev_counts
            FROM scans s JOIN targets t ON s.target_id=t.id
            ORDER BY s.id DESC LIMIT ?
        """, (limit,))
        return [dict(r) for r in cur.fetchall()]


def get_top_findings(limit: int = 50) -> List[Dict[str, Any]]:
    with get_db() as cur:
        cur.execute("""
            SELECT f.severity, f.confidence, f.title, f.tool, t.url, f.created_at
            FROM findings f JOIN scans s ON f.scan_id=s.id JOIN targets t ON s.target_id=t.id
            ORDER BY CASE f.severity
                WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                WHEN 'medium' THEN 2   WHEN 'low' THEN 3 ELSE 4 END,
            f.id DESC LIMIT ?
        """, (limit,))
        return [dict(r) for r in cur.fetchall()]


def get_asset_inventory(target_url: str) -> List[Dict[str, Any]]:
    with get_db() as cur:
        cur.execute("""
            SELECT a.asset_type, a.value, a.extra, a.discovered_at
            FROM assets a JOIN targets t ON a.target_id=t.id
            WHERE t.url=? ORDER BY a.asset_type, a.discovered_at DESC
        """, (target_url,))
        return [dict(r) for r in cur.fetchall()]


try:
    init_db()
except Exception as _init_err:
    print(f"[BB-SUITE] WARNING: Database init failed: {_init_err}", file=sys.stderr)
