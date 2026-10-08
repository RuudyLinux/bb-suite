"""SQLite-based scan history and asset tracking for BB-SUITE."""
from __future__ import annotations
import sqlite3
import json
import os
from datetime import datetime
from typing import Any

DB_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', 'reports', 'bbsuite.db')
)
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    cur  = conn.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS targets (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            url        TEXT NOT NULL UNIQUE,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id   INTEGER REFERENCES targets(id),
            started_at  TEXT,
            finished_at TEXT,
            duration_s  REAL DEFAULT 0,
            tool_count  INTEGER DEFAULT 0,
            sev_counts  TEXT DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS findings (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id        INTEGER REFERENCES scans(id),
            tool           TEXT,
            severity       TEXT,
            title          TEXT,
            detail         TEXT,
            recommendation TEXT,
            created_at     TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS assets (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id    INTEGER REFERENCES targets(id),
            asset_type   TEXT,
            value        TEXT,
            extra        TEXT DEFAULT '{}',
            discovered_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(target_id, asset_type, value)
        );

        CREATE INDEX IF NOT EXISTS idx_findings_scan    ON findings(scan_id);
        CREATE INDEX IF NOT EXISTS idx_findings_sev     ON findings(severity);
        CREATE INDEX IF NOT EXISTS idx_assets_target    ON assets(target_id);
    """)
    conn.commit()
    conn.close()


def upsert_target(url: str) -> int:
    conn = get_conn()
    cur  = conn.cursor()
    cur.execute("INSERT OR IGNORE INTO targets(url) VALUES(?)", (url,))
    conn.commit()
    cur.execute("SELECT id FROM targets WHERE url=?", (url,))
    row = cur.fetchone()
    conn.close()
    return row['id']


def create_scan(target_id: int, started_at: str) -> int:
    conn = get_conn()
    cur  = conn.cursor()
    cur.execute("INSERT INTO scans(target_id, started_at) VALUES(?,?)", (target_id, started_at))
    conn.commit()
    scan_id = cur.lastrowid
    conn.close()
    return scan_id


def finish_scan(scan_id: int, duration_s: float, tool_count: int, sev_counts: dict):
    conn = get_conn()
    cur  = conn.cursor()
    cur.execute(
        "UPDATE scans SET finished_at=?,duration_s=?,tool_count=?,sev_counts=? WHERE id=?",
        (datetime.now().isoformat(), duration_s, tool_count, json.dumps(sev_counts), scan_id)
    )
    conn.commit()
    conn.close()


def save_findings(scan_id: int, tool: str, findings: list[dict]):
    conn = get_conn()
    cur  = conn.cursor()
    for fnd in findings:
        if fnd.get('severity') == 'pass':
            continue  # Don't store pass findings
        cur.execute(
            "INSERT INTO findings(scan_id,tool,severity,title,detail,recommendation) VALUES(?,?,?,?,?,?)",
            (scan_id, tool, fnd.get('severity','info'), fnd.get('title',''),
             fnd.get('detail',''), fnd.get('recommendation',''))
        )
    conn.commit()
    conn.close()


def save_asset(target_id: int, asset_type: str, value: str, extra: dict = None):
    conn = get_conn()
    cur  = conn.cursor()
    try:
        cur.execute(
            "INSERT OR IGNORE INTO assets(target_id,asset_type,value,extra) VALUES(?,?,?,?)",
            (target_id, asset_type, value, json.dumps(extra or {}))
        )
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


def get_scan_history(limit: int = 20) -> list[dict]:
    conn = get_conn()
    cur  = conn.cursor()
    cur.execute("""
        SELECT s.id, t.url, s.started_at, s.finished_at, s.duration_s,
               s.tool_count, s.sev_counts
        FROM scans s JOIN targets t ON s.target_id=t.id
        ORDER BY s.id DESC LIMIT ?
    """, (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_top_findings(limit: int = 50) -> list[dict]:
    conn = get_conn()
    cur  = conn.cursor()
    cur.execute("""
        SELECT f.severity, f.title, f.tool, t.url, f.created_at
        FROM findings f JOIN scans s ON f.scan_id=s.id JOIN targets t ON s.target_id=t.id
        ORDER BY CASE severity
            WHEN 'critical' THEN 0 WHEN 'high' THEN 1
            WHEN 'medium' THEN 2   WHEN 'low' THEN 3 ELSE 4 END,
        f.id DESC LIMIT ?
    """, (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_asset_inventory(target_url: str) -> list[dict]:
    conn = get_conn()
    cur  = conn.cursor()
    cur.execute("""
        SELECT a.asset_type, a.value, a.extra, a.discovered_at
        FROM assets a JOIN targets t ON a.target_id=t.id
        WHERE t.url=? ORDER BY a.asset_type, a.discovered_at DESC
    """, (target_url,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


# Init on import
try:
    init_db()
except Exception as _init_err:
    import sys
    print(f"[BB-SUITE] WARNING: database init failed: {_init_err}", file=sys.stderr)
