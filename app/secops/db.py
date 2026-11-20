"""Stockage de la plateforme SecOps (SQLite, fichier data/secops.db).

Une seule base partagée par les trois équipes d'attaque et la Blue Team : registre des vulnérabilités,
exécutions, preuves, événements de sécurité, incidents multi-composants, utilisateurs et journal d'audit.
"""
import json
import os
import sqlite3
import threading
import time
from pathlib import Path

DB_PATH = Path(os.getenv("SECOPS_DB", str(Path(__file__).resolve().parents[2] / "data" / "secops.db")))
_lock = threading.RLock()
_conn: sqlite3.Connection | None = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL, role TEXT NOT NULL,
  team TEXT, pw_hash TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS counters(name TEXT PRIMARY KEY, value INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS executions(
  id TEXT PRIMARY KEY, scenario_id TEXT NOT NULL, team TEXT NOT NULL, component TEXT NOT NULL,
  mode TEXT NOT NULL, kind TEXT NOT NULL, status TEXT NOT NULL, outcome TEXT, detected INTEGER NOT NULL DEFAULT 0,
  detection_ms INTEGER, started_at REAL NOT NULL, finished_at REAL, duration_ms INTEGER, username TEXT,
  finding_id TEXT, evidence_id TEXT, summary TEXT, incident_id TEXT, blocked_by TEXT);
CREATE TABLE IF NOT EXISTS evidence(
  id TEXT PRIMARY KEY, execution_id TEXT NOT NULL, finding_id TEXT, team TEXT NOT NULL, scenario_id TEXT NOT NULL,
  component TEXT NOT NULL, type TEXT NOT NULL, content TEXT NOT NULL, sha256 TEXT NOT NULL,
  flags_detected TEXT NOT NULL, created_at REAL NOT NULL, mode TEXT NOT NULL, kind TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS findings(
  id TEXT PRIMARY KEY, team TEXT NOT NULL, scenario_id TEXT NOT NULL UNIQUE, category TEXT NOT NULL,
  component TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL, severity TEXT NOT NULL,
  impact TEXT NOT NULL, status TEXT NOT NULL, detection_status TEXT NOT NULL, owner TEXT, mitigation TEXT,
  collaborating_teams TEXT NOT NULL, refs TEXT NOT NULL, retest_result TEXT, created_at REAL NOT NULL,
  updated_at REAL NOT NULL, verified_at REAL, first_execution_id TEXT, last_execution_id TEXT,
  incident_id TEXT, created_by TEXT);
CREATE TABLE IF NOT EXISTS finding_history(
  id INTEGER PRIMARY KEY, finding_id TEXT NOT NULL, at REAL NOT NULL, username TEXT, from_status TEXT,
  to_status TEXT, note TEXT);
CREATE TABLE IF NOT EXISTS security_events(
  id INTEGER PRIMARY KEY, at REAL NOT NULL, severity TEXT NOT NULL, team TEXT, component TEXT, rule TEXT NOT NULL,
  message TEXT NOT NULL, execution_id TEXT, mode TEXT);
CREATE TABLE IF NOT EXISTS incidents(
  id TEXT PRIMARY KEY, title TEXT NOT NULL, entry_team TEXT NOT NULL, entry_component TEXT NOT NULL,
  components TEXT NOT NULL, collaborating_teams TEXT NOT NULL, status TEXT NOT NULL, created_at REAL NOT NULL,
  updated_at REAL NOT NULL, last_execution_id TEXT, finding_id TEXT);
CREATE TABLE IF NOT EXISTS audit_log(
  id INTEGER PRIMARY KEY, at REAL NOT NULL, username TEXT, role TEXT, action TEXT NOT NULL, target TEXT,
  details TEXT, ip TEXT);
CREATE INDEX IF NOT EXISTS ix_exec_team ON executions(team, started_at);
CREATE INDEX IF NOT EXISTS ix_events_at ON security_events(at);
CREATE INDEX IF NOT EXISTS ix_hist_f ON finding_history(finding_id);
"""

JSON_COLUMNS = {"collaborating_teams", "refs", "content", "flags_detected", "components", "details"}


def conn() -> sqlite3.Connection:
    global _conn
    with _lock:
        if _conn is None:
            DB_PATH.parent.mkdir(parents=True, exist_ok=True)
            _conn = sqlite3.connect(str(DB_PATH), check_same_thread=False, isolation_level=None)
            _conn.row_factory = sqlite3.Row
            _conn.execute("PRAGMA journal_mode=WAL")
            _conn.executescript(SCHEMA)
        return _conn


def reset_connection() -> None:
    """Ferme la connexion (tests : changement de fichier de base)."""
    global _conn, DB_PATH
    with _lock:
        if _conn is not None:
            _conn.close()
        _conn = None
        DB_PATH = Path(os.getenv("SECOPS_DB", str(DB_PATH)))


def _decode(row: sqlite3.Row | None) -> dict | None:
    if row is None:
        return None
    d = dict(row)
    for k in JSON_COLUMNS & d.keys():
        if isinstance(d[k], str):
            try:
                d[k] = json.loads(d[k])
            except ValueError:
                pass
    return d


def q(sql: str, args: tuple = ()) -> list[dict]:
    with _lock:
        return [_decode(r) for r in conn().execute(sql, args).fetchall()]


def q1(sql: str, args: tuple = ()) -> dict | None:
    with _lock:
        return _decode(conn().execute(sql, args).fetchone())


def ex(sql: str, args: tuple = ()) -> int:
    with _lock:
        cur = conn().execute(sql, args)
        return cur.lastrowid


def insert(table: str, row: dict) -> None:
    cols = list(row)
    vals = [json.dumps(v, ensure_ascii=False) if k in JSON_COLUMNS and not isinstance(v, str) else v
            for k, v in row.items()]
    ex(f"INSERT INTO {table}({','.join(cols)}) VALUES ({','.join('?' * len(cols))})", tuple(vals))


def update(table: str, key: str, key_value, changes: dict) -> None:
    if not changes:
        return
    sets = ",".join(f"{k}=?" for k in changes)
    vals = [json.dumps(v, ensure_ascii=False) if k in JSON_COLUMNS and not isinstance(v, str) else v
            for k, v in changes.items()]
    ex(f"UPDATE {table} SET {sets} WHERE {key}=?", (*vals, key_value))


def next_id(prefix: str, width: int = 3) -> str:
    """Identifiants lisibles et stables : AGT-001, EXE-000042, EVD-000007..."""
    with _lock:
        c = conn()
        c.execute("INSERT INTO counters(name, value) VALUES (?, 0) ON CONFLICT(name) DO NOTHING", (prefix,))
        c.execute("UPDATE counters SET value = value + 1 WHERE name=?", (prefix,))
        n = c.execute("SELECT value FROM counters WHERE name=?", (prefix,)).fetchone()[0]
    return f"{prefix}-{n:0{width}d}"


def now() -> float:
    return time.time()


def wipe_activity() -> None:
    """Efface l'activité (exécutions, preuves, findings, événements, incidents) ; conserve utilisateurs et audit."""
    with _lock:
        c = conn()
        for t in ("executions", "evidence", "findings", "finding_history", "security_events", "incidents"):
            c.execute(f"DELETE FROM {t}")
        c.execute("DELETE FROM counters WHERE name NOT IN ('AUD')")
