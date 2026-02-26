"""
Database Layer – SQLite-backed persistence for honeypot events.

Tables
------
connections  – one row per inbound TCP session
auth_attempts – every credential guess
commands     – every command executed in a session
threats      – every threat detection alert
file_access  – sensitive file reads
"""
import sqlite3
import datetime
import json
import logging
import threading

from config.settings import DB_ENABLED, DB_PATH

_log = logging.getLogger("system")


class DatabaseManager:
    """Thread-safe SQLite manager for honeypot telemetry."""

    def __init__(self, db_path: str = DB_PATH):
        if not DB_ENABLED:
            self._enabled = False
            return
        self._enabled = True
        self._path    = db_path
        self._lock    = threading.Lock()
        self._conn    = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._create_tables()
        _log.info(json.dumps({"event": "db_init", "path": db_path}))

    # ── Schema ────────────────────────────────────────────────────────────────

    def _create_tables(self):
        with self._lock, self._conn:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS connections (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_ip   TEXT    NOT NULL,
                    port        INTEGER,
                    connected_at TEXT   DEFAULT (datetime('now')),
                    disconnected_at TEXT
                );

                CREATE TABLE IF NOT EXISTS auth_attempts (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_ip   TEXT    NOT NULL,
                    username    TEXT,
                    password    TEXT,
                    success     INTEGER DEFAULT 0,
                    attempted_at TEXT  DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS commands (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_ip   TEXT    NOT NULL,
                    username    TEXT,
                    command     TEXT,
                    issued_at   TEXT    DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS threats (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_ip   TEXT,
                    username    TEXT,
                    category    TEXT,
                    severity    TEXT,
                    rule_id     TEXT,
                    command     TEXT,
                    message     TEXT,
                    detected_at TEXT    DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS file_access (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_ip   TEXT,
                    username    TEXT,
                    file_path   TEXT,
                    accessed_at TEXT    DEFAULT (datetime('now'))
                );
            """)

    # ── Inserts ───────────────────────────────────────────────────────────────

    def _exec(self, sql: str, params=()):
        if not self._enabled:
            return
        try:
            with self._lock, self._conn:
                self._conn.execute(sql, params)
        except Exception as exc:
            _log.error(json.dumps({"event": "db_error", "error": str(exc), "sql": sql}))

    def insert_connection(self, source_ip: str, port: int):
        self._exec(
            "INSERT INTO connections (source_ip, port) VALUES (?, ?)",
            (source_ip, port),
        )

    def close_connection(self, source_ip: str):
        self._exec(
            "UPDATE connections SET disconnected_at = datetime('now') "
            "WHERE source_ip = ? AND disconnected_at IS NULL",
            (source_ip,),
        )

    def insert_auth(self, source_ip: str, username: str, password: str, success: bool):
        self._exec(
            "INSERT INTO auth_attempts (source_ip, username, password, success) VALUES (?, ?, ?, ?)",
            (source_ip, username, password, int(success)),
        )

    def insert_command(self, source_ip: str, username: str, command: str):
        self._exec(
            "INSERT INTO commands (source_ip, username, command) VALUES (?, ?, ?)",
            (source_ip, username, command),
        )

    def insert_threat(self, alert: dict):
        self._exec(
            """INSERT INTO threats
               (source_ip, username, category, severity, rule_id, command, message)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                alert.get("source_ip"), alert.get("username"),
                alert.get("category"), alert.get("severity"),
                alert.get("rule_id"),  alert.get("command", ""),
                alert.get("message"),
            ),
        )

    def insert_file_access(self, source_ip: str, file_path: str, username: str = "corpuser"):
        self._exec(
            "INSERT INTO file_access (source_ip, username, file_path) VALUES (?, ?, ?)",
            (source_ip, username, file_path),
        )

    # ── Queries (for reporting) ───────────────────────────────────────────────

    def get_top_attackers(self, limit: int = 10) -> list[dict]:
        if not self._enabled:
            return []
        with self._lock:
            rows = self._conn.execute(
                "SELECT source_ip, COUNT(*) as attempts FROM auth_attempts "
                "GROUP BY source_ip ORDER BY attempts DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_top_commands(self, limit: int = 10) -> list[dict]:
        if not self._enabled:
            return []
        with self._lock:
            rows = self._conn.execute(
                "SELECT command, COUNT(*) as cnt FROM commands "
                "GROUP BY command ORDER BY cnt DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_threats(self, severity: str = None, limit: int = 100) -> list[dict]:
        if not self._enabled:
            return []
        with self._lock:
            if severity:
                rows = self._conn.execute(
                    "SELECT * FROM threats WHERE severity = ? ORDER BY detected_at DESC LIMIT ?",
                    (severity, limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM threats ORDER BY detected_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [dict(r) for r in rows]

    def close(self):
        if self._enabled and self._conn:
            self._conn.close()
