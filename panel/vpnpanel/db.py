"""SQLite storage. One connection shared by the web threads and the poller, guarded by a lock."""
import os
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS clients (
  id INTEGER PRIMARY KEY,
  server TEXT NOT NULL, container TEXT NOT NULL, pub TEXT NOT NULL,
  name TEXT NOT NULL DEFAULT '', ip TEXT NOT NULL DEFAULT '',
  priv TEXT, psk TEXT,                 -- only for clients created by the panel
  source TEXT NOT NULL,                -- 'panel' | 'imported'
  created INTEGER NOT NULL,
  disabled INTEGER NOT NULL DEFAULT 0,
  migrated_to INTEGER,                 -- id of the client that replaced this one
  deleted INTEGER,                     -- timestamp; row kept for history
  UNIQUE (server, container, pub)
);
CREATE TABLE IF NOT EXISTS peer_state (
  server TEXT NOT NULL, container TEXT NOT NULL, pub TEXT NOT NULL,
  rx INTEGER NOT NULL DEFAULT 0, tx INTEGER NOT NULL DEFAULT 0,
  hs INTEGER NOT NULL DEFAULT 0, endpoint TEXT, seen INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (server, container, pub)
);
CREATE TABLE IF NOT EXISTS traffic (
  server TEXT NOT NULL, container TEXT NOT NULL, pub TEXT NOT NULL, hour INTEGER NOT NULL,
  rx INTEGER NOT NULL DEFAULT 0, tx INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (server, container, pub, hour)
);
CREATE TABLE IF NOT EXISTS health (
  server TEXT NOT NULL, container TEXT NOT NULL, kind TEXT, port INTEGER, up INTEGER,
  peers INTEGER, online INTEGER, last_handshake INTEGER, checked INTEGER, error TEXT,
  PRIMARY KEY (server, container)
);
CREATE TABLE IF NOT EXISTS server_health (
  server TEXT PRIMARY KEY, ok INTEGER, checked INTEGER, error TEXT
);
CREATE TABLE IF NOT EXISTS shares (
  id INTEGER PRIMARY KEY, client_id INTEGER NOT NULL, token_hash TEXT NOT NULL UNIQUE,
  created INTEGER NOT NULL, expires INTEGER NOT NULL, one_time INTEGER NOT NULL DEFAULT 0,
  used_at INTEGER, revoked INTEGER
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY, csrf TEXT NOT NULL, expires INTEGER NOT NULL, ip TEXT
);
CREATE TABLE IF NOT EXISTS logins (ts INTEGER NOT NULL, ip TEXT NOT NULL, ok INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS logins_ip ON logins (ip, ts);
CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, ip TEXT, text TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  login TEXT NOT NULL UNIQUE COLLATE NOCASE,
  name TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL,                  -- 'owner' | 'admin'
  pw_hash TEXT,                        -- NULL until the invite is used
  servers TEXT,                        -- JSON list of server ids for admins; owners see everything
  disabled INTEGER NOT NULL DEFAULT 0,
  created INTEGER NOT NULL, created_by INTEGER, last_login INTEGER
);
CREATE TABLE IF NOT EXISTS invites (
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, token_hash TEXT NOT NULL UNIQUE,
  created INTEGER NOT NULL, expires INTEGER NOT NULL, used_at INTEGER
);
"""

# Columns added after the first release; created on start if missing (no data is lost).
MIGRATIONS = [
    ("sessions", "user_id", "INTEGER"),
    ("logins", "login", "TEXT"),
    ("events", "user_id", "INTEGER"),
    ("events", "server", "TEXT"),
    ("clients", "created_by", "INTEGER"),
]


class DB:
    def __init__(self, path):
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, mode=0o700, exist_ok=True)
        new = not os.path.exists(path)
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        if new:
            os.chmod(path, 0o600)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.lock:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA foreign_keys=ON")
            self.conn.executescript(SCHEMA)
            self._migrate()

    def _migrate(self):
        for table, col, decl in MIGRATIONS:
            cols = {r[1] for r in self.conn.execute(f"PRAGMA table_info({table})")}
            if col not in cols:
                self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
        # Single-password installs become an owner account "admin" with the same password hash.
        if not self.conn.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            old = self.conn.execute("SELECT value FROM settings WHERE key='admin_password'").fetchone()
            if old:
                self.conn.execute("INSERT INTO users(login, name, role, pw_hash, created) VALUES('admin', 'Владелец', "
                                  "'owner', ?, ?)", (old[0], int(time.time())))
                self.conn.execute("DELETE FROM settings WHERE key='admin_password'")
        self.conn.execute("DELETE FROM sessions WHERE user_id IS NULL")

    def q(self, sql, args=()):
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, args).fetchall()]

    def one(self, sql, args=()):
        rows = self.q(sql, args)
        return rows[0] if rows else None

    def x(self, sql, args=()):
        with self.lock:
            cur = self.conn.execute(sql, args)
            return cur.lastrowid

    def tx(self):
        """with db.tx(): ... — explicit transaction under the lock."""
        db = self

        class _T:
            def __enter__(self):
                db.lock.acquire()
                db.conn.execute("BEGIN")
                return db

            def __exit__(self, et, ev, tb):
                try:
                    db.conn.execute("ROLLBACK" if et else "COMMIT")
                finally:
                    db.lock.release()
        return _T()

    # settings
    def get(self, key, default=None):
        r = self.one("SELECT value FROM settings WHERE key=?", (key,))
        return r["value"] if r else default

    def set(self, key, value):
        self.x("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
               (key, value))

    def event(self, text, ip=None, user_id=None, server=None):
        self.x("INSERT INTO events(ts, ip, text, user_id, server) VALUES(?,?,?,?,?)",
               (int(time.time()), ip, text, user_id, server))
