import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    kdf_salt BLOB NOT NULL,
    kdf_params TEXT NOT NULL,
    public_key BLOB NOT NULL,
    private_key BLOB NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS vaults (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    key_version INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS members (
    vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('owner', 'editor', 'viewer')),
    wrapped_key BLOB NOT NULL,
    PRIMARY KEY (vault_id, user_id)
);

CREATE TABLE IF NOT EXISTS entries (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('secret', 'file')),
    payload BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    updated_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE (vault_id, kind, name)
);

CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY,
    vault_id TEXT NOT NULL,
    username TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    at INTEGER NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS audit_vault ON audit (vault_id, id);
"""


def now():
    return int(time.time())


class Store:
    def __init__(self, path):
        self.path = Path(path)
        if str(path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fresh = not self.path.exists()
        else:
            fresh = False
        self.conn = sqlite3.connect(str(path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)
        if fresh:
            os.chmod(self.path, 0o600)

    def close(self):
        self.conn.close()

    @contextmanager
    def transaction(self):
        try:
            yield
            self.conn.commit()
        except BaseException:
            self.conn.rollback()
            raise

    def _one(self, sql, *args):
        return self.conn.execute(sql, args).fetchone()

    def _all(self, sql, *args):
        return self.conn.execute(sql, args).fetchall()

    def add_user(self, username, password_hash, salt, kdf_params, public_key, private_key):
        cur = self.conn.execute(
            "INSERT INTO users (username, password_hash, kdf_salt, kdf_params, public_key, private_key, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (username, password_hash, salt, kdf_params, public_key, private_key, now()),
        )
        return cur.lastrowid

    def get_user(self, username):
        return self._one("SELECT * FROM users WHERE username = ?", username)

    def update_credentials(self, user_id, password_hash, salt, kdf_params, private_key):
        self.conn.execute(
            "UPDATE users SET password_hash = ?, kdf_salt = ?, kdf_params = ?, private_key = ? WHERE id = ?",
            (password_hash, salt, kdf_params, private_key, user_id),
        )

    def create_vault(self, vault_id, name):
        self.conn.execute(
            "INSERT INTO vaults (id, name, created_at) VALUES (?, ?, ?)",
            (vault_id, name, now()),
        )

    def get_vault(self, name):
        return self._one("SELECT * FROM vaults WHERE name = ?", name)

    def set_key_version(self, vault_id, version):
        self.conn.execute("UPDATE vaults SET key_version = ? WHERE id = ?", (version, vault_id))

    def delete_vault(self, vault_id):
        self.conn.execute("DELETE FROM vaults WHERE id = ?", (vault_id,))

    def user_vaults(self, user_id):
        return self._all(
            "SELECT v.name, m.role, "
            "(SELECT COUNT(*) FROM entries e WHERE e.vault_id = v.id) AS entry_count "
            "FROM vaults v JOIN members m ON m.vault_id = v.id "
            "WHERE m.user_id = ? ORDER BY v.name",
            user_id,
        )

    def add_member(self, vault_id, user_id, role, wrapped_key):
        self.conn.execute(
            "INSERT INTO members (vault_id, user_id, role, wrapped_key) VALUES (?, ?, ?, ?)",
            (vault_id, user_id, role, wrapped_key),
        )

    def get_member(self, vault_id, user_id):
        return self._one("SELECT * FROM members WHERE vault_id = ? AND user_id = ?", vault_id, user_id)

    def members(self, vault_id):
        return self._all(
            "SELECT m.user_id, m.role, u.username, u.public_key "
            "FROM members m JOIN users u ON u.id = m.user_id "
            "WHERE m.vault_id = ? ORDER BY u.username",
            vault_id,
        )

    def set_role(self, vault_id, user_id, role):
        self.conn.execute(
            "UPDATE members SET role = ? WHERE vault_id = ? AND user_id = ?",
            (role, vault_id, user_id),
        )

    def set_wrapped_key(self, vault_id, user_id, wrapped_key):
        self.conn.execute(
            "UPDATE members SET wrapped_key = ? WHERE vault_id = ? AND user_id = ?",
            (wrapped_key, vault_id, user_id),
        )

    def remove_member(self, vault_id, user_id):
        self.conn.execute("DELETE FROM members WHERE vault_id = ? AND user_id = ?", (vault_id, user_id))

    def add_entry(self, entry_id, vault_id, name, kind, payload, user_id):
        ts = now()
        self.conn.execute(
            "INSERT INTO entries (id, vault_id, name, kind, payload, created_at, updated_at, updated_by) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (entry_id, vault_id, name, kind, payload, ts, ts, user_id),
        )

    def update_entry(self, entry_id, payload, user_id):
        self.conn.execute(
            "UPDATE entries SET payload = ?, updated_at = ?, updated_by = ? WHERE id = ?",
            (payload, now(), user_id, entry_id),
        )

    def rekey_entry(self, entry_id, payload):
        self.conn.execute("UPDATE entries SET payload = ? WHERE id = ?", (payload, entry_id))

    def get_entry(self, vault_id, kind, name):
        return self._one(
            "SELECT * FROM entries WHERE vault_id = ? AND kind = ? AND name = ?",
            vault_id, kind, name,
        )

    def entries(self, vault_id):
        return self._all(
            "SELECT e.*, u.username AS updated_by_name, length(e.payload) AS size "
            "FROM entries e LEFT JOIN users u ON u.id = e.updated_by "
            "WHERE e.vault_id = ? ORDER BY e.kind, e.name",
            vault_id,
        )

    def delete_entry(self, entry_id):
        self.conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))

    def last_audit_hash(self, vault_id):
        row = self._one("SELECT hash FROM audit WHERE vault_id = ? ORDER BY id DESC LIMIT 1", vault_id)
        return row["hash"] if row else None

    def append_audit(self, vault_id, username, action, target, at, prev_hash, digest):
        self.conn.execute(
            "INSERT INTO audit (vault_id, username, action, target, at, prev_hash, hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (vault_id, username, action, target, at, prev_hash, digest),
        )

    def audit_rows(self, vault_id):
        return self._all("SELECT * FROM audit WHERE vault_id = ? ORDER BY id", vault_id)
