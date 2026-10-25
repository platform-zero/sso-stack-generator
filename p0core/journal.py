"""Operation state is durable; execution success never certifies work acceptance."""
from __future__ import annotations

import contextlib
import fcntl
import json
import os
import sqlite3
import stat
import time
import uuid
from pathlib import Path

from .model import ContractError

TRANSITIONS = {
    "prepared": {"running", "cancelled"},
    "running": {"succeeded", "failed", "cancelled", "indeterminate"},
    "indeterminate": set(), "succeeded": set(), "failed": set(), "cancelled": set(),
}


@contextlib.contextmanager
def operation_lock(directory: Path):
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    observed = directory.lstat()
    if (not stat.S_ISDIR(observed.st_mode) or observed.st_uid != os.getuid()
            or stat.S_IMODE(observed.st_mode) & 0o077):
        raise ContractError("operation directory must be private and owned")
    flags = os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(directory / "operation.lock", flags, 0o600)
    try:
        observed = os.fstat(fd)
        if (not stat.S_ISREG(observed.st_mode) or observed.st_uid != os.getuid()
                or observed.st_nlink != 1 or stat.S_IMODE(observed.st_mode) & 0o077):
            raise ContractError("unsafe operation lock")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ContractError("another operation owns the installation lock") from error
        yield
    finally:
        os.close(fd)


class Journal:
    def __init__(self, path: Path):
        # Parent is checked before SQLite can create sidecars. No process-global
        # umask changes; directory protection contains SQLite's default modes.
        parent = path.parent.lstat()
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid()
                or stat.S_IMODE(parent.st_mode) & 0o077):
            raise ContractError("journal parent must be private and owned")
        if path.exists() or path.is_symlink():
            observed = path.lstat()
            if (not stat.S_ISREG(observed.st_mode) or observed.st_uid != os.getuid()
                    or observed.st_nlink != 1 or stat.S_IMODE(observed.st_mode) & 0o077):
                raise ContractError("unsafe journal file")
        else:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        self.connection = sqlite3.connect(path, timeout=5, isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS operations (
                id TEXT PRIMARY KEY, kind TEXT NOT NULL, input_sha256 TEXT NOT NULL,
                state TEXT NOT NULL, revision INTEGER NOT NULL, created REAL NOT NULL,
                updated REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                operation TEXT NOT NULL, state TEXT NOT NULL,
                revision INTEGER NOT NULL, observed REAL NOT NULL
            );
        """)

    def close(self):
        self.connection.close()

    def create(self, kind: str, input_sha256: str) -> str:
        if kind not in {"install", "start", "stop", "upgrade", "recover", "uninstall", "test", "build"}:
            raise ContractError("invalid operation kind")
        import re
        if not isinstance(input_sha256, str) or not re.fullmatch("[0-9a-f]{64}", input_sha256):
            raise ContractError("invalid operation input identity")
        identity, now = str(uuid.uuid4()), time.time()
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            self.connection.execute("INSERT INTO operations VALUES (?, ?, ?, 'prepared', 0, ?, ?)",
                                    (identity, kind, input_sha256, now, now))
            self.connection.execute("INSERT INTO events(operation,state,revision,observed) VALUES (?, 'prepared', 0, ?)",
                                    (identity, now))
            self.connection.execute("COMMIT")
        except BaseException:
            self.connection.execute("ROLLBACK")
            raise
        return identity

    def transition(self, identity: str, expected_revision: int, state: str):
        if type(expected_revision) is not int:
            raise ContractError("revision must be an integer")
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute("SELECT * FROM operations WHERE id=?", (identity,)).fetchone()
            if row is None or row["revision"] != expected_revision:
                raise ContractError("missing operation or stale revision")
            if state not in TRANSITIONS[row["state"]]:
                raise ContractError("invalid operation transition; reconcile rather than replay")
            now = time.time()
            self.connection.execute("UPDATE operations SET state=?,revision=revision+1,updated=? WHERE id=?",
                                    (state, now, identity))
            self.connection.execute("INSERT INTO events(operation,state,revision,observed) VALUES (?,?,?,?)",
                                    (identity, state, expected_revision + 1, now))
            self.connection.execute("COMMIT")
        except BaseException:
            self.connection.execute("ROLLBACK")
            raise

    @staticmethod
    def status(path: Path) -> dict:
        # A read-only observation must never create a directory/database or repair.
        if not path.exists():
            return {"schemaVersion": 1, "operations": [], "observed": "absent",
                    "installationCertified": False}
        observed = path.lstat()
        parent = path.parent.lstat()
        if (not stat.S_ISREG(observed.st_mode) or observed.st_uid != os.getuid()
                or observed.st_nlink != 1 or stat.S_IMODE(observed.st_mode) & 0o077
                or not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid()
                or stat.S_IMODE(parent.st_mode) & 0o077):
            raise ContractError("unsafe status source")
        # immutable avoids SQLite creating WAL/SHM files for read-only inspection.
        # It is suitable only for checkpointed journals. Live WAL is explicitly
        # unknown rather than silently presenting an incomplete snapshot.
        if Path(str(path) + "-wal").exists():
            return {"schemaVersion": 1, "operations": [], "observed": "live-journal",
                    "installationCertified": False, "requiresLiveReader": True}
        from urllib.parse import quote
        connection = sqlite3.connect("file:" + quote(str(path.resolve()), safe="/") + "?mode=ro&immutable=1", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            rows = connection.execute("SELECT * FROM operations ORDER BY created,id").fetchall()
            return {"schemaVersion": 1, "operations": [dict(row) for row in rows],
                    "observed": "checkpointed", "installationCertified": False}
        finally:
            connection.close()
