"""Durable issue claims with a generation that fences stale executions."""

import sqlite3
import time
from contextlib import contextmanager


class Claims:
    def __init__(self, path, clock=time.time):
        self.path = path
        self.clock = clock
        with self.connection() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS claims (
                issue TEXT PRIMARY KEY, owner TEXT NOT NULL,
                generation INTEGER NOT NULL, expires_at INTEGER NOT NULL
            )""")

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        try:
            db.execute("PRAGMA busy_timeout=10000")
            yield db
        finally:
            db.close()

    def claim(self, issue, owner, ttl=60):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            now = self.clock()
            row = db.execute("SELECT owner, generation, expires_at FROM claims WHERE issue=?", (issue,)).fetchone()
            if row and row[2] > now:
                db.rollback()
                return None
            generation = row[1] + 1 if row else 1
            db.execute("INSERT OR REPLACE INTO claims VALUES (?, ?, ?, ?)",
                       (issue, owner, generation, now + ttl))
            db.commit()
            return generation

    def current(self, issue, owner, generation):
        with self.connection() as db:
            row = db.execute("SELECT owner, generation, expires_at FROM claims WHERE issue=?", (issue,)).fetchone()
            now = self.clock()
            return bool(row and row[0] == owner and row[1] == generation and row[2] > now)

    def perform_current(self, issue, owner, generation, operation):
        """Serialize authority validation and the bounded external operation.

        A successor cannot acquire this claim while the operation is running.
        After a crash or ambiguous API response, the caller must reconcile the
        fixed branch / PR before attempting another operation.
        """
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            now = self.clock()
            row = db.execute("SELECT owner, generation, expires_at FROM claims WHERE issue=?", (issue,)).fetchone()
            if not row or row[0] != owner or row[1] != generation or row[2] <= now:
                db.rollback()
                raise PermissionError("Expired execution generation")
            try:
                result = operation()
                db.commit()
                return result
            except BaseException:
                db.rollback()
                raise

    def release(self, issue, owner, generation):
        with self.connection() as db:
            db.execute("UPDATE claims SET expires_at=0 WHERE issue=? AND owner=? AND generation=?",
                       (issue, owner, generation))
