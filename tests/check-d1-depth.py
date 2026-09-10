"""Compile native claim, lease and signing SQL with D1's expression-depth limit."""
import re
import sqlite3
from pathlib import Path

root = Path(__file__).resolve().parents[1]
with sqlite3.connect(":memory:") as db:
    db.setlimit(sqlite3.SQLITE_LIMIT_EXPR_DEPTH, 100)
    for migration in sorted((root / "migrations").glob("*.sql")):
        db.executescript(migration.read_text())
    checked = 0
    for name in ("workers.ts", "worker-protocol.ts", "native-signing.ts", "input-locks.ts"):
        source = (root / "src/lib/server" / name).read_text()
        for sql in re.findall(r"prepare\(`([^`]+)`\)", source):
            if "${" in sql:
                continue
            db.execute("EXPLAIN " + sql, [None] * sql.count("?")).fetchall()
            checked += 1
    db.execute("EXPLAIN UPDATE signing_intents SET status='signed' WHERE id=?", [None]).fetchall()
    assert checked >= 20, "Native SQL coverage unexpectedly shrank"
    print(f"{checked + 1} native queries compile at D1 expression depth 100")
