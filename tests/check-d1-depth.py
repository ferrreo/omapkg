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
    for name in ("workers.ts", "worker-protocol.ts", "native-signing.ts", "input-locks.ts", "recipe-inspections.ts", "recipe-source-plans.ts", "preserved-imports.ts"):
        source = (root / "src/lib/server" / name).read_text()
        for sql in re.findall(r"prepare\(`([^`]+)`\)", source):
            if "${" in sql:
                continue
            db.execute("EXPLAIN " + sql, [None] * sql.count("?")).fetchall()
            checked += 1
    db.execute("EXPLAIN UPDATE signing_intents SET status='signed' WHERE id=?", [None]).fetchall()
    for view in ("current_preserved_build_inputs", "invalid_preserved_leases"):
        db.execute("SELECT COUNT(*) FROM " + view).fetchall()
    db.execute("EXPLAIN UPDATE workers SET capabilities_json=capabilities_json WHERE id=?", [None]).fetchall()
    db.execute("EXPLAIN DELETE FROM team_memberships WHERE github_id=?", [None]).fetchall()
    db.execute("EXPLAIN UPDATE requests SET status='rejected' WHERE id=?", [None]).fetchall()
    assert checked >= 20, "Native SQL coverage unexpectedly shrank"
    print(f"{checked + 1} native queries compile at D1 expression depth 100")
