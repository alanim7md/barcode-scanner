"""
Run this ONCE on the server to fix duplicate "None branch" sessions.

Usage:
    python fix_null_branches.py

What it does:
- Finds all scans with empty/null branch
- If the same session name exists with a real branch → reassigns them to that branch
- Reports anything it couldn't fix (orphan sessions with no real branch match)
"""

from app import app, db
from sqlalchemy import text

with app.app_context():
    print("=== Scanning for empty-branch scans ===\n")

    null_sessions = db.session.execute(
        text("SELECT DISTINCT session_name FROM scans WHERE branch IS NULL OR branch = ''")
    ).fetchall()

    if not null_sessions:
        print("✅ Nothing to fix — no empty-branch scans found.")
        exit(0)

    total_fixed = 0
    orphans = []

    for row in null_sessions:
        sn = row[0]

        # Find the most common real branch for this session name
        real = db.session.execute(
            text("""
                SELECT branch, COUNT(*) as cnt
                FROM scans
                WHERE session_name = :s AND branch IS NOT NULL AND branch != ''
                GROUP BY branch
                ORDER BY cnt DESC
                LIMIT 1
            """),
            {"s": sn}
        ).fetchone()

        count = db.session.execute(
            text("SELECT COUNT(*) FROM scans WHERE session_name = :s AND (branch IS NULL OR branch = '')"),
            {"s": sn}
        ).scalar()

        if real:
            target_branch = real[0]
            db.session.execute(
                text("UPDATE scans SET branch = :b WHERE session_name = :s AND (branch IS NULL OR branch = '')"),
                {"b": target_branch, "s": sn}
            )
            total_fixed += count
            print(f"  ✅ Fixed {count:>5} scans: '{sn}' → branch '{target_branch}'")
        else:
            orphans.append((sn, count))
            print(f"  ⚠️  No real branch for '{sn}' ({count} scans) — skipped")

    db.session.commit()

    print(f"\n=== Done. Fixed {total_fixed} scans. ===")

    if orphans:
        print(f"\n⚠️  {len(orphans)} session(s) still have no branch (no matching branch found):")
        for sn, cnt in orphans:
            print(f"   - '{sn}' ({cnt} scans) — delete from the Admin → Floors tab if unwanted")
