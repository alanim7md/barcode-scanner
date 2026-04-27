from flask import Flask, render_template, request, jsonify, session, redirect, Response
import sqlite3
from datetime import datetime
import io
import csv
import uuid
import os
import urllib.parse
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24).hex()

def get_gmt3_time():
    from datetime import timezone, timedelta
    return datetime.now(timezone(timedelta(hours=3))).strftime("%Y-%m-%d %H:%M:%S")

DB = "database.db"
USERS_DB = "users.db"

# ---------- BARCODE SUFFIX HELPERS ----------
SUFFIX_DAMAGED = "__DAMAGED"
SUFFIX_FLAGGED = "__FLAGGED"

def clean_barcode(barcode):
    """Strip damage/flag suffixes to get the raw barcode."""
    return barcode.replace(SUFFIX_DAMAGED, '').replace(SUFFIX_FLAGGED, '')

def barcode_variants(barcode):
    """Return (clean, damaged, flagged) tuple for SQL queries."""
    clean = clean_barcode(barcode)
    return clean, clean + SUFFIX_DAMAGED, clean + SUFFIX_FLAGGED

# SQL fragment for grouping queries — reused across summary/admin/export
SQL_CLEAN_BARCODE = f"REPLACE(REPLACE(barcode,'{SUFFIX_DAMAGED}',''),'{SUFFIX_FLAGGED}','')"
SQL_GOOD_COUNT = f"SUM(CASE WHEN barcode NOT LIKE '%{SUFFIX_DAMAGED}%' THEN 1 ELSE 0 END)"
SQL_DAMAGED_COUNT = f"SUM(CASE WHEN barcode LIKE '%{SUFFIX_DAMAGED}%' THEN 1 ELSE 0 END)"
SQL_FLAGGED_COUNT = f"SUM(CASE WHEN barcode LIKE '%{SUFFIX_FLAGGED}%' THEN 1 ELSE 0 END)"

# ---------- DB HELPER ----------
def get_db():
    # timeout=20 helps prevent "database is locked" during concurrent writes
    conn = sqlite3.connect(DB, timeout=20)
    # Enable Write-Ahead Logging (WAL) for significantly better concurrency
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn

def get_users_db():
    conn = sqlite3.connect(USERS_DB, timeout=20)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn

# ---------- DB INIT ----------
def init_db():
    conn = get_db()
    c = conn.cursor()

    # Users table removed from here, moving to users.db below

    c.execute("""
        CREATE TABLE IF NOT EXISTS branches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            barcode TEXT,
            timestamp TEXT,
            user TEXT,
            branch TEXT,
            session_name TEXT
        )
    """)

    try:
        c.execute("ALTER TABLE scans ADD COLUMN flag_reason TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass

    try:
        c.execute("ALTER TABLE scans ADD COLUMN session_name TEXT")
    except sqlite3.OperationalError:
        pass
        
    try:
        c.execute("ALTER TABLE scans ADD COLUMN user TEXT")
    except sqlite3.OperationalError:
        pass
        
    try:
        c.execute("ALTER TABLE scans ADD COLUMN branch TEXT")
    except sqlite3.OperationalError:
        pass

    c.execute("""
        CREATE TABLE IF NOT EXISTS global_settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)

    # Seed admin is moved to users.db setup

    # ----- CREATE INDEXES FOR EXTREME SPEED -----
    # These make searching, grouping, and sorting instantly fast even with millions of rows
    c.execute("CREATE INDEX IF NOT EXISTS idx_scans_barcode ON scans(barcode)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_scans_user_session ON scans(user, session_name)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_scans_branch_session ON scans(branch, session_name)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp)")
    
    try:
        c.execute("DROP INDEX IF EXISTS idx_scans_unique_sync")
    except sqlite3.OperationalError:
        pass

    conn.commit()
    conn.close()

    # Setup Users DB
    u_conn = get_users_db()
    u_c = u_conn.cursor()
    u_c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
    """)
    try:
        u_c.execute("ALTER TABLE users ADD COLUMN session_token TEXT")
    except sqlite3.OperationalError:
        pass
        
    try:
        u_c.execute("ALTER TABLE users ADD COLUMN last_active TEXT")
    except sqlite3.OperationalError:
        pass
        
    u_c.execute("SELECT COUNT(*) FROM users")
    if u_c.fetchone()[0] == 0:
        u_c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                  ('admin', generate_password_hash('admin123'), 'admin'))
    u_conn.commit()
    u_conn.close()

try:
    init_db()
except sqlite3.OperationalError:
    # This happens when multiple uWSGI workers start at the exact same time on PythonAnywhere
    # and race to execute CREATE/ALTER TABLE statements. One worker wins, the others hit a lock.
    # Ignoring the error allows the worker to start up successfully.
    pass

@app.before_request
def check_session_token():
    if request.endpoint in ['login', 'static']:
        return

    user = session.get("user")
    token = session.get("session_token")

    if user:
        conn = get_users_db()
        c = conn.cursor()
        c.execute("SELECT session_token FROM users WHERE username=?", (user,))
        row = c.fetchone()
        conn.close()

        if row and row[0] and row[0] != token:
            session.clear()
            conn.close()
            if request.path.startswith('/api/') or request.method == 'POST':
                from flask import jsonify
                return jsonify({"error": "logged_out", "redirect": "/login"}), 401
            return redirect("/login")
            
        # Update last_active
        c.execute("UPDATE users SET last_active=? WHERE username=?", (get_gmt3_time(), user))
        conn.commit()
        conn.close()

# ---------- LOGIN ----------
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        u = request.form["username"]
        p = request.form["password"]

        conn = get_users_db()
        c = conn.cursor()
        c.execute("SELECT role, password FROM users WHERE username=?", (u,))
        row = c.fetchone()

        if row:
            db_role, db_password = row[0], row[1]
            
            # Check if password matches (either hashed or legacy plain text)
            is_valid = check_password_hash(db_password, p) if db_password.startswith(('scrypt:', 'pbkdf2:')) else db_password == p
            
            if is_valid:
                new_token = str(uuid.uuid4())
                session["user"] = u
                session["role"] = db_role
                session["session_token"] = new_token
                
                c.execute("UPDATE users SET session_token=? WHERE username=?", (new_token, u))
                
                # Auto-upgrade plain text to hashed
                if not db_password.startswith(('scrypt:', 'pbkdf2:')):
                    c.execute("UPDATE users SET password=? WHERE username=?", (generate_password_hash(p), u))
                    
                conn.commit()
                conn.close()
                return redirect("/")
                
        conn.close()
        return redirect("/login?error=1")

    return render_template("login.html")

@app.route("/logout")
def logout():
    user = session.get("user")
    if user:
        conn = get_users_db()
        c = conn.cursor()
        c.execute("UPDATE users SET session_token=NULL, last_active=NULL WHERE username=?", (user,))
        conn.commit()
        conn.close()
    session.clear()
    return redirect("/login")

# ---------- MAIN ----------
@app.route("/")
def index():
    if "user" not in session or "role" not in session:
        return redirect("/login")
    if session["role"] == "moderator":
        return redirect("/admin")
    return render_template("index.html", user=session["user"], role=session["role"])

# ---------- SCAN ----------
def insert_scans_bulk(barcode, qty, is_damaged=False, is_flagged=False, session_name=None, branch=None):
    # Normalize barcode: uppercase and strip whitespace so 'abc' == 'ABC'
    barcode = barcode.strip().upper()
    if session_name is None:
        session_name = request.json.get("session_name", "")
    if branch is None:
        branch = request.json.get("branch")

    user = session.get("user")
    ts = get_gmt3_time()

    conn = get_db()
    c = conn.cursor()

    # --- Session Collision Detection ---
    bc_clean, bc_damaged, bc_flagged = barcode_variants(barcode)
    # Check if this barcode exists in a DIFFERENT session
    c.execute("""
        SELECT session_name, branch FROM scans 
        WHERE (barcode=? OR barcode=? OR barcode=? OR barcode=? OR barcode=?) 
        AND session_name != ? 
        AND session_name != ''
        LIMIT 1
    """, (bc_clean, bc_damaged, bc_flagged, bc_clean + SUFFIX_DAMAGED + SUFFIX_FLAGGED, bc_clean + SUFFIX_FLAGGED + SUFFIX_DAMAGED, session_name))
    collision = c.fetchone()
    
    flag_reason = ""
    warning_msg = None
    if collision:
        is_flagged = True
        prev_session = collision[0]
        prev_branch = collision[1] or "Unknown"
        flag_reason = f"Session Collision: scanned in {prev_session} ({prev_branch})"
        
        # Check if already scanned in current session
        c.execute("""
            SELECT COUNT(*) FROM scans 
            WHERE (barcode=? OR barcode=? OR barcode=? OR barcode=? OR barcode=?) 
            AND session_name = ?
        """, (bc_clean, bc_damaged, bc_flagged, bc_clean + SUFFIX_DAMAGED + SUFFIX_FLAGGED, bc_clean + SUFFIX_FLAGGED + SUFFIX_DAMAGED, session_name))
        if c.fetchone()[0] == 0:
            warning_msg = f"Collision! Barcode previously scanned in session '{prev_session}' ({prev_branch})."
    elif is_flagged:
        flag_reason = "Manual Flag"

    actual_barcode = barcode
    if is_damaged:
        actual_barcode += SUFFIX_DAMAGED
    if is_flagged:
        actual_barcode += SUFFIX_FLAGGED



    rows = [(actual_barcode, ts, user, branch, session_name, flag_reason) for _ in range(qty)]
    c.executemany("""
        INSERT INTO scans (barcode, timestamp, user, branch, session_name, flag_reason)
        VALUES (?, ?, ?, ?, ?, ?)
    """, rows)

    conn.commit()
    conn.close()

    return {"status": "ok", "warning": warning_msg} if warning_msg else {"status": "ok"}

@app.route("/scan", methods=["POST"])
def scan():
    res = insert_scans_bulk(request.json["barcode"], 1)
    return jsonify(res)

@app.route("/manual", methods=["POST"])
def manual():
    res = insert_scans_bulk(request.json["barcode"], int(request.json.get("qty", 1)))
    return jsonify(res)

@app.route("/damaged", methods=["POST"])
def damaged():
    res = insert_scans_bulk(request.json["barcode"], int(request.json.get("qty", 1)), is_damaged=True)
    return jsonify(res)

@app.route("/flag_item", methods=["POST"])
def flag_item():
    barcode = request.json["barcode"].strip().upper()
    session_name = request.json.get("session_name")
    user = session.get("user")
    
    conn = get_db()
    c = conn.cursor()
    bc_clean = clean_barcode(barcode)
    
    # Check if there are any flagged records for this barcode
    c.execute("""
        SELECT COUNT(*) FROM scans 
        WHERE (barcode=? OR barcode=?) AND session_name=? AND user=?
    """, (bc_clean + SUFFIX_FLAGGED, bc_clean + SUFFIX_DAMAGED + SUFFIX_FLAGGED, session_name, user))
    is_flagged = c.fetchone()[0] > 0
    
    if is_flagged:
        # Unflag
        c.execute("""
            UPDATE scans 
            SET barcode = REPLACE(barcode, ?, ''), flag_reason = ''
            WHERE (barcode=? OR barcode=?) AND session_name=? AND user=?
        """, (SUFFIX_FLAGGED, bc_clean + SUFFIX_FLAGGED, bc_clean + SUFFIX_DAMAGED + SUFFIX_FLAGGED, session_name, user))
    else:
        # Flag
        c.execute("""
            UPDATE scans 
            SET barcode = barcode || ?, flag_reason = 'Manual Flag'
            WHERE (barcode=? OR barcode=?) AND session_name=? AND user=?
        """, (SUFFIX_FLAGGED, bc_clean, bc_clean + SUFFIX_DAMAGED, session_name, user))
        
    conn.commit()
    conn.close()
    return jsonify({"status":"ok"})

@app.route("/sync", methods=["POST"])
def sync():
    scans = request.json.get("scans", [])
    if not scans:
        return jsonify({"status": "ok"})

    rows = [
        (
            (s.get("barcode") or "").strip().upper(),
            s.get("timestamp"),
            s.get("user"),
            s.get("branch"),
            s.get("session_name")
        )
        for s in scans
    ]
    conn = get_db()
    c = conn.cursor()
    c.executemany("""
        INSERT OR IGNORE INTO scans (barcode, timestamp, user, branch, session_name)
        VALUES (?, ?, ?, ?, ?)
    """, rows)
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})

@app.route("/undo", methods=["POST"])
def undo():
    user = session.get("user")
    session_name = request.json.get("session_name")
    
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT id FROM scans 
        WHERE user=? AND session_name=?
        ORDER BY timestamp DESC LIMIT 1
    """, (user, session_name))
    row = c.fetchone()
    if row:
        c.execute("DELETE FROM scans WHERE id=?", (row[0],))
        conn.commit()
    conn.close()
    return jsonify({"status": "ok"})

# ---------- SUMMARY ----------
@app.route("/summary")
def summary():
    sess_name = request.args.get("session_name", "")
    conn = get_db()
    c = conn.cursor()

    c.execute(f"""
        SELECT 
            {SQL_CLEAN_BARCODE},
            {SQL_GOOD_COUNT},
            {SQL_DAMAGED_COUNT},
            MIN(timestamp),
            MAX(timestamp),
            {SQL_FLAGGED_COUNT}
        FROM scans
        WHERE user=? AND session_name=?
        GROUP BY 1
        ORDER BY MAX(timestamp) DESC
    """, (session.get("user"), sess_name))

    data = []
    for r in c.fetchall():
        data.append({
            "barcode": r[0],
            "good": r[1],
            "damaged": r[2],
            "first": r[3],
            "last": r[4],
            "flagged": r[5]
        })

    conn.close()
    return jsonify(data)

# ---------- COUNT ----------
@app.route("/count")
def count():
    sess_name = request.args.get("session_name", "")
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM scans WHERE user=? AND session_name=?", (session.get("user"), sess_name))
    total = c.fetchone()[0]
    conn.close()
    return jsonify({"count": total})

# (Removed destructive reset)

@app.route("/branches")
def branches():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT name FROM branches")
    data = [r[0] for r in c.fetchall()]
    conn.close()
    return jsonify(data)

@app.route("/sessions")
def get_sessions():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT DISTINCT session_name FROM scans WHERE session_name != '' AND session_name IS NOT NULL ORDER BY session_name")
    data = [r[0] for r in c.fetchall() if r[0]]
    conn.close()
    return jsonify(data)

@app.route("/add_branch", methods=["POST"])
def add_branch():
    if session["role"] != "admin": return "no"
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO branches (name) VALUES (?)", (request.json["name"],))
    conn.commit()
    conn.close()
    return "ok"

# ---------- HISTORY & USER ACTION ----------
@app.route("/user/delete_scan", methods=["DELETE"])
def user_delete_scan():
    if "user" not in session: return "forbidden"
    data = request.json
    barcode = data.get("barcode")
    session_name = data.get("session_name")
    
    conn = get_db()
    c = conn.cursor()
    bc_clean = clean_barcode(barcode)
    c.execute("""
        DELETE FROM scans 
        WHERE (
            barcode=? OR 
            barcode=? OR 
            barcode=? OR 
            barcode=? OR 
            barcode=?
        ) AND user=? AND session_name=?
    """, (
        bc_clean, 
        bc_clean + SUFFIX_DAMAGED, 
        bc_clean + SUFFIX_FLAGGED, 
        bc_clean + SUFFIX_DAMAGED + SUFFIX_FLAGGED, 
        bc_clean + SUFFIX_FLAGGED + SUFFIX_DAMAGED, 
        session.get("user"), 
        session_name
    ))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})

@app.route("/user/history")
def user_history():
    if "user" not in session: return "forbidden"
    branch = request.args.get("branch", "")
    session_name = request.args.get("session_name", "")
    date = request.args.get("date", "")
    
    query = f"""
        SELECT 
            {SQL_CLEAN_BARCODE},
            branch,
            session_name,
            {SQL_GOOD_COUNT},
            {SQL_DAMAGED_COUNT},
            MAX(timestamp),
            {SQL_FLAGGED_COUNT}
        FROM scans
        WHERE user=?
    """
    params = [session.get("user")]
    
    if branch:
        query += " AND branch=?"
        params.append(branch)
    if session_name:
        query += " AND session_name=?"
        params.append(session_name)
    if date:
        # SQLite dates are stored as YYYY-MM-DD HH:MM:SS, so DATE() works perfectly.
        query += " AND date(timestamp)=?"
        params.append(date)
        
    query += " GROUP BY 1, 2, 3 ORDER BY MAX(timestamp) DESC"
    
    conn = get_db()
    c = conn.cursor()
    c.execute(query, tuple(params))
    data = []
    for r in c.fetchall():
        data.append({
            "barcode": r[0], "branch": r[1], "session_name": r[2],
            "good": r[3], "damaged": r[4], "last": r[5], "flagged": r[6]
        })
    conn.close()
    return jsonify(data)

# ---------- ADMIN ----------
@app.route("/admin")
def admin():
    if session.get("role") not in ["admin", "moderator"]:
        return "forbidden"

    u_conn = get_users_db()
    u_c = u_conn.cursor()
    u_c.execute("SELECT username, role FROM users")
    users = [{"username": r[0], "role": r[1]} for r in u_c.fetchall()]
    u_conn.close()

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, name FROM branches")
    branches = [{"id": r[0], "name": r[1]} for r in c.fetchall()]

    conn.close()
    return render_template("admin.html", users=users, branches=branches, role=session.get("role"))

@app.route("/admin/scans_data")
def admin_scans_data():
    if session.get("role") not in ["admin", "moderator"]: return "forbidden"
    date_from = request.args.get("date_from", "")
    date_to = request.args.get("date_to", "")
    conn = get_db()
    c = conn.cursor()
    
    query = f"""
        SELECT 
            {SQL_CLEAN_BARCODE},
            user,
            branch,
            session_name,
            {SQL_GOOD_COUNT},
            {SQL_DAMAGED_COUNT},
            MIN(timestamp),
            MAX(timestamp),
            {SQL_FLAGGED_COUNT},
            GROUP_CONCAT(DISTINCT flag_reason)
        FROM scans
        WHERE 1=1
    """
    params = []
    if date_from:
        query += " AND timestamp >= ?"
        params.append(date_from.replace("T", " ") + ":00")
    if date_to:
        query += " AND timestamp <= ?"
        params.append(date_to.replace("T", " ") + ":59")
    query += " GROUP BY 1, 2, 3, 4 ORDER BY MAX(timestamp) DESC"
    
    c.execute(query, tuple(params))
    data = []
    for r in c.fetchall():
        reasons = r[9]
        clean_reason = ""
        if reasons:
            valid_reasons = [x.strip() for x in reasons.split(',') if x and x.strip()]
            clean_reason = ", ".join(set(valid_reasons))
            
        data.append({
            "barcode": r[0], "user": r[1], "branch": r[2], "session_name": r[3],
            "good": r[4], "damaged": r[5], "first": r[6], "last": r[7], "flagged": r[8], "reason": clean_reason
        })
    conn.close()
    return jsonify(data)

@app.route("/admin/master_scans")
def admin_master_scans():
    if session.get("role") not in ["admin", "moderator"]: return "forbidden"
    branch = request.args.get("branch", "")
    session_name = request.args.get("session_name", "")
    date_from = request.args.get("date_from", "")
    date_to = request.args.get("date_to", "")
    conn = get_db()
    c = conn.cursor()
    
    query = f"""
        SELECT 
            {SQL_CLEAN_BARCODE},
            {SQL_GOOD_COUNT},
            {SQL_DAMAGED_COUNT},
            MIN(timestamp),
            MAX(timestamp),
            GROUP_CONCAT(DISTINCT user),
            {SQL_FLAGGED_COUNT},
            GROUP_CONCAT(DISTINCT flag_reason)
        FROM scans
        WHERE 1=1
    """
    params = []
    if branch:
        query += " AND branch=?"
        params.append(branch)
    if session_name:
        query += " AND session_name=?"
        params.append(session_name)
    if date_from:
        query += " AND timestamp >= ?"
        params.append(date_from.replace("T", " ") + ":00")
    if date_to:
        query += " AND timestamp <= ?"
        params.append(date_to.replace("T", " ") + ":59")
        
    query += " GROUP BY 1 ORDER BY MAX(timestamp) DESC"
    
    c.execute(query, tuple(params))
    data = []
    for r in c.fetchall():
        reasons = r[7]
        clean_reason = ""
        if reasons:
            valid_reasons = [x.strip() for x in reasons.split(',') if x and x.strip()]
            clean_reason = ", ".join(set(valid_reasons))
            
        data.append({
            "barcode": r[0], "good": r[1], "damaged": r[2], "first": r[3], "last": r[4], "users": r[5], "flagged": r[6], "reason": clean_reason
        })
    conn.close()
    return jsonify(data)

@app.route("/admin/export_csv")
def admin_export_csv():
    if session.get("role") not in ["admin", "moderator"]: return "forbidden"
    mode = request.args.get("mode", "detailed")
    branch = request.args.get("branch", "")
    session_name = request.args.get("session_name", "")
    date_from = request.args.get("date_from", "")
    date_to = request.args.get("date_to", "")
    conn = get_db()
    c = conn.cursor()
    output = io.StringIO()
    writer = csv.writer(output)
    if mode == "master":
        writer.writerow(["Barcode", "Good", "Damaged", "Flagged", "Flag Reason", "First Scan", "Last Scan", "Users"])
        query = f"""
            SELECT {SQL_CLEAN_BARCODE},
                   {SQL_GOOD_COUNT},
                   {SQL_DAMAGED_COUNT},
                   {SQL_FLAGGED_COUNT},
                   GROUP_CONCAT(DISTINCT flag_reason),
                   MIN(timestamp),
                   MAX(timestamp),
                   GROUP_CONCAT(DISTINCT user)
            FROM scans WHERE 1=1
        """
        params = []
        if branch:
            query += " AND branch=?"
            params.append(branch)
        if session_name:
            query += " AND session_name=?"
            params.append(session_name)
        if date_from:
            query += " AND timestamp >= ?"
            params.append(date_from.replace("T", " ") + ":00")
        if date_to:
            query += " AND timestamp <= ?"
            params.append(date_to.replace("T", " ") + ":59")
        query += " GROUP BY 1 ORDER BY MAX(timestamp) DESC"
        c.execute(query, tuple(params))
        for r in c.fetchall():
            row = list(r)
            # Clean flag_reason (index 4)
            reasons = row[4] or ""
            valid = [x.strip() for x in reasons.split(',') if x and x.strip()]
            row[4] = ", ".join(set(valid)) if valid else ""
            writer.writerow(row)
    else:
        writer.writerow(["Barcode", "User", "Branch", "Session", "Good", "Damaged", "Flagged", "Flag Reason", "First Scan", "Last Scan"])
        query = f"""
            SELECT {SQL_CLEAN_BARCODE}, user, branch, session_name,
                   {SQL_GOOD_COUNT},
                   {SQL_DAMAGED_COUNT},
                   {SQL_FLAGGED_COUNT},
                   GROUP_CONCAT(DISTINCT flag_reason),
                   MIN(timestamp),
                   MAX(timestamp)
            FROM scans WHERE 1=1
        """
        params = []
        if date_from:
            query += " AND timestamp >= ?"
            params.append(date_from.replace("T", " ") + ":00")
        if date_to:
            query += " AND timestamp <= ?"
            params.append(date_to.replace("T", " ") + ":59")
        query += " GROUP BY 1, 2, 3, 4 ORDER BY MAX(timestamp) DESC"
        c.execute(query, tuple(params))
        for r in c.fetchall():
            row = list(r)
            # Clean flag_reason (index 7)
            reasons = row[7] or ""
            valid = [x.strip() for x in reasons.split(',') if x and x.strip()]
            row[7] = ", ".join(set(valid)) if valid else ""
            writer.writerow(row)
    conn.close()
    
    # Build filename with context
    fname_parts = ["scans"]
    if branch: fname_parts.append(branch.replace(' ', '_'))
    if session_name: fname_parts.append(session_name.replace(' ', '_'))
    fname_parts.append(mode)
    filename = "_".join(fname_parts) + ".csv"
    encoded_filename = urllib.parse.quote(filename)
    
    return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename*=UTF-8''{encoded_filename}"})

@app.route("/admin/stats")
def admin_stats():
    if session.get("role") not in ["admin", "moderator"]: return "forbidden"
    
    branch = request.args.get("branch", "")
    session_name = request.args.get("session_name", "")
    date_from = request.args.get("date_from", "")
    date_to = request.args.get("date_to", "")
    
    where_clauses = ["1=1"]
    params = []
    
    if branch:
        where_clauses.append("branch=?")
        params.append(branch)
    if session_name:
        where_clauses.append("session_name=?")
        params.append(session_name)
    if date_from:
        where_clauses.append("timestamp >= ?")
        params.append(date_from.replace("T", " ") + ":00")
    if date_to:
        where_clauses.append("timestamp <= ?")
        params.append(date_to.replace("T", " ") + ":59")
        
    where_sql = " AND ".join(where_clauses)
    
    conn = get_db()
    c = conn.cursor()
    
    c.execute(f"SELECT COUNT(*) FROM scans WHERE {where_sql}", tuple(params))
    total_scans = c.fetchone()[0]
    
    c.execute(f"SELECT COUNT(DISTINCT {SQL_CLEAN_BARCODE}) FROM scans WHERE {where_sql}", tuple(params))
    unique_barcodes = c.fetchone()[0]
    
    c.execute(f"SELECT COUNT(DISTINCT {SQL_CLEAN_BARCODE}) FROM scans WHERE barcode LIKE '%{SUFFIX_FLAGGED}%' AND {where_sql}", tuple(params))
    flagged_items = c.fetchone()[0]
    
    conn.close()
    
    # Active Users
    u_conn = get_users_db()
    u_c = u_conn.cursor()
    u_c.execute("SELECT COUNT(*) FROM users WHERE session_token IS NOT NULL AND last_active >= datetime('now', '+3 hours', '-20 minutes')")
    active_users = u_c.fetchone()[0]
    u_conn.close()
    
    return jsonify({
        "total_scans": total_scans,
        "unique_barcodes": unique_barcodes,
        "active_users": active_users,
        "flagged_items": flagged_items
    })

@app.route("/admin/chart_data")
def admin_chart_data():
    if session.get("role") not in ["admin", "moderator"]: return "forbidden"
    time_range = request.args.get("range", "7days")
    conn = get_db()
    c = conn.cursor()
    
    dates = []
    counts = []
    
    if time_range == "24hours":
        c.execute("""
            SELECT strftime('%H:00', timestamp), COUNT(*) 
            FROM scans 
            WHERE timestamp >= datetime('now', '+3 hours', '-24 hours')
            GROUP BY strftime('%Y-%m-%d %H', timestamp)
            ORDER BY strftime('%Y-%m-%d %H', timestamp) ASC
        """)
        for r in c.fetchall():
            dates.append(r[0])
            counts.append(r[1])
    else:
        c.execute("""
            SELECT date(timestamp), COUNT(*) 
            FROM scans 
            WHERE timestamp >= datetime('now', '+3 hours', '-7 days')
            GROUP BY date(timestamp)
            ORDER BY date(timestamp) ASC
        """)
        for r in c.fetchall():
            dates.append(r[0])
            counts.append(r[1])
        
    c.execute("""
        SELECT user, COUNT(*) 
        FROM scans
        WHERE user IS NOT NULL AND user != ''
        GROUP BY user
        ORDER BY COUNT(*) DESC
    """)
    user_labels = []
    user_counts = []
    for r in c.fetchall():
        user_labels.append(r[0])
        user_counts.append(r[1])
        
    conn.close()
    
    return jsonify({
        "time": {"labels": dates, "data": counts},
        "users": {"labels": user_labels, "data": user_counts}
    })

@app.route("/settings")
def get_settings():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT key, value FROM global_settings")
    data = {r[0]: r[1] for r in c.fetchall()}
    conn.close()
    return jsonify(data)

@app.route("/admin/settings", methods=["POST"])
def set_settings():
    if session.get("role") != "admin": return "forbidden"
    data = request.json
    conn = get_db()
    c = conn.cursor()
    for k, v in data.items():
        c.execute("INSERT INTO global_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=?", (k, v, v))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})

@app.route("/admin/adjust_count", methods=["POST"])
def admin_adjust_count():
    if session.get("role") != "admin": return "forbidden"
    data = request.json
    barcode = data["barcode"].strip().upper()
    if data["type"] == "damaged":
        barcode += SUFFIX_DAMAGED
    elif data["type"] == "flagged":
        barcode += SUFFIX_FLAGGED
        
    diff = int(data["diff"])
    
    conn = get_db()
    c = conn.cursor()
    if diff > 0:
        for _ in range(diff):
            c.execute("""
                INSERT INTO scans (barcode, timestamp, user, branch, session_name)
                VALUES (?, ?, ?, ?, ?)
            """, (barcode, get_gmt3_time(), data["user"], data["branch"], data["session_name"]))
    elif diff < 0:
        c.execute("""
            DELETE FROM scans 
            WHERE id IN (
                SELECT id FROM scans 
                WHERE barcode=? AND user=? AND branch=? AND session_name=?
                ORDER BY timestamp DESC
                LIMIT ?
            )
        """, (barcode, data["user"], data["branch"], data["session_name"], abs(diff)))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})

@app.route("/admin/toggle_flag", methods=["POST"])
def admin_toggle_flag():
    role = session.get("role")
    if role not in ["admin", "moderator"]: return jsonify({"error": "forbidden"}), 403
    data = request.json
    barcode = data["barcode"].strip().upper()
    target_user = data.get("user")
    if target_user == "null": target_user = None
    branch = data.get("branch")
    session_name = data.get("session_name")
    
    current_user = session.get("user", "unknown")
    if role == "moderator":
        flag_reason = f"Flagged by moderator {current_user}"
    else:
        flag_reason = "Admin Manual Flag"
    
    conn = get_db()
    c = conn.cursor()
    flagged_bc = barcode + SUFFIX_FLAGGED
    
    # Check if ANY flag exists for this barcode in this session
    query = "SELECT COUNT(*) FROM scans WHERE barcode=?"
    params = [flagged_bc]
    if session_name and session_name != "null":
        query += " AND session_name=?"
        params.append(session_name)
    c.execute(query, tuple(params))
    is_flagged = c.fetchone()[0] > 0
    
    if is_flagged:
        del_query = "DELETE FROM scans WHERE barcode=?"
        del_params = [flagged_bc]
        if session_name and session_name != "null":
            del_query += " AND session_name=?"
            del_params.append(session_name)
        c.execute(del_query, tuple(del_params))
    else:
        if target_user:
            c.execute("INSERT INTO scans (barcode, timestamp, user, branch, session_name, flag_reason) VALUES (?, ?, ?, ?, ?, ?)", 
                     (flagged_bc, get_gmt3_time(), target_user, branch or 'N/A', session_name or 'N/A', flag_reason))
        else:
            q = "SELECT DISTINCT user FROM scans WHERE (barcode=? OR barcode=?)"
            p = [barcode, barcode + SUFFIX_DAMAGED]
            if session_name and session_name != "null":
                q += " AND session_name=?"
                p.append(session_name)
            c.execute(q, tuple(p))
            users = [r[0] for r in c.fetchall()]
            if not users:
                users = [current_user]
            for u in users:
                c.execute("INSERT INTO scans (barcode, timestamp, user, branch, session_name, flag_reason) VALUES (?, ?, ?, ?, ?, ?)", 
                         (flagged_bc, get_gmt3_time(), u, branch or 'N/A', session_name or 'N/A', flag_reason))
            
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})

@app.route("/admin/delete_session", methods=["POST"])
def admin_delete_session():
    if session.get("role") != "admin": return jsonify({"error": "forbidden"}), 403
    data = request.json
    password = data.get("password")
    session_name = data.get("session_name")
    branch = data.get("branch", "")
    
    if not session_name:
        return jsonify({"error": "No session specified"}), 400
    
    # Verify admin password
    u_conn = get_users_db()
    u_c = u_conn.cursor()
    u_c.execute("SELECT password FROM users WHERE username=?", (session.get("user"),))
    row = u_c.fetchone()
    u_conn.close()
    
    if not row:
        return jsonify({"error": "Invalid password"}), 401
    db_password = row[0]
    is_valid = check_password_hash(db_password, password) if db_password.startswith(('scrypt:', 'pbkdf2:')) else db_password == password
    if not is_valid:
        return jsonify({"error": "Invalid password"}), 401
    
    conn = get_db()
    c = conn.cursor()
    if branch:
        c.execute("SELECT COUNT(*) FROM scans WHERE session_name=? AND branch=?", (session_name, branch))
        count = c.fetchone()[0]
        c.execute("DELETE FROM scans WHERE session_name=? AND branch=?", (session_name, branch))
    else:
        c.execute("SELECT COUNT(*) FROM scans WHERE session_name=?", (session_name,))
        count = c.fetchone()[0]
        c.execute("DELETE FROM scans WHERE session_name=?", (session_name,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "deleted": count})

@app.route("/admin/session_info")
def admin_session_info():
    """Get detailed info about all sessions for session management."""
    if session.get("role") not in ["admin", "moderator"]: return jsonify({"error": "forbidden"}), 403
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT session_name, branch, COUNT(*) as scan_count, 
               COUNT(DISTINCT user) as user_count,
               MIN(timestamp) as first_scan, 
               MAX(timestamp) as last_scan
        FROM scans 
        WHERE session_name IS NOT NULL AND session_name != ''
        GROUP BY session_name, branch
        ORDER BY MAX(timestamp) DESC
    """)
    data = []
    for r in c.fetchall():
        data.append({
            "session_name": r[0], "branch": r[1], "scan_count": r[2],
            "user_count": r[3], "first_scan": r[4], "last_scan": r[5]
        })
    conn.close()
    return jsonify(data)

@app.route("/admin/reassign_scans", methods=["POST"])
def admin_reassign_scans():
    """Reassign scans from one session/branch to another."""
    if session.get("role") != "admin": return jsonify({"error": "forbidden"}), 403
    data = request.json
    from_session = data.get("from_session")
    from_branch = data.get("from_branch", "")
    to_session = data.get("to_session")
    to_branch = data.get("to_branch", "")
    
    if not from_session or not to_session:
        return jsonify({"error": "Missing session names"}), 400
    
    conn = get_db()
    c = conn.cursor()
    
    query = "UPDATE scans SET session_name=?"
    params = [to_session]
    if to_branch:
        query += ", branch=?"
        params.append(to_branch)
    query += " WHERE session_name=?"
    params.append(from_session)
    if from_branch:
        query += " AND branch=?"
        params.append(from_branch)
    
    c.execute(query, tuple(params))
    affected = c.rowcount
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "moved": affected})

@app.route("/admin/delete_entries", methods=["POST"])
def admin_delete_entries():
    if session.get("role") != "admin": return jsonify({"error": "forbidden"}), 403
    data = request.json
    password = data.get("password")
    mode = data.get("mode")
    entries = data.get("entries", [])
    
    u_conn = get_users_db()
    u_c = u_conn.cursor()
    u_c.execute("SELECT password FROM users WHERE username=?", (session.get("user"),))
    row = u_c.fetchone()
    u_conn.close()
    
    # Check hashed or plain text password
    if not row:
        return jsonify({"error": "Invalid password"}), 401
        
    db_password = row[0]
    is_valid = check_password_hash(db_password, password) if db_password.startswith(('scrypt:', 'pbkdf2:')) else db_password == password
    
    if not is_valid:
        return jsonify({"error": "Invalid password"}), 401
        
    conn = get_db()
    c = conn.cursor()
        
    for entry in entries:
        barcode = (entry.get("barcode") or "").strip().upper()
        bc_clean, bc_damaged, bc_flagged = barcode_variants(barcode)
        if mode == "master":
            c.execute("""
                DELETE FROM scans 
                WHERE (barcode=? OR barcode=? OR barcode=?) AND branch=? AND session_name=?
            """, (bc_clean, bc_damaged, bc_flagged, entry.get("branch"), entry.get("session_name")))
        else:
            c.execute("""
                DELETE FROM scans 
                WHERE (barcode=? OR barcode=? OR barcode=?) AND user=? AND branch=? AND session_name=?
            """, (bc_clean, bc_damaged, bc_flagged, entry.get("user"), entry.get("branch"), entry.get("session_name")))
            
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})

@app.route("/add_user", methods=["POST"])
def add_user():
    if session.get("role") != "admin": return "forbidden"
    conn = get_users_db()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username,password,role) VALUES (?,?,?)",
                  (request.json["username"], generate_password_hash(request.json["password"]), request.json["role"]))
    except sqlite3.IntegrityError:
        return "exists"
    conn.commit()
    conn.close()
    return "ok"

@app.route("/delete_user/<username>", methods=["DELETE"])
def delete_user(username):
    if session.get("role") != "admin": return "forbidden"
    conn = get_users_db()
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE username=?", (username,))
    conn.commit()
    conn.close()
    return "ok"

@app.route("/user_password", methods=["POST"])
def user_password():
    if session.get("role") != "admin": return "forbidden"
    conn = get_users_db()
    c = conn.cursor()
    c.execute("UPDATE users SET password=? WHERE username=?", (generate_password_hash(request.json["password"]), request.json["username"]))
    conn.commit()
    conn.close()
    return "ok"

@app.route("/force_logout/<username>", methods=["POST"])
def force_logout(username):
    if session.get("role") != "admin": return "forbidden"
    conn = get_users_db()
    c = conn.cursor()
    c.execute("UPDATE users SET session_token=? WHERE username=?", (str(uuid.uuid4()), username))
    conn.commit()
    conn.close()
    return "ok"

@app.route("/delete_branch/<name>", methods=["DELETE"])
def delete_branch(name):
    if session.get("role") != "admin": return "forbidden"
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM branches WHERE name=?", (name,))
    conn.commit()
    conn.close()
    return "ok"

if __name__ == "__main__":
    try:
        from waitress import serve
        print("Starting production server with Waitress on port 5000...")
        serve(app, host="0.0.0.0", port=5000)
    except ImportError:
        print("Waitress not installed. Please run 'pip install waitress' for production mode.")
        print("Falling back to Flask development server...")
        app.run(host="0.0.0.0", debug=False)
