from flask import Flask, render_template, request, jsonify, session, redirect, Response
import sqlite3
from datetime import datetime
import io
import csv
import uuid
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "secret123"

def get_gmt3_time():
    from datetime import timezone, timedelta
    return datetime.now(timezone(timedelta(hours=3))).strftime("%Y-%m-%d %H:%M:%S")

DB = "database.db"
USERS_DB = "users.db"

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
        
    u_c.execute("SELECT COUNT(*) FROM users")
    if u_c.fetchone()[0] == 0:
        u_c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                  ('admin', generate_password_hash('admin123'), 'admin'))
    u_conn.commit()
    u_conn.close()

init_db()

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

        # If user has a token in DB and it doesn't match the one in session, log them out
        if row and row[0] and row[0] != token:
            session.clear()
            if request.path.startswith('/api/') or request.method == 'POST':
                from flask import jsonify
                return jsonify({"error": "logged_out", "redirect": "/login"}), 401
            return redirect("/login")

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
    session.clear()
    return redirect("/login")

# ---------- MAIN ----------
@app.route("/")
def index():
    if "user" not in session or "role" not in session:
        return redirect("/login")
    return render_template("index.html", user=session["user"], role=session["role"])

# ---------- SCAN ----------
def insert_scans_bulk(barcode, qty, is_damaged=False, is_flagged=False, session_name=None, branch=None):
    if session_name is None:
        session_name = request.json.get("session_name", "")
    if branch is None:
        branch = request.json.get("branch")
        
    actual_barcode = barcode
    if is_damaged: actual_barcode += "__DAMAGED"
        
    user = session.get("user")
    ts = get_gmt3_time()
    
    conn = get_db()
    c = conn.cursor()
    
    clean_barcode = barcode.replace('__DAMAGED', '').replace('__FLAGGED', '')
    c.execute("""
        SELECT DISTINCT session_name 
        FROM scans 
        WHERE (barcode = ? OR barcode = ? OR barcode = ?) 
        AND session_name != ? AND session_name != ''
    """, (clean_barcode, clean_barcode + "__DAMAGED", clean_barcode + "__FLAGGED", session_name))
    
    collision_row = c.fetchone()
    warning_msg = None
    old_session = None
    auto_flag = False
    
    if collision_row:
        old_session = collision_row[0]
        warning_msg = "cross_session"
        auto_flag = True
        
    if is_flagged: actual_barcode += "__FLAGGED"
    
    rows = [(actual_barcode, ts, user, branch, session_name) for _ in range(qty)]
    c.executemany("""
        INSERT INTO scans (barcode, timestamp, user, branch, session_name)
        VALUES (?, ?, ?, ?, ?)
    """, rows)
    
    if auto_flag:
        c.execute("SELECT COUNT(*) FROM scans WHERE barcode=? AND session_name=?", (clean_barcode + "__FLAGGED", session_name))
        if c.fetchone()[0] == 0:
            c.execute("""
                INSERT INTO scans (barcode, timestamp, user, branch, session_name) 
                VALUES (?, ?, ?, ?, ?)
            """, (clean_barcode + "__FLAGGED", ts, user, branch, session_name))
            
    conn.commit()
    conn.close()
    
    return {"status": "ok", "warning": warning_msg, "old_session": old_session}

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
    barcode = request.json["barcode"]
    session_name = request.json.get("session_name")
    branch = request.json.get("branch")
    user = session.get("user")
    
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM scans WHERE barcode=? AND session_name=? AND user=?", (barcode + "__FLAGGED", session_name, user))
    is_flagged = c.fetchone()[0] > 0
    
    if is_flagged:
        c.execute("DELETE FROM scans WHERE barcode=? AND session_name=? AND user=?", (barcode + "__FLAGGED", session_name, user))
    else:
        c.execute("INSERT INTO scans (barcode, timestamp, user, branch, session_name) VALUES (?, ?, ?, ?, ?)", 
                 (barcode + "__FLAGGED", get_gmt3_time(), user, branch, session_name))
    conn.commit()
    conn.close()
    return jsonify({"status":"ok"})

@app.route("/sync", methods=["POST"])
def sync():
    scans = request.json.get("scans", [])
    if not scans:
        return jsonify({"status": "ok"})
        
    rows = [(s.get("barcode"), s.get("timestamp"), s.get("user"), s.get("branch"), s.get("session_name")) for s in scans]
    conn = get_db()
    c = conn.cursor()
    c.executemany("""
        INSERT OR IGNORE INTO scans (barcode, timestamp, user, branch, session_name)
        VALUES (?, ?, ?, ?, ?)
    """, rows)
    
    for s in scans:
        barcode = s.get("barcode")
        session_name = s.get("session_name")
        clean_barcode = barcode.replace('__DAMAGED', '').replace('__FLAGGED', '')
        
        c.execute("""
            SELECT 1 FROM scans 
            WHERE (barcode=? OR barcode=? OR barcode=?) 
            AND session_name!=? AND session_name!=''
            LIMIT 1
        """, (clean_barcode, clean_barcode + "__DAMAGED", clean_barcode + "__FLAGGED", session_name))
        
        if c.fetchone():
            c.execute("SELECT COUNT(*) FROM scans WHERE barcode=? AND session_name=?", (clean_barcode + "__FLAGGED", session_name))
            if c.fetchone()[0] == 0:
                c.execute("""
                    INSERT INTO scans (barcode, timestamp, user, branch, session_name) 
                    VALUES (?, ?, ?, ?, ?)
                """, (clean_barcode + "__FLAGGED", get_gmt3_time(), s.get("user"), s.get("branch"), session_name))
                
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

    c.execute("""
        SELECT 
            REPLACE(REPLACE(barcode,'__DAMAGED',''),'__FLAGGED',''),
            SUM(CASE WHEN barcode NOT LIKE '%__DAMAGED' AND barcode NOT LIKE '%__FLAGGED' THEN 1 ELSE 0 END),
            SUM(CASE WHEN barcode LIKE '%__DAMAGED' THEN 1 ELSE 0 END),
            MAX(timestamp),
            SUM(CASE WHEN barcode LIKE '%__FLAGGED' THEN 1 ELSE 0 END)
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
            "last": r[3],
            "flagged": r[4]
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
    c.execute("""
        DELETE FROM scans 
        WHERE (barcode=? OR barcode=? OR barcode=?) AND user=? AND session_name=?
    """, (barcode, barcode + "__DAMAGED", barcode + "__FLAGGED", session.get("user"), session_name))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})

@app.route("/user/history")
def user_history():
    if "user" not in session: return "forbidden"
    branch = request.args.get("branch", "")
    session_name = request.args.get("session_name", "")
    date = request.args.get("date", "")
    
    query = """
        SELECT 
            REPLACE(REPLACE(barcode,'__DAMAGED',''),'__FLAGGED',''),
            branch,
            session_name,
            SUM(CASE WHEN barcode NOT LIKE '%__DAMAGED' AND barcode NOT LIKE '%__FLAGGED' THEN 1 ELSE 0 END),
            SUM(CASE WHEN barcode LIKE '%__DAMAGED' THEN 1 ELSE 0 END),
            MAX(timestamp),
            SUM(CASE WHEN barcode LIKE '%__FLAGGED' THEN 1 ELSE 0 END)
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
    # Grouped view
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT 
            REPLACE(REPLACE(barcode,'__DAMAGED',''),'__FLAGGED',''),
            user,
            branch,
            session_name,
            SUM(CASE WHEN barcode NOT LIKE '%__DAMAGED' AND barcode NOT LIKE '%__FLAGGED' THEN 1 ELSE 0 END),
            SUM(CASE WHEN barcode LIKE '%__DAMAGED' THEN 1 ELSE 0 END),
            MAX(timestamp),
            SUM(CASE WHEN barcode LIKE '%__FLAGGED' THEN 1 ELSE 0 END)
        FROM scans
        GROUP BY 1, 2, 3, 4
        ORDER BY MAX(timestamp) DESC
    """)
    data = []
    for r in c.fetchall():
        data.append({
            "barcode": r[0], "user": r[1], "branch": r[2], "session_name": r[3],
            "good": r[4], "damaged": r[5], "last": r[6], "flagged": r[7]
        })
    conn.close()
    return jsonify(data)

@app.route("/admin/master_scans")
def admin_master_scans():
    if session.get("role") not in ["admin", "moderator"]: return "forbidden"
    branch = request.args.get("branch", "")
    session_name = request.args.get("session_name", "")
    conn = get_db()
    c = conn.cursor()
    
    query = """
        SELECT 
            REPLACE(REPLACE(barcode,'__DAMAGED',''),'__FLAGGED',''),
            SUM(CASE WHEN barcode NOT LIKE '%__DAMAGED' AND barcode NOT LIKE '%__FLAGGED' THEN 1 ELSE 0 END),
            SUM(CASE WHEN barcode LIKE '%__DAMAGED' THEN 1 ELSE 0 END),
            MAX(timestamp),
            GROUP_CONCAT(DISTINCT user),
            SUM(CASE WHEN barcode LIKE '%__FLAGGED' THEN 1 ELSE 0 END)
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
        
    query += " GROUP BY 1 ORDER BY MAX(timestamp) DESC"
    
    c.execute(query, tuple(params))
    data = []
    for r in c.fetchall():
        data.append({
            "barcode": r[0], "good": r[1], "damaged": r[2], "last": r[3], "users": r[4], "flagged": r[5]
        })
    conn.close()
    return jsonify(data)

@app.route("/admin/export_csv")
def admin_export_csv():
    if session.get("role") not in ["admin", "moderator"]: return "forbidden"
    mode = request.args.get("mode", "detailed")
    branch = request.args.get("branch", "")
    session_name = request.args.get("session_name", "")
    conn = get_db()
    c = conn.cursor()
    output = io.StringIO()
    writer = csv.writer(output)
    if mode == "master":
        writer.writerow(["Barcode", "Good", "Damaged", "Flagged", "Last Scan"])
        c.execute("""
            SELECT REPLACE(REPLACE(barcode,'__DAMAGED',''),'__FLAGGED',''),
                   SUM(CASE WHEN barcode NOT LIKE '%__DAMAGED' AND barcode NOT LIKE '%__FLAGGED' THEN 1 ELSE 0 END),
                   SUM(CASE WHEN barcode LIKE '%__DAMAGED' THEN 1 ELSE 0 END),
                   SUM(CASE WHEN barcode LIKE '%__FLAGGED' THEN 1 ELSE 0 END),
                   MAX(timestamp)
            FROM scans WHERE branch=? AND session_name=? GROUP BY 1 ORDER BY MAX(timestamp) DESC
        """, (branch, session_name))
        for r in c.fetchall(): writer.writerow(r)
    else:
        writer.writerow(["Barcode", "User", "Branch", "Session", "Good", "Damaged", "Flagged", "Last Scan"])
        c.execute("""
            SELECT REPLACE(REPLACE(barcode,'__DAMAGED',''),'__FLAGGED',''), user, branch, session_name,
                   SUM(CASE WHEN barcode NOT LIKE '%__DAMAGED' AND barcode NOT LIKE '%__FLAGGED' THEN 1 ELSE 0 END),
                   SUM(CASE WHEN barcode LIKE '%__DAMAGED' THEN 1 ELSE 0 END),
                   SUM(CASE WHEN barcode LIKE '%__FLAGGED' THEN 1 ELSE 0 END),
                   MAX(timestamp)
            FROM scans GROUP BY 1, 2, 3, 4 ORDER BY MAX(timestamp) DESC
        """)
        for r in c.fetchall(): writer.writerow(r)
    conn.close()
    return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=scans_export.csv"})

@app.route("/admin/stats")
def admin_stats():
    if session.get("role") not in ["admin", "moderator"]: return "forbidden"
    conn = get_db()
    c = conn.cursor()
    
    c.execute("SELECT COUNT(*) FROM scans")
    total_scans = c.fetchone()[0]
    
    c.execute("SELECT COUNT(DISTINCT REPLACE(REPLACE(barcode,'__DAMAGED',''),'__FLAGGED','')) FROM scans")
    unique_barcodes = c.fetchone()[0]
    
    c.execute("SELECT COUNT(DISTINCT user) FROM scans")
    active_users = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM scans WHERE barcode LIKE '%__FLAGGED'")
    flagged_items = c.fetchone()[0]
    
    conn.close()
    
    return jsonify({
        "total_scans": total_scans,
        "unique_barcodes": unique_barcodes,
        "active_users": active_users,
        "flagged_items": flagged_items
    })

@app.route("/admin/chart_data")
def admin_chart_data():
    if session.get("role") not in ["admin", "moderator"]: return "forbidden"
    conn = get_db()
    c = conn.cursor()
    
    c.execute("""
        SELECT date(timestamp), COUNT(*) 
        FROM scans 
        WHERE date(timestamp) >= date('now', '-7 days')
        GROUP BY date(timestamp)
        ORDER BY date(timestamp) ASC
    """)
    dates = []
    counts = []
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
    barcode = data["barcode"]
    if data["type"] == "damaged":
        barcode += "__DAMAGED"
    elif data["type"] == "flagged":
        barcode += "__FLAGGED"
        
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
        barcode = entry.get("barcode")
        if mode == "master":
            c.execute("""
                DELETE FROM scans 
                WHERE (barcode=? OR barcode=? OR barcode=?) AND branch=? AND session_name=?
            """, (barcode, barcode + "__DAMAGED", barcode + "__FLAGGED", entry.get("branch"), entry.get("session_name")))
        else:
            c.execute("""
                DELETE FROM scans 
                WHERE (barcode=? OR barcode=? OR barcode=?) AND user=? AND branch=? AND session_name=?
            """, (barcode, barcode + "__DAMAGED", barcode + "__FLAGGED", entry.get("user"), entry.get("branch"), entry.get("session_name")))
            
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
