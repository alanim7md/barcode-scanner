from flask import Flask, render_template, request, jsonify, session, redirect, Response
import sqlite3
from datetime import datetime
import io
import csv
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "secret123"

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
    
    # Unique constraint to prevent duplicate offline syncs
    try:
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_scans_unique_sync ON scans(barcode, timestamp, user, session_name)")
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
    u_c.execute("SELECT COUNT(*) FROM users")
    if u_c.fetchone()[0] == 0:
        u_c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                  ('admin', generate_password_hash('admin123'), 'admin'))
    u_conn.commit()
    u_conn.close()

init_db()

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
                session["user"] = u
                session["role"] = db_role
                
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
def insert_scans_bulk(barcode, qty, is_damaged=False, session_name=None, branch=None):
    if session_name is None:
        session_name = request.json.get("session_name", "")
    if branch is None:
        branch = request.json.get("branch")
        
    actual_barcode = barcode + "__DAMAGED" if is_damaged else barcode
    user = session.get("user")
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    rows = [(actual_barcode, ts, user, branch, session_name) for _ in range(qty)]
    
    conn = get_db()
    c = conn.cursor()
    c.executemany("""
        INSERT INTO scans (barcode, timestamp, user, branch, session_name)
        VALUES (?, ?, ?, ?, ?)
    """, rows)
    conn.commit()
    conn.close()

@app.route("/scan", methods=["POST"])
def scan():
    insert_scans_bulk(request.json["barcode"], 1)
    return jsonify({"status":"ok"})

@app.route("/manual", methods=["POST"])
def manual():
    insert_scans_bulk(request.json["barcode"], int(request.json.get("qty", 1)))
    return jsonify({"status":"ok"})

@app.route("/damaged", methods=["POST"])
def damaged():
    insert_scans_bulk(request.json["barcode"], int(request.json.get("qty", 1)), is_damaged=True)
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
            REPLACE(barcode,'__DAMAGED',''),
            SUM(CASE WHEN barcode NOT LIKE '%__DAMAGED' THEN 1 ELSE 0 END),
            SUM(CASE WHEN barcode LIKE '%__DAMAGED' THEN 1 ELSE 0 END),
            MAX(timestamp)
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
            "last": r[3]
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

# ---------- BRANCHES ----------
@app.route("/branches")
def branches():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT name FROM branches")
    data = [r[0] for r in c.fetchall()]
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
        WHERE (barcode=? OR barcode=?) AND user=? AND session_name=?
    """, (barcode, barcode + "__DAMAGED", session.get("user"), session_name))
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
            REPLACE(barcode,'__DAMAGED',''),
            branch,
            session_name,
            SUM(CASE WHEN barcode NOT LIKE '%__DAMAGED' THEN 1 ELSE 0 END),
            SUM(CASE WHEN barcode LIKE '%__DAMAGED' THEN 1 ELSE 0 END),
            MAX(timestamp)
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
            "good": r[3], "damaged": r[4], "last": r[5]
        })
    conn.close()
    return jsonify(data)

# ---------- ADMIN ----------
@app.route("/admin")
def admin():
    if session.get("role") != "admin":
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
    return render_template("admin.html", users=users, branches=branches)

@app.route("/admin/scans_data")
def admin_scans_data():
    if session.get("role") != "admin": return "forbidden"
    # Grouped view
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT 
            REPLACE(barcode,'__DAMAGED',''),
            user,
            branch,
            session_name,
            SUM(CASE WHEN barcode NOT LIKE '%__DAMAGED' THEN 1 ELSE 0 END),
            SUM(CASE WHEN barcode LIKE '%__DAMAGED' THEN 1 ELSE 0 END),
            MAX(timestamp)
        FROM scans
        GROUP BY 1, 2, 3, 4
        ORDER BY MAX(timestamp) DESC
    """)
    data = []
    for r in c.fetchall():
        data.append({
            "barcode": r[0], "user": r[1], "branch": r[2], "session_name": r[3],
            "good": r[4], "damaged": r[5], "last": r[6]
        })
    conn.close()
    return jsonify(data)

@app.route("/admin/master_scans")
def admin_master_scans():
    if session.get("role") != "admin": return "forbidden"
    branch = request.args.get("branch", "")
    session_name = request.args.get("session_name", "")
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT 
            REPLACE(barcode,'__DAMAGED',''),
            SUM(CASE WHEN barcode NOT LIKE '%__DAMAGED' THEN 1 ELSE 0 END),
            SUM(CASE WHEN barcode LIKE '%__DAMAGED' THEN 1 ELSE 0 END),
            MAX(timestamp),
            GROUP_CONCAT(DISTINCT user)
        FROM scans
        WHERE branch=? AND session_name=?
        GROUP BY 1
        ORDER BY MAX(timestamp) DESC
    """, (branch, session_name))
    data = []
    for r in c.fetchall():
        data.append({
            "barcode": r[0], "good": r[1], "damaged": r[2], "last": r[3], "users": r[4]
        })
    conn.close()
    return jsonify(data)

@app.route("/admin/export_csv")
def admin_export_csv():
    if session.get("role") != "admin": return "forbidden"
    mode = request.args.get("mode", "detailed")
    branch = request.args.get("branch", "")
    session_name = request.args.get("session_name", "")
    conn = get_db()
    c = conn.cursor()
    output = io.StringIO()
    writer = csv.writer(output)
    if mode == "master":
        writer.writerow(["Barcode", "Good", "Damaged", "Last Scan"])
        c.execute("""
            SELECT REPLACE(barcode,'__DAMAGED',''),
                   SUM(CASE WHEN barcode NOT LIKE '%__DAMAGED' THEN 1 ELSE 0 END),
                   SUM(CASE WHEN barcode LIKE '%__DAMAGED' THEN 1 ELSE 0 END),
                   MAX(timestamp)
            FROM scans WHERE branch=? AND session_name=? GROUP BY 1 ORDER BY MAX(timestamp) DESC
        """, (branch, session_name))
        for r in c.fetchall(): writer.writerow(r)
    else:
        writer.writerow(["Barcode", "User", "Branch", "Session", "Good", "Damaged", "Last Scan"])
        c.execute("""
            SELECT REPLACE(barcode,'__DAMAGED',''), user, branch, session_name,
                   SUM(CASE WHEN barcode NOT LIKE '%__DAMAGED' THEN 1 ELSE 0 END),
                   SUM(CASE WHEN barcode LIKE '%__DAMAGED' THEN 1 ELSE 0 END),
                   MAX(timestamp)
            FROM scans GROUP BY 1, 2, 3, 4 ORDER BY MAX(timestamp) DESC
        """)
        for r in c.fetchall(): writer.writerow(r)
    conn.close()
    return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=scans_export.csv"})

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
    barcode = data["barcode"] if data["type"] == "good" else data["barcode"] + "__DAMAGED"
    diff = int(data["diff"])
    
    conn = get_db()
    c = conn.cursor()
    if diff > 0:
        for _ in range(diff):
            c.execute("""
                INSERT INTO scans (barcode, timestamp, user, branch, session_name)
                VALUES (?, ?, ?, ?, ?)
            """, (barcode, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), data["user"], data["branch"], data["session_name"]))
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
                WHERE (barcode=? OR barcode=?) AND branch=? AND session_name=?
            """, (barcode, barcode + "__DAMAGED", entry.get("branch"), entry.get("session_name")))
        else:
            c.execute("""
                DELETE FROM scans 
                WHERE (barcode=? OR barcode=?) AND user=? AND branch=? AND session_name=?
            """, (barcode, barcode + "__DAMAGED", entry.get("user"), entry.get("branch"), entry.get("session_name")))
            
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
        app.run(host="0.0.0.0", debug=True)
