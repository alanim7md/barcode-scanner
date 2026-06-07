from flask import Flask, render_template, request, jsonify, session, redirect, Response, make_response
# pyrefly: ignore [missing-import]
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_compress import Compress
from flask.json.provider import JSONProvider
from sqlalchemy import text
from datetime import datetime
import io
import csv
import uuid
import os
import urllib.parse
import orjson
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# SECRET_KEY should be set in environment for production.
# If not set, a random key is generated per-restart (sessions will be invalidated on restart).
_secret = os.environ.get("SECRET_KEY")
if not _secret:
    import warnings
    warnings.warn(
        "SECRET_KEY environment variable not set. Sessions will be invalidated on server restart. "
        "Set SECRET_KEY in your environment for production deployments.",
        RuntimeWarning
    )
    _secret = os.urandom(24).hex()
app.secret_key = _secret

# Configure Flask-Compress for static assets and API JSON payloads
app.config['COMPRESS_ALGORITHMS'] = ['br', 'gzip']
app.config['COMPRESS_LEVEL'] = 6
app.config['COMPRESS_MIN_SIZE'] = 500
Compress(app)

# Custom high-performance orjson-based JSON provider for Flask
class OrjsonProvider(JSONProvider):
    def dumps(self, obj, **kwargs):
        option = orjson.OPT_NAIVE_UTC | orjson.OPT_SERIALIZE_NUMPY
        if kwargs.get('sort_keys'):
            option |= orjson.OPT_SORT_KEYS
        return orjson.dumps(obj, option=option).decode('utf-8')

    def loads(self, s, **kwargs):
        return orjson.loads(s)

app.json = OrjsonProvider(app)

# Configure SQLAlchemy with absolute paths to project directory database files
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if os.environ.get('TESTING') == 'true':
    app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///:memory:"
    app.config['SQLALCHEMY_BINDS'] = {
        'users': "sqlite:///:memory:"
    }
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(BASE_DIR, 'database.db')}?timeout=20"
    app.config['SQLALCHEMY_BINDS'] = {
        'users': f"sqlite:///{os.path.join(BASE_DIR, 'users.db')}?timeout=20"
    }
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

from sqlalchemy.engine import Engine
from sqlalchemy import event

@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=30000")
    except Exception:
        pass
    finally:
        cursor.close()


def get_gmt3_time():
    from datetime import timezone, timedelta
    return datetime.now(timezone(timedelta(hours=3))).strftime("%Y-%m-%d %H:%M:%S")

# ---------- MODELS ----------
class Branch(db.Model):
    __tablename__ = 'branches'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(120), unique=True, nullable=False)

class Scan(db.Model):
    __tablename__ = 'scans'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    barcode = db.Column(db.String(255), index=True)
    timestamp = db.Column(db.String(50), index=True)
    user = db.Column(db.String(120))
    branch = db.Column(db.String(120))
    session_name = db.Column(db.String(255), index=True)
    flag_reason = db.Column(db.Text, default='')
    is_damaged = db.Column(db.Integer, default=0)
    is_flagged = db.Column(db.Integer, default=0)

    __table_args__ = (
        db.Index('idx_scans_user_session', 'user', 'session_name'),
        db.Index('idx_scans_branch_session', 'branch', 'session_name'),
        db.Index('idx_scans_composite_lookup', 'barcode', 'user', 'branch', 'session_name'),
        db.Index('idx_scans_covering_summary', 'user', 'session_name', 'barcode', 'is_damaged', 'is_flagged', 'timestamp'),
        db.Index('idx_scans_covering_admin', 'barcode', 'user', 'branch', 'session_name', 'is_damaged', 'is_flagged', 'timestamp'),
    )

class GlobalSetting(db.Model):
    __tablename__ = 'global_settings'
    key = db.Column(db.String(120), primary_key=True)
    value = db.Column(db.Text)

class User(db.Model):
    __bind_key__ = 'users'
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50))
    session_token = db.Column(db.String(255))
    last_active = db.Column(db.String(50))

class BranchSession(db.Model):
    __tablename__ = 'branch_sessions'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    branch_name = db.Column(db.String(120), nullable=False)
    session_name = db.Column(db.String(255), nullable=False)
    __table_args__ = (
        db.UniqueConstraint('branch_name', 'session_name', name='uq_branch_session'),
    )

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    timestamp = db.Column(db.String(50), nullable=False)
    operator = db.Column(db.String(120), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text, nullable=False)

def log_audit_action(operator, action, details):
    log_entry = AuditLog(
        timestamp=get_gmt3_time(),
        operator=operator,
        action=action,
        details=details
    )
    db.session.add(log_entry)



# ---------- MEMORY CACHE ----------
class AppCache:
    def __init__(self):
        self._cache = {}

    def get(self, key):
        return self._cache.get(key)

    def set(self, key, value):
        self._cache[key] = value

    def invalidate(self, *keys):
        for k in keys:
            self._cache.pop(k, None)

    def clear(self):
        self._cache.clear()

app_cache = AppCache()

def get_cached_branches():
    val = app_cache.get("branches")
    if val is None:
        b_list = Branch.query.all()
        val = [b.name for b in b_list]
        app_cache.set("branches", val)
    return val

def get_cached_settings():
    val = app_cache.get("settings")
    if val is None:
        settings = GlobalSetting.query.all()
        val = {s.key: s.value for s in settings}
        app_cache.set("settings", val)
    return val

def get_cached_users():
    val = app_cache.get("users")
    if val is None:
        users_list = User.query.all()
        val = [{"username": u.username, "role": u.role} for u in users_list]
        app_cache.set("users", val)
    return val

def get_cached_sessions(branch=None):
    cache_key = f"sessions_branch:{branch}" if branch else "sessions_all"
    val = app_cache.get(cache_key)
    if val is None:
        if branch:
            res = BranchSession.query.filter_by(branch_name=branch).order_by(BranchSession.session_name).all()
        else:
            res = BranchSession.query.order_by(BranchSession.session_name).all()
        val = [r.session_name for r in res]
        app_cache.set(cache_key, val)
    return val


def register_session_in_cache(session_name, branch):
    if not session_name:
        return
    sessions_all = app_cache.get("sessions_all")
    if sessions_all is None or session_name not in sessions_all:
        app_cache.invalidate("sessions_all", f"sessions_branch:{branch}")


# ---------- BARCODE SUFFIX HELPERS ----------
SUFFIX_DAMAGED = "__DAMAGED"
SUFFIX_FLAGGED = "__FLAGGED"

def clean_barcode(barcode):
    """Strip damage/flag suffixes to get the raw barcode."""
    return barcode.replace(SUFFIX_DAMAGED, '').replace(SUFFIX_FLAGGED, '')

# SQL fragments for grouping queries — reused across summary/admin/export
SQL_GOOD_COUNT = "SUM(CASE WHEN is_damaged=0 THEN 1 ELSE 0 END)"
SQL_DAMAGED_COUNT = "SUM(CASE WHEN is_damaged=1 THEN 1 ELSE 0 END)"
SQL_FLAGGED_COUNT = "SUM(CASE WHEN is_flagged=1 THEN 1 ELSE 0 END)"

# Initialize databases and seed admin user
with app.app_context():
    db.create_all()

    # Ensure all composite indexes exist in SQLite database
    try:
        db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_scans_composite_lookup ON scans (barcode, user, branch, session_name)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_scans_covering_summary ON scans (user, session_name, barcode, is_damaged, is_flagged, timestamp)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_scans_covering_admin ON scans (barcode, user, branch, session_name, is_damaged, is_flagged, timestamp)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_scans_collision_check ON scans (barcode, branch, session_name)"))
        db.session.commit()
    except Exception as e:
        print(f"Error creating indexes: {e}")
        db.session.rollback()

    # Seed admin user if it doesn't exist
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin_user = User(
            username='admin',
            password=generate_password_hash('admin123'),
            role='admin'
        )
        db.session.add(admin_user)
        db.session.commit()

    # Seed BranchSession table from existing scans if empty
    if BranchSession.query.count() == 0:
        existing = db.session.query(Scan.branch, Scan.session_name).filter(
            Scan.branch.isnot(None), Scan.branch != '',
            Scan.session_name.isnot(None), Scan.session_name != ''
        ).distinct().all()
        for branch, sess in existing:
            db.session.add(BranchSession(branch_name=branch, session_name=sess))
        db.session.commit()


@app.before_request
def check_session_token():
    if request.endpoint in ['login', 'static']:
        return

    user = session.get("user")
    token = session.get("session_token")

    # Helper to check if request expects a JSON/AJAX response rather than page redirect
    is_ajax = (
        request.path.startswith('/api/') or 
        (request.path.startswith('/admin/') and request.path != '/admin') or
        request.path in ['/scan', '/manual', '/damaged', '/sync', '/flag_item', '/undo', '/branches', '/sessions', '/summary', '/count', '/settings'] or 
        request.method == 'POST'
    )

    if not user or not token:
        if is_ajax:
            return jsonify({"error": "unauthorized", "redirect": "/login"}), 401
        return redirect("/login")

    user_rec = User.query.filter_by(username=user).first()

    if not user_rec or user_rec.session_token != token:
        session.clear()
        if is_ajax:
            return jsonify({"error": "logged_out", "redirect": "/login"}), 401
        return redirect("/login")
        
    # Throttle last_active update to once every 2 minutes (120 seconds) to reduce write locks
    now_gmt3_str = get_gmt3_time()
    should_update = True
    if user_rec.last_active:
        try:
            last_active_dt = datetime.strptime(user_rec.last_active, "%Y-%m-%d %H:%M:%S")
            current_dt = datetime.strptime(now_gmt3_str, "%Y-%m-%d %H:%M:%S")
            if (current_dt - last_active_dt).total_seconds() < 120:
                should_update = False
        except Exception:
            pass
            
    if should_update:
        try:
            user_rec.last_active = now_gmt3_str
            db.session.commit()
        except Exception:
            db.session.rollback()

# ---------- LOGIN ----------
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        u = (request.form.get("username") or "").strip()
        p = request.form.get("password") or ""
        if not u or not p:
            return redirect("/login?error=1")

        user_rec = User.query.filter_by(username=u).first()

        if user_rec:
            db_role, db_password = user_rec.role, user_rec.password
            is_valid = check_password_hash(db_password, p) if db_password.startswith(('scrypt:', 'pbkdf2:')) else db_password == p
            
            if is_valid:
                new_token = str(uuid.uuid4())
                session["user"] = u
                session["role"] = db_role
                session["session_token"] = new_token
                
                user_rec.session_token = new_token
                
                # Auto-upgrade plain text to hashed
                if not db_password.startswith(('scrypt:', 'pbkdf2:')):
                    user_rec.password = generate_password_hash(p)
                    
                try:
                    db.session.commit()
                except Exception:
                    db.session.rollback()
                    return redirect("/login?error=1")
                return redirect("/")
                
        return redirect("/login?error=1")

    return render_template("login.html")

@app.route("/logout")
def logout():
    user = session.get("user")
    if user:
        user_rec = User.query.filter_by(username=user).first()
        if user_rec:
            user_rec.session_token = None
            user_rec.last_active = None
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()
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
def insert_scans_bulk(barcode, qty, is_damaged=False, is_flagged=False, session_name=None, branch=None, is_manual=False):
    barcode = clean_barcode(barcode.strip().upper())
    req_json = request.json or {}
    if session_name is None:
        session_name = req_json.get("session_name", "")
    if branch is None:
        branch = req_json.get("branch") or ""

    # Fallback: if no branch sent, use the globally enforced branch if set
    if not branch:
        settings = get_cached_settings()
        branch = settings.get("global_branch", "") or ""
    # Fallback: if no session sent, use the globally enforced session if set
    if not session_name:
        settings = get_cached_settings()
        session_name = settings.get("global_session", "") or ""

    user = session.get("user")
    ts = get_gmt3_time()


    # --- Session Collision Detection ---
    collision = Scan.query.filter(
        Scan.barcode == barcode,
        Scan.session_name != session_name,
        Scan.session_name != '',
        Scan.branch == branch
    ).first()
    
    flag_reason = ""
    warning_msg = None
    if collision:
        is_flagged = True
        prev_session = collision.session_name
        prev_branch = collision.branch or "Unknown"
        flag_reason = f"Session Collision: scanned in {prev_session} ({prev_branch})"
        
        already_scanned = Scan.query.filter_by(
            barcode=barcode, session_name=session_name, branch=branch
        ).count()
        if already_scanned == 0:
            warning_msg = f"Collision! Barcode previously scanned in session '{prev_session}' ({prev_branch})."
    elif is_flagged:
        flag_reason = "Manual Flag"

    if is_manual:
        is_flagged = True
        if flag_reason and flag_reason != "Manual Flag":
            flag_reason += ", Manual Entry"
        else:
            flag_reason = "Manual Entry"

    to_add = []
    for _ in range(qty):
        to_add.append(Scan(
            barcode=barcode,
            timestamp=ts,
            user=user,
            branch=branch,
            session_name=session_name,
            flag_reason=flag_reason,
            is_damaged=1 if is_damaged else 0,
            is_flagged=1 if is_flagged else 0
        ))
    db.session.add_all(to_add)
    db.session.commit()
    register_session_in_cache(session_name, branch)

    return {"status": "ok", "warning": warning_msg} if warning_msg else {"status": "ok"}

@app.route("/scan", methods=["POST"])
def scan():
    barcode = (request.json or {}).get("barcode", "")
    if not barcode:
        return jsonify({"error": "barcode required"}), 400
    res = insert_scans_bulk(barcode, 1, is_manual=(request.json or {}).get("is_manual", False))
    return jsonify(res)

@app.route("/manual", methods=["POST"])
def manual():
    data = request.json or {}
    barcode = data.get("barcode", "")
    if not barcode:
        return jsonify({"error": "barcode required"}), 400
    qty = max(1, min(int(data.get("qty", 1)), 500))  # cap at 500
    res = insert_scans_bulk(barcode, qty, is_manual=data.get("is_manual", True))
    return jsonify(res)

@app.route("/damaged", methods=["POST"])
def damaged():
    data = request.json or {}
    barcode = data.get("barcode", "")
    if not barcode:
        return jsonify({"error": "barcode required"}), 400
    qty = max(1, min(int(data.get("qty", 1)), 500))  # cap at 500
    res = insert_scans_bulk(barcode, qty, is_damaged=True, is_manual=data.get("is_manual", False))
    return jsonify(res)

@app.route("/flag_item", methods=["POST"])
def flag_item():
    barcode = clean_barcode(request.json["barcode"].strip().upper())
    session_name = request.json.get("session_name")
    user = session.get("user")
    
    is_flagged = Scan.query.filter_by(
        barcode=barcode, session_name=session_name, user=user, is_flagged=1
    ).count() > 0
    
    scans_to_update = Scan.query.filter_by(
        barcode=barcode, session_name=session_name, user=user
    ).all()
    
    if is_flagged:
        for s in scans_to_update:
            s.is_flagged = 0
            s.flag_reason = ''
    else:
        for s in scans_to_update:
            s.is_flagged = 1
            s.flag_reason = 'Manual Flag'
            
    db.session.commit()
    return jsonify({"status":"ok"})

@app.route("/sync", methods=["POST"])
def sync():
    scans = (request.json or {}).get("scans", [])
    if not scans:
        return jsonify({"status": "ok"})

    to_add = []
    for s in scans:
        bc = (s.get("barcode") or "").strip().upper()
        is_damaged = 1 if (s.get("is_damaged", False) or SUFFIX_DAMAGED in bc) else 0
        is_flagged = 1 if (s.get("is_flagged", False) or SUFFIX_FLAGGED in bc or s.get("is_manual", False)) else 0
        
        flag_reason = ""
        if is_flagged:
            flag_reason = "Manual Entry"
            
        bc_clean = clean_barcode(bc)
        to_add.append(Scan(
            barcode=bc_clean,
            timestamp=s.get("timestamp"),
            user=s.get("user"),
            branch=s.get("branch"),
            session_name=s.get("session_name"),
            flag_reason=flag_reason,
            is_damaged=is_damaged,
            is_flagged=is_flagged
        ))

    db.session.add_all(to_add)
    db.session.commit()
    app_cache.clear()
    return jsonify({"status": "ok"})

@app.route("/undo", methods=["POST"])
def undo():
    user = session.get("user")
    session_name = request.json.get("session_name")
    
    last_scan = Scan.query.filter_by(
        user=user, session_name=session_name
    ).order_by(Scan.timestamp.desc()).first()
    
    if last_scan:
        barcode = last_scan.barcode
        db.session.delete(last_scan)
        log_audit_action(user or "unknown", "UNDO_SCAN", f"Undid scan of barcode '{barcode}' in session '{session_name}'.")
        db.session.commit()
    app_cache.clear()
    return jsonify({"status": "ok"})

# ---------- SUMMARY ----------
@app.route("/summary")
def summary():
    sess_name = request.args.get("session_name", "")
    query = text(f"""
        SELECT 
            barcode,
            {SQL_GOOD_COUNT},
            {SQL_DAMAGED_COUNT},
            MIN(timestamp),
            MAX(timestamp),
            {SQL_FLAGGED_COUNT}
        FROM scans
        WHERE user = :user AND session_name = :session_name
        GROUP BY barcode
        ORDER BY MAX(timestamp) DESC
        LIMIT 250
    """)
    res = db.session.execute(query, {"user": session.get("user"), "session_name": sess_name}).fetchall()
    
    data = []
    for r in res:
        data.append({
            "barcode": r[0],
            "good": r[1],
            "damaged": r[2],
            "first": r[3],
            "last": r[4],
            "flagged": r[5]
        })
    return jsonify(data)

# ---------- COUNT ----------
@app.route("/count")
def count():
    sess_name = request.args.get("session_name", "")
    total = Scan.query.filter_by(user=session.get("user"), session_name=sess_name).count()
    return jsonify({"count": total})

@app.route("/branches")
def branches():
    return jsonify(get_cached_branches())

@app.route("/sessions")
def get_sessions():
    branch = request.args.get("branch", "")
    response = make_response(jsonify(get_cached_sessions(branch)))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response

@app.route("/add_branch", methods=["POST"])
def add_branch():
    if session.get("role") != "admin":
        return jsonify({"error": "forbidden"}), 403
    name = (request.json or {}).get("name", "").strip()
    if not name:
        return jsonify({"error": "branch name required"}), 400
    exists = Branch.query.filter_by(name=name).first()
    if not exists:
        db.session.add(Branch(name=name))
        db.session.commit()
        app_cache.invalidate("branches")
    return jsonify({"status": "ok"})

# ---------- HISTORY & USER ACTION ----------
@app.route("/user/delete_scan", methods=["DELETE"])
def user_delete_scan():
    if "user" not in session:
        return jsonify({"error": "forbidden"}), 403
    data = request.json
    barcode = clean_barcode(data.get("barcode").strip().upper())
    session_name = data.get("session_name")
    
    q = Scan.query.filter_by(
        barcode=barcode, user=session.get("user"), session_name=session_name
    )
    count = q.count()
    q.delete(synchronize_session=False)
    
    log_audit_action(session.get("user", "unknown"), "USER_DELETE_SCAN", f"Deleted all scans ({count} items) for barcode '{barcode}' in session '{session_name}'.")
    db.session.commit()
    app_cache.clear()
    return jsonify({"status": "ok"})

@app.route("/user/history")
def user_history():
    if "user" not in session:
        return jsonify({"error": "forbidden"}), 403
    branch = request.args.get("branch", "")
    session_name = request.args.get("session_name", "")
    date = request.args.get("date", "")
    
    sql = f"""
        SELECT 
            barcode,
            branch,
            session_name,
            {SQL_GOOD_COUNT},
            {SQL_DAMAGED_COUNT},
            MAX(timestamp),
            {SQL_FLAGGED_COUNT}
        FROM scans
        WHERE user = :user
    """
    params = {"user": session.get("user")}
    
    if branch:
        sql += " AND branch = :branch"
        params["branch"] = branch
    if session_name:
        sql += " AND session_name = :session_name"
        params["session_name"] = session_name
    if date:
        sql += " AND timestamp >= :date_start AND timestamp <= :date_end"
        params["date_start"] = date + " 00:00:00"
        params["date_end"] = date + " 23:59:59"
        
    sql += " GROUP BY barcode, branch, session_name ORDER BY MAX(timestamp) DESC LIMIT 100"
    
    res = db.session.execute(text(sql), params).fetchall()
    data = []
    for r in res:
        data.append({
            "barcode": r[0], "branch": r[1], "session_name": r[2],
            "good": r[3], "damaged": r[4], "last": r[5], "flagged": r[6]
        })
    return jsonify(data)

# ---------- ADMIN ----------
@app.route("/admin")
def admin():
    if session.get("role") not in ["admin", "moderator"]:
        return redirect("/login")

    users = get_cached_users()

    branches_list = Branch.query.all()
    branches = [{"id": b.id, "name": b.name} for b in branches_list]

    return render_template("admin.html", users=users, branches=branches, role=session.get("role"))

@app.route("/admin/scans_data")
def admin_scans_data():
    if session.get("role") not in ["admin", "moderator"]:
        return jsonify({"error": "forbidden"}), 403
    
    page = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 100))
    offset = (page - 1) * limit
    
    search = request.args.get("search", "").strip()
    flagged_only = request.args.get("flagged_only", "false") == "true"
    date_from = request.args.get("date_from", "")
    date_to = request.args.get("date_to", "")
    
    where_clauses = ["1=1"]
    params = {}
    
    if date_from:
        where_clauses.append("timestamp >= :date_from")
        params["date_from"] = date_from.replace("T", " ") + ":00"
    if date_to:
        where_clauses.append("timestamp <= :date_to")
        params["date_to"] = date_to.replace("T", " ") + ":59"
    if search:
        search_like = f"%{search}%"
        where_clauses.append("(barcode LIKE :search OR user LIKE :search OR branch LIKE :search OR session_name LIKE :search)")
        params["search"] = search_like
        
    where_str = " AND ".join(where_clauses)
    
    having_str = ""
    if flagged_only:
        having_str = f"HAVING {SQL_FLAGGED_COUNT} > 0"
        
    if flagged_only:
        count_query = f"""
            SELECT COUNT(*) FROM (
                SELECT 1 FROM scans
                WHERE {where_str}
                GROUP BY barcode, user, branch, session_name
                {having_str}
            )
        """
    else:
        count_query = f"""
            SELECT COUNT(*) FROM (
                SELECT 1 FROM scans
                WHERE {where_str}
                GROUP BY barcode, user, branch, session_name
            )
        """
        
    total_records = db.session.execute(text(count_query), params).scalar() or 0
    total_pages = max(1, (total_records + limit - 1) // limit)
    
    query = f"""
        SELECT 
            barcode,
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
        WHERE {where_str}
        GROUP BY barcode, user, branch, session_name
        {having_str}
        ORDER BY MAX(timestamp) DESC
        LIMIT :limit OFFSET :offset
    """
    
    main_params = dict(params)
    main_params["limit"] = limit
    main_params["offset"] = offset
    
    res = db.session.execute(text(query), main_params).fetchall()
    data = []
    for r in res:
        reasons = r[9]
        clean_reason = ""
        if reasons:
            valid_reasons = [x.strip() for x in reasons.split(',') if x and x.strip()]
            clean_reason = ", ".join(set(valid_reasons))
            
        data.append({
            "barcode": r[0], "user": r[1], "branch": r[2], "session_name": r[3],
            "good": r[4], "damaged": r[5], "first": r[6], "last": r[7], "flagged": r[8], "reason": clean_reason
        })
    
    return jsonify({
        "data": data,
        "total_pages": total_pages,
        "current_page": page,
        "total_records": total_records
    })

@app.route("/admin/master_scans")
def admin_master_scans():
    if session.get("role") not in ["admin", "moderator"]:
        return jsonify({"error": "forbidden"}), 403
    branch = request.args.get("branch", "")
    session_name = request.args.get("session_name", "")
    date_from = request.args.get("date_from", "")
    date_to = request.args.get("date_to", "")
    
    page = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 100))
    offset = (page - 1) * limit
    
    search = request.args.get("search", "").strip()
    flagged_only = request.args.get("flagged_only", "false") == "true"
    
    where_clauses = ["1=1"]
    params = {}
    
    if branch:
        where_clauses.append("branch = :branch")
        params["branch"] = branch
    if session_name:
        where_clauses.append("session_name = :session_name")
        params["session_name"] = session_name
    if date_from:
        where_clauses.append("timestamp >= :date_from")
        params["date_from"] = date_from.replace("T", " ") + ":00"
    if date_to:
        where_clauses.append("timestamp <= :date_to")
        params["date_to"] = date_to.replace("T", " ") + ":59"
    if search:
        search_like = f"%{search}%"
        where_clauses.append("(barcode LIKE :search OR user LIKE :search)")
        params["search"] = search_like
        
    where_str = " AND ".join(where_clauses)
    
    having_str = ""
    if flagged_only:
        having_str = f"HAVING {SQL_FLAGGED_COUNT} > 0"
        
    if flagged_only:
        count_query = f"""
            SELECT COUNT(*) FROM (
                SELECT 1 FROM scans
                WHERE {where_str}
                GROUP BY barcode
                {having_str}
            )
        """
    else:
        count_query = f"""
            SELECT COUNT(*) FROM (
                SELECT 1 FROM scans
                WHERE {where_str}
                GROUP BY barcode
            )
        """
        
    total_records = db.session.execute(text(count_query), params).scalar() or 0
    total_pages = max(1, (total_records + limit - 1) // limit)
    
    query = f"""
        SELECT 
            barcode,
            {SQL_GOOD_COUNT},
            {SQL_DAMAGED_COUNT},
            MIN(timestamp),
            MAX(timestamp),
            GROUP_CONCAT(DISTINCT user),
            {SQL_FLAGGED_COUNT},
            GROUP_CONCAT(DISTINCT flag_reason)
        FROM scans
        WHERE {where_str}
        GROUP BY barcode
        {having_str}
        ORDER BY MAX(timestamp) DESC
        LIMIT :limit OFFSET :offset
    """
    
    main_params = dict(params)
    main_params["limit"] = limit
    main_params["offset"] = offset
    
    res = db.session.execute(text(query), main_params).fetchall()
    data = []
    for r in res:
        reasons = r[7]
        clean_reason = ""
        if reasons:
            valid_reasons = [x.strip() for x in reasons.split(',') if x and x.strip()]
            clean_reason = ", ".join(set(valid_reasons))
            
        data.append({
            "barcode": r[0], "good": r[1], "damaged": r[2], "first": r[3], "last": r[4], "users": r[5], "flagged": r[6], "reason": clean_reason
        })
    
    return jsonify({
        "data": data,
        "total_pages": total_pages,
        "current_page": page,
        "total_records": total_records
    })

@app.route("/admin/export_csv")
def admin_export_csv():
    if session.get("role") not in ["admin", "moderator"]:
        return jsonify({"error": "forbidden"}), 403
    mode = request.args.get("mode", "detailed")
    branch = request.args.get("branch", "")
    session_name = request.args.get("session_name", "")
    date_from = request.args.get("date_from", "")
    date_to = request.args.get("date_to", "")
    
    output = io.StringIO()
    output.write('\ufeff')
    writer = csv.writer(output)
    
    if mode == "master":
        writer.writerow(["Barcode", "Good", "Damaged", "Flagged", "Flag Reason", "First Scan", "Last Scan", "Users"])
        query = f"""
            SELECT barcode,
                   {SQL_GOOD_COUNT},
                   {SQL_DAMAGED_COUNT},
                   {SQL_FLAGGED_COUNT},
                   GROUP_CONCAT(DISTINCT flag_reason),
                   MIN(timestamp),
                   MAX(timestamp),
                   GROUP_CONCAT(DISTINCT user)
            FROM scans WHERE 1=1
        """
        params = {}
        if branch:
            query += " AND branch = :branch"
            params["branch"] = branch
        if session_name:
            query += " AND session_name = :session_name"
            params["session_name"] = session_name
        if date_from:
            query += " AND timestamp >= :date_from"
            params["date_from"] = date_from.replace("T", " ") + ":00"
        if date_to:
            query += " AND timestamp <= :date_to"
            params["date_to"] = date_to.replace("T", " ") + ":59"
        query += " GROUP BY barcode ORDER BY MAX(timestamp) DESC"
        
        res = db.session.execute(text(query), params).fetchall()
        for r in res:
            row = list(r)
            reasons = row[4] or ""
            valid = [x.strip() for x in reasons.split(',') if x and x.strip()]
            row[4] = ", ".join(set(valid)) if valid else ""
            writer.writerow(row)
    else:
        writer.writerow(["Barcode", "User", "Branch", "Session", "Good", "Damaged", "Flagged", "Flag Reason", "First Scan", "Last Scan"])
        query = f"""
            SELECT barcode, user, branch, session_name,
                   {SQL_GOOD_COUNT},
                   {SQL_DAMAGED_COUNT},
                   {SQL_FLAGGED_COUNT},
                   GROUP_CONCAT(DISTINCT flag_reason),
                   MIN(timestamp),
                   MAX(timestamp)
            FROM scans WHERE 1=1
        """
        params = {}
        if date_from:
            query += " AND timestamp >= :date_from"
            params["date_from"] = date_from.replace("T", " ") + ":00"
        if date_to:
            query += " AND timestamp <= :date_to"
            params["date_to"] = date_to.replace("T", " ") + ":59"
        query += " GROUP BY barcode, user, branch, session_name ORDER BY MAX(timestamp) DESC"
        
        res = db.session.execute(text(query), params).fetchall()
        for r in res:
            row = list(r)
            reasons = row[7] or ""
            valid = [x.strip() for x in reasons.split(',') if x and x.strip()]
            row[7] = ", ".join(set(valid)) if valid else ""
            writer.writerow(row)
            
    fname_parts = ["scans"]
    if branch: fname_parts.append(branch.replace(' ', '_'))
    if session_name: fname_parts.append(session_name.replace(' ', '_'))
    fname_parts.append(mode)
    filename = "_".join(fname_parts) + ".csv"
    encoded_filename = urllib.parse.quote(filename)
    
    return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename*=UTF-8''{encoded_filename}"})

@app.route("/admin/stats")
def admin_stats():
    if session.get("role") not in ["admin", "moderator"]:
        return jsonify({"error": "forbidden"}), 403
    
    branch = request.args.get("branch", "")
    session_name = request.args.get("session_name", "")
    date_from = request.args.get("date_from", "")
    date_to = request.args.get("date_to", "")
    
    where_clauses = ["1=1"]
    params = {}
    
    if branch:
        where_clauses.append("branch = :branch")
        params["branch"] = branch
    if session_name:
        where_clauses.append("session_name = :session_name")
        params["session_name"] = session_name
    if date_from:
        where_clauses.append("timestamp >= :date_from")
        params["date_from"] = date_from.replace("T", " ") + ":00"
    if date_to:
        where_clauses.append("timestamp <= :date_to")
        params["date_to"] = date_to.replace("T", " ") + ":59"
        
    where_sql = " AND ".join(where_clauses)
    
    stats_query = f"""
        SELECT 
            COUNT(*),
            COUNT(DISTINCT barcode),
            COUNT(DISTINCT CASE WHEN is_flagged=1 THEN barcode END)
        FROM scans
        WHERE {where_sql}
    """
    stats_res = db.session.execute(text(stats_query), params).fetchone()
    total_scans = stats_res[0] or 0
    unique_barcodes = stats_res[1] or 0
    flagged_items = stats_res[2] or 0
    
    # Active Users
    active_users = User.query.filter(
        User.session_token.isnot(None),
        text("last_active >= datetime('now', '+3 hours', '-20 minutes')")
    ).count()
    
    return jsonify({
        "total_scans": total_scans,
        "unique_barcodes": unique_barcodes,
        "active_users": active_users,
        "flagged_items": flagged_items
    })

@app.route("/admin/chart_data")
def admin_chart_data():
    if session.get("role") not in ["admin", "moderator"]:
        return jsonify({"error": "forbidden"}), 403
    time_range = request.args.get("range", "7days")
    
    dates = []
    counts = []
    
    if time_range == "24hours":
        res = db.session.execute(text("""
            SELECT strftime('%H:00', timestamp), COUNT(*) 
            FROM scans 
            WHERE timestamp >= datetime('now', '+3 hours', '-24 hours')
            GROUP BY strftime('%Y-%m-%d %H', timestamp)
            ORDER BY strftime('%Y-%m-%d %H', timestamp) ASC
        """)).fetchall()
    else:
        res = db.session.execute(text("""
            SELECT date(timestamp), COUNT(*) 
            FROM scans 
            WHERE timestamp >= datetime('now', '+3 hours', '-7 days')
            GROUP BY date(timestamp)
            ORDER BY date(timestamp) ASC
        """)).fetchall()
        
    for r in res:
        dates.append(r[0])
        counts.append(r[1])
        
    user_res = db.session.execute(text("""
        SELECT user, COUNT(*) 
        FROM scans
        WHERE user IS NOT NULL AND user != ''
        GROUP BY user
        ORDER BY COUNT(*) DESC
    """)).fetchall()
    
    user_labels = []
    user_counts = []
    for r in user_res:
        user_labels.append(r[0])
        user_counts.append(r[1])
        
    return jsonify({
        "time": {"labels": dates, "data": counts},
        "users": {"labels": user_labels, "data": user_counts}
    })

@app.route("/settings")
def get_settings():
    response = make_response(jsonify(get_cached_settings()))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response

@app.route("/admin/settings", methods=["POST"])
def set_settings():
    if session.get("role") != "admin":
        return jsonify({"error": "forbidden"}), 403
    data = request.json
    for k, v in data.items():
        setting = GlobalSetting(key=k, value=str(v))
        db.session.merge(setting)
    db.session.commit()
    app_cache.invalidate("settings")
    return jsonify({"status": "ok"})

@app.route("/admin/adjust_count", methods=["POST"])
def admin_adjust_count():
    if session.get("role") != "admin": return "forbidden"
    data = request.json
    barcode = clean_barcode(data["barcode"].strip().upper())
    is_damaged = 1 if data["type"] == "damaged" else 0
    is_flagged = 1 if data["type"] == "flagged" else 0
        
    diff = int(data["diff"])
    
    if diff > 0:
        to_add = []
        for _ in range(diff):
            to_add.append(Scan(
                barcode=barcode,
                timestamp=get_gmt3_time(),
                user=data["user"],
                branch=data["branch"],
                session_name=data["session_name"],
                is_damaged=is_damaged,
                is_flagged=is_flagged
            ))
        db.session.add_all(to_add)
    elif diff < 0:
        # SQLite doesn't directly support LIMIT in DELETE, so we query matching IDs and delete them
        filter_kwargs = {
            "barcode": barcode,
            "user": data["user"],
            "branch": data["branch"],
            "session_name": data["session_name"],
            "is_damaged": is_damaged
        }
        if data["type"] == "flagged":
            filter_kwargs["is_flagged"] = 1
            
        subquery_ids = db.session.query(Scan.id).filter_by(
            **filter_kwargs
        ).order_by(Scan.timestamp.desc()).limit(abs(diff)).all()
        
        target_ids = [r[0] for r in subquery_ids]
        if target_ids:
            Scan.query.filter(Scan.id.in_(target_ids)).delete(synchronize_session=False)
            
    # Log audit
    operator = session.get("user", "unknown")
    item_type = "damaged" if is_damaged else "flagged" if is_flagged else "good"
    details = f"Adjusted count of '{barcode}' for user '{data['user']}' in branch '{data['branch']}', session '{data['session_name']}' by {diff} ({item_type})."
    log_audit_action(operator, "ADJUST_COUNT", details)

    db.session.commit()
    app_cache.clear()
    return jsonify({"status": "ok"})

@app.route("/admin/toggle_flag", methods=["POST"])
def admin_toggle_flag():
    role = session.get("role")
    if role not in ["admin", "moderator"]: return jsonify({"error": "forbidden"}), 403
    data = request.json
    barcode = clean_barcode(data["barcode"].strip().upper())
    target_user = data.get("user")
    if target_user == "null": target_user = None
    branch = data.get("branch")
    session_name = data.get("session_name")
    
    current_user = session.get("user", "unknown")
    if role == "moderator":
        flag_reason = f"Flagged by moderator {current_user}"
    else:
        flag_reason = "Admin Manual Flag"
    
    # Check if ANY flag exists for this barcode in this session
    q = Scan.query.filter_by(barcode=barcode, is_flagged=1)
    if session_name and session_name != "null":
        q = q.filter_by(session_name=session_name)
    if target_user:
        q = q.filter_by(user=target_user)
        
    is_flagged = q.count() > 0
    
    update_q = Scan.query.filter_by(barcode=barcode)
    if session_name and session_name != "null":
        update_q = update_q.filter_by(session_name=session_name)
    if target_user:
        update_q = update_q.filter_by(user=target_user)
        
    if is_flagged:
        update_q.update({"is_flagged": 0, "flag_reason": ""}, synchronize_session=False)
    else:
        update_q.update({"is_flagged": 1, "flag_reason": flag_reason}, synchronize_session=False)
        
    db.session.commit()
    app_cache.clear()
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
    
    user_rec = User.query.filter_by(username=session.get("user")).first()
    if not user_rec:
        return jsonify({"error": "Invalid password"}), 401
    db_password = user_rec.password
    is_valid = check_password_hash(db_password, password) if db_password.startswith(('scrypt:', 'pbkdf2:')) else db_password == password
    if not is_valid:
        return jsonify({"error": "Invalid password"}), 401
    
    q = Scan.query.filter_by(session_name=session_name)
    if branch:
        q = q.filter_by(branch=branch)
        
    count = q.count()
    q.delete(synchronize_session=False)
    
    # Log audit
    operator = session.get("user", "unknown")
    log_audit_action(operator, "DELETE_SESSION", f"Deleted session '{session_name}' under branch '{branch}' (affected {count} scans).")
    
    db.session.commit()
    app_cache.clear()
    return jsonify({"status": "ok", "deleted": count})

@app.route("/admin/session_info")
def admin_session_info():
    """Get detailed info about all sessions for session management."""
    if session.get("role") not in ["admin", "moderator"]: return jsonify({"error": "forbidden"}), 403
    res = db.session.query(
        Scan.session_name,
        Scan.branch,
        db.func.count(Scan.id).label('scan_count'),
        db.func.count(db.func.distinct(Scan.user)).label('user_count'),
        db.func.min(Scan.timestamp).label('first_scan'),
        db.func.max(Scan.timestamp).label('last_scan')
    ).filter(
        Scan.session_name.isnot(None),
        Scan.session_name != ''
    ).group_by(
        Scan.session_name, Scan.branch
    ).order_by(
        db.func.max(Scan.timestamp).desc()
    ).all()
    
    data = []
    for r in res:
        data.append({
            "session_name": r[0], "branch": r[1], "scan_count": r[2],
            "user_count": r[3], "first_scan": r[4], "last_scan": r[5]
        })
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
    
    q = Scan.query.filter_by(session_name=from_session)
    if from_branch:
        q = q.filter_by(branch=from_branch)
        
    update_dict = {"session_name": to_session}
    if to_branch:
        update_dict["branch"] = to_branch
        
    affected = q.update(update_dict, synchronize_session=False)
    
    # Log audit
    operator = session.get("user", "unknown")
    details = f"Reassigned scans from '{from_session}' ({from_branch or 'any branch'}) to '{to_session}' ({to_branch or 'same branch'}) (affected {affected} scans)."
    log_audit_action(operator, "REASSIGN_SESSION", details)
    
    db.session.commit()
    app_cache.clear()
    return jsonify({"status": "ok", "moved": affected})

@app.route("/admin/delete_entries", methods=["POST"])
def admin_delete_entries():
    if session.get("role") != "admin": return jsonify({"error": "forbidden"}), 403
    data = request.json
    password = data.get("password")
    mode = data.get("mode")
    entries = data.get("entries", [])
    
    user_rec = User.query.filter_by(username=session.get("user")).first()
    if not user_rec:
        return jsonify({"error": "Invalid password"}), 401
        
    db_password = user_rec.password
    is_valid = check_password_hash(db_password, password) if db_password.startswith(('scrypt:', 'pbkdf2:')) else db_password == password
    
    if not is_valid:
        return jsonify({"error": "Invalid password"}), 401
        
    deleted_count = 0
    for entry in entries:
        barcode = clean_barcode((entry.get("barcode") or "").strip().upper())
        q = Scan.query.filter_by(barcode=barcode)
        
        if mode == "master":
            branch_val = entry.get("branch")
            session_val = entry.get("session_name")
            if branch_val and branch_val != "null":
                q = q.filter_by(branch=branch_val)
            if session_val and session_val != "null":
                q = q.filter_by(session_name=session_val)
            deleted_count += q.delete(synchronize_session=False)
        else:
            user_val = entry.get("user")
            branch_val = entry.get("branch")
            session_val = entry.get("session_name")
            
            # In detailed mode, if the field is empty we still filter by it 
            # because the row specifically has an empty value for that column.
            # But we handle "null" string as a fallback just in case.
            if user_val == "null": user_val = None
            if branch_val == "null": branch_val = None
            if session_val == "null": session_val = None
            
            q = q.filter_by(user=user_val, branch=branch_val, session_name=session_val)
            deleted_count += q.delete(synchronize_session=False)
            
    # Log audit
    operator = session.get("user", "unknown")
    details = f"Deleted {deleted_count} scans. Mode: {mode}. Entries: {entries}"
    log_audit_action(operator, "DELETE_SCANS", details)

    db.session.commit()
    app_cache.clear()
    return jsonify({"status": "ok"})

@app.route("/admin/edit_barcode", methods=["POST"])
def admin_edit_barcode():
    role = session.get("role")
    if role not in ["admin", "moderator"]:
        return jsonify({"error": "forbidden"}), 403
    
    data = request.json
    old_bc = clean_barcode(data.get("old_barcode", "").strip().upper())
    new_bc = clean_barcode(data.get("new_barcode", "").strip().upper())
    
    if not old_bc or not new_bc:
        return jsonify({"error": "Invalid barcodes"}), 400
        
    user_filter = data.get("user")
    branch_filter = data.get("branch")
    session_filter = data.get("session_name")
    
    q = Scan.query.filter_by(barcode=old_bc)
    
    if user_filter and user_filter != "null":
        q = q.filter_by(user=user_filter)
    if branch_filter and branch_filter != "null" and branch_filter != "":
        q = q.filter_by(branch=branch_filter)
    if session_filter and session_filter != "null" and session_filter != "":
        q = q.filter_by(session_name=session_filter)
        
    affected = q.count()
    if affected == 0:
        return jsonify({"error": "No matching scans found"}), 404
        
    q.update({"barcode": new_bc}, synchronize_session=False)
    
    # Create audit log entry
    operator = session.get("user", "unknown")
    details = f"Edited barcode '{old_bc}' to '{new_bc}' (affected {affected} scans). Filters: user={user_filter}, branch={branch_filter}, session={session_filter}."
    log_audit_action(operator, "EDIT_BARCODE", details)
    
    db.session.commit()
    app_cache.clear()
    
    return jsonify({"status": "ok", "updated": affected})

@app.route("/admin/audit_logs")
def admin_audit_logs():
    if session.get("role") != "admin":
        return jsonify({"error": "forbidden"}), 403
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(1000).all()
    return jsonify([{
        "id": l.id,
        "timestamp": l.timestamp,
        "operator": l.operator,
        "action": l.action,
        "details": l.details
    } for l in logs])

@app.route("/admin/user_stats")
def admin_user_stats():
    if session.get("role") not in ["admin", "moderator"]:
        return jsonify({"error": "forbidden"}), 403
        
    timeframe = request.args.get("timeframe", "all")
    
    # Calculate date range
    where_sql = "1=1"
    params = {}
    
    from datetime import timezone, timedelta
    gmt3 = timezone(timedelta(hours=3))
    now = datetime.now(gmt3)
    
    if timeframe == "today":
        today_str = now.strftime("%Y-%m-%d")
        where_sql = "timestamp >= :start AND timestamp <= :end"
        params["start"] = today_str + " 00:00:00"
        params["end"] = today_str + " 23:59:59"
    elif timeframe == "yesterday":
        yesterday = now - timedelta(days=1)
        yesterday_str = yesterday.strftime("%Y-%m-%d")
        where_sql = "timestamp >= :start AND timestamp <= :end"
        params["start"] = yesterday_str + " 00:00:00"
        params["end"] = yesterday_str + " 23:59:59"
    elif timeframe == "7days":
        start_date = now - timedelta(days=7)
        where_sql = "timestamp >= :start"
        params["start"] = start_date.strftime("%Y-%m-%d %H:%M:%S")
    elif timeframe == "30days":
        start_date = now - timedelta(days=30)
        where_sql = "timestamp >= :start"
        params["start"] = start_date.strftime("%Y-%m-%d %H:%M:%S")
        
    query = f"""
        SELECT 
            user,
            COUNT(*),
            SUM(CASE WHEN is_damaged=0 THEN 1 ELSE 0 END),
            SUM(CASE WHEN is_damaged=1 THEN 1 ELSE 0 END),
            SUM(CASE WHEN is_flagged=1 THEN 1 ELSE 0 END),
            COUNT(DISTINCT session_name),
            COUNT(DISTINCT branch),
            MAX(timestamp)
        FROM scans
        WHERE {where_sql} AND user IS NOT NULL AND user != ''
        GROUP BY user
        ORDER BY COUNT(*) DESC
    """
    
    rows = db.session.execute(text(query), params).fetchall()
    
    # Merge with roles
    users_list = User.query.all()
    user_roles = {u.username: u.role for u in users_list}
    
    data = []
    for r in rows:
        username = r[0]
        data.append({
            "user": username,
            "role": user_roles.get(username, "counter"),
            "total_scans": r[1] or 0,
            "good_scans": r[2] or 0,
            "damaged_scans": r[3] or 0,
            "flagged_scans": r[4] or 0,
            "sessions_worked": r[5] or 0,
            "branches_worked": r[6] or 0,
            "last_active": r[7] or ""
        })
        
    return jsonify(data)

@app.route("/admin/session_defs")
def admin_session_defs():
    if session.get("role") not in ["admin", "moderator"]:
        return jsonify({"error": "forbidden"}), 403
    defs = BranchSession.query.order_by(BranchSession.branch_name, BranchSession.session_name).all()
    return jsonify([{
        "id": d.id,
        "branch_name": d.branch_name,
        "session_name": d.session_name
    } for d in defs])

@app.route("/admin/add_session_def", methods=["POST"])
def admin_add_session_def():
    if session.get("role") != "admin":
        return jsonify({"error": "forbidden"}), 403
    data = request.json or {}
    b_name = data.get("branch_name", "").strip()
    s_name = data.get("session_name", "").strip()
    
    if not b_name or not s_name:
        return jsonify({"error": "branch_name and session_name required"}), 400
        
    exists = BranchSession.query.filter_by(branch_name=b_name, session_name=s_name).first()
    if exists:
        return jsonify({"error": "exists"}), 409
        
    new_def = BranchSession(branch_name=b_name, session_name=s_name)
    db.session.add(new_def)
    db.session.commit()
    app_cache.invalidate("sessions_all", f"sessions_branch:{b_name}")
    return jsonify({"status": "ok"})

@app.route("/admin/delete_session_def/<int:def_id>", methods=["DELETE"])
def admin_delete_session_def(def_id):
    if session.get("role") != "admin":
        return jsonify({"error": "forbidden"}), 403
    item = db.session.get(BranchSession, def_id)
    if item:
        b_name = item.branch_name
        db.session.delete(item)
        db.session.commit()
        app_cache.invalidate("sessions_all", f"sessions_branch:{b_name}")
    return jsonify({"status": "ok"})

@app.route("/add_user", methods=["POST"])
def add_user():
    if session.get("role") != "admin":
        return jsonify({"error": "forbidden"}), 403
    data = request.json or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    role = data.get("role") or "counter"
    
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    if role not in ("admin", "moderator", "counter"):
        return jsonify({"error": "invalid role"}), 400
    
    exists = User.query.filter_by(username=username).first()
    if exists:
        return jsonify({"error": "exists"}), 409
        
    new_user = User(username=username, password=generate_password_hash(password), role=role)
    db.session.add(new_user)
    try:
        db.session.commit()
        app_cache.invalidate("users")
    except Exception:
        db.session.rollback()
        return jsonify({"error": "exists"}), 409
    return jsonify({"status": "ok"})

@app.route("/delete_user/<username>", methods=["DELETE"])
def delete_user(username):
    if session.get("role") != "admin":
        return jsonify({"error": "forbidden"}), 403
    if username == session.get("user"):
        return jsonify({"error": "cannot delete yourself"}), 400
    User.query.filter_by(username=username).delete()
    db.session.commit()
    app_cache.invalidate("users")
    return jsonify({"status": "ok"})

@app.route("/user_password", methods=["POST"])
def user_password():
    if session.get("role") != "admin":
        return jsonify({"error": "forbidden"}), 403
    data = request.json or {}
    username = data.get("username") or ""
    new_pass_raw = data.get("password") or ""
    if not username or not new_pass_raw:
        return jsonify({"error": "username and password required"}), 400
    
    user_rec = User.query.filter_by(username=username).first()
    if user_rec:
        user_rec.password = generate_password_hash(new_pass_raw)
        db.session.commit()
        app_cache.invalidate("users")
    return jsonify({"status": "ok"})

@app.route("/force_logout/<username>", methods=["POST"])
def force_logout(username):
    if session.get("role") != "admin":
        return jsonify({"error": "forbidden"}), 403
    user_rec = User.query.filter_by(username=username).first()
    if user_rec:
        user_rec.session_token = str(uuid.uuid4())
        db.session.commit()
    return jsonify({"status": "ok"})

@app.route("/delete_branch/<name>", methods=["DELETE"])
def delete_branch(name):
    if session.get("role") != "admin":
        return jsonify({"error": "forbidden"}), 403
    Branch.query.filter_by(name=name).delete()
    db.session.commit()
    app_cache.invalidate("branches")
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    try:
        from waitress import serve
        print("Starting production server with Waitress on port 5000...")
        serve(app, host="0.0.0.0", port=5000)
    except ImportError:
        print("Waitress not installed. Please run 'pip install waitress' for production mode.")
        print("Falling back to Flask development server...")
        app.run(host="0.0.0.0", debug=False)
