from flask import Flask, request, jsonify, render_template, redirect, url_for, g
import json, os, time, base64, sqlite3, requests, hashlib, hmac, re, secrets
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict
import threading

# ==========================================
#   CONFIGURAÇÃO
# ==========================================

DB = "data/licenses.db"
USERS_FILE = "data/users.json"
KEY_PRIV = "private.pem"
KEY_PUB = "public.pem"
SECURITY_LOG_FILE = "data/security.log"

UNLIMITED_EXPIRY = 9999999999999

CHAVE_SECRETA = os.getenv("HMAC_SECRET", "FER4_4LPH4_2024_S3CR3T_K3Y_N0T_SH4R3D")

SESSION_DURATION = 24 * 60 * 60  # 24 horas

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_REPO = "FeraAlpha/painel-licenca-server"
GITHUB_FILE_PATH = "data/users.json"
GITHUB_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_FILE_PATH}"

os.makedirs("data", exist_ok=True)
os.makedirs("data/backups", exist_ok=True)

# ==========================================
#   RATE LIMITER
# ==========================================

class RateLimiter:
    def __init__(self, max_requests=10, window_seconds=60):
        self._lock = threading.Lock()
        self._requests = defaultdict(list)
        self._max = max_requests
        self._window = window_seconds

    def is_allowed(self, key):
        now = time.time()
        with self._lock:
            timestamps = self._requests[key]
            timestamps[:] = [t for t in timestamps if now - t < self._window]
            if len(timestamps) >= self._max:
                return False
            timestamps.append(now)
            return True

    def cleanup(self):
        now = time.time()
        with self._lock:
            expired_keys = [
                k for k, v in self._requests.items()
                if all(now - t >= self._window for t in v)
            ]
            for k in expired_keys:
                del self._requests[k]


class BruteForceProtection:
    def __init__(self, max_fails=5, lockout_seconds=300):
        self._lock = threading.Lock()
        self._fails = defaultdict(list)
        self._max = max_fails
        self._lockout = lockout_seconds

    def record_fail(self, key):
        now = time.time()
        with self._lock:
            self._fails[key].append(now)
            self._fails[key] = [
                t for t in self._fails[key] if now - t < self._lockout
            ]

    def is_locked(self, key):
        now = time.time()
        with self._lock:
            timestamps = self._fails.get(key, [])
            timestamps[:] = [t for t in timestamps if now - t < self._lockout]
            self._fails[key] = timestamps
            return len(timestamps) >= self._max

    def clear(self, key):
        with self._lock:
            self._fails.pop(key, None)

    def remaining_lockout(self, key):
        now = time.time()
        with self._lock:
            timestamps = self._fails.get(key, [])
            if not timestamps:
                return 0
            oldest_relevant = min(t for t in timestamps if now - t < self._lockout)
            remaining = self._lockout - (now - oldest_relevant)
            return max(0, int(remaining))


activate_limiter = RateLimiter(max_requests=10, window_seconds=60)
verify_limiter = RateLimiter(max_requests=30, window_seconds=60)
brute_force = BruteForceProtection(max_fails=5, lockout_seconds=300)

# ==========================================
#   VALIDAÇÃO DE ENTRADA
# ==========================================

USERNAME_RE = re.compile(r'^[a-zA-Z0-9_.\-@]{1,64}$')
FINGERPRINT_RE = re.compile(r'^[a-zA-Z0-9_.\-:]{8,256}$')

def validate_username(val):
    if not val or not isinstance(val, str):
        return None
    val = val.strip()
    if not USERNAME_RE.match(val):
        return None
    return val

def validate_password(val):
    if not val or not isinstance(val, str):
        return None
    val = val.strip()
    if len(val) < 1 or len(val) > 128:
        return None
    return val

def validate_fingerprint(val):
    if not val or not isinstance(val, str):
        return None
    val = val.strip()
    if not FINGERPRINT_RE.match(val):
        return None
    return val

# ==========================================
#   LOGS DE SEGURANÇA
# ==========================================

_log_lock = threading.Lock()

def log_security(event_type, fingerprint=None, ip=None, details=None):
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        req_ip = "N/A"
        user_agent = "N/A"
        try:
            req_ip = ip or request.remote_addr
            user_agent = request.user_agent.string if request.user_agent else "N/A"
        except RuntimeError:
            pass

        log_entry = {
            "timestamp": timestamp,
            "event": event_type,
            "fingerprint": fingerprint,
            "ip": req_ip,
            "user_agent": user_agent,
            "details": details
        }

        with _log_lock:
            with open(SECURITY_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(log_entry) + "\n")
    except Exception:
        pass

# ==========================================
#   ASSINATURA HMAC
# ==========================================

def gerar_assinatura_hmac(expires, fingerprint):
    dados = f"{expires}:{fingerprint}"
    assinatura = hmac.new(
        CHAVE_SECRETA.encode(),
        dados.encode(),
        hashlib.sha256
    ).hexdigest()
    return assinatura

# ==========================================
#   BANCO DE DADOS
# ==========================================

def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS licenses
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  fingerprint TEXT UNIQUE,
                  username TEXT,
                  issued_at INTEGER,
                  expires_at INTEGER,
                  status TEXT DEFAULT 'active',
                  last_used INTEGER,
                  device_info TEXT)''')

    c.execute('''CREATE TABLE IF NOT EXISTS sessions
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  token TEXT NOT NULL,
                  fingerprint TEXT NOT NULL,
                  expires_at INTEGER NOT NULL,
                  created_at INTEGER,
                  last_used INTEGER,
                  ip_address TEXT,
                  user_agent TEXT,
                  UNIQUE(token, fingerprint))''')

    c.execute('''CREATE TABLE IF NOT EXISTS license_usage
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  fingerprint TEXT,
                  action TEXT,
                  timestamp INTEGER,
                  ip_address TEXT,
                  user_agent TEXT)''')

    c.execute('CREATE INDEX IF NOT EXISTS idx_fingerprint ON licenses(fingerprint)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_sessions ON sessions(token, fingerprint)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_license_status ON licenses(status, expires_at)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_usage_fp ON license_usage(fingerprint, timestamp)')

    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

class DBConnection:
    def __init__(self):
        self.conn = None

    def __enter__(self):
        self.conn = sqlite3.connect(DB)
        self.conn.row_factory = sqlite3.Row
        return self.conn

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            if exc_type is None:
                self.conn.commit()
            self.conn.close()
        return False

def verificar_licenca_ativa(fingerprint, expires):
    with DBConnection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id FROM licenses
            WHERE fingerprint = ? AND expires_at = ? AND status = 'active'
        ''', (fingerprint, expires))
        return cursor.fetchone() is not None

def atualizar_uso_licenca(fingerprint, expires):
    with DBConnection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE licenses SET last_used = ?
            WHERE fingerprint = ? AND expires_at = ?
        ''', (int(time.time()), fingerprint, expires))

def registrar_uso(fingerprint, action, ip=None, user_agent=None):
    req_ip = "N/A"
    req_ua = "N/A"
    try:
        req_ip = ip or request.remote_addr
        req_ua = user_agent or (request.user_agent.string if request.user_agent else "N/A")
    except RuntimeError:
        pass

    with DBConnection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO license_usage (fingerprint, action, timestamp, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?)
        ''', (fingerprint, action, int(time.time()), req_ip, req_ua))

def criar_sessao(token, fingerprint, ip=None, user_agent=None):
    req_ip = "N/A"
    req_ua = "N/A"
    try:
        req_ip = ip or request.remote_addr
        req_ua = user_agent or (request.user_agent.string if request.user_agent else "N/A")
    except RuntimeError:
        pass

    with DBConnection() as conn:
        cursor = conn.cursor()
        expires_at = int(time.time()) + SESSION_DURATION
        cursor.execute('''
            INSERT OR REPLACE INTO sessions (token, fingerprint, expires_at, created_at, last_used, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (token, fingerprint, expires_at, int(time.time()), int(time.time()), req_ip, req_ua))

def verificar_sessao(token, fingerprint):
    with DBConnection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id FROM sessions
            WHERE token = ? AND fingerprint = ? AND expires_at > ?
        ''', (token, fingerprint, int(time.time())))
        sessao = cursor.fetchone()
        if sessao:
            cursor.execute('''
                UPDATE sessions SET last_used = ?
                WHERE token = ? AND fingerprint = ?
            ''', (int(time.time()), token, fingerprint))
        return sessao is not None

def invalidar_sessoes_anteriores(fingerprint):
    with DBConnection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            DELETE FROM sessions WHERE fingerprint = ? AND expires_at <= ?
        ''', (fingerprint, int(time.time())))

def limpar_sessoes_expiradas():
    with DBConnection() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM sessions WHERE expires_at <= ?', (int(time.time()),))

# ==========================================
#   ESCRITA ATÔMICA
# ==========================================

def atomic_write(path, data_bytes):
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data_bytes)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

# ==========================================
#   GERENCIAMENTO DE USUÁRIOS
# ==========================================

_users_lock = threading.Lock()

def load_users():
    try:
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                users = data.get("users", [])
                for user in users:
                    if user.get("expires_at") == 0:
                        user["expires_at"] = UNLIMITED_EXPIRY
                return data
    except Exception as e:
        log_security("load_users_error", details=str(e))

    if GITHUB_TOKEN:
        try:
            r = requests.get(GITHUB_API_URL, headers={
                "Authorization": f"Bearer {GITHUB_TOKEN}",
                "Accept": "application/vnd.github+json"
            }, timeout=10)
            if r.ok:
                info = r.json()
                content = base64.b64decode(info.get("content", "")).decode()
                data = json.loads(content)
                users = data.get("users", [])
                for user in users:
                    if user.get("expires_at") == 0:
                        user["expires_at"] = UNLIMITED_EXPIRY
                atomic_write(USERS_FILE, json.dumps(data, indent=2).encode())
                return data
        except Exception as e:
            log_security("github_sync_error", details=str(e))

    return {"users": []}

def save_users_github(data, retries=3):
    if not GITHUB_TOKEN:
        return False

    sha = None
    try:
        r = requests.get(GITHUB_API_URL, headers={
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json"
        }, timeout=10)
        if r.ok:
            sha = r.json().get("sha")
    except Exception:
        pass

    content_b64 = base64.b64encode(json.dumps(data, indent=2).encode()).decode()
    payload = {"message": "update users.json", "content": content_b64}
    if sha:
        payload["sha"] = sha

    for _ in range(retries):
        try:
            res = requests.put(
                GITHUB_API_URL,
                headers={
                    "Authorization": f"Bearer {GITHUB_TOKEN}",
                    "Accept": "application/vnd.github+json"
                },
                json=payload,
                timeout=10
            )
            if res.status_code in (200, 201):
                return True
        except Exception as e:
            log_security("github_upload_error", details=str(e))
            time.sleep(1)

    return False

def save_users(data):
    with _users_lock:
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        atomic_write(f"data/backups/users.{ts}.json", json.dumps(data, indent=2).encode())
        atomic_write(USERS_FILE, json.dumps(data, indent=2).encode())

    try:
        save_users_github(data)
    except Exception as e:
        log_security("save_users_error", details=str(e))

# ==========================================
#   ASSINATURA RSA
# ==========================================

_private_key = None

def _load_private_key():
    global _private_key
    if _private_key is None:
        with open(KEY_PRIV, "rb") as f:
            _private_key = RSA.import_key(f.read())
    return _private_key

def sign_payload(payload_bytes):
    priv = _load_private_key()
    h = SHA256.new(payload_bytes)
    sig = pkcs1_15.new(priv).sign(h)
    return sig

# ==========================================
#   FLASK APP
# ==========================================

app = Flask(__name__, template_folder='templates')

# ==========================================
#   MIDDLEWARE
# ==========================================

@app.before_request
def before_request_handler():
    if request.endpoint not in ('home', 'ping', 'static'):
        log_security(
            "api_request",
            ip=request.remote_addr,
            details={
                "endpoint": request.endpoint,
                "method": request.method,
                "path": request.path
            }
        )

@app.after_request
def after_request_handler(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Cache-Control'] = 'no-store'
    return response

# ==========================================
#   ROTAS PÚBLICAS
# ==========================================

@app.route("/")
def home():
    return "Painel Licença OK", 200

@app.route("/ping", methods=["GET"])
def ping():
    return jsonify({
        "status": "online",
        "timestamp": datetime.now().isoformat(),
        "version": "2.0"
    }), 200

# ==========================================
#   ATIVAÇÃO DE LICENÇA
# ==========================================

@app.route("/activate", methods=["POST"])
def activate():
    try:
        client_ip = request.remote_addr

        if not activate_limiter.is_allowed(client_ip):
            log_security("rate_limit_hit", ip=client_ip, details={"endpoint": "activate"})
            return jsonify({"status": "error", "reason": "rate_limit_exceeded"}), 429

        data = request.json or {}
        username = validate_username(data.get("username"))
        password = validate_password(data.get("password"))
        fingerprint = validate_fingerprint(data.get("fingerprint"))

        if not username or not password or not fingerprint:
            log_security("activate_missing_fields", details={"username": data.get("username")})
            return jsonify({"error": "missing_fields"}), 400

        bf_key = f"{client_ip}:{username}"
        if brute_force.is_locked(bf_key):
            remaining = brute_force.remaining_lockout(bf_key)
            log_security("brute_force_blocked", fingerprint=fingerprint,
                         ip=client_ip, details={"username": username, "remaining": remaining})
            return jsonify({
                "status": "error",
                "reason": "too_many_attempts",
                "retry_after": remaining
            }), 429

        users_data = load_users()
        users = users_data.get("users", [])
        user = next((u for u in users if u["username"] == username and u["password"] == password), None)

        if not user:
            brute_force.record_fail(bf_key)
            log_security("activate_invalid_credentials", fingerprint=fingerprint,
                         ip=client_ip, details={"username": username})
            return jsonify({"status": "error", "reason": "invalid_credentials"}), 403

        brute_force.clear(bf_key)

        if user.get("status") == "blocked":
            log_security("activate_blocked_user", fingerprint=fingerprint,
                         details={"username": username})
            return jsonify({"status": "error", "reason": "account_blocked"}), 403

        now = int(time.time())
        expires = user.get("expires_at", 0)

        if expires == UNLIMITED_EXPIRY:
            pass
        elif expires < now:
            log_security("activate_expired", fingerprint=fingerprint,
                         details={"username": username, "expires": expires})
            return jsonify({"status": "error", "reason": "expired"}), 403

        if user.get("device_id") is None:
            user["device_id"] = fingerprint
            save_users(users_data)
        elif user.get("device_id") != fingerprint:
            log_security("activate_device_mismatch", fingerprint=fingerprint,
                         details={"username": username, "stored_device": user.get("device_id")})
            return jsonify({"status": "error", "reason": "device_mismatch"}), 403

        with DBConnection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM licenses WHERE fingerprint = ?', (fingerprint,))
            existing = cursor.fetchone()
            if not existing:
                cursor.execute('''
                    INSERT INTO licenses (fingerprint, username, issued_at, expires_at, status, last_used)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (fingerprint, username, now, expires, 'active', now))
            else:
                cursor.execute('''
                    UPDATE licenses
                    SET expires_at = ?, status = 'active', last_used = ?, username = ?
                    WHERE fingerprint = ?
                ''', (expires, now, username, fingerprint))

        invalidar_sessoes_anteriores(fingerprint)

        token = secrets.token_hex(32)
        criar_sessao(token, fingerprint)

        client_expires = 0 if expires == UNLIMITED_EXPIRY else expires

        payload = {
            "username": username,
            "fingerprint": fingerprint,
            "issued_at": now,
            "expires_at": client_expires
        }

        payload_bytes = json.dumps(payload, separators=(',', ':')).encode()
        sig = sign_payload(payload_bytes)

        assinatura_hmac = gerar_assinatura_hmac(client_expires, fingerprint)

        log_security("activate_success", fingerprint=fingerprint,
                     details={"username": username, "expires": client_expires})
        registrar_uso(fingerprint, "activate")

        return jsonify({
            "status": "success",
            "payload": base64.b64encode(payload_bytes).decode(),
            "sig": base64.b64encode(sig).decode(),
            "expires_at": client_expires,
            "session_token": token,
            "assinatura": assinatura_hmac,
            "server_time": now
        })

    except Exception as e:
        log_security("activate_error", details=str(e))
        return jsonify({"status": "error", "reason": "internal_error"}), 500

# ==========================================
#   VERIFICAÇÃO DE LICENÇA
# ==========================================

@app.route("/verify_license", methods=["POST"])
def verify_license():
    try:
        client_ip = request.remote_addr

        if not verify_limiter.is_allowed(client_ip):
            log_security("rate_limit_hit", ip=client_ip, details={"endpoint": "verify_license"})
            return jsonify({"valid": False, "reason": "rate_limit_exceeded"}), 429

        data = request.json or {}
        fingerprint = validate_fingerprint(data.get("fingerprint"))
        expires = data.get("expires")

        if not fingerprint or expires is None:
            log_security("verify_missing_fields", fingerprint=data.get("fingerprint"))
            return jsonify({"valid": False, "reason": "missing_fields"}), 400

        try:
            expires_int = int(expires)
        except (ValueError, TypeError):
            log_security("verify_invalid_expires", fingerprint=fingerprint,
                         details={"expires": expires})
            return jsonify({"valid": False, "reason": "invalid_expires_format"}), 400

        if not verificar_licenca_ativa(fingerprint, expires_int):
            log_security("license_not_found", fingerprint=fingerprint,
                         details={"expires": expires_int})
            return jsonify({"valid": False, "reason": "license_not_found"}), 404

        now = int(time.time())
        if expires_int != UNLIMITED_EXPIRY and expires_int < now:
            log_security("license_expired", fingerprint=fingerprint,
                         details={"expires": expires_int, "now": now})
            return jsonify({"valid": False, "reason": "license_expired"}), 403

        atualizar_uso_licenca(fingerprint, expires_int)
        registrar_uso(fingerprint, "license_verified")

        log_security("license_verified", fingerprint=fingerprint)

        return jsonify({
            "valid": True,
            "expires_at": expires_int,
            "is_unlimited": expires_int == UNLIMITED_EXPIRY,
            "server_time": now
        })

    except Exception as e:
        log_security("verify_error", details=str(e))
        return jsonify({"valid": False, "reason": "internal_error"}), 500

# ==========================================
#   VERIFICAÇÃO DE SESSÃO
# ==========================================

@app.route("/verify_session", methods=["GET"])
def verify_session():
    try:
        token = request.args.get("token")
        fp = validate_fingerprint(request.args.get("fp"))

        if not token or not fp:
            return jsonify({"valid": False, "reason": "missing_params"}), 400

        if verificar_sessao(token, fp):
            log_security("session_valid", fingerprint=fp)
            return jsonify({"valid": True, "server_time": int(time.time())})
        else:
            log_security("session_invalid", fingerprint=fp)
            return jsonify({"valid": False, "reason": "session_invalid_or_expired"})

    except Exception as e:
        log_security("session_error", details=str(e))
        return jsonify({"valid": False, "reason": "internal_error"}), 500

# ==========================================
#   ADMIN - AUTENTICAÇÃO
# ==========================================

def check_admin(a):
    ADMIN_USER = os.getenv("ADMIN_USER", "admin")
    ADMIN_PASS = os.getenv("ADMIN_PASS", "1234")
    return a and a.username == ADMIN_USER and a.password == ADMIN_PASS

def need_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.authorization
        if not check_admin(auth):
            return ("Unauthorized", 401, {"WWW-Authenticate": 'Basic realm="Login Required"'})
        return f(*args, **kwargs)
    return wrapper

# ==========================================
#   ADMIN - PAINEL
# ==========================================

@app.route("/admin")
@need_admin
def admin():
    data = load_users()

    with DBConnection() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM licenses WHERE status = 'active'")
        total_licenses = cursor.fetchone()[0]

        cursor.execute('''
            SELECT fingerprint, username, MAX(last_used) as last_used
            FROM licenses
            WHERE status = 'active'
            GROUP BY fingerprint
            ORDER BY last_used DESC
            LIMIT 10
        ''')
        recent_usage = cursor.fetchall()

    return render_template("admin_index.html",
                           users=data.get("users", []),
                           datetime=datetime,
                           total_licenses=total_licenses,
                           recent_usage=recent_usage)

# ==========================================
#   ADMIN - RELATÓRIO DE USO
# ==========================================

@app.route("/admin/usage_report")
@need_admin
def admin_usage_report():
    with DBConnection() as conn:
        cursor = conn.cursor()

        cursor.execute('''
            SELECT fingerprint, action, timestamp, ip_address, user_agent
            FROM license_usage
            ORDER BY timestamp DESC
            LIMIT 100
        ''')

        usage_data = []
        for row in cursor.fetchall():
            usage_data.append({
                "fingerprint": row[0],
                "action": row[1],
                "timestamp": datetime.fromtimestamp(row[2]).strftime("%Y-%m-%d %H:%M:%S"),
                "ip": row[3],
                "user_agent": row[4]
            })

    return render_template("usage_report.html", usage_data=usage_data)

# ==========================================
#   ADMIN - GERAR LICENÇA
# ==========================================

@app.route("/admin/generate", methods=["POST"])
@need_admin
def admin_generate():
    username = request.form.get("username")
    password = request.form.get("password")
    prefix = request.form.get("prefix") or "FERA"
    expire_days_raw = request.form.get("expire_days", "30")

    try:
        expire_days = int(expire_days_raw)
    except Exception:
        expire_days = 30

    if expire_days == 0:
        expires_at = UNLIMITED_EXPIRY
    else:
        expires_at = int(time.time()) + expire_days * 86400

    key = prefix + "-" + os.urandom(4).hex().upper()

    data = load_users()
    users = data.get("users", [])

    for u in users:
        if u.get("username") == username:
            u["password"] = password
            u["key"] = key
            u["expires_at"] = expires_at
            save_users(data)

            log_security("admin_user_updated", details={"username": username, "expires_at": expires_at})
            return ("", 302, {"Location": "/admin"})

    users.append({
        "username": username,
        "password": password,
        "key": key,
        "device_id": None,
        "expires_at": expires_at,
        "created_at": int(time.time())
    })

    save_users(data)
    log_security("admin_user_created", details={"username": username, "expires_at": expires_at})
    return ("", 302, {"Location": "/admin"})

# ==========================================
#   ADMIN - VISUALIZAR BANCO
# ==========================================

@app.route("/admin/database")
@need_admin
def admin_database():
    with DBConnection() as conn:
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM licenses ORDER BY last_used DESC')

        licenses_db = []
        for row in cursor.fetchall():
            licenses_db.append({
                "id": row[0],
                "fingerprint": row[1],
                "username": row[2],
                "issued_at": datetime.fromtimestamp(row[3]).strftime("%Y-%m-%d %H:%M:%S") if row[3] else "N/A",
                "expires_at": "ILIMITADO" if row[4] == UNLIMITED_EXPIRY else datetime.fromtimestamp(row[4]).strftime("%Y-%m-%d %H:%M:%S"),
                "status": row[5],
                "last_used": datetime.fromtimestamp(row[6]).strftime("%Y-%m-%d %H:%M:%S") if row[6] else "NUNCA"
            })

    return render_template("database_view.html", licenses=licenses_db)

# ==========================================
#   ADMIN - RENOVAR +30 DIAS
# ==========================================

@app.route("/admin/renew/<int:index>", methods=["POST", "GET"])
@need_admin
def admin_renew(index):
    data = load_users()
    users = data.get("users", [])

    if 0 <= index < len(users):
        now = int(time.time())
        current = users[index].get("expires_at", 0)
        add_days = 30

        if current == UNLIMITED_EXPIRY:
            users[index]["expires_at"] = UNLIMITED_EXPIRY
        else:
            if current < now:
                new_exp = now + add_days * 86400
            else:
                new_exp = current + add_days * 86400
            users[index]["expires_at"] = new_exp

        save_users(data)

        fingerprint = users[index].get("device_id")
        if fingerprint:
            with DBConnection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE licenses SET expires_at = ?, status = 'active'
                    WHERE fingerprint = ?
                ''', (users[index]["expires_at"], fingerprint))

        log_security("admin_renewed", details={"username": users[index]["username"], "new_expires": users[index]["expires_at"]})

    return ("", 302, {"Location": "/admin"})

# ==========================================
#   ADMIN - RENOVAR CUSTOM
# ==========================================

@app.route("/admin/renew_custom/<int:index>", methods=["POST", "GET"])
@need_admin
def admin_renew_custom(index):
    days_raw = None
    if request.method == "POST":
        days_raw = request.form.get("days", "30")
    else:
        days_raw = request.args.get("days", "30")

    try:
        days = int(days_raw)
    except Exception:
        days = 30

    data = load_users()
    users = data.get("users", [])

    if 0 <= index < len(users):
        now = int(time.time())
        current = users[index].get("expires_at", 0)

        if days == 0:
            users[index]["expires_at"] = UNLIMITED_EXPIRY
        else:
            if current == UNLIMITED_EXPIRY:
                new_exp = now + days * 86400
            else:
                if current < now:
                    new_exp = now + days * 86400
                else:
                    new_exp = current + days * 86400
            users[index]["expires_at"] = new_exp

        save_users(data)

        fingerprint = users[index].get("device_id")
        if fingerprint:
            with DBConnection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE licenses SET expires_at = ?, status = 'active'
                    WHERE fingerprint = ?
                ''', (users[index]["expires_at"], fingerprint))

        log_security("admin_renewed_custom", details={"username": users[index]["username"], "days": days, "new_expires": users[index]["expires_at"]})

    return ("", 302, {"Location": "/admin"})

# ==========================================
#   ADMIN - RESETAR KEY
# ==========================================

@app.route("/admin/reset/<int:index>", methods=["POST", "GET"])
@need_admin
def admin_reset(index):
    data = load_users()
    users = data.get("users", [])

    if 0 <= index < len(users):
        old_key = users[index].get("key", "FERA-XXXX")
        prefix = old_key.split("-")[0]
        new_key = f"{prefix}-{os.urandom(4).hex().upper()}"
        users[index]["key"] = new_key
        save_users(data)

        log_security("admin_key_reset", details={"username": users[index]["username"], "new_key": new_key})

    return ("", 302, {"Location": "/admin"})

# ==========================================
#   ADMIN - RESETAR DEVICE
# ==========================================

@app.route("/admin/reset_device/<int:index>", methods=["POST", "GET"])
@need_admin
def admin_reset_device(index):
    data = load_users()
    users = data.get("users", [])

    if 0 <= index < len(users):
        users[index]["device_id"] = None
        save_users(data)

        log_security("admin_device_reset", details={"username": users[index]["username"]})

    return ("", 302, {"Location": "/admin"})

# ==========================================
#   ADMIN - RESETAR TODOS OS DEVICES
# ==========================================

@app.route("/admin/reset_all_devices", methods=["POST"])
@need_admin
def admin_reset_all_devices():
    data = load_users()
    users = data.get("users", [])

    for user in users:
        user["device_id"] = None

    save_users(data)

    log_security("admin_reset_all_devices", details={"count": len(users)})
    return ("", 302, {"Location": "/admin"})

# ==========================================
#   ADMIN - LIMPAR EXPIRADOS
# ==========================================

@app.route("/admin/clean_expired", methods=["POST"])
@need_admin
def admin_clean_expired():
    data = load_users()
    users = data.get("users", [])
    now = int(time.time())

    filtered_users = []
    expired_fingerprints = []

    for user in users:
        expires_at = user.get("expires_at", 0)

        if expires_at == UNLIMITED_EXPIRY:
            filtered_users.append(user)
        elif expires_at > now:
            filtered_users.append(user)
        else:
            if user.get("device_id"):
                expired_fingerprints.append(user["device_id"])

    data["users"] = filtered_users
    save_users(data)

    if expired_fingerprints:
        with DBConnection() as conn:
            cursor = conn.cursor()
            placeholders = ','.join(['?' for _ in expired_fingerprints])
            cursor.execute(
                f'UPDATE licenses SET status = "expired" WHERE fingerprint IN ({placeholders})',
                expired_fingerprints
            )

    log_security("admin_clean_expired", details={"removed_count": len(users) - len(filtered_users)})
    return ("", 302, {"Location": "/admin"})

# ==========================================
#   ADMIN - TORNAR ILIMITADA
# ==========================================

@app.route("/admin/make_unlimited/<int:index>", methods=["POST"])
@need_admin
def admin_make_unlimited(index):
    data = load_users()
    users = data.get("users", [])

    if 0 <= index < len(users):
        users[index]["expires_at"] = UNLIMITED_EXPIRY
        save_users(data)

        fingerprint = users[index].get("device_id")
        if fingerprint:
            with DBConnection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE licenses SET expires_at = ?
                    WHERE fingerprint = ?
                ''', (UNLIMITED_EXPIRY, fingerprint))

        log_security("admin_make_unlimited", details={"username": users[index]["username"]})

    return ("", 302, {"Location": "/admin"})

# ==========================================
#   ADMIN - DELETAR USUÁRIO
# ==========================================

@app.route("/admin/delete/<int:index>", methods=["POST", "GET"])
@need_admin
def admin_delete(index):
    data = load_users()
    users = data.get("users", [])

    if 0 <= index < len(users):
        deleted_user = users.pop(index)
        save_users(data)

        fingerprint = deleted_user.get("device_id")
        if fingerprint:
            with DBConnection() as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM licenses WHERE fingerprint = ?', (fingerprint,))
                cursor.execute('DELETE FROM sessions WHERE fingerprint = ?', (fingerprint,))

        log_security("admin_delete_user", details={"username": deleted_user.get("username")})

    return ("", 302, {"Location": "/admin"})

# ==========================================
#   REVENDEDORES
# ==========================================

def carregar_revendedores():
    revendedores = {}

    for chave, valor in os.environ.items():
        if chave.startswith('RESELLER_') and chave != 'RESELLER_TOKEN':
            nome = chave[9:]
            token = valor.strip()
            if token:
                revendedores[token] = nome

    token_legado = os.getenv('RESELLER_TOKEN')
    if token_legado:
        for parte in token_legado.split(','):
            parte = parte.strip()
            if '|' in parte:
                nome, token = parte.split('|', 1)
                revendedores[token.strip()] = nome.strip()
            else:
                revendedores[parte] = parte

    return revendedores

RESELLER_MAP = carregar_revendedores()

@app.route("/reseller/generate", methods=["POST"])
def reseller_generate():
    token = request.form.get("token")
    username = request.form.get("username")
    password = request.form.get("password")
    prefix = request.form.get("prefix") or "FERA"
    expire_days_raw = request.form.get("expire_days", "30")

    try:
        expire_days = int(expire_days_raw)
    except Exception:
        expire_days = 30

    if token not in RESELLER_MAP:
        log_security("reseller_invalid_token", details={"token": token})
        return jsonify({"error": "invalid_token"}), 403

    reseller_nome = RESELLER_MAP[token]

    if not username or not password:
        return jsonify({"error": "missing_fields"}), 400

    if expire_days == 0:
        expires_at = UNLIMITED_EXPIRY
    else:
        expires_at = int(time.time()) + expire_days * 86400

    key = prefix + "-" + os.urandom(4).hex().upper()

    data = load_users()
    users = data.get("users", [])

    for u in users:
        if u.get("username") == username:
            u["password"] = password
            u["key"] = key
            u["expires_at"] = expires_at
            u["reseller"] = reseller_nome
            save_users(data)

            log_security("reseller_updated", details={"username": username, "reseller": reseller_nome})
            return jsonify({
                "ok": True,
                "key": key,
                "username": username,
                "expires_at": expires_at
            })

    users.append({
        "username": username,
        "password": password,
        "key": key,
        "device_id": None,
        "expires_at": expires_at,
        "reseller": reseller_nome,
        "created_at": int(time.time())
    })

    save_users(data)

    log_security("reseller_created", details={"username": username, "expires_at": expires_at, "reseller": reseller_nome})
    return jsonify({
        "ok": True,
        "key": key,
        "username": username,
        "expires_at": expires_at
    })

# ==========================================
#   ADMIN - ESTATÍSTICAS REVENDEDOR
# ==========================================

@app.route("/admin/reseller_stats")
@need_admin
def admin_reseller_stats():
    reseller_filter = request.args.get("reseller", "")
    days = request.args.get("days", "7")
    try:
        days = int(days)
    except Exception:
        days = 7

    since = int(time.time()) - (days * 86400)

    data = load_users()
    users = data.get("users", [])

    revendedores = set()
    for u in users:
        if u.get("reseller"):
            revendedores.add(u["reseller"])
    revendedores = sorted(revendedores)

    total_usuarios_criados = 0
    total_ativacoes = 0
    stats = []
    chart_data = {}
    usuarios_lista = []

    if reseller_filter:
        usuarios_rev = [u for u in users if u.get("reseller") == reseller_filter]
        total_usuarios_criados = len(usuarios_rev)

        now_ts = int(time.time())
        for u in usuarios_rev:
            created = u.get("created_at")
            expires = u.get("expires_at")
            status = u.get("status", "active")
            dias_desde_criacao = (now_ts - created) // 86400 if created else None
            data_criacao = datetime.fromtimestamp(created).strftime("%d/%m/%Y %H:%M") if created else "—"
            if expires == UNLIMITED_EXPIRY:
                expiracao_str = "Ilimitado"
            elif expires:
                expiracao_str = datetime.fromtimestamp(expires).strftime("%d/%m/%Y %H:%M")
            else:
                expiracao_str = "—"
            if status == "blocked":
                status_str = "Bloqueado"
            elif expires and expires < now_ts and expires != UNLIMITED_EXPIRY:
                status_str = "Expirado"
            else:
                status_str = "Ativo"

            usuarios_lista.append({
                "username": u["username"],
                "data_criacao": data_criacao,
                "dias_desde_criacao": dias_desde_criacao,
                "expiracao": expiracao_str,
                "status": status_str,
                "device_id": u.get("device_id", "—")
            })

        fingerprints = [u["device_id"] for u in usuarios_rev if u.get("device_id")]

        if fingerprints:
            with DBConnection() as conn:
                cursor = conn.cursor()
                placeholders = ','.join(['?' for _ in fingerprints])

                cursor.execute(f'''
                    SELECT COUNT(*) as total
                    FROM license_usage
                    WHERE fingerprint IN ({placeholders}) AND timestamp >= ? AND action = 'activate'
                ''', fingerprints + [since])
                row = cursor.fetchone()
                if row:
                    total_ativacoes = row[0]

                cursor.execute(f'''
                    SELECT DATE(timestamp, 'unixepoch') as dia, COUNT(*) as total
                    FROM license_usage
                    WHERE fingerprint IN ({placeholders}) AND timestamp >= ? AND action = 'activate'
                    GROUP BY dia
                    ORDER BY dia ASC
                ''', fingerprints + [since])
                for row in cursor.fetchall():
                    chart_data[row[0]] = row[1]

                cursor.execute(f'''
                    SELECT fingerprint, action, timestamp, ip_address
                    FROM license_usage
                    WHERE fingerprint IN ({placeholders}) AND timestamp >= ? AND action = 'activate'
                    ORDER BY timestamp DESC
                    LIMIT 50
                ''', fingerprints + [since])
                recent = cursor.fetchall()
                for r in recent:
                    stats.append({
                        "fingerprint": r[0],
                        "action": r[1],
                        "timestamp": datetime.fromtimestamp(r[2]).strftime("%Y-%m-%d %H:%M:%S"),
                        "ip": r[3]
                    })

    return render_template("reseller_stats.html",
                           revendedores=revendedores,
                           selected=reseller_filter,
                           days=days,
                           total_usuarios_criados=total_usuarios_criados,
                           total_ativacoes=total_ativacoes,
                           stats=stats,
                           chart_data=chart_data,
                           usuarios_lista=usuarios_lista)

# ==========================================
#   RUN
# ==========================================

if __name__ == "__main__":
    limpar_sessoes_expiradas()
    log_security("server_started", details={"timestamp": datetime.now().isoformat()})
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 10000)), debug=False)
