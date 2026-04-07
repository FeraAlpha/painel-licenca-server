from flask import Flask, request, jsonify, render_template, redirect, url_for
import json, os, time, base64, sqlite3, requests, hashlib, hmac, threading, atexit
import jwt
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from datetime import datetime, timedelta, timezone
from functools import wraps
from collections import defaultdict
from logging.handlers import RotatingFileHandler
import logging

# Configurações de banco e arquivos
DB = "data/licenses.db"
USERS_FILE = "data/users.json"
KEY_PRIV = "private.pem"
KEY_PUB = "public.pem"
SECURITY_LOG_FILE = "data/security.log"

# Constante para licença ilimitada
UNLIMITED_EXPIRY = 9999999999999

# Chave secreta para HMAC (DEVE SER IGUAL À DO CLIENTE)
CHAVE_SECRETA = "FER4_4LPH4_2024_S3CR3T_K3Y_N0T_SH4R3D"

# Configuração JWT
JWT_SECRET = os.getenv("JWT_SECRET", "fer4_jwt_s3cr3t_k3y_ch4ng3_m3")
JWT_ALGORITHM = "RS256"
JWT_EXPIRY_HOURS = 24

# ------------------------------
#   CONFIGURAÇÃO DE LOG COM ROTAÇÃO
# ------------------------------
os.makedirs("data", exist_ok=True)

security_logger = logging.getLogger('security')
security_logger.setLevel(logging.INFO)

handler = RotatingFileHandler(
    SECURITY_LOG_FILE,
    maxBytes=5 * 1024 * 1024,  # 5 MB
    backupCount=3,
    encoding='utf-8'
)
formatter = logging.Formatter('%(asctime)s - %(message)s')
handler.setFormatter(formatter)
security_logger.addHandler(handler)

def log_security(event_type, fingerprint=None, ip=None, details=None, severity="INFO"):
    """Registra eventos de segurança com rotação automática"""
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ip = ip or (request.remote_addr if 'request' in globals() else "N/A")
        user_agent = request.user_agent.string if 'request' in globals() and request.user_agent else "N/A"
        
        log_entry = {
            "timestamp": timestamp,
            "severity": severity,
            "event": event_type,
            "fingerprint": fingerprint,
            "ip": ip,
            "user_agent": user_agent,
            "details": details or {}
        }
        
        security_logger.info(json.dumps(log_entry, ensure_ascii=False))
        
        if severity in ["CRITICAL", "ERROR", "WARNING"]:
            print(f"[{severity}] {event_type}: {details}")
    except Exception as e:
        print(f"Erro ao logar segurança: {e}")

# ------------------------------
#   GERENCIAMENTO AUTOMÁTICO DE CHAVES RSA
# ------------------------------
def ensure_rsa_keys():
    """Gera as chaves RSA se não existirem"""
    if not os.path.exists(KEY_PRIV) or not os.path.exists(KEY_PUB):
        log_security("rsa_keys_generating", details={"reason": "keys_not_found"})
        try:
            key = RSA.generate(2048)
            private_key = key.export_key()
            public_key = key.publickey().export_key()
            
            with open(KEY_PRIV, "wb") as f:
                f.write(private_key)
            with open(KEY_PUB, "wb") as f:
                f.write(public_key)
            
            log_security("rsa_keys_generated", severity="INFO")
            print("✅ Chaves RSA geradas automaticamente")
        except Exception as e:
            log_security("rsa_keys_generation_error", details=str(e), severity="ERROR")
            raise

# Chamar a função imediatamente para garantir que as chaves existam
ensure_rsa_keys()

# ------------------------------
#   SANITIZAÇÃO DE INPUTS
# ------------------------------
def sanitize_input(value, max_length=100, allowed_chars=None):
    """Sanitiza uma string de entrada, limitando tamanho e removendo caracteres perigosos"""
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    value = value.strip()[:max_length]
    if allowed_chars:
        import re
        pattern = f"[^{re.escape(allowed_chars)}]"
        value = re.sub(pattern, "", value)
    return value

# ------------------------------
#   FUNÇÃO AUXILIAR: converter tempo de expiração (CORRIGIDA COM MINUTOS)
# ------------------------------
def calcular_timestamp_expira(expire_days=None, expire_hours=None, expire_minutes=None, expire_seconds=None, agora=None):
    """
    Calcula o timestamp de expiração baseado nos parâmetros.
    PRIORIDADE: seconds > minutes > hours > days
    """
    if agora is None:
        agora = int(time.time())
    
    total_seconds = 0
    
    if expire_seconds is not None and expire_seconds != "":
        try:
            total_seconds = int(expire_seconds)
        except:
            total_seconds = 0
    elif expire_minutes is not None and expire_minutes != "":
        try:
            total_seconds = int(float(expire_minutes) * 60)
        except:
            total_seconds = 0
    elif expire_hours is not None and expire_hours != "":
        try:
            total_seconds = int(float(expire_hours) * 3600)
        except:
            total_seconds = 0
    elif expire_days is not None and expire_days != "":
        try:
            total_seconds = int(float(expire_days) * 86400)
        except:
            total_seconds = 0
    
    if total_seconds == 0:
        return UNLIMITED_EXPIRY
    else:
        return agora + total_seconds

# ------------------------------
#   RATE LIMITING EM MEMÓRIA
# ------------------------------
RATE_LIMIT = {
    'activate': {'limit': 5, 'window': 300},
    'verify_license': {'limit': 10, 'window': 300},
    'validate_token': {'limit': 20, 'window': 300},
}

request_counts = defaultdict(list)

def check_rate_limit(endpoint, ip):
    now = time.time()
    window = RATE_LIMIT.get(endpoint, {}).get('window', 300)
    limit = RATE_LIMIT.get(endpoint, {}).get('limit', 10)
    
    request_counts[ip] = [t for t in request_counts[ip] if t > now - window]
    
    if len(request_counts[ip]) >= limit:
        return False
    request_counts[ip].append(now)
    return True

# ------------------------------
#   LIMPEZA AUTOMÁTICA DO BANCO
# ------------------------------
class DatabaseCleaner:
    def __init__(self, interval_seconds=86400):
        self.interval = interval_seconds
        self.timer = None
        self.running = False
        
    def start(self):
        self.running = True
        self._schedule()
        log_security("db_cleaner_started", details={"interval": self.interval}, severity="INFO")
        
    def stop(self):
        self.running = False
        if self.timer:
            self.timer.cancel()
        log_security("db_cleaner_stopped", severity="INFO")
        
    def _schedule(self):
        if self.running:
            self.timer = threading.Timer(self.interval, self.clean)
            self.timer.daemon = True
            self.timer.start()
            
    def clean(self):
        try:
            conn = get_db()
            cursor = conn.cursor()
            now = int(time.time())
            
            cursor.execute('DELETE FROM sessions WHERE expires_at < ?', (now,))
            deleted_sessions = cursor.rowcount
            
            thirty_days_ago = now - (30 * 86400)
            cursor.execute('DELETE FROM revoked_tokens WHERE revoked_at < ?', (thirty_days_ago,))
            deleted_revoked = cursor.rowcount
            
            ninety_days_ago = now - (90 * 86400)
            cursor.execute('DELETE FROM license_usage WHERE timestamp < ?', (ninety_days_ago,))
            deleted_usage = cursor.rowcount
            
            conn.commit()
            conn.close()
            
            log_security("db_cleanup_executed", details={
                "deleted_sessions": deleted_sessions,
                "deleted_revoked_tokens": deleted_revoked,
                "deleted_usage_logs": deleted_usage
            }, severity="INFO")
            
            print(f"🧹 Limpeza DB: {deleted_sessions} sessões, {deleted_revoked} tokens revogados, {deleted_usage} logs removidos")
        except Exception as e:
            log_security("db_cleanup_error", details=str(e), severity="ERROR")
        finally:
            self._schedule()
    
    def clean_once(self):
        self.clean()

# ------------------------------
#   CONFIG GITHUB
# ------------------------------
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_REPO = "FeraAlpha/painel-licenca-server"
GITHUB_FILE_PATH = "data/users.json"
GITHUB_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_FILE_PATH}"

os.makedirs("data", exist_ok=True)
os.makedirs("data/backups", exist_ok=True)

# ------------------------------
#   FUNÇÕES JWT
# ------------------------------
def gerar_token_jwt(fingerprint, username, expires_at):
    now = datetime.now(timezone.utc)
    
    if not os.path.exists(KEY_PRIV):
        log_security("jwt_private_key_missing", details={"error": f"Arquivo {KEY_PRIV} não encontrado"})
        return gerar_token_jwt_fallback(fingerprint, username, expires_at)
    
    try:
        with open(KEY_PRIV, "rb") as f:
            private_key = RSA.import_key(f.read())
        
        payload = {
            "fp": fingerprint,
            "user": username,
            "exp": now + timedelta(hours=JWT_EXPIRY_HOURS),
            "iat": now,
            "lic_exp": expires_at
        }
        
        token = jwt.encode(payload, private_key, algorithm="RS256")
        return token
        
    except (ValueError, TypeError) as e:
        log_security("jwt_private_key_invalid", details={"error": str(e)})
        return gerar_token_jwt_fallback(fingerprint, username, expires_at)
    except Exception as e:
        log_security("jwt_generation_error", details={"error": str(e)})
        return gerar_token_jwt_fallback(fingerprint, username, expires_at)

def gerar_token_jwt_fallback(fingerprint, username, expires_at):
    now = datetime.now(timezone.utc)
    payload = {
        "fp": fingerprint,
        "user": username,
        "exp": now + timedelta(hours=JWT_EXPIRY_HOURS),
        "iat": now,
        "lic_exp": expires_at,
        "alg_fallback": "HS256"
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def validar_token_jwt(token):
    try:
        if os.path.exists(KEY_PUB):
            try:
                with open(KEY_PUB, "rb") as f:
                    public_key = RSA.import_key(f.read())
                payload = jwt.decode(
                    token, 
                    public_key, 
                    algorithms=["RS256"],
                    options={"require": ["exp", "iat", "fp", "user"]}
                )
                return {"valid": True, "payload": payload}
            except:
                pass
        
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"],
            options={"require": ["exp", "iat", "fp", "user"]}
        )
        return {"valid": True, "payload": payload}
        
    except jwt.ExpiredSignatureError:
        return {"valid": False, "reason": "token_expired"}
    except jwt.InvalidTokenError as e:
        return {"valid": False, "reason": f"invalid_token: {str(e)}"}
    except Exception as e:
        return {"valid": False, "reason": f"validation_error: {str(e)}"}

# ------------------------------
#   BANCO SQL
# ------------------------------
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
                  UNIQUE(token, fingerprint))''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS license_usage
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  fingerprint TEXT,
                  action TEXT,
                  timestamp INTEGER,
                  ip_address TEXT,
                  user_agent TEXT)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS revoked_tokens
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  token TEXT UNIQUE,
                  fingerprint TEXT,
                  revoked_at INTEGER,
                  reason TEXT)''')
    
    c.execute('CREATE INDEX IF NOT EXISTS idx_fingerprint ON licenses(fingerprint)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_sessions ON sessions(token, fingerprint)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_license_status ON licenses(status, expires_at)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_revoked_tokens ON revoked_tokens(token)')
    
    conn.commit()
    conn.close()

init_db()

# ------------------------------
#   FUNÇÕES DO BANCO
# ------------------------------
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def verificar_licenca_ativa(fingerprint, expires):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM licenses 
        WHERE fingerprint = ? AND expires_at = ? AND status = 'active'
    ''', (fingerprint, expires))
    licenca = cursor.fetchone()
    conn.close()
    return licenca is not None

def atualizar_uso_licenca(fingerprint, expires):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE licenses SET last_used = ?
        WHERE fingerprint = ? AND expires_at = ?
    ''', (int(time.time()), fingerprint, expires))
    conn.commit()
    conn.close()

def registrar_uso(fingerprint, action, ip=None, user_agent=None):
    conn = get_db()
    cursor = conn.cursor()
    ip = ip or (request.remote_addr if 'request' in globals() else "N/A")
    user_agent = user_agent or (request.user_agent.string if 'request' in globals() and request.user_agent else "N/A")
    cursor.execute('''
        INSERT INTO license_usage (fingerprint, action, timestamp, ip_address, user_agent)
        VALUES (?, ?, ?, ?, ?)
    ''', (fingerprint, action, int(time.time()), ip, user_agent))
    conn.commit()
    conn.close()

def criar_sessao(token, fingerprint):
    conn = get_db()
    cursor = conn.cursor()
    expires_at = int(time.time()) + (24 * 60 * 60)
    cursor.execute('''
        INSERT OR REPLACE INTO sessions (token, fingerprint, expires_at, created_at, last_used)
        VALUES (?, ?, ?, ?, ?)
    ''', (token, fingerprint, expires_at, int(time.time()), int(time.time())))
    conn.commit()
    conn.close()

def verificar_sessao(token, fingerprint):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM sessions 
        WHERE token = ? AND fingerprint = ? AND expires_at > ?
    ''', (token, fingerprint, int(time.time())))
    sessao = cursor.fetchone()
    if sessao:
        cursor.execute('''
            UPDATE sessions SET last_used = ? 
            WHERE token = ? AND fingerprint = ?
        ''', (int(time.time()), token, fingerprint))
        conn.commit()
    conn.close()
    return sessao is not None

def revogar_token(token, fingerprint=None, reason="admin_revoked"):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR IGNORE INTO revoked_tokens (token, fingerprint, revoked_at, reason)
        VALUES (?, ?, ?, ?)
    ''', (token, fingerprint, int(time.time()), reason))
    conn.commit()
    conn.close()

def token_esta_revogado(token):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM revoked_tokens WHERE token = ?', (token,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

# ------------------------------
#   WRITE ATÔMICO
# ------------------------------
def atomic_write(path, data_bytes):
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data_bytes)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

# ------------------------------
#   LOAD USERS
# ------------------------------
def load_users():
    try:
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                users = data.get("users", [])
                for user in users:
                    if user.get("expires_at") == 0:
                        user["expires_at"] = UNLIMITED_EXPIRY
                    if "status" not in user:
                        user["status"] = "active"
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
                    if "status" not in user:
                        user["status"] = "active"
                atomic_write(USERS_FILE, json.dumps(data, indent=2).encode())
                return data
        except Exception as e:
            log_security("github_sync_error", details=str(e))

    return {"users": []}

# ------------------------------
#   SAVE USERS
# ------------------------------
def save_users_github(data, retries=3):
    if not GITHUB_TOKEN:
        return False
    sha = None
    try:
        r = requests.get(GITHUB_API_URL, headers={
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json"
        })
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
                json=payload
            )
            if res.status_code in (200, 201):
                return True
        except Exception as e:
            log_security("github_upload_error", details=str(e))
            time.sleep(1)
    return False

def save_users(data):
    try:
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        atomic_write(f"data/backups/users.{ts}.json", json.dumps(data, indent=2).encode())
        atomic_write(USERS_FILE, json.dumps(data, indent=2).encode())
        try:
            save_users_github(data)
        except Exception as e:
            log_security("save_users_error", details=str(e))
        return True
    except Exception as e:
        log_security("save_users_critical_error", details=str(e))
        print(f"ERRO CRÍTICO AO SALVAR USERS: {str(e)}")
        return False

# ------------------------------
#   ASSINATURA
# ------------------------------
def sign_payload(payload_bytes):
    try:
        with open(KEY_PRIV, "rb") as f:
            priv = RSA.import_key(f.read())
        h = SHA256.new(payload_bytes)
        sig = pkcs1_15.new(priv).sign(h)
        return sig
    except Exception as e:
        log_security("sign_payload_error", details=str(e))
        return None

def gerar_assinatura_hmac(expires, fingerprint):
    dados = f"{expires}:{fingerprint}"
    assinatura = hmac.new(
        CHAVE_SECRETA.encode(),
        dados.encode(),
        hashlib.sha256
    ).hexdigest()
    return assinatura

# ------------------------------
#   FLASK APP
# ------------------------------
app = Flask(__name__, template_folder='templates')

# ------------------------------
#   MIDDLEWARE DE SEGURANÇA
# ------------------------------
@app.before_request
def before_request():
    if request.endpoint in RATE_LIMIT:
        if not check_rate_limit(request.endpoint, request.remote_addr):
            return jsonify({"error": "rate_limited", "message": "Too many requests. Try again later."}), 429
    
    if request.endpoint not in ['home', 'ping']:
        log_security(
            "api_request",
            ip=request.remote_addr,
            details={
                "endpoint": request.endpoint,
                "method": request.method,
                "path": request.path,
                "user_agent": request.user_agent.string if request.user_agent else None
            }
        )

# ------------------------------
#   ROTAS PÚBLICAS
# ------------------------------
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

# ------------------------------
#   VERIFICAÇÃO DE LICENÇA
# ------------------------------
@app.route("/verify_license", methods=["POST"])
def verify_license():
    try:
        data = request.json or {}
        fingerprint = sanitize_input(data.get("fingerprint"))
        expires = data.get("expires")
        
        if not fingerprint or not expires:
            log_security("verify_missing_fields", fingerprint=fingerprint)
            return jsonify({"valid": False, "reason": "missing_fields"}), 400
        
        try:
            expires_int = int(expires)
        except ValueError:
            log_security("verify_invalid_expires", fingerprint=fingerprint, details={"expires": expires})
            return jsonify({"valid": False, "reason": "invalid_expires_format"}), 400
        
        if not verificar_licenca_ativa(fingerprint, expires_int):
            log_security("license_not_found", fingerprint=fingerprint, details={"expires": expires_int})
            return jsonify({"valid": False, "reason": "license_not_found"}), 404
        
        now = int(time.time())
        if expires_int != UNLIMITED_EXPIRY and expires_int < now:
            log_security("license_expired", fingerprint=fingerprint, details={"expires": expires_int, "now": now})
            return jsonify({"valid": False, "reason": "license_expired"}), 403
        
        atualizar_uso_licenca(fingerprint, expires_int)
        registrar_uso(fingerprint, "license_verified")
        
        log_security("license_verified", fingerprint=fingerprint)
        
        return jsonify({
            "valid": True,
            "expires_at": expires_int,
            "is_unlimited": expires_int == UNLIMITED_EXPIRY
        })
        
    except Exception as e:
        log_security("verify_error", details=str(e))
        return jsonify({"valid": False, "reason": "internal_error"}), 500

# ------------------------------
#   VERIFICAÇÃO DE SESSÃO
# ------------------------------
@app.route("/verify_session", methods=["GET"])
def verify_session():
    try:
        token = sanitize_input(request.args.get("token"))
        fp = sanitize_input(request.args.get("fp"))
        
        if not token or not fp:
            return jsonify({"valid": False, "reason": "missing_params"}), 400
        
        if verificar_sessao(token, fp):
            log_security("session_valid", fingerprint=fp)
            return jsonify({"valid": True})
        else:
            log_security("session_invalid", fingerprint=fp)
            return jsonify({"valid": False, "reason": "session_invalid_or_expired"})
            
    except Exception as e:
        log_security("session_error", details=str(e))
        return jsonify({"valid": False, "reason": "internal_error"}), 500

# ------------------------------
#   VALIDAÇÃO DE TOKEN JWT
# ------------------------------
@app.route("/token/validate", methods=["POST"])
def validate_token():
    try:
        data = request.json or {}
        token = sanitize_input(data.get("token"))
        fingerprint = sanitize_input(data.get("fingerprint"))
        
        if not token:
            log_security("token_missing", ip=request.remote_addr)
            return jsonify({"valid": False, "reason": "token_required"}), 400
        
        if token_esta_revogado(token):
            log_security("token_revoked", ip=request.remote_addr)
            return jsonify({"valid": False, "reason": "token_revoked"}), 403
        
        result = validar_token_jwt(token)
        
        if not result["valid"]:
            log_security("token_invalid", 
                        ip=request.remote_addr, 
                        details={"reason": result["reason"]})
            return jsonify({"valid": False, "reason": result["reason"]}), 401
        
        payload = result["payload"]
        
        if fingerprint and payload.get("fp") != fingerprint:
            log_security("token_fingerprint_mismatch",
                        fingerprint=fingerprint,
                        details={"token_fp": payload.get("fp")})
            return jsonify({"valid": False, "reason": "fingerprint_mismatch"}), 403
        
        fp = payload.get("fp")
        if fp:
            licenca_valida = verificar_licenca_ativa(fp, payload.get("lic_exp", 0))
            if not licenca_valida:
                log_security("token_license_inactive", fingerprint=fp)
                return jsonify({"valid": False, "reason": "license_inactive"}), 403
        
        log_security("token_validated", fingerprint=payload.get("fp"))
        
        return jsonify({
            "valid": True,
            "payload": {
                "fingerprint": payload.get("fp"),
                "username": payload.get("user"),
                "license_expires": payload.get("lic_exp")
            }
        })
        
    except Exception as e:
        log_security("token_validation_error", details=str(e))
        return jsonify({"valid": False, "reason": "internal_error"}), 500

# ------------------------------
#   CLIENTE - ATIVAÇÃO
# ------------------------------
@app.route("/activate", methods=["POST"])
def activate():
    try:
        data = request.json or {}
        username = sanitize_input(data.get("username"))
        password = sanitize_input(data.get("password"))
        fingerprint = sanitize_input(data.get("fingerprint"))
        
        if not username or not password or not fingerprint:
            log_security("activate_missing_fields", details={"username": username})
            return jsonify({"error": "missing_fields"}), 400

        users = load_users().get("users", [])
        user = next((u for u in users if u["username"] == username and u["password"] == password), None)

        if not user:
            log_security("activate_invalid_credentials", fingerprint=fingerprint, details={"username": username})
            return jsonify({"status": "error", "reason": "invalid_credentials"}), 403

        # Verificar se o usuário está bloqueado
        if user.get("status") == "blocked":
            log_security("activate_blocked_user", fingerprint=fingerprint, details={"username": username})
            return jsonify({"status": "error", "reason": "user_blocked"}), 403

        now = int(time.time())
        expires = user.get("expires_at", 0)
        
        if expires == UNLIMITED_EXPIRY:
            pass
        elif expires < now:
            log_security("activate_expired", fingerprint=fingerprint, details={"username": username, "expires": expires})
            return jsonify({"status": "error", "reason": "expired"}), 403

        device_id = user.get("device_id")
        
        if device_id is None:
            user["device_id"] = fingerprint
            save_users({"users": users})
            log_security("device_activated", fingerprint=fingerprint, details={"username": username})
        elif device_id != fingerprint:
            log_security("activate_device_mismatch", fingerprint=fingerprint, 
                        details={"username": username, "stored_device": device_id})
            return jsonify({"status": "error", "reason": "device_mismatch"}), 403

        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM licenses WHERE fingerprint = ?', (fingerprint,))
        existing = cursor.fetchone()
        
        if not existing:
            cursor.execute('''
                INSERT INTO licenses (fingerprint, username, issued_at, expires_at, status, last_used)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (fingerprint, username, now, expires, 'active', now))
        else:
            cursor.execute('''
                UPDATE licenses 
                SET expires_at = ?, status = 'active', last_used = ?
                WHERE fingerprint = ?
            ''', (expires, now, fingerprint))
        
        conn.commit()
        conn.close()
        
        token = hashlib.sha256(f"{fingerprint}:{now}:{os.urandom(16).hex()}".encode()).hexdigest()
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
        
        try:
            jwt_token = gerar_token_jwt(fingerprint, username, expires)
        except Exception as jwt_error:
            log_security("jwt_generation_critical", details={"error": str(jwt_error)})
            jwt_token = None
        
        log_security("activate_success", fingerprint=fingerprint, details={"username": username, "expires": client_expires})
        registrar_uso(fingerprint, "activate")

        return jsonify({
            "status": "success",
            "payload": base64.b64encode(payload_bytes).decode() if payload_bytes else None,
            "sig": base64.b64encode(sig).decode() if sig else None,
            "expires_at": client_expires,
            "session_token": token,
            "assinatura": assinatura_hmac,
            "jwt_token": jwt_token
        })

    except Exception as e:
        log_security("activate_error", details=str(e))
        print(f"ERRO NA ATIVAÇÃO: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "reason": "internal_error"}), 500

# ------------------------------
#   ADMIN
# ------------------------------
def check_admin(a):
    ADMIN_USER = os.getenv("ADMIN_USER", "admin")
    ADMIN_PASS = os.getenv("ADMIN_PASS", "1234")
    return a and a.username == ADMIN_USER and a.password == ADMIN_PASS

def need_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.authorization
        if not check_admin(auth):
            return ("Unauthorized", 401, {"WWW-Authenticate": 'Basic realm=\"Login Required\"'})
        return f(*args, **kwargs)
    return wrapper

@app.route("/admin")
@need_admin
def admin():
    data = load_users()
    
    conn = get_db()
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
    
    conn.close()
    
    return render_template("admin_index.html", 
                         users=data.get("users", []), 
                         datetime=datetime,
                         total_licenses=total_licenses,
                         recent_usage=recent_usage)

@app.route("/admin/usage_report")
@need_admin
def admin_usage_report():
    conn = get_db()
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
    
    conn.close()
    
    return render_template("usage_report.html", usage_data=usage_data)

@app.route("/admin/revoke_tokens", methods=["POST"])
@need_admin
def admin_revoke_tokens():
    try:
        data = request.json or {}
        fingerprint = sanitize_input(data.get("fingerprint"))
        username = sanitize_input(data.get("username"))
        reason = data.get("reason", "admin_revoked")
        
        conn = get_db()
        cursor = conn.cursor()
        
        if fingerprint:
            cursor.execute('''
                INSERT OR IGNORE INTO revoked_tokens (token, fingerprint, revoked_at, reason)
                SELECT token, fingerprint, ?, ? FROM sessions WHERE fingerprint = ?
            ''', (int(time.time()), reason, fingerprint))
            cursor.execute('DELETE FROM sessions WHERE fingerprint = ?', (fingerprint,))
        elif username:
            cursor.execute('SELECT fingerprint FROM licenses WHERE username = ?', (username,))
            fingerprints = [row[0] for row in cursor.fetchall()]
            for fp in fingerprints:
                cursor.execute('''
                    INSERT OR IGNORE INTO revoked_tokens (token, fingerprint, revoked_at, reason)
                    SELECT token, fingerprint, ?, ? FROM sessions WHERE fingerprint = ?
                ''', (int(time.time()), reason, fp))
                cursor.execute('DELETE FROM sessions WHERE fingerprint = ?', (fp,))
        
        conn.commit()
        conn.close()
        
        log_security("admin_revoked_tokens", 
                    details={"fingerprint": fingerprint, "username": username, "reason": reason})
        
        return jsonify({"success": True, "message": "Tokens revogados com sucesso"})
        
    except Exception as e:
        log_security("admin_revoke_error", details=str(e))
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/admin/generate", methods=["POST"])
@need_admin
def admin_generate():
    username = sanitize_input(request.form.get("username"))
    password = sanitize_input(request.form.get("password"))
    prefix = sanitize_input(request.form.get("prefix") or "FERA")
    
    # LER TODOS OS TIPOS DE EXPIRAÇÃO
    expire_seconds_raw = request.form.get("expire_seconds", "").strip()
    expire_seconds_raw = expire_seconds_raw if expire_seconds_raw else None
    
    expire_minutes_raw = request.form.get("expire_minutes", "").strip()
    expire_minutes_raw = expire_minutes_raw if expire_minutes_raw else None
    
    expire_hours_raw = request.form.get("expire_hours", "").strip()
    expire_hours_raw = expire_hours_raw if expire_hours_raw else None
    
    expire_days_raw = request.form.get("expire_days", "").strip()
    expire_days_raw = expire_days_raw if expire_days_raw else None
    
    expires_at = calcular_timestamp_expira(
        expire_days=expire_days_raw,
        expire_hours=expire_hours_raw,
        expire_minutes=expire_minutes_raw,
        expire_seconds=expire_seconds_raw
    )

    key = prefix + "-" + os.urandom(4).hex().upper()

    data = load_users()
    users = data.get("users", [])

    for u in users:
        if u.get("username") == username:
            u["password"] = password
            u["key"] = key
            u["expires_at"] = expires_at
            u["status"] = "active"
            save_users(data)
            log_security("admin_user_updated", details={"username": username, "expires_at": expires_at})
            return ("", 302, {"Location": "/admin"})

    users.append({
        "username": username,
        "password": password,
        "key": key,
        "device_id": None,
        "expires_at": expires_at,
        "created_at": int(time.time()),
        "status": "active"
    })

    save_users(data)
    log_security("admin_user_created", details={"username": username, "expires_at": expires_at})
    return ("", 302, {"Location": "/admin"})

@app.route("/admin/toggle_block/<int:index>", methods=["POST"])
@need_admin
def admin_toggle_block(index):
    """Alterna o status do usuário entre bloqueado e ativo"""
    data = load_users()
    users = data.get("users", [])
    
    if 0 <= index < len(users):
        user = users[index]
        current_status = user.get("status", "active")
        
        if current_status == "blocked":
            user["status"] = "active"
            log_security("admin_unblocked", details={"username": user["username"]})
        else:
            user["status"] = "blocked"
            log_security("admin_blocked", details={"username": user["username"]})
        
        save_users(data)
        
        fingerprint = user.get("device_id")
        if fingerprint:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE licenses SET status = ?
                WHERE fingerprint = ?
            ''', (user["status"], fingerprint))
            conn.commit()
            conn.close()
        
        if current_status != "blocked" and fingerprint:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR IGNORE INTO revoked_tokens (token, fingerprint, revoked_at, reason)
                SELECT token, fingerprint, ?, 'user_blocked' FROM sessions WHERE fingerprint = ?
            ''', (int(time.time()), fingerprint))
            cursor.execute('DELETE FROM sessions WHERE fingerprint = ?', (fingerprint,))
            conn.commit()
            conn.close()
        
        return ("", 302, {"Location": "/admin"})
    
    return ("", 302, {"Location": "/admin"})

@app.route("/admin/database")
@need_admin
def admin_database():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT * FROM licenses 
        ORDER BY last_used DESC
    ''')
    
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
    
    conn.close()
    
    return render_template("database_view.html", licenses=licenses_db)

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
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE licenses SET expires_at = ?, status = 'active'
                WHERE fingerprint = ?
            ''', (users[index]["expires_at"], fingerprint))
            conn.commit()
            conn.close()
        
        log_security("admin_renewed", details={"username": users[index]["username"], "new_expires": users[index]["expires_at"]})

    return ("", 302, {"Location": "/admin"})

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
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE licenses SET expires_at = ?, status = 'active'
                WHERE fingerprint = ?
            ''', (users[index]["expires_at"], fingerprint))
            conn.commit()
            conn.close()
        
        log_security("admin_renewed_custom", details={"username": users[index]["username"], "days": days, "new_expires": users[index]["expires_at"]})

    return ("", 302, {"Location": "/admin"})

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
        conn = get_db()
        cursor = conn.cursor()
        placeholders = ','.join(['?' for _ in expired_fingerprints])
        cursor.execute(f'UPDATE licenses SET status = "expired" WHERE fingerprint IN ({placeholders})', expired_fingerprints)
        conn.commit()
        conn.close()
    
    log_security("admin_clean_expired", details={"removed_count": len(users) - len(filtered_users)})
    return ("", 302, {"Location": "/admin"})

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
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE licenses SET expires_at = ?
                WHERE fingerprint = ?
            ''', (UNLIMITED_EXPIRY, fingerprint))
            conn.commit()
            conn.close()
        
        log_security("admin_make_unlimited", details={"username": users[index]["username"]})

    return ("", 302, {"Location": "/admin"})

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
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('DELETE FROM licenses WHERE fingerprint = ?', (fingerprint,))
            conn.commit()
            conn.close()
        
        log_security("admin_delete_user", details={"username": deleted_user.get("username")})

    return ("", 302, {"Location": "/admin"})

# ------------------------------
#   REVENDEDORES
# ------------------------------
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
    token = sanitize_input(request.form.get("token"))
    username = sanitize_input(request.form.get("username"))
    password = sanitize_input(request.form.get("password"))
    prefix = sanitize_input(request.form.get("prefix") or "FERA")
    
    expire_seconds_raw = request.form.get("expire_seconds", "").strip()
    expire_seconds_raw = expire_seconds_raw if expire_seconds_raw else None
    
    expire_minutes_raw = request.form.get("expire_minutes", "").strip()
    expire_minutes_raw = expire_minutes_raw if expire_minutes_raw else None
    
    expire_hours_raw = request.form.get("expire_hours", "").strip()
    expire_hours_raw = expire_hours_raw if expire_hours_raw else None
    
    expire_days_raw = request.form.get("expire_days", "").strip()
    expire_days_raw = expire_days_raw if expire_days_raw else None
    
    expires_at = calcular_timestamp_expira(
        expire_days=expire_days_raw,
        expire_hours=expire_hours_raw,
        expire_minutes=expire_minutes_raw,
        expire_seconds=expire_seconds_raw
    )

    if token not in RESELLER_MAP:
        log_security("reseller_invalid_token", details={"token": token})
        return jsonify({"error": "invalid_token"}), 403

    reseller_nome = RESELLER_MAP[token]

    if not username or not password:
        return jsonify({"error": "missing_fields"}), 400

    key = prefix + "-" + os.urandom(4).hex().upper()

    data = load_users()
    users = data.get("users", [])

    for u in users:
        if u.get("username") == username:
            u["password"] = password
            u["key"] = key
            u["expires_at"] = expires_at
            u["reseller"] = reseller_nome
            u["status"] = "active"
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
        "created_at": int(time.time()),
        "status": "active"
    })

    save_users(data)
    
    log_security("reseller_created", details={"username": username, "expires_at": expires_at, "reseller": reseller_nome})
    return jsonify({
        "ok": True,
        "key": key,
        "username": username,
        "expires_at": expires_at
    })

@app.route("/reseller/users", methods=["GET"])
def reseller_users():
    token = request.args.get("token")
    if not token:
        return jsonify({"error": "token_required"}), 400
    
    if token not in RESELLER_MAP:
        log_security("reseller_invalid_token", details={"token": token})
        return jsonify({"error": "invalid_token"}), 403
    
    reseller_nome = RESELLER_MAP[token]
    data = load_users()
    users = data.get("users", [])
    
    reseller_users = [u for u in users if u.get("reseller") == reseller_nome]
    
    user_list = []
    for u in reseller_users:
        expires_at = u.get("expires_at", 0)
        now = int(time.time())
        status = u.get("status", "active")
        
        if status == "blocked":
            status_display = "Bloqueado"
        elif expires_at == UNLIMITED_EXPIRY:
            status_display = "Ilimitado"
        elif expires_at < now:
            status_display = "Expirado"
        else:
            status_display = "Ativo"
        
        user_list.append({
            "username": u.get("username"),
            "password": u.get("password"),
            "device_id": u.get("device_id"),
            "expires_at": expires_at,
            "status": status,
            "status_display": status_display,
            "key": u.get("key")
        })
    
    return jsonify({"users": user_list})

@app.route("/reseller/reset_device", methods=["POST"])
def reseller_reset_device():
    token = sanitize_input(request.form.get("token"))
    username = sanitize_input(request.form.get("username"))
    
    if not token or not username:
        return jsonify({"error": "missing_fields"}), 400
    
    if token not in RESELLER_MAP:
        log_security("reseller_invalid_token", details={"token": token})
        return jsonify({"error": "invalid_token"}), 403
    
    reseller_nome = RESELLER_MAP[token]
    data = load_users()
    users = data.get("users", [])
    
    user_index = None
    user = None
    for i, u in enumerate(users):
        if u.get("username") == username:
            user_index = i
            user = u
            break
    
    if not user:
        return jsonify({"error": "user_not_found"}), 404
    
    if user.get("reseller") != reseller_nome:
        return jsonify({"error": "not_authorized"}), 403
    
    user["device_id"] = None
    user.pop("device_user_agent", None)
    
    if not save_users(data):
        return jsonify({"error": "save_failed"}), 500
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM sessions WHERE fingerprint IN (SELECT fingerprint FROM licenses WHERE username = ?)", (username,))
    cursor.execute("UPDATE licenses SET device_info = NULL, last_used = NULL WHERE username = ?", (username,))
    conn.commit()
    conn.close()
    
    log_security("reseller_reset_device",
                details={"reseller": reseller_nome, "username": username},
                severity="INFO")
    
    return jsonify({"ok": True, "message": f"Dispositivo do usuário {username} resetado com sucesso."}), 200

@app.route("/admin/reseller_stats")
@need_admin
def admin_reseller_stats():
    reseller_filter = sanitize_input(request.args.get("reseller", ""))
    days = request.args.get("days", "7")
    try:
        days = int(days)
    except:
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
                "expiracao": expiracao_str,
                "status": status_str,
                "device_id": u.get("device_id", "—")
            })

        fingerprints = [u["device_id"] for u in usuarios_rev if u.get("device_id")]

        if fingerprints:
            conn = get_db()
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
            conn.close()

    return render_template("reseller_stats.html",
                           revendedores=revendedores,
                           selected=reseller_filter,
                           days=days,
                           total_usuarios_criados=total_usuarios_criados,
                           total_ativacoes=total_ativacoes,
                           stats=stats,
                           chart_data=chart_data,
                           usuarios_lista=usuarios_lista)

# ------------------------------
#   INICIAR SERVIDOR
# ------------------------------
if __name__ == "__main__":
    db_cleaner = DatabaseCleaner(interval_seconds=86400)
    db_cleaner.start()
    atexit.register(lambda: db_cleaner.stop())
    
    log_security("server_started", details={"timestamp": datetime.now().isoformat()})
    
    port = int(os.getenv("PORT", 10000))
    debug = os.getenv("FLASK_DEBUG", "False").lower() == "true"
    
    print("\n" + "="*60)
    print("🚀 SERVIDOR DE LICENÇAS INICIADO")
    print("="*60)
    print(f"📁 Banco de dados: {DB}")
    print(f"🔐 JWT Algorithm: RS256 (HS256 como fallback)")
    print(f"🛡️ Rate limiting: Ativado (memória)")
    print(f"🧹 Limpeza automática: Ativada (a cada 24h)")
    print(f"📝 Log com rotação: Ativado (5MB, 3 backups)")
    print(f"🔒 Bloqueio/Desbloqueio: Ativado")
    print(f"🌐 Porta: {port}")
    print("="*60 + "\n")
    
    app.run(host="0.0.0.0", port=port, debug=debug)
