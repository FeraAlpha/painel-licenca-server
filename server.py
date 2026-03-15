from flask import Flask, request, jsonify, render_template, redirect, url_for
import json, os, time, base64, sqlite3, requests, hashlib, hmac
import jwt
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from datetime import datetime, timedelta, timezone
from functools import wraps
from collections import defaultdict

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
JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    import secrets
    JWT_SECRET = secrets.token_urlsafe(32)
    print("⚠️ AVISO: JWT_SECRET não definida. Usando chave aleatória. Isso pode causar problemas em reinicializações!")

JWT_ALGORITHM = "RS256"
JWT_EXPIRY_HOURS = 24

# ------------------------------
#   RATE LIMITING
# ------------------------------
RATE_LIMIT = {
    'attempts': 5,      # Tentativas permitidas
    'window': 300,       # Janela de 5 minutos
    'ban_time': 1800     # Ban de 30 minutos
}
rate_limit_data = defaultdict(list)
banned_ips = {}

def check_rate_limit(ip, endpoint):
    """Verifica rate limit por IP"""
    now = time.time()
    
    # Verificar se IP está banido
    if ip in banned_ips:
        if now - banned_ips[ip] < RATE_LIMIT['ban_time']:
            return False, f"IP banido por {RATE_LIMIT['ban_time'] - (now - banned_ips[ip]):.0f} segundos"
        else:
            del banned_ips[ip]
    
    # Limpar entradas antigas
    rate_limit_data[ip] = [t for t in rate_limit_data[ip] if now - t < RATE_LIMIT['window']]
    
    # Verificar tentativas
    if len(rate_limit_data[ip]) >= RATE_LIMIT['attempts']:
        banned_ips[ip] = now
        rate_limit_data[ip] = []
        log_security("rate_limit_ban", ip=ip, details={"endpoint": endpoint}, severity="WARNING")
        return False, "Muitas tentativas. IP banido por 30 minutos."
    
    return True, "OK"

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
#   FUNÇÕES DE SEGURANÇA
# ------------------------------
def log_security(event_type, fingerprint=None, ip=None, details=None, severity="INFO"):
    """Registra eventos de segurança com níveis de severidade"""
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ip = ip or request.remote_addr if 'request' in globals() else "N/A"
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
        
        with open(SECURITY_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")
        
        # Se for severidade alta, também log no console
        if severity in ["CRITICAL", "ERROR", "WARNING"]:
            print(f"[{severity}] {event_type}: {details}")
            
    except Exception as e:
        print(f"Erro ao logar segurança: {e}")

def gerar_assinatura_hmac(expires, fingerprint):
    """Gera assinatura HMAC igual ao cliente"""
    dados = f"{expires}:{fingerprint}"
    assinatura = hmac.new(
        CHAVE_SECRETA.encode(),
        dados.encode(),
        hashlib.sha256
    ).hexdigest()
    return assinatura

def sanitize_input(value, max_length=50, allowed_chars=None):
    """Sanitiza input do usuário"""
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    
    # Remover caracteres potencialmente perigosos
    value = value.strip()[:max_length]
    if allowed_chars:
        value = ''.join(c for c in value if c in allowed_chars)
    return value

# ------------------------------
#   FUNÇÕES JWT
# ------------------------------
def gerar_token_jwt(fingerprint, username, expires_at):
    """Gera um token JWT para o cliente com fallback para HS256"""
    now = datetime.now(timezone.utc)
    
    if not os.path.exists(KEY_PRIV):
        log_security("jwt_private_key_missing", 
                    details={"error": f"Arquivo {KEY_PRIV} não encontrado"})
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
        
    except Exception as e:
        log_security("jwt_generation_error", 
                    details={"error": str(e)})
        return gerar_token_jwt_fallback(fingerprint, username, expires_at)

def gerar_token_jwt_fallback(fingerprint, username, expires_at):
    """Fallback para gerar token JWT com HS256 quando RSA falha"""
    now = datetime.now(timezone.utc)
    
    payload = {
        "fp": fingerprint,
        "user": username,
        "exp": now + timedelta(hours=JWT_EXPIRY_HOURS),
        "iat": now,
        "lic_exp": expires_at,
        "alg_fallback": "HS256"
    }
    
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return token

def validar_token_jwt(token):
    """Valida um token JWT e retorna o payload se válido"""
    try:
        # Tenta validar com HS256 (fallback)
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
    
    # Tabela de licenças
    c.execute('''CREATE TABLE IF NOT EXISTS licenses
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  fingerprint TEXT UNIQUE, 
                  username TEXT,
                  issued_at INTEGER, 
                  expires_at INTEGER, 
                  status TEXT DEFAULT 'active',
                  last_used INTEGER,
                  device_info TEXT)''')
    
    # Tabela de sessões
    c.execute('''CREATE TABLE IF NOT EXISTS sessions
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  token TEXT NOT NULL,
                  fingerprint TEXT NOT NULL,
                  expires_at INTEGER NOT NULL,
                  created_at INTEGER,
                  last_used INTEGER,
                  UNIQUE(token, fingerprint))''')
    
    # Tabela de uso de licenças
    c.execute('''CREATE TABLE IF NOT EXISTS license_usage
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  fingerprint TEXT,
                  action TEXT,
                  timestamp INTEGER,
                  ip_address TEXT,
                  user_agent TEXT)''')
    
    # Tabela para revogação de tokens
    c.execute('''CREATE TABLE IF NOT EXISTS revoked_tokens
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  token TEXT UNIQUE,
                  fingerprint TEXT,
                  revoked_at INTEGER,
                  reason TEXT)''')
    
    # Criar índices
    c.execute('CREATE INDEX IF NOT EXISTS idx_fingerprint ON licenses(fingerprint)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_sessions ON sessions(token, fingerprint)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_license_status ON licenses(status, expires_at)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_revoked_tokens ON revoked_tokens(token)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_license_usage ON license_usage(fingerprint, timestamp)')
    
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

def verificar_licenca_ativa(fingerprint, expires, username=None):
    """Verifica se a licença está ativa no banco"""
    conn = get_db()
    cursor = conn.cursor()
    
    query = '''
        SELECT * FROM licenses 
        WHERE fingerprint = ? AND expires_at = ? AND status = 'active'
    '''
    params = [fingerprint, expires]
    
    cursor.execute(query, params)
    licenca = cursor.fetchone()
    conn.close()
    
    return licenca is not None

def atualizar_uso_licenca(fingerprint, expires):
    """Atualiza o último uso da licença"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        UPDATE licenses SET last_used = ?
        WHERE fingerprint = ? AND expires_at = ?
    ''', (int(time.time()), fingerprint, expires))
    
    conn.commit()
    conn.close()

def registrar_uso(fingerprint, action, ip=None, user_agent=None):
    """Registra uso da licença para auditoria"""
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
    """Cria uma nova sessão"""
    conn = get_db()
    cursor = conn.cursor()
    
    expires_at = int(time.time()) + (24 * 60 * 60)  # 24 horas
    
    cursor.execute('''
        INSERT OR REPLACE INTO sessions (token, fingerprint, expires_at, created_at, last_used)
        VALUES (?, ?, ?, ?, ?)
    ''', (token, fingerprint, expires_at, int(time.time()), int(time.time())))
    
    conn.commit()
    conn.close()

def verificar_sessao(token, fingerprint):
    """Verifica se a sessão é válida"""
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
    """Revoga um token JWT"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT OR IGNORE INTO revoked_tokens (token, fingerprint, revoked_at, reason)
        VALUES (?, ?, ?, ?)
    ''', (token, fingerprint, int(time.time()), reason))
    
    conn.commit()
    conn.close()

def token_esta_revogado(token):
    """Verifica se um token foi revogado"""
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
                    # Garantir campo status
                    if "status" not in user:
                        user["status"] = "active"
                return data
    except Exception as e:
        log_security("load_users_error", details=str(e), severity="ERROR")

    # Se falhar, retorna estrutura vazia
    return {"users": []}

# ------------------------------
#   SAVE USERS
# ------------------------------
def save_users(data):
    try:
        # Backup
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        atomic_write(f"data/backups/users.{ts}.json", json.dumps(data, indent=2).encode())

        # Local
        atomic_write(USERS_FILE, json.dumps(data, indent=2).encode())
        return True
    except Exception as e:
        log_security("save_users_critical_error", details=str(e), severity="CRITICAL")
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
        log_security("sign_payload_error", details=str(e), severity="ERROR")
        return None

# ------------------------------
#   FLASK APP
# ------------------------------
app = Flask(__name__, template_folder='templates')

# ------------------------------
#   MIDDLEWARE DE SEGURANÇA
# ------------------------------
@app.before_request
def before_request():
    # Rate limiting para endpoints sensíveis
    sensitive_endpoints = ['activate', 'verify_license', 'validate_token']
    if request.endpoint in sensitive_endpoints:
        allowed, message = check_rate_limit(request.remote_addr, request.endpoint)
        if not allowed:
            return jsonify({"error": "rate_limited", "message": message}), 429

@app.after_request
def add_security_headers(response):
    """Adiciona headers de segurança"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

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
    """Verifica se uma licença é válida"""
    try:
        data = request.json or {}
        fingerprint = sanitize_input(data.get("fingerprint", ""))
        expires = data.get("expires")
        
        if not fingerprint or not expires:
            return jsonify({"valid": False, "reason": "missing_fields"}), 400
        
        try:
            expires_int = int(expires)
        except ValueError:
            return jsonify({"valid": False, "reason": "invalid_expires_format"}), 400
        
        if not verificar_licenca_ativa(fingerprint, expires_int):
            return jsonify({"valid": False, "reason": "license_not_found"}), 404
        
        now = int(time.time())
        if expires_int != UNLIMITED_EXPIRY and expires_int < now:
            return jsonify({"valid": False, "reason": "license_expired"}), 403
        
        atualizar_uso_licenca(fingerprint, expires_int)
        registrar_uso(fingerprint, "license_verified")
        
        return jsonify({
            "valid": True,
            "expires_at": expires_int,
            "is_unlimited": expires_int == UNLIMITED_EXPIRY
        })
        
    except Exception as e:
        log_security("verify_error", details=str(e), severity="ERROR")
        return jsonify({"valid": False, "reason": "internal_error"}), 500

# ------------------------------
#   VERIFICAÇÃO DE SESSÃO
# ------------------------------
@app.route("/verify_session", methods=["GET"])
def verify_session():
    try:
        token = request.args.get("token")
        fp = request.args.get("fp")
        
        if not token or not fp:
            return jsonify({"valid": False, "reason": "missing_params"}), 400
        
        if verificar_sessao(token, fp):
            return jsonify({"valid": True})
        else:
            return jsonify({"valid": False, "reason": "session_invalid_or_expired"})
            
    except Exception as e:
        log_security("session_error", details=str(e), severity="ERROR")
        return jsonify({"valid": False, "reason": "internal_error"}), 500

# ------------------------------
#   VALIDAÇÃO DE TOKEN JWT
# ------------------------------
@app.route("/token/validate", methods=["POST"])
def validate_token():
    try:
        data = request.json or {}
        token = data.get("token")
        fingerprint = sanitize_input(data.get("fingerprint", ""))
        
        if not token:
            return jsonify({"valid": False, "reason": "token_required"}), 400
        
        if token_esta_revogado(token):
            return jsonify({"valid": False, "reason": "token_revoked"}), 403
        
        result = validar_token_jwt(token)
        
        if not result["valid"]:
            return jsonify({"valid": False, "reason": result["reason"]}), 401
        
        payload = result["payload"]
        
        if fingerprint and payload.get("fp") != fingerprint:
            return jsonify({"valid": False, "reason": "fingerprint_mismatch"}), 403
        
        return jsonify({
            "valid": True,
            "payload": {
                "fingerprint": payload.get("fp"),
                "username": payload.get("user"),
                "license_expires": payload.get("lic_exp")
            }
        })
        
    except Exception as e:
        log_security("token_validation_error", details=str(e), severity="ERROR")
        return jsonify({"valid": False, "reason": "internal_error"}), 500

# ------------------------------
#   CLIENTE - ATIVAÇÃO
# ------------------------------
@app.route("/activate", methods=["POST"])
def activate():
    try:
        data = request.json or {}
        username = sanitize_input(data.get("username", ""))
        password = sanitize_input(data.get("password", ""))
        fingerprint = sanitize_input(data.get("fingerprint", ""))
        
        if not username or not password or not fingerprint:
            return jsonify({"error": "missing_fields"}), 400

        users = load_users().get("users", [])
        user = next((u for u in users if u["username"] == username and u["password"] == password), None)

        if not user:
            log_security("activate_invalid_credentials", fingerprint=fingerprint)
            return jsonify({"status": "error", "reason": "invalid_credentials"}), 403

        # Verificar se usuário está bloqueado
        if user.get("status") == "blocked":
            log_security("activate_blocked_user", fingerprint=fingerprint)
            return jsonify({"status": "error", "reason": "user_blocked"}), 403

        now = int(time.time())
        expires = user.get("expires_at", 0)
        
        if expires == UNLIMITED_EXPIRY:
            pass
        elif expires < now:
            return jsonify({"status": "error", "reason": "expired"}), 403

        device_id = user.get("device_id")
        
        if device_id is None:
            user["device_id"] = fingerprint
            save_users({"users": users})
        elif device_id != fingerprint:
            return jsonify({"status": "error", "reason": "device_mismatch"}), 403

        # Salvar no banco SQLite
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
        
        # Criar sessão
        token = hashlib.sha256(f"{fingerprint}:{now}:{os.urandom(16).hex()}".encode()).hexdigest()
        criar_sessao(token, fingerprint)
        
        client_expires = 0 if expires == UNLIMITED_EXPIRY else expires
        
        # Gerar resposta
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
        except:
            jwt_token = None
        
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
        log_security("activate_error", details=str(e), severity="ERROR")
        return jsonify({"status": "error", "reason": "internal_error"}), 500

# ------------------------------
#   ADMIN - AUTENTICAÇÃO
# ------------------------------
def check_admin(auth):
    ADMIN_USER = os.getenv("ADMIN_USER", "admin")
    ADMIN_PASS = os.getenv("ADMIN_PASS", "1234")
    return auth and auth.username == ADMIN_USER and auth.password == ADMIN_PASS

def need_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.authorization
        if not check_admin(auth):
            return ("Unauthorized", 401, {"WWW-Authenticate": 'Basic realm="Login Required"'})
        return f(*args, **kwargs)
    return wrapper

# ------------------------------
#   ADMIN - PAINEL PRINCIPAL
# ------------------------------
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
    
    now_timestamp = int(time.time())
    
    return render_template("admin_index.html", 
                         users=data.get("users", []), 
                         datetime=datetime,
                         now_timestamp=now_timestamp,
                         total_licenses=total_licenses,
                         recent_usage=recent_usage)

# ------------------------------
#   ADMIN - BLOQUEAR/DESBLOQUEAR USUÁRIO (CORRIGIDO)
# ------------------------------
@app.route("/admin/toggle_block/<int:index>", methods=["POST"])
@need_admin
def admin_toggle_block(index):
    """Alterna entre bloquear/desbloquear um usuário"""
    try:
        data = load_users()
        users = data.get("users", [])
        
        if 0 <= index < len(users):
            current_status = users[index].get("status", "active")
            
            if current_status == "blocked":
                users[index]["status"] = "active"
                new_status = "active"
                log_msg = "Usuário desbloqueado com sucesso"
            else:
                users[index]["status"] = "blocked"
                new_status = "blocked"
                log_msg = "Usuário bloqueado com sucesso"
            
            save_users(data)
            
            # Atualizar banco de dados
            fingerprint = users[index].get("device_id")
            if fingerprint:
                conn = get_db()
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE licenses SET status = ?
                    WHERE fingerprint = ?
                ''', (new_status, fingerprint))
                
                # Se estiver bloqueando, revogar tokens
                if new_status == "blocked":
                    cursor.execute('SELECT token FROM sessions WHERE fingerprint = ?', (fingerprint,))
                    tokens = cursor.fetchall()
                    for token_row in tokens:
                        revogar_token(token_row[0], fingerprint, "user_blocked")
                    cursor.execute('DELETE FROM sessions WHERE fingerprint = ?', (fingerprint,))
                
                conn.commit()
                conn.close()
            
            log_security("admin_toggle_block", 
                        details={
                            "username": users[index]["username"],
                            "new_status": new_status
                        })
            
            return redirect(url_for('admin', msg=log_msg, highlight=index))
        else:
            return redirect(url_for('admin', msg="Usuário não encontrado"))
            
    except Exception as e:
        log_security("admin_toggle_block_error", details=str(e), severity="ERROR")
        return redirect(url_for('admin', msg=f"Erro: {str(e)}"))

# ------------------------------
#   ADMIN - GERAR KEY
# ------------------------------
@app.route("/admin/generate", methods=["POST"])
@need_admin
def admin_generate():
    username = sanitize_input(request.form.get("username", ""))
    password = sanitize_input(request.form.get("password", ""))
    prefix = sanitize_input(request.form.get("prefix", "FERA"))
    expire_days_raw = request.form.get("expire_days", "30")
    
    try:
        expire_days = int(expire_days_raw)
    except:
        expire_days = 30

    if expire_days == 0:
        expires_at = UNLIMITED_EXPIRY
    else:
        expires_at = int(time.time()) + expire_days * 86400

    key = prefix + "-" + os.urandom(4).hex().upper()

    data = load_users()
    users = data.get("users", [])

    # Verificar se usuário já existe
    for i, u in enumerate(users):
        if u.get("username") == username:
            u["password"] = password
            u["key"] = key
            u["expires_at"] = expires_at
            if "status" not in u:
                u["status"] = "active"
            save_users(data)
            return redirect(url_for('admin', msg="Usuário atualizado", highlight=i))

    # Criar novo usuário
    users.append({
        "username": username,
        "password": password,
        "key": key,
        "device_id": None,
        "expires_at": expires_at,
        "status": "active",
        "created_at": int(time.time())
    })

    save_users(data)
    return redirect(url_for('admin', msg="Usuário criado com sucesso", highlight=len(users)-1))

# ------------------------------
#   ADMIN - RENOVAR +30 DIAS
# ------------------------------
@app.route("/admin/renew/<int:index>", methods=["POST"])
@need_admin
def admin_renew(index):
    data = load_users()
    users = data.get("users", [])

    if 0 <= index < len(users):
        now = int(time.time())
        current = users[index].get("expires_at", 0)

        if current == UNLIMITED_EXPIRY:
            users[index]["expires_at"] = UNLIMITED_EXPIRY
        else:
            if current < now:
                new_exp = now + 30 * 86400
            else:
                new_exp = current + 30 * 86400
            users[index]["expires_at"] = new_exp

        save_users(data)
        
        # Atualizar banco
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

    return redirect(url_for('admin', msg="Licença renovada +30 dias", highlight=index))

# ------------------------------
#   ADMIN - RENOVAR CUSTOM
# ------------------------------
@app.route("/admin/renew_custom/<int:index>", methods=["POST"])
@need_admin
def admin_renew_custom(index):
    days_raw = request.form.get("days", "30")

    try:
        days = int(days_raw)
    except:
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
        
        # Atualizar banco
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

    return redirect(url_for('admin', msg=f"Licença renovada +{days} dias", highlight=index))

# ------------------------------
#   ADMIN - RESETAR KEY
# ------------------------------
@app.route("/admin/reset/<int:index>", methods=["POST"])
@need_admin
def admin_reset(index):
    data = load_users()
    users = data.get("users", [])

    if 0 <= index < len(users):
        old_key = users[index].get("key", "FERA-XXXX")
        prefix = old_key.split("-")[0] if "-" in old_key else "FERA"
        new_key = f"{prefix}-{os.urandom(4).hex().upper()}"
        users[index]["key"] = new_key
        save_users(data)

    return redirect(url_for('admin', msg="Key resetada", highlight=index))

# ------------------------------
#   ADMIN - RESETAR DEVICE
# ------------------------------
@app.route("/admin/reset_device/<int:index>", methods=["POST"])
@need_admin
def admin_reset_device(index):
    data = load_users()
    users = data.get("users", [])

    if 0 <= index < len(users):
        users[index]["device_id"] = None
        save_users(data)

    return redirect(url_for('admin', msg="Dispositivo resetado", highlight=index))

# ------------------------------
#   ADMIN - RESETAR TODOS DEVICES
# ------------------------------
@app.route("/admin/reset_all_devices", methods=["POST"])
@need_admin
def admin_reset_all_devices():
    data = load_users()
    users = data.get("users", [])
    
    for user in users:
        user["device_id"] = None
    
    save_users(data)
    
    return redirect(url_for('admin', msg=f"Todos os {len(users)} dispositivos foram resetados"))

# ------------------------------
#   ADMIN - LIMPAR EXPIRADOS
# ------------------------------
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
    
    removed_count = len(users) - len(filtered_users)
    data["users"] = filtered_users
    save_users(data)
    
    if expired_fingerprints:
        conn = get_db()
        cursor = conn.cursor()
        placeholders = ','.join(['?' for _ in expired_fingerprints])
        cursor.execute(f'UPDATE licenses SET status = "expired" WHERE fingerprint IN ({placeholders})', expired_fingerprints)
        conn.commit()
        conn.close()
    
    return redirect(url_for('admin', msg=f"{removed_count} usuários expirados removidos"))

# ------------------------------
#   ADMIN - TORNAR ILIMITADO
# ------------------------------
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

    return redirect(url_for('admin', msg="Licença tornada ilimitada", highlight=index))

# ------------------------------
#   ADMIN - DELETAR USUÁRIO
# ------------------------------
@app.route("/admin/delete/<int:index>", methods=["POST"])
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
            cursor.execute('DELETE FROM sessions WHERE fingerprint = ?', (fingerprint,))
            conn.commit()
            conn.close()

    return redirect(url_for('admin', msg="Usuário deletado"))

# ------------------------------
#   ADMIN - RELATÓRIO DE USO
# ------------------------------
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

# ------------------------------
#   ADMIN - BANCO DE DADOS
# ------------------------------
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

# ------------------------------
#   REVENDEDOR - GERAR KEY
# ------------------------------
@app.route("/reseller/generate", methods=["POST"])
def reseller_generate():
    token = sanitize_input(request.form.get("token", ""))
    username = sanitize_input(request.form.get("username", ""))
    password = sanitize_input(request.form.get("password", ""))
    prefix = sanitize_input(request.form.get("prefix", "FERA"))
    expire_days_raw = request.form.get("expire_days", "30")
    
    try:
        expire_days = int(expire_days_raw)
    except:
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
            if "status" not in u:
                u["status"] = "active"
            save_users(data)
            
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
        "status": "active",
        "reseller": reseller_nome,
        "created_at": int(time.time())
    })

    save_users(data)
    
    return jsonify({
        "ok": True,
        "key": key,
        "username": username,
        "expires_at": expires_at
    })

# ------------------------------
#   ADMIN - ESTATÍSTICAS REVENDEDORES
# ------------------------------
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
    log_security("server_started", details={"timestamp": datetime.now().isoformat()})
    
    port = int(os.getenv("PORT", 10000))
    debug = os.getenv("FLASK_DEBUG", "False").lower() == "true"
    
    app.run(host="0.0.0.0", port=port, debug=debug)
