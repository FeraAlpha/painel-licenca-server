from flask import Flask, request, jsonify, render_template, redirect, url_for
import json, os, time, base64, sqlite3, requests, hashlib, hmac
import jwt
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from datetime import datetime, timedelta, timezone
from functools import wraps

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
JWT_ALGORITHM = "RS256"  # Vamos usar RSA para compatibilidade com seus .pem
JWT_EXPIRY_HOURS = 24  # Token válido por 24 horas

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
def log_security(event_type, fingerprint=None, ip=None, details=None):
    """Registra eventos de segurança"""
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ip = ip or request.remote_addr if 'request' in globals() else "N/A"
        user_agent = request.user_agent.string if 'request' in globals() and request.user_agent else "N/A"
        
        log_entry = {
            "timestamp": timestamp,
            "event": event_type,
            "fingerprint": fingerprint,
            "ip": ip,
            "user_agent": user_agent,
            "details": details
        }
        
        with open(SECURITY_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception:
        pass

def gerar_assinatura_hmac(expires, fingerprint):
    """Gera assinatura HMAC igual ao cliente"""
    dados = f"{expires}:{fingerprint}"
    assinatura = hmac.new(
        CHAVE_SECRETA.encode(),
        dados.encode(),
        hashlib.sha256
    ).hexdigest()
    return assinatura

# ------------------------------
#   FUNÇÕES JWT
# ------------------------------
def gerar_token_jwt(fingerprint, username, expires_at):
    """Gera um token JWT para o cliente"""
    now = datetime.now(timezone.utc)
    
    # Carrega a chave privada
    with open(KEY_PRIV, "rb") as f:
        private_key = RSA.import_key(f.read())
    
    payload = {
        "fp": fingerprint,           # fingerprint do dispositivo
        "user": username,             # nome do usuário
        "exp": now + timedelta(hours=JWT_EXPIRY_HOURS),  # expiração
        "iat": now,                    # emitido em
        "lic_exp": expires_at           # expiração da licença (para referência)
    }
    
    token = jwt.encode(payload, private_key, algorithm="RS256")
    return token

def validar_token_jwt(token):
    """Valida um token JWT e retorna o payload se válido"""
    try:
        # Carrega a chave pública
        with open(KEY_PUB, "rb") as f:
            public_key = RSA.import_key(f.read())
        
        # Decodifica e valida o token
        payload = jwt.decode(
            token, 
            public_key, 
            algorithms=["RS256"],
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
#   BANCO SQL MELHORADO
# ------------------------------
def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    
    # Tabela de licenças existente
    c.execute('''CREATE TABLE IF NOT EXISTS licenses
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  fingerprint TEXT UNIQUE, 
                  username TEXT,
                  issued_at INTEGER, 
                  expires_at INTEGER, 
                  status TEXT DEFAULT 'active',
                  last_used INTEGER,
                  device_info TEXT)''')
    
    # ✅ NOVA: Tabela de sessões
    c.execute('''CREATE TABLE IF NOT EXISTS sessions
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  token TEXT NOT NULL,
                  fingerprint TEXT NOT NULL,
                  expires_at INTEGER NOT NULL,
                  created_at INTEGER,
                  last_used INTEGER,
                  UNIQUE(token, fingerprint))''')
    
    # ✅ NOVA: Tabela de uso de licenças (log)
    c.execute('''CREATE TABLE IF NOT EXISTS license_usage
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  fingerprint TEXT,
                  action TEXT,
                  timestamp INTEGER,
                  ip_address TEXT,
                  user_agent TEXT)''')
    
    # ✅ NOVA: Tabela para revogação de tokens JWT
    c.execute('''CREATE TABLE IF NOT EXISTS revoked_tokens
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  token TEXT UNIQUE,
                  fingerprint TEXT,
                  revoked_at INTEGER,
                  reason TEXT)''')
    
    # Criar índices para melhor performance
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
    """Verifica se a licença está ativa no banco"""
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
        # Atualizar último uso
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
                # Corrige valores antigos: se for 0, converte para UNLIMITED_EXPIRY
                users = data.get("users", [])
                for user in users:
                    if user.get("expires_at") == 0:
                        user["expires_at"] = UNLIMITED_EXPIRY
                return data
    except Exception as e:
        log_security("load_users_error", details=str(e))

    # tenta recuperar do GitHub
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
                # Corrige valores
                users = data.get("users", [])
                for user in users:
                    if user.get("expires_at") == 0:
                        user["expires_at"] = UNLIMITED_EXPIRY
                atomic_write(USERS_FILE, json.dumps(data, indent=2).encode())
                return data
        except Exception as e:
            log_security("github_sync_error", details=str(e))

    return {"users": []}

# ------------------------------
#   SAVE USERS (CORRIGIDA)
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
        # backup
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        atomic_write(f"data/backups/users.{ts}.json", json.dumps(data, indent=2).encode())

        # local
        atomic_write(USERS_FILE, json.dumps(data, indent=2).encode())

        # sync cloud (não bloqueante)
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
    with open(KEY_PRIV, "rb") as f:
        priv = RSA.import_key(f.read())
    h = SHA256.new(payload_bytes)
    sig = pkcs1_15.new(priv).sign(h)
    return sig

# ------------------------------
#   FLASK APP
# ------------------------------
app = Flask(__name__, template_folder='templates')

# ------------------------------
#   MIDDLEWARE DE SEGURANÇA
# ------------------------------
@app.before_request
def before_request():
    # Log de requisições suspeitas
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
    """Endpoint para teste de conexão"""
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
        fingerprint = data.get("fingerprint")
        expires = data.get("expires")
        
        if not fingerprint or not expires:
            log_security("verify_missing_fields", fingerprint=fingerprint)
            return jsonify({"valid": False, "reason": "missing_fields"}), 400
        
        # Converter expires para int
        try:
            expires_int = int(expires)
        except ValueError:
            log_security("verify_invalid_expires", fingerprint=fingerprint, details={"expires": expires})
            return jsonify({"valid": False, "reason": "invalid_expires_format"}), 400
        
        # ✅ 1. Verificar se a licença existe no banco
        if not verificar_licenca_ativa(fingerprint, expires_int):
            log_security("license_not_found", fingerprint=fingerprint, details={"expires": expires_int})
            return jsonify({"valid": False, "reason": "license_not_found"}), 404
        
        # ✅ 2. Verificar se não expirou (exceto se for ilimitada)
        now = int(time.time())
        if expires_int != UNLIMITED_EXPIRY and expires_int < now:
            log_security("license_expired", fingerprint=fingerprint, details={"expires": expires_int, "now": now})
            return jsonify({"valid": False, "reason": "license_expired"}), 403
        
        # ✅ 3. Atualizar uso e registrar
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
    """Verifica se uma sessão é válida"""
    try:
        token = request.args.get("token")
        fp = request.args.get("fp")  # fingerprint
        
        if not token or not fp:
            return jsonify({"valid": False, "reason": "missing_params"}), 400
        
        # Verificar sessão
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
#   VALIDAÇÃO DE TOKEN JWT (NOVO)
# ------------------------------
@app.route("/token/validate", methods=["POST"])
def validate_token():
    """Valida um token JWT enviado pelo cliente"""
    try:
        data = request.json or {}
        token = data.get("token")
        fingerprint = data.get("fingerprint")
        
        if not token:
            log_security("token_missing", ip=request.remote_addr)
            return jsonify({"valid": False, "reason": "token_required"}), 400
        
        # Verificar se o token foi revogado
        if token_esta_revogado(token):
            log_security("token_revoked", ip=request.remote_addr)
            return jsonify({"valid": False, "reason": "token_revoked"}), 403
        
        # Validar o token JWT
        result = validar_token_jwt(token)
        
        if not result["valid"]:
            log_security("token_invalid", 
                        ip=request.remote_addr, 
                        details={"reason": result["reason"]})
            return jsonify({"valid": False, "reason": result["reason"]}), 401
        
        payload = result["payload"]
        
        # Se forneceu fingerprint, verificar se corresponde
        if fingerprint and payload.get("fp") != fingerprint:
            log_security("token_fingerprint_mismatch",
                        fingerprint=fingerprint,
                        details={"token_fp": payload.get("fp")})
            return jsonify({"valid": False, "reason": "fingerprint_mismatch"}), 403
        
        # Verificar se a licença ainda está ativa no banco
        fp = payload.get("fp")
        if fp:
            licenca_valida = verificar_licenca_ativa(fp, payload.get("lic_exp", 0))
            if not licenca_valida:
                log_security("token_license_inactive", fingerprint=fp)
                return jsonify({"valid": False, "reason": "license_inactive"}), 403
        
        # Token válido!
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
#   CLIENTE - ATIVAÇÃO (CORRIGIDA)
# ------------------------------
@app.route("/activate", methods=["POST"])
def activate():
    try:
        data = request.json or {}
        username = data.get("username")
        password = data.get("password")
        fingerprint = data.get("fingerprint")
        
        if not username or not password or not fingerprint:
            log_security("activate_missing_fields", details={"username": username})
            return jsonify({"error": "missing_fields"}), 400

        users = load_users().get("users", [])
        user = next((u for u in users if u["username"] == username and u["password"] == password), None)

        if not user:
            log_security("activate_invalid_credentials", fingerprint=fingerprint, details={"username": username})
            return jsonify({"status": "error", "reason": "invalid_credentials"}), 403

        now = int(time.time())
        expires = user.get("expires_at", 0)
        
        # Para licença ilimitada
        if expires == UNLIMITED_EXPIRY:
            # Licença ilimitada - sempre válida
            pass
        elif expires < now:
            log_security("activate_expired", fingerprint=fingerprint, details={"username": username, "expires": expires})
            return jsonify({"status": "error", "reason": "expired"}), 403

        # ✅ CORREÇÃO: Tratar device_id nulo corretamente
        device_id = user.get("device_id")
        
        # Se device_id é None (nunca ativado), atribuir o fingerprint
        if device_id is None:
            user["device_id"] = fingerprint
            save_users({"users": users})
            log_security("device_activated", fingerprint=fingerprint, details={"username": username})
        # Se device_id existe e é diferente, recusar
        elif device_id != fingerprint:
            log_security("activate_device_mismatch", fingerprint=fingerprint, 
                        details={"username": username, "stored_device": device_id})
            return jsonify({"status": "error", "reason": "device_mismatch"}), 403
        # Se device_id é igual, permitir (já ativado neste dispositivo)

        # ✅ SALVAR LICENÇA NO BANCO DE DADOS
        conn = get_db()
        cursor = conn.cursor()
        
        # Verificar se já existe
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
        
        # ✅ CRIAR SESSÃO
        token = hashlib.sha256(f"{fingerprint}:{now}:{os.urandom(16).hex()}".encode()).hexdigest()
        criar_sessao(token, fingerprint)
        
        # Para resposta, se for ilimitado, envia 0 para o cliente
        client_expires = 0 if expires == UNLIMITED_EXPIRY else expires
        
        payload = {
            "username": username,
            "fingerprint": fingerprint,
            "issued_at": now,
            "expires_at": client_expires
        }

        payload_bytes = json.dumps(payload, separators=(',', ':')).encode()
        sig = sign_payload(payload_bytes)
        
        # ✅ GERAR ASSINATURA HMAC (para validação local do cliente)
        assinatura_hmac = gerar_assinatura_hmac(client_expires, fingerprint)
        
        # ✅ GERAR TOKEN JWT
        jwt_token = gerar_token_jwt(fingerprint, username, expires)
        
        log_security("activate_success", fingerprint=fingerprint, details={"username": username, "expires": client_expires})
        registrar_uso(fingerprint, "activate")

        return jsonify({
            "status": "success",
            "payload": base64.b64encode(payload_bytes).decode(),
            "sig": base64.b64encode(sig).decode(),
            "expires_at": client_expires,
            "session_token": token,
            "assinatura": assinatura_hmac,
            "jwt_token": jwt_token
        })

    except Exception as e:
        log_security("activate_error", details=str(e))
        # ✅ IMPORTANTE: Log mais detalhado do erro
        print(f"ERRO NA ATIVAÇÃO: {str(e)}")  # Vai aparecer nos logs do Render
        import traceback
        traceback.print_exc()  # Mostra o stack trace completo
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
    
    # Buscar estatísticas do banco
    conn = get_db()
    cursor = conn.cursor()
    
    # Contar licenças ativas
    cursor.execute("SELECT COUNT(*) FROM licenses WHERE status = 'active'")
    total_licenses = cursor.fetchone()[0]
    
    # Últimos usos
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

# ------------------------------
#   ROTA ADMIN - RELATÓRIO DE USO
# ------------------------------
@app.route("/admin/usage_report")
@need_admin
def admin_usage_report():
    conn = get_db()
    cursor = conn.cursor()
    
    # Últimos 100 usos
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
#   ADMIN - REVOGAR TOKENS (NOVO)
# ------------------------------
@app.route("/admin/revoke_tokens", methods=["POST"])
@need_admin
def admin_revoke_tokens():
    """Revoga todos os tokens de um usuário/fingerprint"""
    try:
        data = request.json or {}
        fingerprint = data.get("fingerprint")
        username = data.get("username")
        reason = data.get("reason", "admin_revoked")
        
        conn = get_db()
        cursor = conn.cursor()
        
        if fingerprint:
            # Revogar tokens específicos do fingerprint
            cursor.execute('''
                INSERT OR IGNORE INTO revoked_tokens (token, fingerprint, revoked_at, reason)
                SELECT token, fingerprint, ?, ? FROM sessions WHERE fingerprint = ?
            ''', (int(time.time()), reason, fingerprint))
            
            # Limpar sessões
            cursor.execute('DELETE FROM sessions WHERE fingerprint = ?', (fingerprint,))
            
        elif username:
            # Buscar fingerprints do usuário
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

# ------------------------------
#   GERAR KEY (ADMIN) - ATUALIZADA
# ------------------------------
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

    # Se expire_days == 0 => ilimitado
    if expire_days == 0:
        expires_at = UNLIMITED_EXPIRY
    else:
        expires_at = int(time.time()) + expire_days * 86400

    key = prefix + "-" + os.urandom(4).hex().upper()

    data = load_users()
    users = data.get("users", [])

    # evita duplicados
    for u in users:
        if u.get("username") == username:
            u["password"] = password
            u["key"] = key
            u["expires_at"] = expires_at
            # admin não altera revendedor
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

# ------------------------------
#   ROTA ADMIN - LICENÇAS DO BANCO
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
#   RENOVAR +30 DIAS
# ------------------------------
@app.route("/admin/renew/<int:index>", methods=["POST", "GET"])
@need_admin
def admin_renew(index):
    data = load_users()
    users = data.get("users", [])

    if 0 <= index < len(users):
        now = int(time.time())
        current = users[index].get("expires_at", 0)

        add_days = 30

        # se já é ilimitado, mantém ilimitado
        if current == UNLIMITED_EXPIRY:
            users[index]["expires_at"] = UNLIMITED_EXPIRY
        else:
            if current < now:
                new_exp = now + add_days * 86400
            else:
                new_exp = current + add_days * 86400
            users[index]["expires_at"] = new_exp

        save_users(data)
        
        # ✅ ATUALIZAR BANCO DE DADOS TAMBÉM
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

# ------------------------------
#   RENOVAR CUSTOM DIAS
# ------------------------------
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

        # days == 0 => ilimitado
        if days == 0:
            users[index]["expires_at"] = UNLIMITED_EXPIRY
        else:
            # se já é ilimitado, converte para dias a partir de agora
            if current == UNLIMITED_EXPIRY:
                new_exp = now + days * 86400
            else:
                if current < now:
                    new_exp = now + days * 86400
                else:
                    new_exp = current + days * 86400
            users[index]["expires_at"] = new_exp

        save_users(data)
        
        # ✅ ATUALIZAR BANCO DE DADOS TAMBÉM
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

# ------------------------------
#   RESETAR KEY
# ------------------------------
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

# ------------------------------
#   RESETAR DEVICE
# ------------------------------
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

# ------------------------------
#   RESETAR TODOS OS DEVICES
# ------------------------------
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

# ------------------------------
#   LIMPAR USUÁRIOS EXPIRADOS
# ------------------------------
@app.route("/admin/clean_expired", methods=["POST"])
@need_admin
def admin_clean_expired():
    data = load_users()
    users = data.get("users", [])
    now = int(time.time())
    
    # Filtrar apenas usuários não expirados ou ilimitados
    filtered_users = []
    expired_fingerprints = []
    
    for user in users:
        expires_at = user.get("expires_at", 0)
        
        # Se for ilimitado, mantém
        if expires_at == UNLIMITED_EXPIRY:
            filtered_users.append(user)
        # Se não expirou, mantém
        elif expires_at > now:
            filtered_users.append(user)
        # Se expirou, remove
        else:
            if user.get("device_id"):
                expired_fingerprints.append(user["device_id"])
    
    data["users"] = filtered_users
    save_users(data)
    
    # ✅ REMOVER DO BANCO DE DADOS TAMBÉM
    if expired_fingerprints:
        conn = get_db()
        cursor = conn.cursor()
        placeholders = ','.join(['?' for _ in expired_fingerprints])
        cursor.execute(f'UPDATE licenses SET status = "expired" WHERE fingerprint IN ({placeholders})', expired_fingerprints)
        conn.commit()
        conn.close()
    
    log_security("admin_clean_expired", details={"removed_count": len(users) - len(filtered_users)})
    return ("", 302, {"Location": "/admin"})

# ------------------------------
#   TORNAR LICENÇA ILIMITADA
# ------------------------------
@app.route("/admin/make_unlimited/<int:index>", methods=["POST"])
@need_admin
def admin_make_unlimited(index):
    data = load_users()
    users = data.get("users", [])

    if 0 <= index < len(users):
        users[index]["expires_at"] = UNLIMITED_EXPIRY
        save_users(data)
        
        # ✅ ATUALIZAR BANCO DE DADOS TAMBÉM
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

# ------------------------------
#   DELETAR USUÁRIO
# ------------------------------
@app.route("/admin/delete/<int:index>", methods=["POST", "GET"])
@need_admin
def admin_delete(index):
    data = load_users()
    users = data.get("users", [])

    if 0 <= index < len(users):
        deleted_user = users.pop(index)
        save_users(data)
        
        # ✅ REMOVER DO BANCO DE DADOS TAMBÉM
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
#   CONFIGURAÇÃO DE MÚLTIPLOS REVENDEDORES
# ------------------------------
def carregar_revendedores():
    """
    Lê todas as variáveis de ambiente que começam com 'RESELLER_' 
    e também a variável legada RESELLER_TOKEN (se existir).
    Retorna um dicionário {token: nome_do_revendedor}
    """
    revendedores = {}
    
    # 1. Variáveis individuais: RESELLER_NOME=token
    for chave, valor in os.environ.items():
        if chave.startswith('RESELLER_') and chave != 'RESELLER_TOKEN':
            nome = chave[9:]  # remove 'RESELLER_'
            token = valor.strip()
            if token:  # ignora valores vazios
                revendedores[token] = nome
    
    # 2. Variável legada RESELLER_TOKEN (formato "nome|token,nome|token" ou "token,token")
    token_legado = os.getenv('RESELLER_TOKEN')
    if token_legado:
        for parte in token_legado.split(','):
            parte = parte.strip()
            if '|' in parte:
                nome, token = parte.split('|', 1)
                revendedores[token.strip()] = nome.strip()
            else:
                # apenas token, usa o próprio token como nome (compatibilidade)
                revendedores[parte] = parte
    
    return revendedores

# Mapeamento global: token -> nome do revendedor
RESELLER_MAP = carregar_revendedores()

# ------------------------------
#   REVENDEDOR - GERAR KEY EXTERNA (TOKEN)
# ------------------------------
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

    # Verifica se o token está no mapeamento
    if token not in RESELLER_MAP:
        log_security("reseller_invalid_token", details={"token": token})
        return jsonify({"error": "invalid_token"}), 403

    # Obtém o nome do revendedor
    reseller_nome = RESELLER_MAP[token]

    if not username or not password:
        return jsonify({"error": "missing_fields"}), 400

    # expire_days == 0 => ilimitado
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
            u["reseller"] = reseller_nome          # <-- salva revendedor
            save_users(data)
            
            log_security("reseller_updated", details={"username": username, "reseller": reseller_nome})
            return jsonify({
                "ok": True,
                "key": key,
                "username": username,
                "expires_at": expires_at
            })

    # Novo usuário
    users.append({
        "username": username,
        "password": password,
        "key": key,
        "device_id": None,
        "expires_at": expires_at,
        "reseller": reseller_nome,                  # <-- salva revendedor
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

# ------------------------------
#   ESTATÍSTICAS POR REVENDEDOR
# ------------------------------
@app.route("/admin/reseller_stats")
@need_admin
def admin_reseller_stats():
    # Parâmetros
    reseller_filter = request.args.get("reseller", "")
    days = request.args.get("days", "7")
    try:
        days = int(days)
    except:
        days = 7

    # Calcular timestamp de início
    since = int(time.time()) - (days * 86400)

    # Carregar usuários
    data = load_users()
    users = data.get("users", [])

    # Mapear revendedores disponíveis (nomes únicos)
    revendedores = set()
    for u in users:
        if u.get("reseller"):
            revendedores.add(u["reseller"])
    revendedores = sorted(revendedores)

    # Inicializar variáveis
    total_usuarios_criados = 0
    total_ativacoes = 0
    stats = []  # últimos 50 registros de ativação
    chart_data = {}  # para o gráfico: data -> contagem
    usuarios_lista = []  # lista de usuários do revendedor (detalhes)

    if reseller_filter:
        # Filtrar usuários do revendedor
        usuarios_rev = [u for u in users if u.get("reseller") == reseller_filter]
        total_usuarios_criados = len(usuarios_rev)

        # Preparar lista de usuários com detalhes
        now_ts = int(time.time())
        for u in usuarios_rev:
            created = u.get("created_at")
            expires = u.get("expires_at")
            status = u.get("status", "active")
            # Calcular dias desde a criação
            dias_desde_criacao = (now_ts - created) // 86400 if created else None
            # Formatar data de criação
            data_criacao = datetime.fromtimestamp(created).strftime("%d/%m/%Y %H:%M") if created else "—"
            # Formatar expiração
            if expires == UNLIMITED_EXPIRY:
                expiracao_str = "Ilimitado"
            elif expires:
                expiracao_str = datetime.fromtimestamp(expires).strftime("%d/%m/%Y %H:%M")
            else:
                expiracao_str = "—"
            # Status amigável
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

        # Obter fingerprints dos usuários que já ativaram
        fingerprints = [u["device_id"] for u in usuarios_rev if u.get("device_id")]

        if fingerprints:
            conn = get_db()
            cursor = conn.cursor()
            placeholders = ','.join(['?' for _ in fingerprints])

            # Contar ativações totais no período
            cursor.execute(f'''
                SELECT COUNT(*) as total
                FROM license_usage
                WHERE fingerprint IN ({placeholders}) AND timestamp >= ? AND action = 'activate'
            ''', fingerprints + [since])
            row = cursor.fetchone()
            if row:
                total_ativacoes = row[0]

            # Dados para o gráfico: ativações por dia
            cursor.execute(f'''
                SELECT DATE(timestamp, 'unixepoch') as dia, COUNT(*) as total
                FROM license_usage
                WHERE fingerprint IN ({placeholders}) AND timestamp >= ? AND action = 'activate'
                GROUP BY dia
                ORDER BY dia ASC
            ''', fingerprints + [since])
            for row in cursor.fetchall():
                chart_data[row[0]] = row[1]

            # Listar últimos 50 registros de ativação
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
#   RUN
# ------------------------------
if __name__ == "__main__":
    # Log inicial
    log_security("server_started", details={"timestamp": datetime.now().isoformat()})
    
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 10000)), debug=False)
