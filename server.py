from flask import Flask, request, jsonify, render_template, redirect, url_for
import json, os, time, base64, sqlite3, requests, hashlib, hmac
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from datetime import datetime, timedelta
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
    
    # Criar índices para melhor performance
    c.execute('CREATE INDEX IF NOT EXISTS idx_fingerprint ON licenses(fingerprint)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_sessions ON sessions(token, fingerprint)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_license_status ON licenses(status, expires_at)')
    
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
#   VERIFICAÇÃO DE LICENÇA (NOVO)
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
#   VERIFICAÇÃO DE SESSÃO (NOVO)
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
#   CLIENTE - ATIVAÇÃO (ATUALIZADA)
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

        if user.get("device_id") is None:
            user["device_id"] = fingerprint
            save_users({"users": users})
        elif user.get("device_id") != fingerprint:
            log_security("activate_device_mismatch", fingerprint=fingerprint, details={"username": username, "stored_device": user.get("device_id")})
            return jsonify({"status": "error", "reason": "device_mismatch"}), 403

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
        
        log_security("activate_success", fingerprint=fingerprint, details={"username": username, "expires": client_expires})
        registrar_uso(fingerprint, "activate")

        return jsonify({
            "status": "success",
            "payload": base64.b64encode(payload_bytes).decode(),
            "sig": base64.b64encode(sig).decode(),
            "expires_at": client_expires,
            "session_token": token,
            "assinatura": assinatura_hmac  # Nova assinatura HMAC
        })

    except Exception as e:
        log_security("activate_error", details=str(e))
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
            save_users(data)
            
            log_security("admin_user_updated", details={"username": username, "expires_at": expires_at})
            return ("", 302, {"Location": "/admin"})

    users.append({
        "username": username,
        "password": password,
        "key": key,
        "device_id": None,
        "expires_at": expires_at
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
#   RENOVAR +30 DIAS (ACEITA POST e GET) - ATUALIZADA
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
#   RENOVAR CUSTOM DIAS (ACEITA POST e GET) - ATUALIZADA
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
#   RESETAR KEY - ATUALIZADA
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
#   RESETAR DEVICE - ATUALIZADA
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
#   RESETAR TODOS OS DEVICES - ATUALIZADA
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
#   LIMPAR USUÁRIOS EXPIRADOS - ATUALIZADA
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
#   TORNAR LICENÇA ILIMITADA - ATUALIZADA
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
#   DELETAR USUÁRIO - ATUALIZADA
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
#   REVENDEDOR - GERAR KEY EXTERNA (TOKEN) - ATUALIZADA
# ------------------------------
@app.route("/reseller/generate", methods=["POST"])
def reseller_generate():
    RESELLER_TOKEN = os.getenv("RESELLER_TOKEN", "MINHA_SENHA_REVENDEDOR")

    token = request.form.get("token")
    username = request.form.get("username")
    password = request.form.get("password")
    prefix = request.form.get("prefix") or "FERA"
    expire_days_raw = request.form.get("expire_days", "30")
    
    try:
        expire_days = int(expire_days_raw)
    except Exception:
        expire_days = 30

    if token != RESELLER_TOKEN:
        log_security("reseller_invalid_token")
        return jsonify({"error": "invalid_token"}), 403

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
            save_users(data)
            
            log_security("reseller_updated", details={"username": username})
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
        "expires_at": expires_at
    })

    save_users(data)
    
    log_security("reseller_created", details={"username": username, "expires_at": expires_at})
    return jsonify({
        "ok": True,
        "key": key,
        "username": username,
        "expires_at": expires_at
    })

# ------------------------------
#   RUN
# ------------------------------
if __name__ == "__main__":
    # Log inicial
    log_security("server_started", details={"timestamp": datetime.now().isoformat()})
    
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 10000)), debug=False)
