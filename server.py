from flask import Flask, request, jsonify, render_template, redirect, url_for
import json, os, time, base64, sqlite3, requests
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from datetime import datetime
from functools import wraps

DB = "data/licenses.db"
USERS_FILE = "data/users.json"
KEY_PRIV = "private.pem"
KEY_PUB = "public.pem"

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
#   BANCO SQL
# ------------------------------
def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS licenses
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT, username TEXT,
                  issued_at INTEGER, expires_at INTEGER, payload TEXT)''')
    conn.commit()
    conn.close()

init_db()

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
                return json.load(f)
    except Exception:
        pass

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
                atomic_write(USERS_FILE, json.dumps(data, indent=2).encode())
                return data
        except Exception:
            pass

    return {"users": []}

# ------------------------------
#   SAVE USERS
# ------------------------------
def save_users_github(data, retries=3):
    if not GITHUB_TOKEN:
        print("⚠️ Nenhum token GitHub configurado.")
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
        except Exception:
            pass

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
    except Exception:
        pass

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
#   FLASK
# ------------------------------
app = Flask(__name__, template_folder='templates')

@app.route("/")
def home():
    return "Painel Licença OK", 200

# ------------------------------
#   CLIENTE - ATIVAÇÃO
# ------------------------------
@app.route("/activate", methods=["POST"])
def activate():
    data = request.json or {}
    username = data.get("username")
    password = data.get("password")
    fingerprint = data.get("fingerprint")

    if not username or not password or not fingerprint:
        return jsonify({"error": "missing_fields"}), 400

    users = load_users().get("users", [])
    user = next((u for u in users if u["username"] == username and u["password"] == password), None)

    if not user:
        return jsonify({"status": "error", "reason": "invalid_credentials"}), 403

    now = int(time.time())
    expires = user.get("expires_at", 0)
    if expires != 0 and expires < now:
        return jsonify({"status": "error", "reason": "expired"}), 403

    if user.get("device_id") is None:
        user["device_id"] = fingerprint
        save_users({"users": users})
    elif user.get("device_id") != fingerprint:
        return jsonify({"status": "error", "reason": "device_mismatch"}), 403

    payload = {
        "username": username,
        "fingerprint": fingerprint,
        "issued_at": now,
        "expires_at": user.get("expires_at", 0)
    }

    payload_bytes = json.dumps(payload, separators=(',', ':')).encode()
    sig = sign_payload(payload_bytes)

    return jsonify({
        "payload": base64.b64encode(payload_bytes).decode(),
        "sig": base64.b64encode(sig).decode(),
        "expires_at": user.get("expires_at", 0)
    })


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
            # solicitar autenticação básica
            return ("Unauthorized", 401, {"WWW-Authenticate": 'Basic realm=\"Login Required\"'})
        return f(*args, **kwargs)
    return wrapper


@app.route("/admin")
@need_admin
def admin():
    data = load_users()
    return render_template("admin_index.html", users=data.get("users", []), datetime=datetime)


# ------------------------------
#   GERAR KEY (ADMIN)
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
        expires_at = 0
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
            return ("", 302, {"Location": "/admin"})

    users.append({
        "username": username,
        "password": password,
        "key": key,
        "device_id": None,
        "expires_at": expires_at
    })

    save_users(data)
    return ("", 302, {"Location": "/admin"})


# ------------------------------
#   RENOVAR +30 DIAS (ACEITA POST e GET)
# ------------------------------
@app.route("/admin/renew/<int:index>", methods=["POST", "GET"])
@need_admin
def admin_renew(index):
    """
    Se chamado via GET: aplica +30 dias por padrão
    Se chamado via POST: aplica +30 dias também
    """
    data = load_users()
    users = data.get("users", [])

    if 0 <= index < len(users):
        now = int(time.time())
        current = users[index].get("expires_at", 0)

        add_days = 30

        # se current == 0 (ilimitado) e pedem renovar, manter ilimitado
        if current == 0:
            # deixa ilimitado
            users[index]["expires_at"] = 0
        else:
            if current < now:
                new_exp = now + add_days * 86400
            else:
                new_exp = current + add_days * 86400
            users[index]["expires_at"] = new_exp

        save_users(data)

    return ("", 302, {"Location": "/admin"})


# ------------------------------
#   RENOVAR CUSTOM DIAS (ACEITA POST e GET)
# ------------------------------
@app.route("/admin/renew_custom/<int:index>", methods=["POST", "GET"])
@need_admin
def admin_renew_custom(index):
    """
    POST: espera form field 'days'
    GET: aceita ?days=7 no querystring
    """
    data = load_users()
    users = data.get("users", [])

    days_raw = None
    if request.method == "POST":
        days_raw = request.form.get("days", "30")
    else:
        days_raw = request.args.get("days", "30")

    try:
        days = int(days_raw)
    except Exception:
        days = 30

    if 0 <= index < len(users):
        now = int(time.time())
        current = users[index].get("expires_at", 0)

        # days == 0 => ilimitado
        if days == 0:
            users[index]["expires_at"] = 0
        else:
            if current == 0:
                # se já é ilimitado, não reduza; apenas some dias a partir de now
                new_exp = now + days * 86400
            else:
                if current < now:
                    new_exp = now + days * 86400
                else:
                    new_exp = current + days * 86400
            users[index]["expires_at"] = new_exp

        save_users(data)

    return ("", 302, {"Location": "/admin"})


# ------------------------------
#   ROTA RÁPIDA PARA +X DIAS VIA LINK (GET)
#   Exemplo: /admin/quick_renew/2/7  -> adiciona 7 dias ao usuário 2
# ------------------------------
@app.route("/admin/quick_renew/<int:index>/<int:days>", methods=["GET"])
@need_admin
def admin_quick_renew(index, days):
    data = load_users()
    users = data.get("users", [])

    if 0 <= index < len(users):
        now = int(time.time())
        current = users[index].get("expires_at", 0)

        if days == 0:
            users[index]["expires_at"] = 0
        else:
            if current == 0:
                new_exp = now + days * 86400
            else:
                if current < now:
                    new_exp = now + days * 86400
                else:
                    new_exp = current + days * 86400
            users[index]["expires_at"] = new_exp

        save_users(data)

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
        users.pop(index)
        save_users(data)

    return ("", 302, {"Location": "/admin"})


# ------------------------------
#   REVENDEDOR - GERAR KEY EXTERNA (TOKEN)
# ------------------------------
@app.route("/reseller/generate", methods=["POST"])
def reseller_generate():
    """
    Gera uma key externa para revendedores via token.
    Não precisa autenticação admin. Seguro e separado.
    """
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
        return jsonify({"error": "invalid_token"}), 403

    if not username or not password:
        return jsonify({"error": "missing_fields"}), 400

    # expire_days == 0 => ilimitado
    if expire_days == 0:
        expires_at = 0
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
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 10000)), debug=False)
