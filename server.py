from flask import Flask, request, jsonify, render_template
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
#   CONFIGURAÇÕES GITHUB
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
#   FUNÇÃO — WRITE ATÔMICO
# ------------------------------
def atomic_write(path, data_bytes):
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data_bytes)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


# ------------------------------
#   USERS — LOAD RESILIENTE
# ------------------------------
def load_users():
    # 1) tenta local
    try:
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        print("❌ Erro lendo users.json local:", e)

    # 2) tenta pegar do GitHub
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

                # salva local como backup
                atomic_write(USERS_FILE, json.dumps(data, indent=2).encode())
                return data
        except Exception as e:
            print("❌ Falha ao recuperar users.json do GitHub:", e)

    # fallback
    return {"users": []}


# ------------------------------
#   SAVE USERS — GITHUB + BACKUP
# ------------------------------
def save_users_github(data, retries=3):
    if not GITHUB_TOKEN:
        print("⚠  GITHUB_TOKEN não configurado, salvando somente local.")
        return False

    # pega SHA atual
    sha = None
    try:
        r = requests.get(GITHUB_API_URL, headers={
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json"
        }, timeout=10)
        if r.ok:
            sha = r.json().get("sha")
    except:
        pass

    content_b64 = base64.b64encode(json.dumps(data, indent=2).encode()).decode()

    payload = {
        "message": "Painel → update users.json",
        "content": content_b64
    }
    if sha:
        payload["sha"] = sha

    # envia com retries
    for i in range(1, retries+1):
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
                print("✅ users.json sincronizado com GitHub")
                return True
            else:
                print(f"❌ Falha GitHub [{res.status_code}]:", res.text)
        except Exception as e:
            print(f"❌ Tentativa {i} falhou:", e)

        time.sleep(1)

    return False


def save_users(data):
    # backup local
    try:
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        atomic_write(f"data/backups/users.{ts}.json", json.dumps(data, indent=2).encode())
    except Exception as e:
        print("❌ Erro ao criar backup:", e)

    # salva local
    try:
        atomic_write(USERS_FILE, json.dumps(data, indent=2).encode())
    except Exception as e:
        print("❌ Erro ao salvar local:", e)

    # sincroniza
    ok = save_users_github(data)
    if not ok:
        print("⚠  Não sincronizou com GitHub.")


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
app = Flask(_name_, template_folder='templates')


@app.route("/")
def home():
    return "Painel Licença OK", 200


# ------------------------------
#   CLIENTE
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

    if user["expires_at"] < now:
        return jsonify({"status": "error", "reason": "expired"}), 403

    if user["device_id"] is None:
        user["device_id"] = fingerprint
        save_users({"users": users})

    elif user["device_id"] != fingerprint:
        return jsonify({"status": "error", "reason": "device_mismatch"}), 403

    payload = {
        "username": username,
        "fingerprint": fingerprint,
        "issued_at": now,
        "expires_at": user["expires_at"]
    }

    payload_bytes = json.dumps(payload, separators=(',', ':')).encode()
    sig = sign_payload(payload_bytes)

    return jsonify({
        "payload": base64.b64encode(payload_bytes).decode(),
        "sig": base64.b64encode(sig).decode(),
        "expires_at": user["expires_at"]
    })


# ------------------------------
#   ADMIN LOGIN
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
    return render_template("admin_index.html", users=data["users"], datetime=datetime)


# ------------------------------
#   GERAR KEY
# ------------------------------
@app.route("/admin/generate", methods=["POST"])
@need_admin
def admin_generate():
    username = request.form.get("username")
    password = request.form.get("password")
    prefix = request.form.get("prefix") or "FERA"
    expire_days = int(request.form.get("expire_days") or 30)

    key = prefix + "-" + os.urandom(4).hex().upper()
    expires_at = int(time.time()) + expire_days * 86400

    data = load_users()
    users = data.get("users", [])

    # evita duplicado — atualiza usuário existente
    found = False
    for u in users:
        if u["username"] == username:
            u["password"] = password
            u["key"] = key
            u["expires_at"] = expires_at
            found = True
            break

    if not found:
        users.append({
            "username": username,
            "password": password,
            "key": key,
            "device_id": None,
            "expires_at": expires_at
        })

    data["users"] = users
    save_users(data)
    return ("", 302, {"Location": "/admin"})


# ------------------------------
#   DELETAR USUÁRIO
# ------------------------------
@app.route("/admin/delete/<int:index>", methods=["POST"])
@need_admin
def admin_delete(index):
    data = load_users()
    if 0 <= index < len(data["users"]):
        data["users"].pop(index)
        save_users(data)
    return ("", 302, {"Location": "/admin"})


# ------------------------------
#   RUN
# ------------------------------
if _name_ == "_main_":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 10000)), debug=False)
