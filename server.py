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
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  fingerprint TEXT,
                  username TEXT,
                  issued_at INTEGER,
                  expires_at INTEGER,
                  payload TEXT)''')
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
#   LOAD USERS COM FAILSAFE
# ------------------------------
def load_users():
    try:
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except:
        print("❌ Erro lendo local, tentando GitHub...")

    # tenta github
    if GITHUB_TOKEN:
        try:
            r = requests.get(GITHUB_API_URL, headers={
                "Authorization": f"Bearer {GITHUB_TOKEN}",
                "Accept": "application/vnd.github+json"
            })
            if r.ok:
                info = r.json()
                content = base64.b64decode(info.get("content", "")).decode()
                data = json.loads(content)
                atomic_write(USERS_FILE, json.dumps(data, indent=2).encode())
                return data
        except:
            print("❌ Falha GitHub")

    return {"users": []}

# ------------------------------
#   SAVE USERS (LOCAL + BACKUP + GITHUB)
# ------------------------------
def save_users_github(data):
    if not GITHUB_TOKEN:
        print("⚠️ Sem token GitHub")
        return False

    try:
        res_info = requests.get(
            GITHUB_API_URL,
            headers={"Authorization": f"Bearer {GITHUB_TOKEN}", "Accept":"application/vnd.github+json"}
        )
        sha = res_info.json().get("sha")
    except:
        sha = None

    content_b64 = base64.b64encode(json.dumps(data, indent=2).encode()).decode()

    payload = {
        "message": "Painel sync users.json",
        "content": content_b64
    }
    if sha:
        payload["sha"] = sha

    try:
        res = requests.put(
            GITHUB_API_URL,
            headers={"Authorization": f"Bearer {GITHUB_TOKEN}", "Accept": "application/vnd.github+json"},
            json=payload
        )
        if res.status_code in (200, 201):
            print("✅ GitHub atualizado!")
            return True
    except:
        pass

    print("⚠️ Falha GitHub")
    return False


def save_users(data):
    # backup
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    atomic_write(f"data/backups/users.{ts}.json", json.dumps(data, indent=2).encode())

    # local
    atomic_write(USERS_FILE, json.dumps(data, indent=2).encode())

    # GitHub
    save_users_github(data)

# ------------------------------
#   ASSINATURA RSA
# ------------------------------
def sign_payload(payload_bytes):
    with open(KEY_PRIV, "rb") as f:
        priv = RSA.import_key(f.read())
    h = SHA256.new(payload_bytes)
    return pkcs1_15.new(priv).sign(h)

# ------------------------------
#   FLASK
# ------------------------------
app = Flask(__name__, template_folder='templates')

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
        return jsonify({"error":"missing_fields"}), 400

    users = load_users()["users"]
    user = next((u for u in users if u["username"] == username and u["password"] == password), None)

    if not user:
        return jsonify({"status":"error","reason":"invalid_credentials"}), 403

    now = int(time.time())

    if user["expires_at"] < now:
        return jsonify({"status":"error","reason":"expired"}), 403

    if user["device_id"] is None:
        user["device_id"] = fingerprint
        save_users({"users": users})
    elif user["device_id"] != fingerprint:
        return jsonify({"status":"error","reason":"device_mismatch"}), 403

    payload = {
        "username": username,
        "fingerprint": fingerprint,
        "issued_at": now,
        "expires_at": user["expires_at"]
    }

    bytes_payload = json.dumps(payload, separators=(',',':')).encode()
    sig = sign_payload(bytes_payload)

    return jsonify({
        "payload": base64.b64encode(bytes_payload).decode(),
        "sig": base64.b64encode(sig).decode(),
        "expires_at": user["expires_at"]
    })

# ------------------------------
#   ADMIN AUTH
# ------------------------------
def check_admin(a):
    return a and a.username == os.getenv("ADMIN_USER","admin") and a.password == os.getenv("ADMIN_PASS","1234")

def need_admin(f):
    @wraps(f)
    def w(*args, **kwargs):
        a = request.authorization
        if not check_admin(a):
            return ("Unauthorized", 401, {"WWW-Authenticate": 'Basic realm=\"Painel Admin\"'})
        return f(*args, **kwargs)
    return w

@app.route("/admin")
@need_admin
def admin():
    return render_template("admin_index.html", users=load_users()["users"], datetime=datetime)

# ------------------------------
#   GERAR USER/KEY
# ------------------------------
@app.route("/admin/generate", methods=["POST"])
@need_admin
def admin_generate():
    username = request.form.get("username")
    password = request.form.get("password")
    prefix = request.form.get("prefix") or "FERA"
    exp_days = int(request.form.get("expire_days") or 30)

    new_key = prefix + "-" + os.urandom(4).hex().upper()
    expires_at = int(time.time()) + exp_days * 86400

    data = load_users()
    users = data["users"]

    # se já existe → atualiza
    exists = False
    for u in users:
        if u["username"] == username:
            u["password"] = password
            u["key"] = new_key
            u["expires_at"] = expires_at
            exists = True
            break

    if not exists:
        users.append({
            "username": username,
            "password": password,
            "key": new_key,
            "device_id": None,
            "expires_at": expires_at
        })

    save_users(data)
    return ("", 302, {"Location": "/admin"})

# ------------------------------
#   RENOVAR +30 DIAS
# ------------------------------
@app.route("/admin/renew/<int:i>", methods=["POST"])
@need_admin
def admin_renew(i):
    data = load_users()
    users = data["users"]

    if 0 <= i < len(users):
        now = int(time.time())
        cur = users[i]["expires_at"]
        users[i]["expires_at"] = (now if cur < now else cur) + 30*86400
        save_users(data)

    return ("", 302, {"Location": "/admin"})

# ------------------------------
#   RESETAR KEY
# ------------------------------
@app.route("/admin/reset/<int:i>", methods=["POST"])
@need_admin
def admin_reset_key(i):
    data = load_users()
    users = data["users"]

    if 0 <= i < len(users):
        prefix = users[i]["key"].split("-")[0]
        users[i]["key"] = prefix + "-" + os.urandom(4).hex().upper()
        save_users(data)

    return ("", 302, {"Location": "/admin"})

# ------------------------------
#   RESETAR DEVICE
# ------------------------------
@app.route("/admin/reset_device/<int:i>", methods=["POST"])
@need_admin
def admin_reset_device(i):
    data = load_users()
    users = data["users"]

    if 0 <= i < len(users):
        users[i]["device_id"] = None
        save_users(data)

    return ("", 302, {"Location": "/admin"})

# ------------------------------
#   RUN
# ------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT",10000)), debug=False)
