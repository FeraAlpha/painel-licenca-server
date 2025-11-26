from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import json, os, time, base64, sqlite3, requests
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from datetime import datetime
from functools import wraps

# ------------------------------
#   CONFIGURAÇÕES
# ------------------------------
DB = "data/licenses.db"
USERS_FILE = "data/users.json"
KEY_PRIV = "private.pem"

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_REPO = "FeraAlpha/painel-licenca-server"
GITHUB_FILE_PATH = "data/users.json"
GITHUB_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_FILE_PATH}"

os.makedirs("data", exist_ok=True)
os.makedirs("data/backups", exist_ok=True)

# ------------------------------
#   INICIALIZAR BANCO SQL
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
#   LOAD USERS
# ------------------------------
def load_users():
    try:
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except:
        pass

    if GITHUB_TOKEN:
        try:
            r = requests.get(GITHUB_API_URL, headers={
                "Authorization": f"Bearer {GITHUB_TOKEN}",
                "Accept": "application/vnd.github+json"
            })
            if r.ok:
                file_info = r.json()
                content = base64.b64decode(file_info["content"]).decode()
                data = json.loads(content)
                atomic_write(USERS_FILE, json.dumps(data, indent=2).encode())
                return data
        except:
            pass

    return {"users": []}

# ------------------------------
#   SAVE USERS
# ------------------------------
def save_users_github(data):
    if not GITHUB_TOKEN:
        print("⚠ Nenhum token GitHub configurado.")
        return False

    sha = None
    try:
        r = requests.get(GITHUB_API_URL, headers={
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json"
        })
        if r.ok:
            sha = r.json().get("sha")
    except:
        pass

    encoded = base64.b64encode(json.dumps(data, indent=2).encode()).decode()

    payload = {"message": "update users.json", "content": encoded}
    if sha:
        payload["sha"] = sha

    r = requests.put(
        GITHUB_API_URL,
        headers={
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json"
        },
        json=payload
    )

    return r.status_code in (200, 201)

def save_users(data):
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    atomic_write(f"data/backups/users.{ts}.json", json.dumps(data, indent=2).encode())
    atomic_write(USERS_FILE, json.dumps(data, indent=2).encode())
    save_users_github(data)

# ------------------------------
#   ASSINAR PAYLOAD
# ------------------------------
def sign_payload(payload_bytes):
    with open(KEY_PRIV, "rb") as f:
        priv = RSA.import_key(f.read())
    h = SHA256.new(payload_bytes)
    sig = pkcs1_15.new(priv).sign(h)
    return sig

# ------------------------------
#   INICIAR SERVIDOR
# ------------------------------
app = Flask(__name__)
CORS(app)  # 🔥 PERMITE ACESSO DO GITHUB PAGES

@app.route("/")
def home():
    return "Painel Licença OK", 200

# ------------------------------
#   ATIVAÇÃO DO CLIENTE
# ------------------------------
@app.route("/activate", methods=["POST"])
def activate():
    data = request.json or {}
    username = data.get("username")
    password = data.get("password")
    fingerprint = data.get("fingerprint")

    if not username or not password or not fingerprint:
        return jsonify({"error": "missing_fields"}), 400

    users = load_users()["users"]
    user = next((u for u in users
                 if u["username"] == username and u["password"] == password), None)

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

    p_bytes = json.dumps(payload).encode()
    sig = sign_payload(p_bytes)

    return jsonify({
        "payload": base64.b64encode(p_bytes).decode(),
        "sig": base64.b64encode(sig).decode(),
        "expires_at": user["expires_at"]
    })


# ============================================================
# ✅ ROTA DO REVENDEDOR /reseller/generate (a que você usa)
# ============================================================
@app.route("/reseller/generate", methods=["POST"])
def reseller_generate():

    RESELLER_TOKEN = os.getenv("RESELLER_TOKEN", "MINHA_SENHA_REVENDEDOR")

    token = request.form.get("token")
    username = request.form.get("username")
    password = request.form.get("password")
    prefix = request.form.get("prefix") or "FERA"
    expire_days = int(request.form.get("expire_days") or 30)

    if token != RESELLER_TOKEN:
        return jsonify({"error": "invalid_token"}), 403

    if not username or not password:
        return jsonify({"error": "missing_fields"}), 400

    key = prefix + "-" + os.urandom(4).hex().upper()
    expires_at = int(time.time()) + expire_days * 86400

    data = load_users()
    users = data["users"]

    existing = next((u for u in users if u["username"] == username), None)

    if existing:
        existing["password"] = password
        existing["key"] = key
        existing["expires_at"] = expires_at
    else:
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
        "generated_key": key,
        "username": username,
        "expires_at": expires_at
    })


# ------------------------------
#   EXECUTAR SERVIDOR
# ------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 10000)), debug=False)
