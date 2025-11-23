from flask import Flask, request, jsonify, send_file, render_template
import json, os, time, base64, sqlite3
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

DB = "data/licenses.db"
USERS_FILE = "data/users.json"
KEY_PRIV = "private.pem"
KEY_PUB = "public.pem"

# Criar pasta data se não existir
os.makedirs("data", exist_ok=True)

def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS licenses
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT, username TEXT,
                  issued_at INTEGER, expires_at INTEGER, payload TEXT)''')
    conn.commit()
    conn.close()

def load_users():
    if not os.path.exists(USERS_FILE):
        return {"users": []}
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_users(data):
    os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

init_db()

# AQUI CORRIGIDO — USAR __name__
app = Flask(__name__, template_folder='templates')

def sign_payload(payload_bytes):
    with open(KEY_PRIV, "rb") as f:
        priv = RSA.import_key(f.read())
    h = SHA256.new(payload_bytes)
    sig = pkcs1_15.new(priv).sign(h)
    return sig

@app.route("/")
def home():
    return "Painel Licença OK", 200

@app.route("/activate", methods=["POST"])
def activate():
    data = request.json or {}
    username = data.get("username")
    password = data.get("password")
    fingerprint = data.get("fingerprint")

    if not username or not password or not fingerprint:
        return jsonify({"error": "username, password and fingerprint required"}), 400

    users = load_users().get("users", [])
    user = None
    for u in users:
        if u.get("username") == username and u.get("password") == password:
            user = u
            break

    if not user:
        return jsonify({"status": "error", "reason": "invalid credentials"}), 403

    now = int(time.time())
    expires_at = user.get("expires_at")
    if expires_at and expires_at < now:
        return jsonify({"status": "error", "reason": "expired"}), 403

    if not user.get("device_id"):
        user["device_id"] = fingerprint
        save_users({"users": users})
    elif user.get("device_id") != fingerprint:
        return jsonify({"status": "error", "reason": "device_mismatch"}), 403

    issued = now
    expires = expires_at or (issued + 365 * 86400)

    payload = {
        "username": username,
        "fingerprint": fingerprint,
        "issued_at": issued,
        "expires_at": expires
    }

    payload_bytes = json.dumps(payload, separators=(',', ':')).encode()
    sig = sign_payload(payload_bytes)

    return jsonify({
        "payload": base64.b64encode(payload_bytes).decode(),
        "sig": base64.b64encode(sig).decode(),
        "expires_at": expires
    })

from functools import wraps

def check_admin(a):
    ADMIN_USER = os.getenv("ADMIN_USER", "admin")
    ADMIN_PASS = os.getenv("ADMIN_PASS", "1234")
    return a and a.username == ADMIN_USER and a.password == ADMIN_PASS

def need_admin(f):
    @wraps(f)
    def inner(*args, **kwargs):
        auth = request.authorization
        if not check_admin(auth):
            return ("Unauthorized", 401, {"WWW-Authenticate": 'Basic realm="Login Required"'})
        return f(*args, **kwargs)
    return inner

@app.route("/admin")
@need_admin
def admin():
    return render_template("admin_index.html", users=users, datetime=datetime)

@app.route("/admin/generate", methods=["POST"])
@need_admin
def admin_generate():
    username = request.form.get("username") or ""
    password = request.form.get("password") or ""
    prefix = request.form.get("prefix") or "FERA"
    expire_days = int(request.form.get("expire_days") or 365)

    key = prefix + "-" + os.urandom(6).hex().upper()
    expires_at = int(time.time()) + expire_days * 86400 if expire_days > 0 else None

    data = load_users()
    data["users"].append({
        "username": username,
        "password": password,
        "key": key,
        "device_id": None,
        "expires_at": expires_at
    })
    save_users(data)

    return ("", 302, {"Location": "/admin"})

@app.route("/admin/delete/<int:index>", methods=["POST"])
@need_admin
def admin_delete(index):
    data = load_users()
    if 0 <= index < len(data["users"]):
        data["users"].pop(index)
        save_users(data)
    return ("", 302, {"Location": "/admin"})

# CORRETO FINAL
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 10000)), debug=False)
