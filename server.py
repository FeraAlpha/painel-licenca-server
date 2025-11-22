from flask import Flask, request, jsonify, send_file, render_template
import json, os, time, base64, sqlite3, traceback
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

DB = "data/licenses.db"
USERS_FILE = "data/users.json"
KEY_PRIV = "private.pem"
KEY_PUB = "public.pem"

# Ensure data dir
os.makedirs("data", exist_ok=True)

def init_db():
    try:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS licenses
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT, username TEXT, issued_at INTEGER, expires_at INTEGER, payload TEXT)''')
        conn.commit()
    except Exception:
        print("ERROR init_db:", traceback.format_exc())
    finally:
        try:
            conn.close()
        except:
            pass

def load_users():
    if not os.path.exists(USERS_FILE):
        return {"users": []}
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            # Normalize: ensure top-level "users" and keys in english
            if isinstance(data, dict) and "users" in data and isinstance(data["users"], list):
                # quick normalization: if user objects use portuguese keys, rename them
                normalized = []
                for u in data["users"]:
                    if not isinstance(u, dict):
                        continue
                    # common portuguese keys map (if present)
                    if "nome de usuário" in u or "nome" in u or "usuario" in u:
                        username = u.get("username") or u.get("nome de usuário") or u.get("nome") or u.get("usuario")
                        password = u.get("password") or u.get("senha")
                        key = u.get("key") or u.get("chave")
                        device = u.get("device_id") or u.get("device") or u.get("device id") or u.get("deviceId") or u.get("deviceID") or u.get("device-id")
                        expires = u.get("expires_at") or u.get("expira_em") or u.get("expires")
                        normalized.append({
                            "username": username,
                            "password": password,
                            "key": key,
                            "device_id": device if device is not None else None,
                            "expires_at": expires
                        })
                    else:
                        # keep as is
                        normalized.append(u)
                data["users"] = normalized
            return data
    except Exception:
        print("ERROR load_users:", traceback.format_exc())
        return {"users": []}

def save_users(data):
    try:
        os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception:
        print("ERROR save_users:", traceback.format_exc())

init_db()
app = Flask(_name_, template_folder='templates')

# Check presence of keys (startup)
if not os.path.exists(KEY_PRIV):
    print("WARN: private key file not found:", KEY_PRIV)
if not os.path.exists(KEY_PUB):
    print("WARN: public key file not found:", KEY_PUB)

def sign_payload(payload_bytes):
    try:
        with open(KEY_PRIV, "rb") as f:
            priv = RSA.import_key(f.read())
        h = SHA256.new(payload_bytes)
        sig = pkcs1_15.new(priv).sign(h)
        return sig
    except Exception as e:
        print("ERROR sign_payload:", traceback.format_exc())
        raise

@app.route("/")
def home():
    return "Painel Licença OK", 200

@app.route("/activate", methods=["POST"])
def activate():
    try:
        data = request.json or {}
        username = data.get("username")
        password = data.get("password")
        fingerprint = data.get("fingerprint")

        if not username or not password or not fingerprint:
            return jsonify({"error":"username, password and fingerprint required"}), 400

        users = load_users().get("users", [])
        user = None
        for u in users:
            if u.get("username") == username and u.get("password") == password:
                user = u
                break

        if not user:
            return jsonify({"status":"error","reason":"invalid credentials"}), 403

        now = int(time.time())
        expires_at = user.get("expires_at")
        if expires_at and isinstance(expires_at, (int, float)) and expires_at < now:
            return jsonify({"status":"error","reason":"expired"}), 403

        if not user.get("device_id"):
            user["device_id"] = fingerprint
            save_users({"users": users})
        elif user.get("device_id") != fingerprint:
            return jsonify({"status":"error","reason":"device_mismatch"}), 403

        issued = now
        expires = expires_at or (issued + 365*86400)

        payload = {
            "username": username,
            "fingerprint": fingerprint,
            "issued_at": issued,
            "expires_at": expires
        }

        payload_bytes = json.dumps(payload, separators=(',',':')).encode()
        try:
            sig = sign_payload(payload_bytes)
        except Exception:
            # don't leak private key content; return generic error but log
            return jsonify({"status":"error","reason":"signature_failed"}), 500

        return jsonify({
            "payload": base64.b64encode(payload_bytes).decode(),
            "sig": base64.b64encode(sig).decode(),
            "expires_at": expires
        })
    except Exception:
        print("ERROR /activate:", traceback.format_exc())
        return jsonify({"status":"error","reason":"internal_server_error"}), 500

from functools import wraps

def check_admin(a):
    ADMIN_USER = os.getenv("ADMIN_USER","admin")
    ADMIN_PASS = os.getenv("ADMIN_PASS","1234")
    try:
        return a and getattr(a, "username", None) == ADMIN_USER and getattr(a, "password", None) == ADMIN_PASS
    except Exception:
        return False

def need_admin(f):
    @wraps(f)
    def inner(*args, **kwargs):
        auth = request.authorization
        if not check_admin(auth):
            return ("Unauthorized",401,{"WWW-Authenticate":'Basic realm="Login Required"'})
        return f(*args, **kwargs)
    return inner

@app.route("/admin")
@need_admin
def admin():
    return render_template("admin_index.html", users=load_users().get("users", []))

@app.route("/admin/generate", methods=["POST"])
@need_admin
def admin_generate():
    username = request.form.get("username") or ""
    password = request.form.get("password") or ""
    prefix = request.form.get("prefix") or "FERA"
    expire_days = int(request.form.get("expire_days") or 365)

    key = prefix + "-" + os.urandom(6).hex().upper()
    expires_at = int(time.time()) + expire_days*86400 if expire_days > 0 else None

    data = load_users()
    data.setdefault("users", []).append({
        "username": username,
        "password": password,
        "key": key,
        "device_id": None,
        "expires_at": expires_at
    })
    save_users(data)

    return ("",302,{"Location":"/admin"})

@app.route("/admin/delete/<int:index>", methods=["POST"])
@need_admin
def admin_delete(index):
    data = load_users()
    if 0 <= index < len(data.get("users", [])):
        data["users"].pop(index)
        save_users(data)
    return ("",302,{"Location":"/admin"})

if _name_ == "_main_":
    # In production the platform will run the WSGI; debug False
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 10000)), debug=False)
