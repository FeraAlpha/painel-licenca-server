from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/", methods=["GET"])
def home():
    return "Servidor Ligado com Sucesso!", 200

@app.route("/check", methods=["POST"])
def check():
    data = request.json
    if not data or "key" not in data or "device" not in data:
        return jsonify({"status": "error", "message": "Dados inválidos"}), 400

    # EXEMPLO: key válida e device liberado
    if data["key"] == "FERA123" and data["device"] == "meu_celular":
        return jsonify({"status": "valid"}), 200

    return jsonify({"status": "invalid"}), 403


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
