from flask import Flask, render_template, jsonify
import socket
import json

app = Flask(__name__)

NODE_HOST = "127.0.0.1"
NODE_PORT = 5000

def get_blocks():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((NODE_HOST, NODE_PORT))
            s.sendall(b"GET_CHAIN:")
            data = b""
            while True:
                part = s.recv(4096)
                if not part:
                    break
                data += part
            return json.loads(data.decode())
    except Exception as e:
        print("Fehler beim Abrufen der Blockchain:", e)
        return []

def get_miners():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((NODE_HOST, NODE_PORT))
            s.sendall(b"GET_MINERS")
            data = s.recv(4096)
            return json.loads(data.decode())
    except Exception as e:
        print("Fehler beim Abrufen der Miner-Liste:", e)
        return []

def get_address_info(address):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((NODE_HOST, NODE_PORT))
            s.sendall(f"GET_CHAIN:".encode())
            data = b""
            while True:
                part = s.recv(4096)
                if not part:
                    break
                data += part
            chain = json.loads(data.decode())
            balance = 0.0
            transactions = []
            for block in chain:
                for tx in block.get("transactions", []):
                    if isinstance(tx, dict):
                        if tx.get("recipient") == address:
                            balance += float(tx.get("amount", 0))
                            transactions.append(tx)
                        elif tx.get("sender") == address:
                            balance -= float(tx.get("amount", 0))
                            transactions.append(tx)
            return {"address": address, "balance": balance, "transactions": transactions}
    except Exception as e:
        print("Fehler beim Abrufen der Adressdaten:", e)
        return {"address": address, "balance": 0.0, "transactions": []}

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/blocks")
def blocks():
    return jsonify(get_blocks())

@app.route("/miners")
def miners():
    return jsonify(get_miners())

@app.route("/address/<address>")
def address(address):
    info = get_address_info(address)
    return render_template("address.html", info=info)

@app.route("/latest_block")
def latest_block():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((NODE_HOST, NODE_PORT))
            s.sendall(b"GET_CHAIN:")
            data = b""
            while True:
                part = s.recv(4096)
                if not part:
                    break
                data += part
            chain = json.loads(data.decode())
            if chain:
                return jsonify(chain[-1])  # letzter Block
            else:
                return jsonify({})
    except Exception as e:
        print("Fehler beim Abrufen des neuesten Blocks:", e)
        return jsonify({})

if __name__ == "__main__":
    app.run(debug=True)
