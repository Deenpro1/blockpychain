import time
import random
import json
import hashlib
import socket
import sys
import os
import logging

TOKEN_FILE = "miner_token.json"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("miner.log"),
        logging.StreamHandler()
    ]
)

def get_token_and_id(server_host, server_port):
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, "r") as f:
            data = json.load(f)
            return data["miner_id"], data["token"]
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server_host, server_port))
            s.sendall(b"GET_MINERID")
            data = s.recv(1024)
            resp = json.loads(data.decode())
            with open(TOKEN_FILE, "w") as f:
                json.dump(resp, f)
            return resp["miner_id"], resp["token"]
    except Exception as e:
        logging.error(f"Fehler beim Abrufen der Miner-ID und des Tokens vom Server: {e}")
        sys.exit(1)

def send_authenticated_request(server_host, server_port, command, miner_id, token):
    """
    Sendet einen Befehl mit Miner-ID und Token an den Node.
    Erwartet als Antwort einen String.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server_host, server_port))
            # Format: <COMMAND>:<miner_id>:<token>
            msg = f"{command}:{miner_id}:{token}"
            s.sendall(msg.encode())
            data = s.recv(4096)
            return data.decode()
    except Exception as e:
        logging.error(f"Fehler bei Anfrage '{command}' an den Server: {e}")
        return None

def get_prev_hash_from_server(server_host, server_port, miner_id, token):
    result = send_authenticated_request(server_host, server_port, "GET_PREVHASH", miner_id, token)
    return result if result else "0" * 64

def get_block_index_from_server(server_host, server_port, miner_id, token):
    result = send_authenticated_request(server_host, server_port, "GET_BLOCKINDEX", miner_id, token)
    try:
        return int(result)
    except Exception:
        return 1

def get_difficulty_from_server(server_host, server_port, miner_id, token):
    result = send_authenticated_request(server_host, server_port, "GET_DIFFICULTY", miner_id, token)
    try:
        return int(result)
    except Exception:
        return 5

def report_hashrate_to_server(server_host, server_port, miner_id, token, hashrate):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server_host, server_port))
            msg = f"REPORT_HASHRATE:{miner_id}:{token}:{hashrate}"
            s.sendall(msg.encode())
    except Exception as e:
        logging.error(f"Fehler beim Senden der Hashrate an den Server: {e}")

class Block:
    def __init__(self, index, transactions, timestamp, previous_hash, nonce=0):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = json.dumps({
            "index": self.index,
            "transactions": self.transactions,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

def mine_block(miner_id, token, block_index, previous_hash, difficulty, reward_address):
    transactions = [{
        "sender": "SYSTEM",
        "recipient": reward_address,
        "amount": 1,
        "timestamp": time.time(),
        "type": "reward"
    }]
    new_block = Block(
        index=block_index,
        transactions=transactions,
        timestamp=time.time(),
        previous_hash=previous_hash
    )
    new_block.nonce = random.randint(0, 100000)
    new_block.hash = new_block.calculate_hash()
    hashes = 0
    start_time = time.time()
    last_report = start_time

    iteration = 0
    while not new_block.hash.startswith("0" * difficulty):
        new_block.nonce += 1
        new_block.hash = new_block.calculate_hash()
        hashes += 1
        iteration += 1

        now = time.time()
        if now - last_report >= 1.0:
            mh_s = hashes / 1_000_000 / (now - last_report)
            sys.stdout.write(
                f"\rMiner {miner_id} - Block {block_index} | Difficulty: {difficulty} | Iteration {iteration}, Nonce: {new_block.nonce}, Hashrate: {mh_s:.2f} MH/s, Hash-Vorschau: {new_block.hash[:20]}..."
            )
            sys.stdout.flush()
            hashes = 0
            last_report = now

    sys.stdout.write("\n")
    total_time = time.time() - start_time
    avg_hashrate = iteration / 1_000_000 / total_time if total_time > 0 else 0
    logging.info(f"Miner {miner_id} hat Block {block_index} gefunden! (Nonce: {new_block.nonce}, Iterationen: {iteration}, Ø Hashrate: {avg_hashrate:.2f} MH/s, Difficulty: {difficulty})")
    return new_block, avg_hashrate

def miner(miner_id, token, server_host, server_port, reward_address, difficulty=4, max_blocks=5):
    while True:
        current_block_index = get_block_index_from_server(server_host, server_port, miner_id, token)
        current_previous_hash = get_prev_hash_from_server(server_host, server_port, miner_id, token)
        difficulty = get_difficulty_from_server(server_host, server_port, miner_id, token)

        if current_block_index > max_blocks:
            print("Maximale Blockanzahl erreicht. Miner stoppt.")
            break

        new_block, avg_hashrate = mine_block(miner_id, token, current_block_index, current_previous_hash, difficulty, reward_address)

        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((server_host, server_port))
            block_data = json.dumps(new_block.__dict__)
            msg = f"NEW_BLOCK:{miner_id}:{token}:{block_data}"
            client.send(msg.encode())
            response = client.recv(1024).decode()
            if response == "BLOCK_ACCEPTED":
                print(f"Miner {miner_id}: Block {current_block_index} wurde vom Node akzeptiert.")
            else:
                print(f"Miner {miner_id}: Block {current_block_index} wurde vom Node abgelehnt (Konflikt).")
        except Exception as e:
            logging.error(f"Miner {miner_id} konnte Block {current_block_index} nicht senden: {e}")
        finally:
            client.close()

        report_hashrate_to_server(server_host, server_port, miner_id, token, avg_hashrate)
        time.sleep(1)

if __name__ == '__main__':
    server_host = "127.0.0.1"
    server_port = 5000

    miner_id, token = get_token_and_id(server_host, server_port)
    difficulty = get_difficulty_from_server(server_host, server_port, miner_id, token)
    print(f"Miner {miner_id} startet mit Difficulty {difficulty}...")

    reward_address = input("Gib die Wallet-Adresse ein, die als Belohnung (1 Token) verwendet werden soll: ").strip()
    if not reward_address:
        print("Es muss eine gültige Adresse eingegeben werden. Starte erneut.")
        sys.exit(1)
    miner(miner_id, token, server_host=server_host, server_port=server_port, reward_address=reward_address, difficulty=difficulty, max_blocks=128)

