import time
import random
import json
import hashlib
import socket
import sys

def get_prev_hash_from_server(server_host, server_port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server_host, server_port))
            s.sendall(b"GET_PREVHASH")
            data = s.recv(1024)
            return data.decode()
    except Exception as e:
        print(f"Fehler beim Abrufen des vorherigen Hash vom Server: {e}")
        return "0" * 64  # Fallback

def get_block_index_from_server(server_host, server_port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server_host, server_port))
            s.sendall(b"GET_BLOCKINDEX")
            data = s.recv(1024)
            return int(data.decode())
    except Exception as e:
        print(f"Fehler beim Abrufen des Blockindex vom Server: {e}")
        return 1  # Fallback

def get_miner_id_from_server(server_host, server_port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server_host, server_port))
            s.sendall(b"GET_MINERID")
            data = s.recv(1024)
            return int(data.decode())
    except Exception as e:
        print(f"Fehler beim Abrufen der Miner-ID vom Server: {e}")
        return random.randint(10000, 99999)  # Fallback

def get_difficulty_from_server(server_host, server_port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server_host, server_port))
            s.sendall(b"GET_DIFFICULTY")
            data = s.recv(1024)
            return int(data.decode())
    except Exception as e:
        print(f"Fehler beim Abrufen der Difficulty vom Server: {e}")
        return 5  # Fallback


# Block-Klasse – muss identisch zu der im Node sein!
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

def mine_block(miner_id, block_index, previous_hash, difficulty, reward_address):
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

    iteration = 0
    while not new_block.hash.startswith("0" * difficulty):
        new_block.nonce += 1
        new_block.hash = new_block.calculate_hash()
        iteration += 1
        if iteration % 10000 == 0:
            sys.stdout.write(
                f"\rMiner {miner_id} - Block {block_index}: Iteration {iteration}, aktueller Nonce: {new_block.nonce}, Hash-Vorschau: {new_block.hash[:20]}..."
            )
            sys.stdout.flush()
    sys.stdout.write("\n")
    print(f"Miner {miner_id} hat Block {block_index} gefunden! (Nonce: {new_block.nonce}, Iterationen: {iteration})")
    return new_block

def miner(miner_id, server_host, server_port, reward_address, difficulty=4, max_blocks=5):
    while True:
        # Immer aktuelle Werte vom Node holen
        current_block_index = get_block_index_from_server(server_host, server_port)
        current_previous_hash = get_prev_hash_from_server(server_host, server_port)

        if current_block_index > max_blocks:
            print("Maximale Blockanzahl erreicht. Miner stoppt.")
            break

        new_block = mine_block(miner_id, current_block_index, current_previous_hash, difficulty, reward_address)

        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((server_host, server_port))
            block_data = json.dumps(new_block.__dict__)
            client.send(f"NEW_BLOCK:{block_data}".encode())
            # Warte auf Bestätigung vom Node
            response = client.recv(1024).decode()
            if response == "BLOCK_ACCEPTED":
                print(f"Miner {miner_id}: Block {current_block_index} wurde vom Node akzeptiert.")
            else:
                print(f"Miner {miner_id}: Block {current_block_index} wurde vom Node abgelehnt (Konflikt).")
        except Exception as e:
            print(f"Miner {miner_id} konnte Block {current_block_index} nicht senden: {e}")
        finally:
            client.close()

        time.sleep(1)
if __name__ == '__main__':
    server_host = "127.0.0.1"
    server_port = 5000

    miner_id = get_miner_id_from_server(server_host, server_port)
    difficulty = get_difficulty_from_server(server_host, server_port)
    print(f"Miner {miner_id} startet mit Difficulty {difficulty}...")

    reward_address = input("Gib die Wallet-Adresse ein, die als Belohnung (1 Token) verwendet werden soll: ").strip()
    if not reward_address:
        print("Es muss eine gültige Adresse eingegeben werden. Starte erneut.")
        sys.exit(1)
    miner(miner_id, server_host=server_host, server_port=server_port, reward_address=reward_address, difficulty=difficulty, max_blocks=128)
