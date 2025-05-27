import time
import threading
import hashlib
import json
import socket
from ecdsa import VerifyingKey, SECP256k1, BadSignatureError

next_miner_id = 1
miner_id_lock = threading.Lock()
active_miners = set()

# Block-Klasse
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

class Blockchain:
    def __init__(self, difficulty=3):
        self.chain = [self.create_genesis_block()]
        self.difficulty = difficulty
        self.lock = threading.Lock()
        self.pending_transactions = []

    def create_genesis_block(self):
        return Block(0, ["Genesis Block"], time.time(), "0")

    def get_latest_block(self):
        with self.lock:
            return self.chain[-1]

    def add_block(self, block):
        with self.lock:
            # Konfliktbehandlung: Nur akzeptieren, wenn previous_hash aktuell ist!
            if block.previous_hash != self.chain[-1].hash:
                print("Block abgelehnt: falscher previous_hash (veralteter Block, evtl. Fork)!")
                return False
            if block.hash != block.calculate_hash():
                print("Block abgelehnt: ungültiger Hash!")
                return False
            if not block.hash.startswith('0' * self.difficulty):
                print("Block abgelehnt: Difficulty nicht erfüllt!")
                return False
            self.chain.append(block)
            self.pending_transactions = []
            print(f"Block {block.index} erfolgreich hinzugefügt. Kettenlänge: {len(self.chain)}")
            return True

    def add_transaction(self, transaction):
        with self.lock:
            self.pending_transactions.append(transaction)
            print("Transaktion wurde zur Pending-Liste hinzugefügt:", transaction)

def compute_balance(address, blockchain):
    balance = 0.0
    with blockchain.lock:
        for block in blockchain.chain:
            for tx in block.transactions:
                if isinstance(tx, dict):
                    if tx.get("recipient") == address:
                        balance += float(tx.get("amount", 0))
                    if tx.get("sender") == address:
                        balance -= float(tx.get("amount", 0))
    return balance

def validate_transaction(tx, blockchain):
    required_fields = ["sender", "recipient", "amount", "timestamp", "type"]
    for field in required_fields:
        if field not in tx:
            print("Transaktion fehlt das Feld:", field)
            return False

    try:
        amount = float(tx["amount"])
        if amount <= 0:
            print("Der Betrag muss größer als 0 sein.")
            return False
    except:
        print("Ungültiger Betrag in der Transaktion.")
        return False

    if tx["type"] == "reward":
        if tx.get("sender") != "SYSTEM":
            print("Reward-Transaktion muss von SYSTEM kommen.")
            return False
        if amount != 1:
            print("Reward-Transaktion muss genau 1 Token betragen.")
            return False
        return True

    if "signature" not in tx:
        print("Transfer-Transaktionen benötigen eine Signatur.")
        return False

    signature_hex = tx["signature"]
    try:
        signature = bytes.fromhex(signature_hex)
        public_key_bytes = bytes.fromhex(tx["sender"])
        verifying_key = VerifyingKey.from_string(public_key_bytes, curve=SECP256k1)
    except Exception as e:
        print("Fehler beim Wiederherstellen des öffentlichen Schlüssels:", e)
        return False

    tx_copy = tx.copy()
    del tx_copy["signature"]
    tx_str = json.dumps(tx_copy, sort_keys=True)
    try:
        verifying_key.verify(signature, tx_str.encode())
    except BadSignatureError:
        print("Die Signatur der Transaktion ist ungültig.")
        return False
    except Exception as e:
        print("Fehler bei der Signaturüberprüfung:", e)
        return False

    sender_balance = compute_balance(tx["sender"], blockchain)
    if sender_balance < amount:
        print(f"Unzureichender Saldo für {tx['sender']}. Aktueller Saldo: {sender_balance}, aber benötigt: {amount}")
        return False

    return True

def blockchain_server(port, blockchain):
    global next_miner_id, active_miners
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", port))
    server.listen(5)
    print(f"Blockchain-Server läuft und hört auf Port {port}...")

    while True:
        conn, addr = server.accept()
        data = conn.recv(4096).decode()
        if data.startswith("GET_MINERID"):
            try:
                with miner_id_lock:
                    miner_id = next_miner_id
                    next_miner_id += 1
                active_miners.add(miner_id)
                conn.sendall(str(miner_id).encode())
                time.sleep(0.1)
            except Exception as e:
                print("Fehler bei der Vergabe der Miner-ID:", e)
        elif data.startswith("GET_MINERS"):
            try:
                conn.sendall(json.dumps(list(active_miners)).encode())
                time.sleep(0.1)
            except Exception as e:
                print("Fehler beim Senden der Miner-Liste:", e)
        elif data.startswith("GET_DIFFICULTY"):
            try:
                conn.sendall(str(blockchain.difficulty).encode())
                time.sleep(0.1)
            except Exception as e:
                print("Fehler beim Senden der Difficulty:", e)
        elif data.startswith("GET_BLOCKINDEX"):
            try:
                blockindex = len(blockchain.chain)
                conn.sendall(str(blockindex).encode())
                time.sleep(0.1)
            except Exception as e:
                print("Fehler beim Senden des Blockindex:", e)
        elif data.startswith("GET_PREVHASH"):
            try:
                prev_hash = blockchain.get_latest_block().hash
                conn.sendall(prev_hash.encode())
                time.sleep(0.1)
            except Exception as e:
                print("Fehler beim Senden des vorherigen Hash:", e)
        elif data.startswith("NEW_BLOCK:"):
            try:
                block_data = json.loads(data.split("NEW_BLOCK:")[1])
                new_block = Block(
                    block_data["index"],
                    block_data["transactions"],
                    block_data["timestamp"],
                    block_data["previous_hash"],
                    block_data["nonce"]
                )
                accepted = blockchain.add_block(new_block)
                if accepted:
                    conn.sendall(b"BLOCK_ACCEPTED")
                else:
                    conn.sendall(b"BLOCK_REJECTED")
                print(f"Block {new_block.index} von {addr} verarbeitet.")
            except Exception as e:
                print("Fehler beim Verarbeiten des Blocks:", e)
                conn.sendall(b"BLOCK_REJECTED")
        elif data.startswith("NEW_TX:"):
            try:
                tx_data = json.loads(data.split("NEW_TX:")[1])
                if validate_transaction(tx_data, blockchain):
                    blockchain.add_transaction(tx_data)
                    print(f"Transaktion von {addr} empfangen und validiert.")
                else:
                    print(f"Ungültige Transaktion von {addr}:", tx_data)
            except Exception as e:
                print("Fehler beim Verarbeiten der Transaktion:", e)
        elif data.startswith("GET_CHAIN:"):
            try:
                chain_data = []
                with blockchain.lock:
                    for block in blockchain.chain:
                        chain_data.append(block.__dict__)
                response = json.dumps(chain_data)
                conn.sendall(response.encode())
                time.sleep(0.1)
            except Exception as e:
                print("Fehler beim Senden der Blockchain:", e)
        conn.close()

if __name__ == '__main__':
    blockchain = Blockchain(difficulty=5)
    server_thread = threading.Thread(target=blockchain_server, args=(5000, blockchain))
    server_thread.daemon = True
    server_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Server wird beendet.")
