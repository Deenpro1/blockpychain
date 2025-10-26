import time
import threading
import hashlib
import json
import socket
import uuid
import os
import logging
from ecdsa import VerifyingKey, SECP256k1, BadSignatureError
import uuid

ADMIN_PASSWORD = uuid.uuid4().hex
print(f"Admin-Password: {ADMIN_PASSWORD}")

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("blockchain.log"),
        logging.StreamHandler()
    ]
)

next_miner_id = 1
miner_id_lock = threading.Lock()
active_miners = set()
miner_hashrates = {}
miner_tokens = {}
TOKEN_FILE = "miner_tokens.json"
TARGET_BLOCK_TIME = 100
MIN_DIFFICULTY = 10
MAX_DIFFICULTY = 100
MAX_CONNECTIONS = 20
CONNECTION_TIMEOUT = 10

def save_tokens():
    with open(TOKEN_FILE, "w") as f:
        json.dump(miner_tokens, f)

def load_tokens():
    global miner_tokens
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, "r") as f:
            miner_tokens = json.load(f)
    else:
        miner_tokens = {}

load_tokens()

class Block:
    def __init__(self, index, transactions, timestamp, previous_hash, nonce=0):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        try:
            block_string = json.dumps({
                "index": self.index,
                "transactions": self.transactions,
                "timestamp": self.timestamp,
                "previous_hash": self.previous_hash,
                "nonce": self.nonce
            }, sort_keys=True).encode()
            return hashlib.sha256(block_string).hexdigest()
        except Exception as e:
            logging.error(f"Error while hashing: {e}")
            return ""

class Blockchain:
    def __init__(self, difficulty=3):
        self.chain = [self.create_genesis_block()]
        self.difficulty = difficulty
        self.lock = threading.Lock()
        self.pending_transactions = []
        self.last_block_time = time.time()
        self.seen_tx_hashes = set()

    def create_genesis_block(self):
        return Block(0, ["Genesis Block"], time.time(), "0")

    def get_latest_block(self):
        with self.lock:
            return self.chain[-1]

    def add_block(self, block):
        with self.lock:
            try:
                if block.previous_hash != self.chain[-1].hash:
                    logging.warning("Didn´t accept Block: Wrongh prev_hash!")
                    return False
                if block.hash != block.calculate_hash():
                    logging.warning("Didn´t accept Block: wrong Hash!")
                    return False
                if not block.hash.startswith('0' * self.difficulty):
                    logging.warning("Didn´t accept Block: Difficulty not reached!")
                    return False
                for tx in block.transactions:
                    if isinstance(tx, dict):
                        tx_hash = self._tx_hash(tx)
                        if tx_hash in self.seen_tx_hashes:
                            logging.warning("Didn´t accept Block: Multiple Transactions recogmized!")
                            return False
                self.chain.append(block)
                for tx in block.transactions:
                    if isinstance(tx, dict):
                        self.seen_tx_hashes.add(self._tx_hash(tx))
                self.pending_transactions = []
                logging.info(f"Block {block.index} added. Blockchain lenght: {len(self.chain)}")
                previous_block_time = self.last_block_time
                self.last_block_time = time.time()
                self.adjust_difficulty(previous_block_time)
                return True
            except Exception as e:
                logging.error(f"Error while adding Block: {e}")
                return False

    def add_transaction(self, transaction):
        with self.lock:
            try:
                tx_hash = self._tx_hash(transaction)
                if tx_hash in self.seen_tx_hashes:
                    logging.warning(f"Transaction not accepted: Replay/Double-Spend recognized! {transaction}")
                    return False
                self.pending_transactions.append(transaction)
                logging.info(f"Transaction was put to the Pending-List: {transaction}")
                return True
            except Exception as e:
                logging.error(f"Error while adding Transaction: {e}")
                return False

    def adjust_difficulty(self, previous_block_time):
        try:
            if not miner_hashrates:
                return
            avg_hashrate = sum(miner_hashrates.values()) / len(miner_hashrates)
            logging.info(f"Avrage Hashrate: {avg_hashrate:.1f} KH/s")
            if len(self.chain) > 1:
                actual_time = self.last_block_time - previous_block_time
            else:
                actual_time = TARGET_BLOCK_TIME
            logging.info(f"Zeit seit letztem Block: {actual_time:.2f} s (Ziel: {TARGET_BLOCK_TIME}s)")
            if actual_time < TARGET_BLOCK_TIME * 0.8 and self.difficulty < MAX_DIFFICULTY:
                self.difficulty += 2
                logging.info(f"Difficulty rised to {self.difficulty}")
            elif actual_time > TARGET_BLOCK_TIME * 1.2 and self.difficulty > MIN_DIFFICULTY:
                self.difficulty -= 1
                logging.info(f"Difficulty lowed to {self.difficulty}")
        except Exception as e:
            logging.error(f"Error while changing difficulty: {e}")

    def _tx_hash(self, tx):
        try:
            tx_copy = dict(tx)
            tx_copy.pop("signature", None)
            return hashlib.sha256(json.dumps(tx_copy, sort_keys=True).encode()).hexdigest()
        except Exception as e:
            logging.error(f"Error while calculating hash: {e}")
            return ""

def compute_balance(address, blockchain):
    balance = 0.0
    with blockchain.lock:
        for block in blockchain.chain:
            for tx in block.transactions:
                if isinstance(tx, dict):
                    if tx.get("recipient") == address:
                        try:
                            balance += float(tx.get("amount", 0))
                        except Exception:
                            continue
                    if tx.get("sender") == address:
                        try:
                            balance -= float(tx.get("amount", 0))
                        except Exception:
                            continue
    return balance

def validate_transaction(tx, blockchain):
    required_fields = ["sender", "recipient", "amount", "timestamp", "type"]
    for field in required_fields:
        if field not in tx:
            logging.warning(f"In Transaction field is missing: {field}")
            return False

    try:
        amount = float(tx["amount"])
        if amount <= 0:
            logging.warning("The amount must be bigger than 0.")
            return False
    except Exception:
        logging.warning("Invalid amount.")
        return False

    if tx["type"] == "reward":
        if tx.get("sender") != "SYSTEM":
            logging.warning("Reward-Transaction must come frome SYSTEM.")
            return False
        if amount != 1:
            logging.warning("Reward-Transaction must be 1 Token.")
            return False
        return True

    if "signature" not in tx:
        logging.warning("Transfer-Transakcions need a signature.")
        return False

    signature_hex = tx["signature"]
    try:
        signature = bytes.fromhex(signature_hex)
        public_key_bytes = bytes.fromhex(tx["sender"])
        verifying_key = VerifyingKey.from_string(public_key_bytes, curve=SECP256k1)
    except Exception as e:
        logging.warning(f"Error while getting key: {e}")
        return False

    tx_copy = tx.copy()
    del tx_copy["signature"]
    tx_str = json.dumps(tx_copy, sort_keys=True)
    try:
        verifying_key.verify(signature, tx_str.encode())
    except BadSignatureError:
        logging.warning("The signature isn´t valid.")
        return False
    except Exception as e:
        logging.warning(f"Error while checking Signature: {e}")
        return False

    sender_balance = compute_balance(tx["sender"], blockchain)
    if sender_balance < amount:
        logging.warning(f"Invalid Balance for {tx['sender']}. Balance: {sender_balance}, but needed: {amount}")
        return False

    return True

def check_token(miner_id, token):
    return str(miner_id) in miner_tokens and miner_tokens[str(miner_id)] == token

def blockchain_server(port, blockchain):
    global next_miner_id, active_miners, miner_hashrates, miner_tokens
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.settimeout(CONNECTION_TIMEOUT)
    server.bind(("0.0.0.0", port))
    server.listen(MAX_CONNECTIONS)
    logging.info(f"Blockchain-Server is running and port = {port}... (max. {MAX_CONNECTIONS} Verbindungen)")

    while True:
        try:
            conn, addr = server.accept()
            conn.settimeout(CONNECTION_TIMEOUT)
            try:
                data = conn.recv(4096).decode()
                if not data:
                    conn.close()
                    continue
                    
                if data.startswith("GET_MINERID"):
                    try:
                        with miner_id_lock:
                            miner_id = next_miner_id
                            next_miner_id += 1
                        token = str(uuid.uuid4())
                        miner_tokens[str(miner_id)] = token
                        save_tokens()
                        active_miners.add(miner_id)
                        response = json.dumps({"miner_id": miner_id, "token": token})
                        conn.sendall(response.encode())
                        time.sleep(0.1)
                    except Exception as e:
                        logging.error(f"Error while giving MinerID: {e}")

                
                elif data.startswith("ADMIN_SEND:"):
                    # Format: ADMIN_SEND:<recipient>:<amount>:<password>
                    parts = data.strip().split(":")
                    if len(parts) == 4:
                        _, recipient, amount, password = parts
                        if password != ADMIN_PASSWORD:
                            conn.sendall(b"ADMIN_TX_UNAUTHORIZED")
                            logging.warning("Admin-Transaction: Invalid Passwort.")
                            continue
                        try:
                            amount = float(amount)
                            tx = {
                                "sender": "SYSTEM",
                                "recipient": recipient,
                                "amount": amount,
                                "timestamp": time.time(),
                                "type": "reward"
                            }
                            with blockchain.lock:
                                blockchain.add_transaction(tx)
                            conn.sendall(b"ADMIN_TX_ACCEPTED")
                            logging.info(f"Admin-Transaction: SYSTEM -> {recipient} ({amount})")
                        except Exception as e:
                            conn.sendall(b"ADMIN_TX_ERROR")
                            logging.error(f"Error in ADMIN_SEND: {e}")
                    else:
                        conn.sendall(b"ADMIN_TX_ERROR")
                
                elif data.startswith("GET_BLOCKINDEX:"):
                    parts = data.strip().split(":")
                    if len(parts) == 3:
                        _, miner_id, token = parts
                        if not check_token(miner_id, token):
                            conn.sendall(b"UNAUTHORIZED")
                            continue
                        blockindex = len(blockchain.chain)
                        conn.sendall(str(blockindex).encode())
                        time.sleep(0.1)
                elif data.startswith("GET_PREVHASH:"):
                    parts = data.strip().split(":")
                    if len(parts) == 3:
                        _, miner_id, token = parts
                        if not check_token(miner_id, token):
                            conn.sendall(b"UNAUTHORIZED")
                            continue
                        prev_hash = blockchain.get_latest_block().hash
                        conn.sendall(prev_hash.encode())
                        time.sleep(0.1)
                elif data.startswith("GET_DIFFICULTY:"):
                    parts = data.strip().split(":")
                    if len(parts) == 3:
                        _, miner_id, token = parts
                        if not check_token(miner_id, token):
                            conn.sendall(b"UNAUTHORIZED")
                            continue
                        conn.sendall(str(blockchain.difficulty).encode())
                        time.sleep(0.1)

                elif data.startswith("GET_MINERS"):
                    logging.info(f"GET_MINERS von {addr}")
                    conn.sendall(json.dumps(list(active_miners)).encode())
                    time.sleep(0.1)

                elif data.startswith("NEW_BLOCK:"):
                    
                    parts = data.split(":", 3)
                    if len(parts) != 4:
                        conn.sendall(b"BLOCK_REJECTED")
                        continue
                    _, miner_id, token, block_json = parts
                    if not check_token(miner_id, token):
                        logging.warning("Block invalid: Invalid Token")
                        conn.sendall(b"BLOCK_REJECTED")
                        continue
                    block_data = json.loads(block_json)
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
                    logging.info(f"Block {new_block.index} von {addr} verarbeitet.")

                elif data.startswith("NEW_TX:"):
                    try:
                        tx_data = json.loads(data.split("NEW_TX:")[1])
                        if validate_transaction(tx_data, blockchain):
                            blockchain.add_transaction(tx_data)
                            logging.info(f"Transaction from {addr} valid.")
                        else:
                            logging.warning(f"Invalid Transaction from {addr}: {tx_data}")
                    except Exception as e:
                        logging.error(f"Error while validation Transaction: {e}")

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
                        logging.error(f"Error while sending chain: {e}")

                elif data.startswith("GET_ADDRESS:"):
                    try:
                        address = data.split(":", 1)[1]
                        balance = 0.0
                        transactions = []
                        with blockchain.lock:
                            for block in blockchain.chain:
                                for tx in block.transactions:
                                    if isinstance(tx, dict):
                                        if tx.get("recipient") == address:
                                            balance += float(tx.get("amount", 0))
                                            transactions.append(tx)
                                        elif tx.get("sender") == address:
                                            balance -= float(tx.get("amount", 0))
                                            transactions.append(tx)
                        response = json.dumps({"address": address, "balance": balance, "transactions": transactions})
                        conn.sendall(response.encode())
                        # Optional: Logging
                        logging.info(f"GET_ADDRESS für {address} von {addr}")
                    except Exception as e:
                        logging.error(f"Error in GET_ADDRESS: {e}")

                elif data.startswith("REPORT_HASHRATE:"):
                    # Format: REPORT_HASHRATE:<miner_id>:<token>:<hashrate>
                    parts = data.strip().split(":")
                    if len(parts) == 4:
                        _, miner_id, token, hashrate = parts
                        if not check_token(miner_id, token):
                            logging.warning("Invalid Hashrate: Invalid Token!")
                            continue
                        miner_hashrates[int(miner_id)] = float(hashrate)
                        logging.info(f"Hashrate from Miner {miner_id} aktualisiert: {float(hashrate):.2f} MH/s")
            except Exception as e:
                logging.error(f"Error while connectiong to miner {addr}: {e}")
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
        except socket.timeout:
            continue
        except Exception as e:
            logging.error(f"Fehler im Hauptserver-Loop: {e}")

if __name__ == '__main__':
    blockchain = Blockchain(difficulty=5)
    server_thread = threading.Thread(target=blockchain_server, args=(5000, blockchain))
    server_thread.daemon = True
    server_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Closing Server.")
        logging.info("Closing Server.")



