import time
import random
import json
import hashlib
import socket
import sys
import os
import logging
import threading

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
        logging.error(f"Error while getting MinerID: {e}")
        sys.exit(1)

def send_authenticated_request(server_host, server_port, command, miner_id, token):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server_host, server_port))
            msg = f"{command}:{miner_id}:{token}"
            s.sendall(msg.encode())
            data = s.recv(4096)
            return data.decode()
    except Exception as e:
        logging.error(f"Error while get '{command}' to node: {e}")
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
        logging.error(f"Error ehile sending: {e}")

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

def mine_block_multithreaded(miner_id, token, block_index, previous_hash, difficulty, reward_address, num_threads):
    transactions = [{
        "sender": "SYSTEM",
        "recipient": reward_address,
        "amount": 1,
        "timestamp": time.time(),
        "type": "reward"
    }]
    base_block = Block(
        index=block_index,
        transactions=transactions,
        timestamp=time.time(),
        previous_hash=previous_hash
    )

    found_event = threading.Event()
    result = {"block": None, "iteration": 0, "hashes": 0}
    lock = threading.Lock()

    def worker(thread_idx):
        nonlocal result
        local_block = Block(
            index=base_block.index,
            transactions=base_block.transactions,
            timestamp=base_block.timestamp,
            previous_hash=base_block.previous_hash,
            nonce=random.randint(0, 100000) + thread_idx * 1000000
        )
        hashes = 0
        iteration = 0
        last_report = time.time()
        while not found_event.is_set():
            local_block.nonce += num_threads
            local_block.hash = local_block.calculate_hash()
            hashes += 1
            iteration += 1
            if local_block.hash.startswith("0" * difficulty):
                with lock:
                    if not found_event.is_set():
                        found_event.set()
                        result["block"] = Block(
                            index=local_block.index,
                            transactions=local_block.transactions,
                            timestamp=local_block.timestamp,
                            previous_hash=local_block.previous_hash,
                            nonce=local_block.nonce
                        )
                        result["block"].hash = local_block.hash
                        result["iteration"] = iteration
                        result["hashes"] = hashes
                break
            now = time.time()
            if now - last_report >= 1.0 and thread_idx == 0:
                mh_s = hashes / 1_000_000 / (now - last_report)
                sys.stdout.write(
                    f"\r[Thread {thread_idx}] Miner {miner_id} - Block {block_index} | Difficulty: {difficulty} | Iteration {iteration}, Nonce: {local_block.nonce}, Hashrate: {mh_s:.2f} MH/s, Hash-Preview: {local_block.hash[:20]}..."
                )
                sys.stdout.flush()
                hashes = 0
                last_report = now

    threads = []
    for i in range(num_threads):
        t = threading.Thread(target=worker, args=(i,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    sys.stdout.write("\n")
    return result["block"], result["iteration"]

def miner(miner_id, token, server_host, server_port, reward_address, difficulty=4, num_threads=1):
    while True:
        current_block_index = get_block_index_from_server(server_host, server_port, miner_id, token)
        current_previous_hash = get_prev_hash_from_server(server_host, server_port, miner_id, token)
        difficulty = get_difficulty_from_server(server_host, server_port, miner_id, token)

        new_block, iteration = mine_block_multithreaded(
            miner_id, token, current_block_index, current_previous_hash, difficulty, reward_address, num_threads
        )

        avg_hashrate = iteration / 1_000_000 / max(1, (time.time() - new_block.timestamp))
        logging.info(f"Miner {miner_id} mined Block {current_block_index} (Nonce: {new_block.nonce}, Iteration: {iteration}, Difficulty: {difficulty})")

        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((server_host, server_port))
            block_data = json.dumps(new_block.__dict__)
            msg = f"NEW_BLOCK:{miner_id}:{token}:{block_data}"
            client.send(msg.encode())
            response = client.recv(1024).decode()
            if response == "BLOCK_ACCEPTED":
                print(f"Miner {miner_id}: Block {current_block_index} accepted by node.")
            else:
                print(f"Miner {miner_id}: Block {current_block_index} invalid.")
        except Exception as e:
            logging.error(f"Miner {miner_id} couldnt send Block {current_block_index}: {e}")
        finally:
            client.close()

        report_hashrate_to_server(server_host, server_port, miner_id, token, avg_hashrate)
        time.sleep(1)

if __name__ == '__main__':
    server_host = "127.0.0.1"
    server_port = 5000

    try:
        num_threads = int(input("How many threads should be used? [1-32]: ").strip())
        if num_threads < 1:
            num_threads = 1
        if num_threads > 32:
            num_threads = 32
    except Exception:
        num_threads = 1

    miner_id, token = get_token_and_id(server_host, server_port)
    difficulty = get_difficulty_from_server(server_host, server_port, miner_id, token)
    print(f"Miner {miner_id} startet mit Difficulty {difficulty} und {num_threads} Thread(s)...")

    reward_address = input("Enter Adress, which will recieve the reward: ").strip()
    if not reward_address:
        print("Invalid Adress")
        sys.exit(1)
    miner(miner_id, token, server_host=server_host, server_port=server_port, reward_address=reward_address, difficulty=difficulty, num_threads=num_threads)
