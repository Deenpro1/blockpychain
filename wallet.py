import time
import json
import socket
import sys
from ecdsa import SigningKey, SECP256k1

class Wallet:
    def __init__(self, private_key_hex=None):
        if private_key_hex:
            try:
                self.private_key = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
            except Exception as e:
                print("Key load error:", e)
                raise
        else:
            self.private_key = SigningKey.generate(curve=SECP256k1)
        self.public_key = self.private_key.get_verifying_key()

    def get_address(self):
        return self.public_key.to_string().hex()

    def get_private_key(self):
        return self.private_key.to_string().hex()

    def sign_transaction(self, transaction: dict) -> str:
        tx_str = json.dumps(transaction, sort_keys=True)
        signature = self.private_key.sign(tx_str.encode())
        return signature.hex()

    def create_transaction(self, recipient: str, amount: float) -> dict:
        transaction = {
            "sender": self.get_address(),
            "recipient": recipient,
            "amount": amount,
            "timestamp": time.time(),
            "type": "transfer"
        }
        transaction["signature"] = self.sign_transaction(transaction)
        return transaction

def send_transaction_to_node(transaction: dict, server_host="127.0.0.1", server_port=5000):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        try:
            client.connect((server_host, server_port))
            tx_data = json.dumps(transaction)
            client.send(f"NEW_TX:{tx_data}".encode())
            print("Transaction sent to node.")
        except Exception as e:
            print("Send error:", e)

def get_blockchain_from_node(server_host="127.0.0.1", server_port=5000):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        try:
            client.connect((server_host, server_port))
            client.send("GET_CHAIN:".encode())
            response = b""
            while True:
                data = client.recv(4096)
                if not data:
                    break
                response += data
            return json.loads(response.decode())
        except Exception as e:
            print("Blockchain fetch error:", e)
            return []

def compute_balance(chain_data, address):
    balance = 0.0
    for block in chain_data:
        for tx in block.get("transactions", []):
            if isinstance(tx, dict):
                if tx.get("recipient") == address:
                    balance += float(tx.get("amount", 0))
                if tx.get("sender") == address:
                    balance -= float(tx.get("amount", 0))
    return balance

def get_transaction_history(chain_data, address):
    history = []
    for block in chain_data:
        for tx in block.get("transactions", []):
            if isinstance(tx, dict):
                if tx.get("sender") == address or tx.get("recipient") == address:
                    history.append(tx)
    return history

def print_transaction_history(history, my_address):
    if not history:
        print("Couldn´t find any transactions.")
        return
    for i, tx in enumerate(history, 1):
        sender = "My Adress" if tx.get("sender") == my_address else tx.get("sender")
        recipient = "My Adress" if tx.get("recipient") == my_address else tx.get("recipient")
        amount = tx.get("amount")
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(tx.get("timestamp", 0)))
        print(f"{i}. {timestamp} | From: {sender} | TO: {recipient} | Amount: {amount}")

def main():
    print("Welcome to your Wallet!")
    use_existing = input("Use existing private key? (j/n): ").strip().lower()
    if use_existing == 'j':
        private_key_hex = input("Enter your private key: ").strip()
        try:
            wallet = Wallet(private_key_hex=private_key_hex)
        except Exception:
            print("Couldn't load wallet. Creating new one.")
            wallet = Wallet()
    else:
        wallet = Wallet()

    print("\nWallet created!")
    print("Your address:")
    print(wallet.get_address())
    print("\nSave your private key:")
    print(wallet.get_private_key())

    menu = """
Options:
1. New Transaction
2. Show Address
3. Show Private Key
4. Show Balance
5. Show Transaction History
6. Exit
"""
    while True:
        print(menu)
        choice = input("Your choice: ").strip()
        if choice == "1":
            recipient = input("Recipient address: ").strip()
            amount_str = input("Amount (e.g. 1.0): ").strip()
            try:
                amount = float(amount_str)
            except ValueError:
                print("Invalid amount!")
                continue
            tx = wallet.create_transaction(recipient, amount)
            print("Transaction created:")
            print(json.dumps(tx, indent=4))
            send_transaction_to_node(tx)
        elif choice == "2":
            print("Your address:")
            print(wallet.get_address())
        elif choice == "3":
            print("Your private key:")
            print(wallet.get_private_key())
        elif choice == "4":
            print("Fetching blockchain...")
            chain_data = get_blockchain_from_node()
            balance = compute_balance(chain_data, wallet.get_address())
            print(f"Your balance: {balance} Token")
        elif choice == "5":
            print("Transaction history is loading...")
            chain_data = get_blockchain_from_node()
            history = get_transaction_history(chain_data, wallet.get_address())
            print_transaction_history(history, wallet.get_address())
        elif choice == "6":
            print("Exiting...")
            sys.exit(0)
        else:
            print("Invalid choice.")

if __name__ == '__main__':
    main()
