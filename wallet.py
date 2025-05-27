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
                print("Fehler beim Laden des privaten Schlüssels:", e)
                raise
        else:
            self.private_key = SigningKey.generate(curve=SECP256k1)
        self.public_key = self.private_key.get_verifying_key()

    def get_address(self):
        """Gibt die Wallet-Adresse (hexadezimale Darstellung des öffentlichen Schlüssels) zurück."""
        return self.public_key.to_string().hex()

    def get_private_key(self):
        """Gibt den privaten Schlüssel als Hexadezimalstring zurück. Bewahre ihn sicher auf!"""
        return self.private_key.to_string().hex()

    def sign_transaction(self, transaction: dict) -> str:
        """Signiert eine Transaktion (als JSON-String) und gibt die Signatur zurück."""
        tx_str = json.dumps(transaction, sort_keys=True)
        signature = self.private_key.sign(tx_str.encode())
        return signature.hex()

    def create_transaction(self, recipient: str, amount: float) -> dict:
        """Erzeugt und signiert eine neue Transfer-Transaktion."""
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
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((server_host, server_port))
        tx_data = json.dumps(transaction)
        client.send(f"NEW_TX:{tx_data}".encode())
        print("Transaktion erfolgreich an den Node gesendet.")
    except Exception as e:
        print("Fehler beim Senden der Transaktion:", e)
    finally:
        client.close()

def get_blockchain_from_node(server_host="127.0.0.1", server_port=5000):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((server_host, server_port))
        client.send("GET_CHAIN:".encode())
        response = ""
        while True:
            data = client.recv(4096)
            if not data:
                break
            response += data.decode()
        chain_data = json.loads(response)
        return chain_data
    except Exception as e:
        print("Fehler beim Abrufen der Blockchain:", e)
        return []
    finally:
        client.close()

def compute_balance(chain_data, address):
    balance = 0.0
    for block in chain_data:
        transactions = block.get("transactions", [])
        for tx in transactions:
            if isinstance(tx, dict):
                if tx.get("recipient") == address:
                    balance += float(tx.get("amount", 0))
                if tx.get("sender") == address:
                    balance -= float(tx.get("amount", 0))
    return balance

def main():
    print("Willkommen in deiner Wallet!")
    use_existing = input("Möchtest du einen bestehenden privaten Schlüssel verwenden? (j/n): ").strip().lower()
    if use_existing == 'j':
        private_key_hex = input("Gib deinen privaten Schlüssel (Hex) ein: ").strip()
        try:
            wallet = Wallet(private_key_hex=private_key_hex)
        except Exception:
            print("Konnte Wallet nicht laden. Es wird eine neue Wallet erstellt.")
            wallet = Wallet()
    else:
        wallet = Wallet()

    print("\nWallet erstellt!")
    print("Deine Wallet-Adresse lautet:")
    print(wallet.get_address())
    print("\nSpeichere deinen privaten Schlüssel (bewahre ihn sicher auf!):")
    print(wallet.get_private_key())
    
    menu = """
Optionen:
1. Transaktion erstellen und senden
2. Wallet-Adresse anzeigen
3. Privaten Schlüssel anzeigen
4. Balance anzeigen
5. Programm beenden
"""
    while True:
        print(menu)
        choice = input("Deine Auswahl: ").strip()
        if choice == "1":
            recipient = input("Empfänger-Adresse: ").strip()
            amount_str = input("Betrag (z.B. 1.0): ").strip()
            try:
                amount = float(amount_str)
            except ValueError:
                print("Ungültiger Betrag!")
                continue
            tx = wallet.create_transaction(recipient, amount)
            print("Erzeugte Transaktion:")
            print(json.dumps(tx, indent=4))
            send_transaction_to_node(tx)
        elif choice == "2":
            print("Deine Wallet-Adresse lautet:")
            print(wallet.get_address())
        elif choice == "3":
            print("Dein privater Schlüssel (bewahre ihn sicher auf!):")
            print(wallet.get_private_key())
        elif choice == "4":
            print("Abrufen der Blockchain vom Node...")
            chain_data = get_blockchain_from_node()
            balance = compute_balance(chain_data, wallet.get_address())
            print(f"Dein aktueller Kontostand beträgt: {balance} Token")
        elif choice == "5":
            print("Programm wird beendet.")
            sys.exit(0)
        else:
            print("Ungültige Auswahl, bitte erneut versuchen.")

if __name__ == '__main__':
    main()
