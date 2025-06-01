import socket

def admin_console():
    admin_password = input("Type admin password from node: ").strip()
    print("Admin-Console is runnming. Send coins with: send <reciever> <amount>")
    while True:
        try:
            cmd = input("admin> ").strip()
            if cmd.startswith("send "):
                parts = cmd.split()
                if len(parts) != 3:
                    print("Syntax: send <reciever> <amount>")
                    continue
                recipient = parts[1]
                try:
                    amount = float(parts[2])
                except Exception:
                    print("Amount must be a number.")
                    continue

                
                try:
                    with socket.create_connection(("127.0.0.1", 5000), timeout=5) as s:
                        msg = f"ADMIN_SEND:{recipient}:{amount}:{admin_password}"
                        s.sendall(msg.encode())
                        response = s.recv(4096).decode()
                        if response == "ADMIN_TX_ACCEPTED":
                            print(f"Transaction: SYSTEM -> {recipient} ({amount}) was added.")
                        elif response == "ADMIN_TX_UNAUTHORIZED":
                            print("Wrong Admin Password.")
                        else:
                            print("Transaction error.")
                except Exception as e:
                    print(f"Error while connecting to Node: {e}")

            elif cmd in ("exit", "quit"):
                print("Admin-Console exiting...")
                break
            else:
                print("Ungültige Aktion.")
        except Exception as e:
            print(f"Error in admin console: {e}")

if __name__ == '__main__':
    admin_console()
