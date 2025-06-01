# blockpychain

A simple Python-based blockchain implementation with mining, wallet, and admin functionality.

---

## Installation

1. **Clone the repository**
`git clone https://github.com/deenpro1/blockpychain.git`


2. **Install dependencies**
   Make sure you have Python 3.8+ installed.
`pip install -r requirements.txt`


3. **Start the node**
`python node.py`

   The node will generate an admin password and print it to the console on first start. Save this password securely; you will need it for admin actions.

4. **(Optional) Start the admin console**
`python admin.py`
You will be prompted for the admin password.


---

## Q&A

**Q: How do I mine blocks?**  
A: Use the `miner.py` script to connect to the node and start mining. Make sure the node is running.

**Q: How do I send tokens as admin?**  
A: Start `admin.py`, enter the admin password (shown when the node starts), and use the command `send <recipient> <amount>`.

**Q: Where is the blockchain data stored?**  
A: The blockchain and token data are stored in the current directory as files like `miner_tokens.json` and `blockchain.log`.

**Q: What dependencies are required?**  
A: Only the `ecdsa` package is required. All other modules are part of the Python standard library.

**Q: How do I reset the admin password?**  
A: Delete the `admin_password.txt` file (if implemented) or restart the node to generate a new password. Be aware that this may affect admin access.

**Q: How do I connect a wallet or explorer?**  
A: Use `wallet.py` or `block_explorer.py` to interact with the node. Make sure the node is running and reachable.

---

For further questions, please check the code comments or open an issue.
