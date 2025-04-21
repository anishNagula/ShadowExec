import os
import socket
import subprocess
import logging
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
import base64
import sys
import csv

# Create necessary directories
os.makedirs('logs', exist_ok=True)
os.makedirs('certificates', exist_ok=True)
ROOT_EXEC_DIR = "root_files"
os.makedirs(ROOT_EXEC_DIR, exist_ok=True)

# Basic logging setup, dumps into logs/server.log
logging.basicConfig(
    filename='logs/server.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Cert file paths (RSA keys)
PUBLIC_KEY_PATH = "certificates/server.pem"
PRIVATE_KEY_PATH = "certificates/server_private.pem"

# Path to users.csv (since server.py is in the 'server' folder, and users.csv is in the root directory)
USERS_FILE = "users.csv"  # The path goes one level up to the root directory

# Check if the server keys exist, otherwise generate them
if not os.path.exists(PUBLIC_KEY_PATH) or not os.path.exists(PRIVATE_KEY_PATH):
    logging.info("Generating server RSA keypair...")
    key = RSA.generate(2048)
    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(key.export_key())
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(key.publickey().export_key())
    logging.info("Server keys generated.")

# Load the private key for decrypting commands from the client
with open(PRIVATE_KEY_PATH, "rb") as f:
    private_key = RSA.import_key(f.read())
rsa_decryptor = PKCS1_OAEP.new(private_key)

# Function to add a user to the CSV file
def add_user(username, password):
    try:
        # Ensure the path is correct and the file is accessible
        users_file_path = os.path.abspath(USERS_FILE)
        logging.info(f"Attempting to add user to: {users_file_path}")

        if not os.path.exists(users_file_path):
            logging.info(f"{users_file_path} does not exist. Creating a new file.")
            # Create the CSV file if it does not exist
            with open(users_file_path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["username", "password"])  # Add headers

        # Check if the username already exists
        with open(users_file_path, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row["username"] == username:
                    logging.warning(f"Username '{username}' already exists.")
                    return "❌ Username already exists."

        # Add the new user to the CSV file
        with open(users_file_path, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([username, password])
        
        logging.info(f"User '{username}' added successfully.")
        return f"User '{username}' added."
    except Exception as e:
        logging.error(f"Error adding user: {e}")
        return f"❌ Error adding user: {e}"

# Get local IP address for LAN usage
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # Random external IP just to grab local address
        return s.getsockname()[0]
    except:
        return "127.0.0.1"  # Fallback to localhost
    finally:
        s.close()

# List of allowed commands to execute
SAFE_COMMANDS = {
    "whoami",
    "hostname",
    "uptime",
    "date",
    "time",
    "ifconfig",
    "ipconfig",
    "python",
    "getconf",
    "dir",           # Windows
    "ls",            # Linux/macOS
    "pwd",
    "echo",
    "uname",
    "shutdown",      # Will shutdown server, not the computer
    "exit",
    "quit",
    "clear"
}

# Check if the command is in our allowlist
def is_command_safe(cmd):
    cmd_parts = cmd.strip().split()
    base_cmd = cmd_parts[0].lower()
    return base_cmd in SAFE_COMMANDS

# Bind UDP socket to our local IP and port
SERVER_IP = get_local_ip()
PORT = 9999

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((SERVER_IP, PORT))

print(f"✅ Server is running on {SERVER_IP}:{PORT}")
logging.info(f"Server started on {SERVER_IP}:{PORT}")

# Server main loop
while True:
    try:
        data, client_addr = sock.recvfrom(8192)
        decrypted_cmd = rsa_decryptor.decrypt(data).decode().strip()

        logging.info(f"Received from {client_addr}: {decrypted_cmd}")
        print(f"[Client {client_addr}] CMD: {decrypted_cmd}")

        # Handling the 'adduser' command
        if decrypted_cmd.lower().startswith("adduser "):
            parts = decrypted_cmd.split()
            if len(parts) == 3:
                username = parts[1]
                password = parts[2]
                msg = add_user(username, password)
            else:
                msg = "❌ Usage: adduser <username> <password>"

        elif decrypted_cmd.lower() in {"exit", "quit", "shutdown"}:
            response_msg = "Server is shutting down safely..."
            logging.info(response_msg)
            print(f"[!] {response_msg}")

            aes_key = os.urandom(16)
            cipher_aes = AES.new(aes_key, AES.MODE_EAX)
            ciphertext, tag = cipher_aes.encrypt_and_digest(response_msg.encode())

            response = (
                base64.b64encode(aes_key) + b"|" +
                base64.b64encode(cipher_aes.nonce) + b"|" +
                base64.b64encode(tag) + b"|" +
                base64.b64encode(ciphertext)
            )
            sock.sendto(response, client_addr)
            sock.close()
            sys.exit(0)

        elif not is_command_safe(decrypted_cmd):
            msg = "❌ Command not allowed for security reasons."
            logging.warning(f"Blocked command from {client_addr}: {decrypted_cmd}")

        else:
            msg = subprocess.getoutput(decrypted_cmd)

        aes_key = os.urandom(16)
        cipher_aes = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(msg.encode())

        response = (
            base64.b64encode(aes_key) + b"|" +
            base64.b64encode(cipher_aes.nonce) + b"|" +
            base64.b64encode(tag) + b"|" +
            base64.b64encode(ciphertext)
        )
        sock.sendto(response, client_addr)

    except Exception as e:
        logging.error(f"Error: {e}")
        print(f"[!] Error occurred: {e}")
