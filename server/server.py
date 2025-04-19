import socket
import os
import subprocess
import logging
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
import base64
import sys

# === Ensure required folders exist ===
os.makedirs('logs', exist_ok=True)
os.makedirs('certificates', exist_ok=True)

# === Logging Setup ===
logging.basicConfig(
    filename='logs/server.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# === RSA Key Paths ===
PUBLIC_KEY_PATH = "certificates/server.pem"
PRIVATE_KEY_PATH = "certificates/server_private.pem"

# === Generate RSA Keys if Absent ===
if not os.path.exists(PUBLIC_KEY_PATH) or not os.path.exists(PRIVATE_KEY_PATH):
    logging.info("Generating server RSA keypair...")
    key = RSA.generate(2048)
    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(key.export_key())
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(key.publickey().export_key())
    logging.info("Server keys generated.")

# === Load Server Private Key ===
with open(PRIVATE_KEY_PATH, "rb") as f:
    private_key = RSA.import_key(f.read())
rsa_decryptor = PKCS1_OAEP.new(private_key)

# === Get Local IP Address ===
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except:
        return "127.0.0.1"
    finally:
        s.close()

# === Allowed Commands (Cross-platform safe subset) ===
SAFE_COMMANDS = {
    "whoami",
    "hostname",
    "uptime",
    "date",
    "time",
    "dir",           # Windows
    "ls",            # Linux/macOS
    "pwd",
    "echo",
    "uname",
    "shutdown",      # Will shutdown server, not machine
    "exit",
    "quit",
    "clear"          # Optional, cleans terminal output
}

def is_command_safe(cmd):
    cmd_parts = cmd.strip().split()
    base_cmd = cmd_parts[0].lower()
    return base_cmd in SAFE_COMMANDS

# === Server Setup ===
SERVER_IP = get_local_ip()
PORT = 9999

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((SERVER_IP, PORT))

print(f"✅ Server is running on {SERVER_IP}:{PORT}")
logging.info(f"Server started on {SERVER_IP}:{PORT}")

# === Main Loop ===
while True:
    try:
        data, client_addr = sock.recvfrom(8192)
        decrypted_cmd = rsa_decryptor.decrypt(data).decode().strip()

        logging.info(f"Received from {client_addr}: {decrypted_cmd}")
        print(f"[Client {client_addr}] CMD: {decrypted_cmd}")

        # Check for shutdown command
        if decrypted_cmd.lower() in {"exit", "quit", "shutdown"}:
            response_msg = "Server is shutting down safely..."
            logging.info(response_msg)
            print(f"[!] {response_msg}")

            # Encrypt and send shutdown response
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

        # Restrict commands to safe list
        if not is_command_safe(decrypted_cmd):
            msg = "❌ Command not allowed for security reasons."
            logging.warning(f"Blocked command from {client_addr}: {decrypted_cmd}")
        else:
            msg = subprocess.getoutput(decrypted_cmd)

        # Encrypt the response
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
