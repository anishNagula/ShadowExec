import socket
import os
import subprocess
import logging
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
import base64
import sys

# create logs and cert folder if not already there
os.makedirs('logs', exist_ok=True)
os.makedirs('certificates', exist_ok=True)
ROOT_EXEC_DIR = "root_files"
os.makedirs(ROOT_EXEC_DIR, exist_ok=True)

# basic logging setup, dumps into logs/server.log
logging.basicConfig(
    filename='logs/server.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# cert file paths (RSA keys)
PUBLIC_KEY_PATH = "certificates/server.pem"
PRIVATE_KEY_PATH = "certificates/server_private.pem"

# generate RSA keypair if missing
if not os.path.exists(PUBLIC_KEY_PATH) or not os.path.exists(PRIVATE_KEY_PATH):
    logging.info("Generating server RSA keypair...")
    key = RSA.generate(2048)
    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(key.export_key())
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(key.publickey().export_key())
    logging.info("Server keys generated.")

# load the private key for decrypting cmds from client
with open(PRIVATE_KEY_PATH, "rb") as f:
    private_key = RSA.import_key(f.read())
rsa_decryptor = PKCS1_OAEP.new(private_key)

# get local IP addr, for 2 devices in local network (LAN)
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # random ext IP just to grab our local addr
        return s.getsockname()[0]
    except:
        return "127.0.0.1"  # fallback to localhost
    finally:
        s.close()

# allowed commands only –> to not exec anything dangerous
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

# check if the command is in our allowlist
def is_command_safe(cmd):
    cmd_parts = cmd.strip().split()
    base_cmd = cmd_parts[0].lower()
    return base_cmd in SAFE_COMMANDS

# bind UDP socket to our local IP and some port
SERVER_IP = get_local_ip()
PORT = 9999

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((SERVER_IP, PORT))

print(f"✅ Server is running on {SERVER_IP}:{PORT}")
logging.info(f"Server started on {SERVER_IP}:{PORT}")

# server main loop
while True:
    try:
        data, client_addr = sock.recvfrom(8192)
        decrypted_cmd = rsa_decryptor.decrypt(data).decode().strip()

        logging.info(f"Received from {client_addr}: {decrypted_cmd}")
        print(f"[Client {client_addr}] CMD: {decrypted_cmd}")

        if decrypted_cmd.lower() in {"exit", "quit", "shutdown"}:
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

        elif decrypted_cmd.lower().startswith("run "):
            filename = decrypted_cmd[4:].strip()
            filename = os.path.basename(filename)  # strip path parts
            filepath = os.path.join(ROOT_EXEC_DIR, filename)

            if os.path.isfile(filepath):
                try:
                    if os.name != 'nt':
                        subprocess.run(["chmod", "+x", filepath])
                    msg = subprocess.getoutput(filepath)
                except Exception as e:
                    msg = f"[!] Error running file: {str(e)}"
                    logging.error(msg)
            else:
                msg = f"[!] File '{filename}' not found in {ROOT_EXEC_DIR}/"

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