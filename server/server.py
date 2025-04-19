import socket
import subprocess
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64
import logging

# === Logging setup ===
os.makedirs("logs", exist_ok=True)
logging.basicConfig(filename='logs/server.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# === Load RSA keys ===
with open("certificates/server.key", "rb") as f:
    server_private_key = RSA.import_key(f.read())
decryptor = PKCS1_OAEP.new(server_private_key)

with open("certificates/client_public.pem", "rb") as f:
    client_public_key = RSA.import_key(f.read())
encryptor = PKCS1_OAEP.new(client_public_key)

# === Get local IP address ===
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Public DNS to determine outbound interface
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"  # fallback to localhost

local_ip = get_local_ip()

# === Start server ===
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind((local_ip, 9999))

print(f"🟢 Server running at IP address: {local_ip}:9999")
logging.info(f"Server started on {local_ip}:9999")

# === Allowlisted commands ===
ALLOWED = ["whoami", "ipconfig", "ifconfig", "dir", "ls", "echo", "ver", "hostname", "tasklist", "ps", "type", "cat", "pwd", "cd", "clear"]

# === Track working directories per client ===
client_dirs = {}

try:
    while True:
        data, addr = server_socket.recvfrom(4096)
        command = decryptor.decrypt(data).decode().strip()

        logging.info(f"Command received from {addr}: {command}")
        print(f"\n📩 From {addr} — Command: {command}")

        # === Handle handshake ===
        if command == "Connection Initiated":
            result = "🔐 Handshake successful. Secure channel established."

        # === Init working directory for new client ===
        elif addr not in client_dirs:
            client_dirs[addr] = os.getcwd()
            result = f"📍 Session started in: {client_dirs[addr]}"

        else:
            os.chdir(client_dirs[addr])

            # === Handle 'cd' ===
            if command.startswith("cd "):
                path = command[3:].strip()
                try:
                    os.chdir(path)
                    client_dirs[addr] = os.getcwd()
                    result = f"📁 Changed directory to: {client_dirs[addr]}"
                except Exception as e:
                    result = f"❌ Failed to change directory: {e}"

            # === Allowed commands ===
            elif any(command.split()[0].lower() == cmd for cmd in ALLOWED):
                result = subprocess.getoutput(command)

            # === Empty = show current directory ===
            elif command.strip() == "":
                result = f"📍 Current directory: {client_dirs[addr]}"

            else:
                result = "❌ Command not allowed."

        # === Hybrid Encryption Response ===
        aes_key = get_random_bytes(16)
        cipher_aes = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(result.encode())

        encrypted_key = encryptor.encrypt(aes_key)

        response = b"|".join([
            base64.b64encode(encrypted_key),
            base64.b64encode(cipher_aes.nonce),
            base64.b64encode(tag),
            base64.b64encode(ciphertext)
        ])

        server_socket.sendto(response, addr)
        print("✅ Encrypted response sent.")
        logging.info("Response sent securely.")

except KeyboardInterrupt:
    print("\n🛑 Server stopped manually.")
    logging.info("Server stopped by user.")
    server_socket.close()
