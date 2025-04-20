import socket
import os
import base64
import tkinter as tk
from tkinter import scrolledtext, messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES

# cert paths setup
os.makedirs('certificates', exist_ok=True)
PRIVATE_KEY_PATH = "certificates/client_private.pem"
PUBLIC_KEY_PATH = "certificates/client_public.pem"
SERVER_PUBLIC_PATH = "certificates/server.pem"

# gen keys if not there
if not os.path.exists(PRIVATE_KEY_PATH) or not os.path.exists(PUBLIC_KEY_PATH):
    key = RSA.generate(2048)
    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(key.export_key())
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(key.publickey().export_key())

# load our private + server's public key
with open(PRIVATE_KEY_PATH, "rb") as f:
    private_key = RSA.import_key(f.read())
with open(SERVER_PUBLIC_PATH, "rb") as f:
    server_pub = RSA.import_key(f.read())

rsa_encryptor = PKCS1_OAEP.new(server_pub)
rsa_decryptor = PKCS1_OAEP.new(private_key)

# ui class (tkinter)
class SecureClientApp:
    def __init__(self, master):
        self.master = master
        self.master.title("🔐 Secure Remote Command Client")
        self.master.geometry("700x500")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(5)  # to not hang

        self.build_gui()

    def build_gui(self):
        # server ip input
        tk.Label(self.master, text="Server IP:").grid(row=0, column=0, sticky="w", padx=10, pady=5)
        self.server_ip_entry = tk.Entry(self.master, width=25)
        self.server_ip_entry.insert(0, "127.0.0.1")
        self.server_ip_entry.grid(row=0, column=1, padx=10, pady=5, sticky="w")

        # quit btn
        self.exit_button = tk.Button(self.master, text="Exit", width=10, command=self.safe_exit, bg="white", fg="black")
        self.exit_button.grid(row=0, column=3, sticky="e", padx=10)

        # cmd input box
        tk.Label(self.master, text="Command:").grid(row=1, column=0, sticky="nw", padx=10, pady=5)
        self.command_entry = tk.Text(self.master, height=3, width=60)
        self.command_entry.grid(row=1, column=1, columnspan=2, padx=10, pady=5)

        # send btn
        self.send_button = tk.Button(self.master, text="Send", width=12, command=self.send_command)
        self.send_button.grid(row=1, column=3, sticky="e", padx=10)

        # resp box
        tk.Label(self.master, text="Server Response:").grid(row=2, column=0, sticky="nw", padx=10, pady=5)
        self.response_box = scrolledtext.ScrolledText(self.master, height=20, width=80)
        self.response_box.grid(row=3, column=0, columnspan=4, padx=10, pady=5)
        self.response_box.config(state=tk.DISABLED)

    def send_command(self):
        server_ip = self.server_ip_entry.get().strip()
        if not server_ip:
            messagebox.showerror("Error", "Please enter the server IP address.")
            return

        command = self.command_entry.get("1.0", tk.END).strip()
        if not command:
            messagebox.showerror("Error", "Please enter a command.")
            return

        try:
            # encrypt cmd w/ server’s public key
            encrypted_cmd = rsa_encryptor.encrypt(command.encode())
            self.sock.sendto(encrypted_cmd, (server_ip, 9999))

            # recv response and decrypt using AES
            response, _ = self.sock.recvfrom(8192)
            enc_key_b64, nonce_b64, tag_b64, ciphertext_b64 = response.split(b"|")

            aes_key = base64.b64decode(enc_key_b64)
            nonce = base64.b64decode(nonce_b64)
            tag = base64.b64decode(tag_b64)
            ciphertext = base64.b64decode(ciphertext_b64)

            cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
            decrypted_response = cipher.decrypt_and_verify(ciphertext, tag).decode()

            self.append_response(f">>> {command}\n{decrypted_response}\n\n")
        except Exception as e:
            self.append_response(f"[!] Error: {str(e)}\n")

    def append_response(self, text):
        self.response_box.config(state=tk.NORMAL)
        self.response_box.insert(tk.END, text)
        self.response_box.see(tk.END)
        self.response_box.config(state=tk.DISABLED)

    def safe_exit(self):
        try:
            self.sock.close()
        except:
            pass
        self.master.quit()

# main loop
if __name__ == "__main__":
    root = tk.Tk()
    app = SecureClientApp(root)
    root.mainloop()
