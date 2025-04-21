import socket
import os
import base64
import csv
import tkinter as tk
from tkinter import scrolledtext, messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES

# cert paths setup
os.makedirs('certificates', exist_ok=True)
PRIVATE_KEY_PATH = "certificates/client_private.pem"
PUBLIC_KEY_PATH = "certificates/client_public.pem"
SERVER_PUBLIC_PATH = "certificates/server.pem"
USERS_FILE = "users.csv"

# generate keys if missing
if not os.path.exists(PRIVATE_KEY_PATH) or not os.path.exists(PUBLIC_KEY_PATH):
    key = RSA.generate(2048)
    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(key.export_key())
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(key.publickey().export_key())

# load server public key
with open(SERVER_PUBLIC_PATH, "rb") as f:
    server_pub = RSA.import_key(f.read())

rsa_encryptor = PKCS1_OAEP.new(server_pub)

# initialize users file if not exists
if not os.path.exists(USERS_FILE):
    with open(USERS_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["username", "password"])

# GUI app
class SecureClientApp:
    def __init__(self, master):
        self.master = master
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(5)

        self.username = None
        self.show_login()

    def show_login(self):
        self.clear_window()
        self.master.title("🔐 Secure Remote Command Login")

        tk.Label(self.master, text="Username:").grid(row=0, column=0, padx=10, pady=5)
        self.username_entry = tk.Entry(self.master, width=30)
        self.username_entry.grid(row=0, column=1, padx=10, pady=5)

        tk.Label(self.master, text="Password:").grid(row=1, column=0, padx=10, pady=5)
        self.password_entry = tk.Entry(self.master, show="*", width=30)
        self.password_entry.grid(row=1, column=1, padx=10, pady=5)

        tk.Button(self.master, text="Login", command=self.login).grid(row=2, column=0, pady=10)
        tk.Button(self.master, text="Sign Up", command=self.sign_up).grid(row=2, column=1, pady=10)

    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not username or not password:
            messagebox.showerror("Error", "Please enter both fields.")
            return

        with open(USERS_FILE, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row["username"] == username and row["password"] == password:
                    self.username = username
                    self.build_main_gui()
                    return

        messagebox.showerror("Login Failed", "Invalid credentials.")

    def sign_up(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not username or not password:
            messagebox.showerror("Error", "Please enter both fields.")
            return

        with open(USERS_FILE, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row["username"] == username:
                    messagebox.showerror("Error", "Username already exists.")
                    return

        # Append new user data to CSV
        with open(USERS_FILE, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([username, password])
            messagebox.showinfo("Success", "User registered. You can log in now.")

    def build_main_gui(self):
        self.clear_window()
        self.master.title(f"🔐 Secure Command Client - {self.username}")
        self.master.geometry("700x500")

        tk.Label(self.master, text="Server IP:").grid(row=0, column=0, sticky="w", padx=10, pady=5)
        self.server_ip_entry = tk.Entry(self.master, width=25)
        self.server_ip_entry.insert(0, "127.0.0.1")
        self.server_ip_entry.grid(row=0, column=1, padx=10, pady=5, sticky="w")

        self.exit_button = tk.Button(self.master, text="Exit", width=10, command=self.safe_exit, bg="white", fg="black")
        self.exit_button.grid(row=0, column=3, sticky="e", padx=10)

        tk.Label(self.master, text="Command:").grid(row=1, column=0, sticky="nw", padx=10, pady=5)
        self.command_entry = tk.Text(self.master, height=3, width=60)
        self.command_entry.grid(row=1, column=1, columnspan=2, padx=10, pady=5)

        self.send_button = tk.Button(self.master, text="Send", width=12, command=self.send_command)
        self.send_button.grid(row=1, column=3, sticky="e", padx=10)

        tk.Label(self.master, text="Server Response:").grid(row=2, column=0, sticky="nw", padx=10, pady=5)
        self.response_box = scrolledtext.ScrolledText(self.master, height=20, width=80)
        self.response_box.grid(row=3, column=0, columnspan=4, padx=10, pady=5)
        self.response_box.config(state=tk.DISABLED)

    def send_command(self):
        server_ip = self.server_ip_entry.get().strip()
        command = self.command_entry.get("1.0", tk.END).strip()
        if not server_ip or not command:
            messagebox.showerror("Error", "Please fill in both fields.")
            return

        try:
            encrypted_cmd = rsa_encryptor.encrypt(command.encode())
            self.sock.sendto(encrypted_cmd, (server_ip, 9999))

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

    def clear_window(self):
        for widget in self.master.winfo_children():
            widget.destroy()

# launch
if __name__ == "__main__":
    root = tk.Tk()
    app = SecureClientApp(root)
    root.mainloop()
