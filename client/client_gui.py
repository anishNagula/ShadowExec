import tkinter as tk
from tkinter import scrolledtext, messagebox
import socket
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
import logging
import os
import traceback

# === Logging setup ===
os.makedirs("logs", exist_ok=True)
logging.basicConfig(filename='logs/client.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def show_error_popup(title, msg):
    try:
        temp_root = tk.Tk()
        temp_root.withdraw()
        messagebox.showerror(title, msg)
        temp_root.destroy()
    except Exception as e:
        print(f"[!] GUI Error: {e}")
        print(msg)

print("✅ Client is starting...")
logging.info("Client script starting...")

# === Ensure certificate folder exists ===
os.makedirs("certificates", exist_ok=True)

# === Key generation/loading ===
client_private_path = "certificates/client_private.pem"
client_public_path = "certificates/client_public.pem"
server_pub_path = "certificates/server.pem"

try:
    if not os.path.exists(client_private_path) or not os.path.exists(client_public_path):
        logging.info("Generating new RSA keypair for client...")
        key = RSA.generate(2048)
        with open(client_private_path, "wb") as f:
            f.write(key.export_key())
        with open(client_public_path, "wb") as f:
            f.write(key.publickey().export_key())
        logging.info("Generated client keys.")
    else:
        logging.info("Found existing client keys.")

    with open(client_private_path, "rb") as f:
        client_private_key = RSA.import_key(f.read())
    decryptor = PKCS1_OAEP.new(client_private_key)

    if not os.path.exists(server_pub_path):
        raise FileNotFoundError("Server public key (server.pem) not found.")

    with open(server_pub_path, "rb") as f:
        server_public_key = RSA.import_key(f.read())
    encryptor = PKCS1_OAEP.new(server_public_key)

    logging.info("RSA keys loaded successfully.")
    print("✅ RSA keys loaded successfully")

except Exception as e:
    traceback.print_exc()
    logging.error(f"RSA Key Error: {e}")
    show_error_popup("Key Error", f"Failed to load or generate RSA keys:\n{e}")
    exit(1)

# === UDP Socket Setup ===
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_addr = None

# === Command history tracking ===
command_history = []
history_index = -1

def connect_to_server():
    global server_addr
    server_ip = ip_entry.get().strip()
    if not server_ip:
        show_error_popup("Error", "Please enter the server IP address")
        return

    try:
        server_addr = (server_ip, 9999)
        test_message = "Connection Initiated".encode()
        encrypted_msg = encryptor.encrypt(test_message)
        sock.sendto(encrypted_msg, server_addr)
        logging.info(f"Sent encrypted handshake to {server_ip}:9999")

        response, _ = sock.recvfrom(8192)
        logging.info(f"Received response from server")

        parts = response.split(b"|")
        if len(parts) != 4:
            raise ValueError("Invalid response format from server.")

        enc_key = base64.b64decode(parts[0])
        nonce = base64.b64decode(parts[1])
        tag = base64.b64decode(parts[2])
        ciphertext = base64.b64decode(parts[3])

        aes_key = decryptor.decrypt(enc_key)
        cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        decrypted_msg = cipher_aes.decrypt_and_verify(ciphertext, tag).decode()

        messagebox.showinfo("✅ Connected", f"Server Response:\n{decrypted_msg}")
        logging.info(f"Server response: {decrypted_msg}")
        status_label.config(text=f"Connected to {server_ip}")

    except Exception as e:
        server_addr = None
        logging.error(f"Connection error: {e}")
        traceback.print_exc()
        show_error_popup("❌ Connection Error", f"Failed to connect: {e}")
        status_label.config(text="Disconnected")

def send_command():
    global server_addr, command_history, history_index
    if not server_addr:
        show_error_popup("Error", "Please connect to the server first!")
        return

    command = cmd_entry.get().strip()
    if not command:
        return

    try:
        status_label.config(text="🔐 Encrypting & Sending...")
        root.update_idletasks()
        logging.info(f"Sending command: {command}")

        encrypted_cmd = encryptor.encrypt(command.encode())
        sock.sendto(encrypted_cmd, server_addr)

        data, _ = sock.recvfrom(8192)
        logging.info("Received encrypted response from server")

        enc_key_b64, nonce_b64, tag_b64, ciphertext_b64 = data.split(b"|")
        aes_key = decryptor.decrypt(base64.b64decode(enc_key_b64))
        cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=base64.b64decode(nonce_b64))
        decrypted_msg = cipher_aes.decrypt_and_verify(base64.b64decode(ciphertext_b64), base64.b64decode(tag_b64)).decode()

        output_box.insert(tk.END, f"\n[~] $ {command}\n{decrypted_msg}\n", "response")
        output_box.see(tk.END)
        status_label.config(text="✅ Ready")

        if command not in command_history:
            command_history.append(command)
        history_index = len(command_history)

    except Exception as e:
        logging.error(f"Command error: {e}")
        traceback.print_exc()
        output_box.insert(tk.END, f"\n[!] ERROR: {e}\n", "error")
        output_box.see(tk.END)
        status_label.config(text="❌ Error")
    finally:
        cmd_entry.delete(0, tk.END)

def handle_key(event):
    global history_index
    if not command_history:
        return
    if event.keysym == "Up":
        history_index = max(0, history_index - 1)
    elif event.keysym == "Down":
        history_index = min(len(command_history)-1, history_index + 1)
    cmd_entry.delete(0, tk.END)
    cmd_entry.insert(0, command_history[history_index])

def disconnect_and_close():
    global server_addr
    try:
        if server_addr:
            sock.close()
            logging.info("Disconnected from server and socket closed.")
        else:
            logging.info("Socket closed without active server connection.")
    except Exception as e:
        logging.error(f"Error during disconnect: {e}")
    finally:
        server_addr = None
        root.destroy()

# === GUI Setup ===
root = tk.Tk()
root.title("🔐 Secure Client Command Panel")
root.geometry("780x530")
root.config(bg="#121212")  # Dark background
root.attributes("-fullscreen", True)

# === Colors ===
bg_color = "#121212"
fg_color = "#E0E0E0"
entry_bg = "#1F1F1F"
entry_fg = "#FFFFFF"
btn_bg = "#2E2E2E"
btn_fg = "#FFFFFF"
highlight_color = "#00BCD4"
error_color = "#FF5555"
success_color = "#00FF00"

tk.Label(root, text="🔌 Server IP Address", bg=bg_color, fg=fg_color, font=("Segoe UI", 11, "bold")).pack(pady=(10, 0))
ip_entry = tk.Entry(root, width=80, bg=entry_bg, fg=entry_fg, insertbackground='white', font=("Consolas", 11), relief=tk.FLAT)
ip_entry.pack(padx=10, pady=5)

connect_button = tk.Button(root, text="Connect to Server", command=connect_to_server, bg=highlight_color, fg="black", font=("Segoe UI", 12), activebackground="#00ACC1")
connect_button.pack(pady=5)

tk.Label(root, text="💻 Command Input", bg=bg_color, fg=fg_color, font=("Segoe UI", 11, "bold")).pack(pady=(15, 0))
cmd_entry = tk.Entry(root, width=80, bg=entry_bg, fg=entry_fg, insertbackground='white', font=("Consolas", 11), relief=tk.FLAT)
cmd_entry.pack(padx=10, pady=5)
cmd_entry.bind("<Up>", handle_key)
cmd_entry.bind("<Down>", handle_key)

send_button = tk.Button(root, text="Send Command", command=send_command, bg=highlight_color, fg="black", font=("Segoe UI", 12), activebackground="#444")
send_button.pack(pady=5)

status_label = tk.Label(root, text="🔄 Not Connected", bg=bg_color, fg=highlight_color, font=("Segoe UI", 11, "italic"))
status_label.pack(pady=(5, 5))

output_box = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=90, height=15, bg="#181818", fg=fg_color, font=("Consolas", 11), relief=tk.FLAT, borderwidth=0, insertbackground='white')
output_box.tag_config("response", foreground=success_color)
output_box.tag_config("error", foreground=error_color)
output_box.pack(padx=10, pady=(5, 10))

disconnect_button = tk.Button(root, text="🔌 Disconnect & Close", command=disconnect_and_close, bg=highlight_color, fg="black", font=("Segoe UI", 12), activebackground="#B71C1C")
disconnect_button.pack(pady=(0, 10))

logging.info("Client GUI initialized.")
print("✅ GUI loaded")
root.mainloop()
