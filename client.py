"""
IEA Client — Online Image Encryption Application Client.

A Tkinter GUI client that connects to the IEA server via TCP socket.
Features:
- User registration and login
- Real-time chat with other users
- Send/receive DES-encrypted, digitally signed images
- Session key exchange via RSA
- Handles RSA key rotation from server

No external dependencies — uses only Python built-in modules.
"""

import socket
import threading
import json
import time
import os
import sys
import base64
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import BUFFER_SIZE
from crypto_utils.des_algorithm import des_encrypt, des_decrypt
from crypto_utils.rsa import (
    rsa_encrypt, rsa_decrypt, bytes_to_int, int_to_bytes, generate_rsa_keys
)
from crypto_utils.signature import sign, verify


class IEAClient:
    """Main client class managing connection, crypto, and state."""

    def __init__(self):
        self.sock = None
        self.username = None
        self.connected = False

        # RSA keys (integers)
        self.public_key = None   # (e, n)
        self.private_key = None  # (d, n)

        # Other users' public keys: {username: (e, n)}
        self.peer_public_keys = {}

        # DES session keys: {username: 8-byte key}
        self.session_keys = {}

        # Received images directory
        self.received_dir = "received_images"
        os.makedirs(self.received_dir, exist_ok=True)

        # GUI reference
        self.app = None

        # Message receive thread
        self.recv_thread = None

    # ---- Connection ----

    def connect(self, host, port):
        """Connect to the server."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((host, int(port)))
            self.connected = True
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False

    def disconnect(self):
        """Disconnect from the server."""
        self.connected = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass

    # ---- Protocol ----

    def send_msg(self, msg_dict):
        """Send a JSON message with 4-byte length prefix."""
        try:
            data = json.dumps(msg_dict).encode("utf-8")
            length = len(data).to_bytes(4, "big")
            self.sock.sendall(length + data)
        except Exception as e:
            print(f"Send failed: {e}")
            self.connected = False

    def recv_msg(self):
        """Receive a JSON message. Returns dict or None."""
        try:
            # Read 4-byte length
            length_data = b""
            while len(length_data) < 4:
                chunk = self.sock.recv(4 - len(length_data))
                if not chunk:
                    return None
                length_data += chunk

            msg_length = int.from_bytes(length_data, "big")
            if msg_length > 50 * 1024 * 1024:
                return None

            # Read body
            data = b""
            while len(data) < msg_length:
                chunk = self.sock.recv(min(BUFFER_SIZE, msg_length - len(data)))
                if not chunk:
                    return None
                data += chunk

            return json.loads(data.decode("utf-8"))
        except Exception as e:
            if self.connected:
                print(f"Receive failed: {e}")
            return None

    # ---- Background receiver ----

    def start_receiving(self):
        """Start background thread to receive messages."""
        self.recv_thread = threading.Thread(target=self._receive_loop, daemon=True)
        self.recv_thread.start()

    def _receive_loop(self):
        """Continuously receive and dispatch messages."""
        while self.connected:
            msg = self.recv_msg()
            if msg is None:
                if self.connected:
                    self.connected = False
                    if self.app:
                        self.app.root.after(0, lambda: self.app.on_disconnect())
                break
            self._dispatch(msg)

    def _dispatch(self, msg):
        """Dispatch received message to appropriate handler."""
        msg_type = msg.get("type", "")
        if self.app:
            # Schedule GUI updates on main thread
            self.app.root.after(0, lambda m=msg, t=msg_type: self.app.handle_message(t, m))

    # ---- Crypto operations ----

    def generate_session_key(self):
        """Generate a random 8-byte DES session key."""
        return os.urandom(8)

    def encrypt_image(self, image_bytes, des_key):
        """Encrypt image bytes with DES."""
        return des_encrypt(image_bytes, des_key)

    def decrypt_image(self, encrypted_bytes, des_key):
        """Decrypt image bytes with DES."""
        return des_decrypt(encrypted_bytes, des_key)

    def sign_image(self, image_bytes):
        """Sign image data with our RSA private key."""
        return sign(image_bytes, self.private_key)

    def verify_image(self, image_bytes, signature, sender_public_key):
        """Verify image signature with sender's RSA public key."""
        return verify(image_bytes, signature, sender_public_key)

    def encrypt_session_key(self, des_key, recipient_public_key):
        """Encrypt a DES session key with recipient's RSA public key."""
        key_int = bytes_to_int(des_key)
        encrypted_int = rsa_encrypt(key_int, recipient_public_key)
        return str(encrypted_int)

    def decrypt_session_key(self, encrypted_key_str):
        """Decrypt a DES session key with our RSA private key."""
        encrypted_int = int(encrypted_key_str)
        decrypted_int = rsa_decrypt(encrypted_int, self.private_key)
        key_bytes = int_to_bytes(decrypted_int)
        # Pad to 8 bytes if needed
        if len(key_bytes) < 8:
            key_bytes = b'\x00' * (8 - len(key_bytes)) + key_bytes
        return key_bytes[:8]


class IEAApp:
    #tkinter

    def __init__(self):
        self.client = IEAClient()
        self.client.app = self
        self.current_chat_user = None

        self.root = tk.Tk()
        self.root.title("IEA — Image Encryption Application")
        self.root.geometry("900x650")
        self.root.minsize(800, 550)

        # Chat history per user: {username: [list of message strings]}
        self.chat_histories = {}

        self._build_login_screen()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    #  Login Screen 

    def _build_login_screen(self):
        self._clear_root()

        frame = tk.Frame(self.root, padx=30, pady=30)
        frame.place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(frame, text="IEA — Image Encryption App", font=("Arial", 18, "bold")).grid(
            row=0, column=0, columnspan=2, pady=(0, 20)
        )

        tk.Label(frame, text="Server IP:", font=("Arial", 11)).grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.entry_host = tk.Entry(frame, font=("Arial", 11), width=25)
        self.entry_host.grid(row=1, column=1, pady=5)
        self.entry_host.insert(0, "127.0.0.1")

        tk.Label(frame, text="Port:", font=("Arial", 11)).grid(row=2, column=0, sticky="e", padx=5, pady=5)
        self.entry_port = tk.Entry(frame, font=("Arial", 11), width=25)
        self.entry_port.grid(row=2, column=1, pady=5)
        self.entry_port.insert(0, "9999")

        tk.Label(frame, text="Username:", font=("Arial", 11)).grid(row=3, column=0, sticky="e", padx=5, pady=5)
        self.entry_user = tk.Entry(frame, font=("Arial", 11), width=25)
        self.entry_user.grid(row=3, column=1, pady=5)

        tk.Label(frame, text="Password:", font=("Arial", 11)).grid(row=4, column=0, sticky="e", padx=5, pady=5)
        self.entry_pass = tk.Entry(frame, font=("Arial", 11), width=25, show="*")
        self.entry_pass.grid(row=4, column=1, pady=5)

        btn_frame = tk.Frame(frame)
        btn_frame.grid(row=5, column=0, columnspan=2, pady=15)

        tk.Button(btn_frame, text="Register", font=("Arial", 11), width=12, command=self._on_register).pack(
            side="left", padx=5
        )
        tk.Button(btn_frame, text="Login", font=("Arial", 11), width=12, command=self._on_login).pack(
            side="left", padx=5
        )

        self.login_status = tk.Label(frame, text="", font=("Arial", 10), fg="red")
        self.login_status.grid(row=6, column=0, columnspan=2)

    def _on_register(self):
        """Handle register button click."""
        host = self.entry_host.get().strip()
        port = self.entry_port.get().strip()
        username = self.entry_user.get().strip()
        password = self.entry_pass.get().strip()

        if not all([host, port, username, password]):
            self.login_status.config(text="All fields required", fg="red")
            return

        if not self.client.connected:
            if not self.client.connect(host, port):
                self.login_status.config(text="Cannot connect to server", fg="red")
                return

        self.client.send_msg({
            "type": "REGISTER",
            "username": username,
            "password": password
        })

        # Wait for response (blocking, but short)
        response = self.client.recv_msg()
        if response and response.get("success"):
            self.login_status.config(text="Registered! Now click Login.", fg="green")
        else:
            msg = response.get("message", "Registration failed") if response else "No response"
            self.login_status.config(text=msg, fg="red")

        # Disconnect after registration (will reconnect on login)
        self.client.disconnect()

    def _on_login(self):
        """Handle login button click."""
        host = self.entry_host.get().strip()
        port = self.entry_port.get().strip()
        username = self.entry_user.get().strip()
        password = self.entry_pass.get().strip()

        if not all([host, port, username, password]):
            self.login_status.config(text="All fields required", fg="red")
            return

        if not self.client.connect(host, port):
            self.login_status.config(text="Cannot connect to server", fg="red")
            return

        self.client.send_msg({
            "type": "LOGIN",
            "username": username,
            "password": password
        })

        response = self.client.recv_msg()
        if response and response.get("success"):
            self.client.username = username

            # Store RSA keys
            pub = response.get("public_key")
            priv = response.get("private_key")
            if pub and priv:
                self.client.public_key = (int(pub["e"]), int(pub["n"]))
                self.client.private_key = (int(priv["d"]), int(priv["n"]))

            # Start receiving messages in background
            self.client.start_receiving()

            # Switch to main screen
            self._build_main_screen()
        else:
            msg = response.get("message", "Login failed") if response else "No response"
            self.login_status.config(text=msg, fg="red")
            self.client.disconnect()

    # ---- Main Chat Screen ----

    def _build_main_screen(self):
        """Build the main chat interface."""
        self._clear_root()
        self.root.title(f"IEA — {self.client.username}")

        # Top bar
        top_frame = tk.Frame(self.root, pady=5, padx=10)
        top_frame.pack(fill="x")
        tk.Label(top_frame, text=f"Logged in as: {self.client.username}", font=("Arial", 11, "bold")).pack(side="left")
        self.key_status = tk.Label(top_frame, text="RSA keys: Active", font=("Arial", 9), fg="green")
        self.key_status.pack(side="left", padx=20)
        tk.Button(top_frame, text="Logout", command=self._on_logout).pack(side="right")

        # Main content: paned window with user list and chat
        paned = tk.PanedWindow(self.root, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=5, pady=5)

        # Left: User list
        left_frame = tk.Frame(paned, width=200)
        tk.Label(left_frame, text="Online Users", font=("Arial", 11, "bold")).pack(pady=5)
        self.user_listbox = tk.Listbox(left_frame, font=("Arial", 10))
        self.user_listbox.pack(fill="both", expand=True, padx=5, pady=5)
        self.user_listbox.bind("<<ListboxSelect>>", self._on_user_select)
        paned.add(left_frame, minsize=150)

        # Right: Chat area
        right_frame = tk.Frame(paned)

        # Chat partner label
        self.chat_label = tk.Label(right_frame, text="Select a user to chat", font=("Arial", 12, "bold"))
        self.chat_label.pack(pady=5)

        # Chat display
        self.chat_display = scrolledtext.ScrolledText(right_frame, font=("Arial", 10), state="disabled", wrap="word")
        self.chat_display.pack(fill="both", expand=True, padx=5)

        # Message input area
        input_frame = tk.Frame(right_frame)
        input_frame.pack(fill="x", padx=5, pady=5)

        self.msg_entry = tk.Entry(input_frame, font=("Arial", 10))
        self.msg_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        self.msg_entry.bind("<Return>", lambda e: self._on_send_chat())

        tk.Button(input_frame, text="Send", font=("Arial", 10), command=self._on_send_chat).pack(side="left", padx=2)
        tk.Button(input_frame, text="Send Image", font=("Arial", 10), command=self._on_send_image).pack(side="left", padx=2)

        paned.add(right_frame, minsize=400)

        # Request user list
        self.client.send_msg({"type": "GET_USERS"})

    # ---- Chat Operations ----

    def _on_user_select(self, event):
        """When a user is selected from the list."""
        selection = self.user_listbox.curselection()
        if not selection:
            return
        selected_user = self.user_listbox.get(selection[0])
        if selected_user == self.client.username:
            return

        self.current_chat_user = selected_user
        self.chat_label.config(text=f"Chat with: {selected_user}")

        # Load chat history
        self._refresh_chat_display()

        # Request their public key if we don't have it
        if selected_user not in self.client.peer_public_keys:
            self.client.send_msg({"type": "GET_PUBLIC_KEY", "username": selected_user})

        # Establish session key if we don't have one
        if selected_user not in self.client.session_keys:
            self._establish_session_key(selected_user)

    def _establish_session_key(self, target_user):
        """Generate and send a DES session key to target user."""
        # We need their public key first — request it and handle in message handler
        if target_user not in self.client.peer_public_keys:
            self.client.send_msg({"type": "GET_PUBLIC_KEY", "username": target_user})
            # Session key will be established when we get the public key response
            return

        des_key = self.client.generate_session_key()
        self.client.session_keys[target_user] = des_key

        # Encrypt DES key with recipient's RSA public key
        encrypted_key = self.client.encrypt_session_key(des_key, self.client.peer_public_keys[target_user])

        self.client.send_msg({
            "type": "SEND_SESSION_KEY",
            "to": target_user,
            "encrypted_key": encrypted_key
        })

        self._append_chat(target_user, "[SYSTEM] Session key established (DES)")

    def _on_send_chat(self):
        """Send a chat message."""
        if not self.current_chat_user:
            messagebox.showwarning("Warning", "Select a user first")
            return

        text = self.msg_entry.get().strip()
        if not text:
            return

        self.msg_entry.delete(0, "end")

        # Encrypt message with DES session key if available
        des_key = self.client.session_keys.get(self.current_chat_user)
        if des_key:
            encrypted = des_encrypt(text.encode("utf-8"), des_key)
            content = base64.b64encode(encrypted).decode("utf-8")
            encrypted_flag = True
        else:
            content = text
            encrypted_flag = False

        self.client.send_msg({
            "type": "CHAT",
            "to": self.current_chat_user,
            "content": content,
            "encrypted": encrypted_flag
        })

        self._append_chat(self.current_chat_user, f"[You]: {text}")

    def _on_send_image(self):
        """Send an encrypted, signed image."""
        if not self.current_chat_user:
            messagebox.showwarning("Warning", "Select a user first")
            return

        filepath = filedialog.askopenfilename(
            title="Select Image",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp *.gif"), ("All files", "*.*")]
        )
        if not filepath:
            return

        try:
            with open(filepath, "rb") as f:
                image_bytes = f.read()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file: {e}")
            return

        # Need session key
        des_key = self.client.session_keys.get(self.current_chat_user)
        if not des_key:
            messagebox.showwarning("Warning", "No session key established. Please select the user first.")
            return

        # Need recipient's public key for session key exchange (already done if session key exists)
        # Need our private key for signing
        if not self.client.private_key:
            messagebox.showerror("Error", "No RSA private key. Cannot sign image.")
            return

        self._append_chat(self.current_chat_user, f"[You]: Encrypting and signing image...")

        # Run encryption in background thread to avoid freezing GUI
        def encrypt_and_send():
            try:
                # 1. Encrypt image with DES
                encrypted_image = self.client.encrypt_image(image_bytes, des_key)

                # 2. Sign the encrypted image
                signature = self.client.sign_image(encrypted_image)

                # 3. Encrypt the DES key with recipient's RSA public key (for per-image key exchange)
                recipient_pub = self.client.peer_public_keys.get(self.current_chat_user)
                if recipient_pub:
                    encrypted_key = self.client.encrypt_session_key(des_key, recipient_pub)
                else:
                    encrypted_key = ""

                # 4. Send
                self.client.send_msg({
                    "type": "SEND_IMAGE",
                    "to": self.current_chat_user,
                    "image_data": base64.b64encode(encrypted_image).decode("utf-8"),
                    "encrypted_key": encrypted_key,
                    "signature": str(signature),
                })

                filename = os.path.basename(filepath)
                self.root.after(0, lambda: self._append_chat(
                    self.current_chat_user,
                    f"[You]: Sent encrypted image: {filename} ({len(image_bytes)} bytes)"
                ))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Image send failed: {e}"))

        threading.Thread(target=encrypt_and_send, daemon=True).start()

    # ---- Message Handling (from server) ----

    def handle_message(self, msg_type, msg):
        """Handle a message received from the server (called on main thread)."""

        if msg_type == "USER_LIST":
            self._update_user_list(msg.get("users", []))

        elif msg_type == "PUBLIC_KEY_RESPONSE":
            self._handle_public_key_response(msg)

        elif msg_type == "CHAT":
            self._handle_incoming_chat(msg)

        elif msg_type == "IMAGE":
            self._handle_incoming_image(msg)

        elif msg_type == "SESSION_KEY_UPDATE":
            self._handle_session_key_update(msg)

        elif msg_type == "KEY_ROTATION":
            self._handle_key_rotation(msg)

        elif msg_type == "ERROR":
            messagebox.showerror("Server Error", msg.get("message", "Unknown error"))

    def _update_user_list(self, users):
        """Update the user list in the GUI."""
        if not hasattr(self, "user_listbox"):
            return
        self.user_listbox.delete(0, "end")
        for user in users:
            if user != self.client.username:
                self.user_listbox.insert("end", user)

    def _handle_public_key_response(self, msg):
        """Store a peer's public key."""
        username = msg.get("username", "")
        pub = msg.get("public_key")
        if pub and username:
            self.client.peer_public_keys[username] = (int(pub["e"]), int(pub["n"]))
            # Now establish session key if we were waiting
            if username not in self.client.session_keys and username == self.current_chat_user:
                self._establish_session_key(username)

    def _handle_incoming_chat(self, msg):
        """Handle an incoming chat message."""
        sender = msg.get("from", "unknown")
        content = msg.get("content", "")
        is_encrypted = msg.get("encrypted", False)

        if is_encrypted:
            des_key = self.client.session_keys.get(sender)
            if des_key:
                try:
                    decrypted = des_decrypt(base64.b64decode(content), des_key)
                    content = decrypted.decode("utf-8")
                except Exception:
                    content = "[Could not decrypt message]"
            else:
                content = "[No session key — cannot decrypt]"

        self._append_chat(sender, f"[{sender}]: {content}")

    def _handle_incoming_image(self, msg):
        """Handle an incoming encrypted image."""
        sender = msg.get("from", "unknown")
        image_data_b64 = msg.get("image_data", "")
        encrypted_key_str = msg.get("encrypted_key", "")
        signature_str = msg.get("signature", "")
        filename = msg.get("filename", "image.enc")

        self._append_chat(sender, f"[{sender}]: Received encrypted image...")

        def decrypt_and_save():
            try:
                encrypted_image = base64.b64decode(image_data_b64)

                # Get DES key - either from per-image encrypted key or session key
                des_key = None
                if encrypted_key_str and self.client.private_key:
                    try:
                        des_key = self.client.decrypt_session_key(encrypted_key_str)
                    except Exception:
                        pass

                if not des_key:
                    des_key = self.client.session_keys.get(sender)

                if not des_key:
                    self.root.after(0, lambda: self._append_chat(
                        sender, f"[SYSTEM] Cannot decrypt image — no DES key"
                    ))
                    return

                # Verify signature
                sig_valid = False
                sender_pub = self.client.peer_public_keys.get(sender)
                if sender_pub and signature_str:
                    try:
                        sig_int = int(signature_str)
                        sig_valid = self.client.verify_image(encrypted_image, sig_int, sender_pub)
                    except Exception:
                        pass

                # Decrypt image
                decrypted_image = self.client.decrypt_image(encrypted_image, des_key)

                # Save decrypted image
                # Determine extension from magic bytes
                ext = ".bin"
                if decrypted_image[:8] == b'\x89PNG\r\n\x1a\n':
                    ext = ".png"
                elif decrypted_image[:2] == b'\xff\xd8':
                    ext = ".jpg"
                elif decrypted_image[:6] in (b'GIF87a', b'GIF89a'):
                    ext = ".gif"
                elif decrypted_image[:2] == b'BM':
                    ext = ".bmp"

                save_name = f"from_{sender}_{int(time.time())}{ext}"
                save_path = os.path.join(self.client.received_dir, save_name)
                with open(save_path, "wb") as f:
                    f.write(decrypted_image)

                sig_text = "Valid" if sig_valid else "Invalid/Unverified"
                self.root.after(0, lambda: self._append_chat(
                    sender,
                    f"[SYSTEM] Image decrypted and saved: {save_name}\n"
                    f"         Signature: {sig_text}\n"
                    f"         Size: {len(decrypted_image)} bytes"
                ))

            except Exception as e:
                err_msg = str(e)
                self.root.after(0, lambda m=err_msg: self._append_chat(
                    sender, f"[SYSTEM] Image decryption failed: {m}"
                ))

        threading.Thread(target=decrypt_and_save, daemon=True).start()

    def _handle_session_key_update(self, msg):
        """Handle receiving a session key from another user."""
        sender = msg.get("from", "")
        encrypted_key = msg.get("encrypted_key", "")

        if encrypted_key and self.client.private_key:
            try:
                des_key = self.client.decrypt_session_key(encrypted_key)
                self.client.session_keys[sender] = des_key
                self._append_chat(sender, f"[SYSTEM] Session key received from {sender}")
            except Exception as e:
                self._append_chat(sender, f"[SYSTEM] Failed to decrypt session key: {e}")

    def _handle_key_rotation(self, msg):
        """Handle RSA key rotation from server."""
        pub = msg.get("public_key")
        priv = msg.get("private_key")
        if pub and priv:
            self.client.public_key = (int(pub["e"]), int(pub["n"]))
            self.client.private_key = (int(priv["d"]), int(priv["n"]))
            if hasattr(self, "key_status"):
                self.key_status.config(text="RSA keys: Rotated ✓", fg="blue")
                self.root.after(3000, lambda: self.key_status.config(text="RSA keys: Active", fg="green"))
            # Note: existing session keys remain valid (they use DES, not RSA)

    # ---- GUI Helpers ----

    def _append_chat(self, user, text):
        """Append text to chat history for a user and refresh display if active."""
        if user not in self.chat_histories:
            self.chat_histories[user] = []
        self.chat_histories[user].append(text)

        if user == self.current_chat_user and hasattr(self, "chat_display"):
            self.chat_display.config(state="normal")
            self.chat_display.insert("end", text + "\n")
            self.chat_display.config(state="disabled")
            self.chat_display.see("end")

    def _refresh_chat_display(self):
        """Refresh the chat display for the current user."""
        if not hasattr(self, "chat_display"):
            return
        self.chat_display.config(state="normal")
        self.chat_display.delete("1.0", "end")
        history = self.chat_histories.get(self.current_chat_user, [])
        for line in history:
            self.chat_display.insert("end", line + "\n")
        self.chat_display.config(state="disabled")
        self.chat_display.see("end")

    def _clear_root(self):
        """Remove all widgets from root."""
        for widget in self.root.winfo_children():
            widget.destroy()

    def _on_logout(self):
        """Logout and return to login screen."""
        self.client.disconnect()
        self.current_chat_user = None
        self.chat_histories.clear()
        self._build_login_screen()

    def _on_close(self):
        """Handle window close."""
        self.client.disconnect()
        self.root.destroy()

    def on_disconnect(self):
        """Called when connection to server is lost."""
        messagebox.showerror("Disconnected", "Connection to server lost")
        self._on_logout()

    def run(self):
        """Start the GUI event loop."""
        self.root.mainloop()


if __name__ == "__main__":
    app = IEAApp()
    app.run()
