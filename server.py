"""
IEA Server — Online Image Encryption Application Server.

A multi-threaded TCP socket server that handles:
- User registration and login
- RSA key generation and distribution
- Periodic RSA key rotation
- Message routing between clients (chat + encrypted images)
- Encrypted image storage
- Admin monitoring

No external dependencies — uses only Python built-in modules.
"""

import socket
import threading
import json
import time
import os
import base64
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import (
    SERVER_HOST, SERVER_PORT, BUFFER_SIZE,
    RSA_KEY_BITS, KEY_ROTATION_INTERVAL,
    UPLOAD_FOLDER, ADMIN_USERNAME, ADMIN_PASSWORD
)
import database
from crypto_utils.rsa import generate_rsa_keys


# ---- Global State ----
# Maps username -> client socket
connected_clients = {}
# Lock for thread-safe access to shared state
clients_lock = threading.Lock()
# Server start time
server_start_time = time.time()
# Flag to stop key rotation thread
running = True


# ---- Protocol helpers ----
# Message format: 4-byte length prefix (big-endian) + JSON bytes

def send_message(sock, msg_dict):
    """Send a JSON message with 4-byte length prefix."""
    try:
        data = json.dumps(msg_dict).encode("utf-8")
        length = len(data).to_bytes(4, "big")
        sock.sendall(length + data)
    except Exception as e:
        print(f"[ERROR] Failed to send message: {e}")


def receive_message(sock):
    """Receive a JSON message with 4-byte length prefix. Returns dict or None."""
    try:
        # Read 4-byte length
        length_data = b""
        while len(length_data) < 4:
            chunk = sock.recv(4 - len(length_data))
            if not chunk:
                return None
            length_data += chunk

        msg_length = int.from_bytes(length_data, "big")
        if msg_length > 50 * 1024 * 1024:  # 50MB max
            print(f"[WARNING] Message too large: {msg_length} bytes")
            return None

        # Read the message body
        data = b""
        while len(data) < msg_length:
            chunk = sock.recv(min(BUFFER_SIZE, msg_length - len(data)))
            if not chunk:
                return None
            data += chunk

        return json.loads(data.decode("utf-8"))
    except Exception as e:
        print(f"[ERROR] Failed to receive message: {e}")
        return None


# ---- Client Handler ----

def handle_client(client_sock, client_addr):
    """Handle a single client connection."""
    username = None
    print(f"[INFO] New connection from {client_addr}")

    try:
        while running:
            msg = receive_message(client_sock)
            if msg is None:
                break

            msg_type = msg.get("type", "")

            if msg_type == "REGISTER":
                handle_register(client_sock, msg)

            elif msg_type == "LOGIN":
                result = handle_login(client_sock, msg)
                if result:
                    username = result
                    with clients_lock:
                        connected_clients[username] = client_sock
                    # Notify all clients about updated user list
                    broadcast_user_list()
                    database.add_admin_log("USER_LOGIN", f"{username} logged in from {client_addr}")

            elif msg_type == "GET_USERS":
                handle_get_users(client_sock)

            elif msg_type == "GET_PUBLIC_KEY":
                handle_get_public_key(client_sock, msg)

            elif msg_type == "CHAT":
                handle_chat(msg, username)

            elif msg_type == "SEND_IMAGE":
                handle_send_image(msg, username)

            elif msg_type == "SEND_SESSION_KEY":
                handle_send_session_key(msg, username)

            elif msg_type == "GET_SESSION_KEY":
                handle_get_session_key(client_sock, msg, username)

            elif msg_type == "ADMIN_LOGIN":
                handle_admin_login(client_sock, msg)

            elif msg_type == "ADMIN_STATS":
                handle_admin_stats(client_sock)

            elif msg_type == "ADMIN_LOGS":
                handle_admin_logs(client_sock)

            else:
                send_message(client_sock, {"type": "ERROR", "message": f"Unknown message type: {msg_type}"})

    except Exception as e:
        print(f"[ERROR] Client {client_addr} error: {e}")
    finally:
        # Cleanup on disconnect
        if username:
            with clients_lock:
                if username in connected_clients:
                    del connected_clients[username]
            database.logout_user(username)
            database.add_admin_log("USER_LOGOUT", f"{username} disconnected")
            broadcast_user_list()
            print(f"[INFO] {username} disconnected")
        else:
            print(f"[INFO] Connection from {client_addr} closed")
        client_sock.close()


# ---- Message Handlers ----

def handle_register(sock, msg):
    """Handle user registration."""
    username = msg.get("username", "").strip()
    password = msg.get("password", "").strip()

    if not username or not password:
        send_message(sock, {"type": "REGISTER_RESPONSE", "success": False, "message": "Username and password required"})
        return

    if len(username) < 3:
        send_message(sock, {"type": "REGISTER_RESPONSE", "success": False, "message": "Username must be at least 3 characters"})
        return

    success = database.register_user(username, password)
    if success:
        # Generate RSA keys for the new user
        public_key, private_key = generate_rsa_keys(RSA_KEY_BITS)
        database.store_rsa_keys(username, public_key, private_key)
        database.add_admin_log("USER_REGISTER", f"New user registered: {username}")
        send_message(sock, {"type": "REGISTER_RESPONSE", "success": True, "message": "Registration successful"})
        print(f"[INFO] User registered: {username}")
    else:
        send_message(sock, {"type": "REGISTER_RESPONSE", "success": False, "message": "Username already taken"})


def handle_login(sock, msg):
    """Handle user login. Returns username on success, None on failure."""
    username = msg.get("username", "").strip()
    password = msg.get("password", "").strip()

    user = database.login_user(username, password)
    if user:
        # Get the user's RSA keys
        public_key = database.get_public_key(username)
        private_key = database.get_private_key(username)

        response = {
            "type": "LOGIN_RESPONSE",
            "success": True,
            "message": "Login successful",
            "username": username,
        }
        if public_key:
            response["public_key"] = {"e": str(public_key[0]), "n": str(public_key[1])}
        if private_key:
            response["private_key"] = {"d": str(private_key[0]), "n": str(private_key[1])}

        send_message(sock, response)
        print(f"[INFO] User logged in: {username}")
        return username
    else:
        send_message(sock, {"type": "LOGIN_RESPONSE", "success": False, "message": "Invalid username or password"})
        return None


def handle_get_users(sock):
    """Send list of online users."""
    users = database.get_online_users()
    send_message(sock, {"type": "USER_LIST", "users": users})


def handle_get_public_key(sock, msg):
    """Send a user's public RSA key."""
    target = msg.get("username", "")
    public_key = database.get_public_key(target)
    if public_key:
        send_message(sock, {
            "type": "PUBLIC_KEY_RESPONSE",
            "username": target,
            "public_key": {"e": str(public_key[0]), "n": str(public_key[1])}
        })
    else:
        send_message(sock, {
            "type": "PUBLIC_KEY_RESPONSE",
            "username": target,
            "public_key": None,
            "message": "User not found or no key"
        })


def handle_chat(msg, sender):
    """Route a chat message to the recipient."""
    receiver = msg.get("to", "")
    content = msg.get("content", "")

    if not sender:
        return

    # Save message in database
    database.save_message(sender, receiver, content)

    # Forward to recipient if online
    with clients_lock:
        if receiver in connected_clients:
            recv_sock = connected_clients[receiver]
            send_message(recv_sock, {
                "type": "CHAT",
                "from": sender,
                "content": content,
                "encrypted": msg.get("encrypted", False),
                "timestamp": time.time()
            })


def handle_send_image(msg, sender):
    """Handle encrypted image transfer."""
    receiver = msg.get("to", "")
    image_data_b64 = msg.get("image_data", "")
    encrypted_key = msg.get("encrypted_key", "")
    signature = msg.get("signature", "")

    if not sender:
        return

    # Save encrypted image to disk
    timestamp = int(time.time() * 1000)
    filename = f"{sender}_to_{receiver}_{timestamp}.enc"
    filepath = os.path.join(UPLOAD_FOLDER, filename)

    try:
        image_bytes = base64.b64decode(image_data_b64)
        with open(filepath, "wb") as f:
            f.write(image_bytes)
    except Exception as e:
        print(f"[ERROR] Failed to save image: {e}")
        return

    # Save record in database
    database.save_image_record(sender, receiver, filename, encrypted_key, signature)
    database.save_message(sender, receiver, f"[IMAGE: {filename}]", is_image=True)
    database.add_admin_log("IMAGE_SENT", f"{sender} -> {receiver}: {filename}")

    # Forward to recipient if online
    with clients_lock:
        if receiver in connected_clients:
            recv_sock = connected_clients[receiver]
            send_message(recv_sock, {
                "type": "IMAGE",
                "from": sender,
                "image_data": image_data_b64,
                "encrypted_key": encrypted_key,
                "signature": signature,
                "filename": filename,
                "timestamp": time.time()
            })

    print(f"[INFO] Image sent: {sender} -> {receiver} ({filename})")


def handle_send_session_key(msg, sender):
    """Store an encrypted session key from sender to receiver."""
    receiver = msg.get("to", "")
    encrypted_key = msg.get("encrypted_key", "")

    database.store_session_key(sender, receiver, encrypted_key)
    database.add_admin_log("SESSION_KEY", f"Session key: {sender} -> {receiver}")

    # Notify receiver about new session key
    with clients_lock:
        if receiver in connected_clients:
            recv_sock = connected_clients[receiver]
            send_message(recv_sock, {
                "type": "SESSION_KEY_UPDATE",
                "from": sender,
                "encrypted_key": encrypted_key,
            })


def handle_get_session_key(sock, msg, username):
    """Retrieve the session key from another user."""
    from_user = msg.get("from_user", "")
    encrypted_key = database.get_session_key(from_user, username)
    send_message(sock, {
        "type": "SESSION_KEY_RESPONSE",
        "from_user": from_user,
        "encrypted_key": encrypted_key
    })


def handle_admin_login(sock, msg):
    """Authenticate admin."""
    username = msg.get("username", "")
    password = msg.get("password", "")
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        send_message(sock, {"type": "ADMIN_LOGIN_RESPONSE", "success": True})
        database.add_admin_log("ADMIN_LOGIN", "Admin logged in")
    else:
        send_message(sock, {"type": "ADMIN_LOGIN_RESPONSE", "success": False, "message": "Invalid admin credentials"})


def handle_admin_stats(sock):
    """Send server statistics to admin."""
    stats = database.get_server_stats()
    stats["uptime"] = time.time() - server_start_time
    with clients_lock:
        stats["connected_clients"] = list(connected_clients.keys())
    send_message(sock, {"type": "ADMIN_STATS_RESPONSE", "stats": stats})


def handle_admin_logs(sock):
    """Send recent admin logs."""
    logs = database.get_admin_logs()
    send_message(sock, {"type": "ADMIN_LOGS_RESPONSE", "logs": logs})


# ---- Broadcast ----

def broadcast_user_list():
    """Send updated user list to all connected clients."""
    users = database.get_online_users()
    msg = {"type": "USER_LIST", "users": users}
    with clients_lock:
        for username, sock in list(connected_clients.items()):
            try:
                send_message(sock, msg)
            except Exception:
                pass


# ---- RSA Key Rotation ----

def key_rotation_thread():
    """Periodically regenerate RSA keys for all users."""
    while running:
        time.sleep(KEY_ROTATION_INTERVAL)
        if not running:
            break
        print(f"\n[KEY ROTATION] Starting RSA key rotation...")
        usernames = database.get_all_registered_usernames()
        for username in usernames:
            try:
                public_key, private_key = generate_rsa_keys(RSA_KEY_BITS)
                database.store_rsa_keys(username, public_key, private_key)

                # If user is online, send them their new keys
                with clients_lock:
                    if username in connected_clients:
                        sock = connected_clients[username]
                        send_message(sock, {
                            "type": "KEY_ROTATION",
                            "public_key": {"e": str(public_key[0]), "n": str(public_key[1])},
                            "private_key": {"d": str(private_key[0]), "n": str(private_key[1])},
                        })
            except Exception as e:
                print(f"[ERROR] Key rotation failed for {username}: {e}")

        database.add_admin_log("KEY_ROTATION", f"RSA keys rotated for {len(usernames)} users")
        print(f"[KEY ROTATION] Completed for {len(usernames)} users")


# ---- Main Server ----

def start_server():
    """Start the IEA server."""
    global running

    # Initialize database
    database.init_database()
    print("[INFO] Database initialized")

    # Create upload directory
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

    # Mark all users as offline on start
    conn = database.get_connection()
    conn.execute("UPDATE users SET is_online = 0")
    conn.commit()
    conn.close()

    # Start key rotation background thread
    rotation_thread = threading.Thread(target=key_rotation_thread, daemon=True)
    rotation_thread.start()
    print(f"[INFO] RSA key rotation enabled (interval: {KEY_ROTATION_INTERVAL}s)")

    # Create server socket
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((SERVER_HOST, SERVER_PORT))
    server_sock.listen(10)
    server_sock.settimeout(1.0)  # 1 second timeout for accept() so we can check 'running'

    # Get local IP for display
    try:
        temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        temp_sock.connect(("8.8.8.8", 80))
        local_ip = temp_sock.getsockname()[0]
        temp_sock.close()
    except Exception:
        local_ip = "127.0.0.1"

    print(f"\n{'='*50}")
    print(f"  IEA Server Started")
    print(f"  Listening on {SERVER_HOST}:{SERVER_PORT}")
    print(f"  Local IP: {local_ip}:{SERVER_PORT}")
    print(f"  Clients should connect to: {local_ip}:{SERVER_PORT}")
    print(f"{'='*50}\n")

    database.add_admin_log("SERVER_START", f"Server started on {SERVER_HOST}:{SERVER_PORT}")

    try:
        while running:
            try:
                client_sock, client_addr = server_sock.accept()
                thread = threading.Thread(
                    target=handle_client,
                    args=(client_sock, client_addr),
                    daemon=True
                )
                thread.start()
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        print("\n[INFO] Server shutting down...")
        running = False
    finally:
        server_sock.close()
        database.add_admin_log("SERVER_STOP", "Server stopped")
        print("[INFO] Server stopped")


if __name__ == "__main__":
    start_server()
