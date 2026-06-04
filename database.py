"""
Database module for the Online Image Encryption Application.
Uses SQLite — built into Python, no external dependencies.
"""

import sqlite3
import os
import time
from config import DB_PATH


def get_connection():
    """Get a database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_database():
    """Create all tables if they don't exist."""
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            public_key_e TEXT,
            public_key_n TEXT,
            private_key_d TEXT,
            private_key_n TEXT,
            is_online INTEGER DEFAULT 0,
            created_at REAL
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            content TEXT NOT NULL,
            is_image INTEGER DEFAULT 0,
            timestamp REAL
        );

        CREATE TABLE IF NOT EXISTS images (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            filename TEXT NOT NULL,
            encrypted_key TEXT,
            signature TEXT,
            timestamp REAL
        );

        CREATE TABLE IF NOT EXISTS admin_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event TEXT NOT NULL,
            details TEXT,
            timestamp REAL
        );

        CREATE TABLE IF NOT EXISTS session_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user1 TEXT NOT NULL,
            user2 TEXT NOT NULL,
            encrypted_key_for_user2 TEXT,
            timestamp REAL
        );
    """)
    conn.commit()
    conn.close()


# ---- User operations ----

def register_user(username, password):
    """Register a new user. Returns True on success, False if username taken."""
    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO users (username, password, created_at) VALUES (?, ?, ?)",
            (username, password, time.time())
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def login_user(username, password):
    """Check login credentials. Returns user row or None."""
    conn = get_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, password)
    ).fetchone()
    if user:
        conn.execute("UPDATE users SET is_online = 1 WHERE username = ?", (username,))
        conn.commit()
    conn.close()
    return dict(user) if user else None


def logout_user(username):
    """Mark user as offline."""
    conn = get_connection()
    conn.execute("UPDATE users SET is_online = 0 WHERE username = ?", (username,))
    conn.commit()
    conn.close()


def get_online_users():
    """Get list of online usernames."""
    conn = get_connection()
    rows = conn.execute("SELECT username FROM users WHERE is_online = 1").fetchall()
    conn.close()
    return [row["username"] for row in rows]


def get_all_users():
    """Get all users with their status."""
    conn = get_connection()
    rows = conn.execute("SELECT username, is_online, created_at FROM users").fetchall()
    conn.close()
    return [dict(row) for row in rows]


# ---- RSA key operations ----

def store_rsa_keys(username, public_key, private_key):
    """Store RSA keys for a user. public_key = (e, n), private_key = (d, n)."""
    e, n = public_key
    d, _ = private_key
    conn = get_connection()
    conn.execute(
        "UPDATE users SET public_key_e = ?, public_key_n = ?, private_key_d = ?, private_key_n = ? WHERE username = ?",
        (str(e), str(n), str(d), str(n), username)
    )
    conn.commit()
    conn.close()


def get_public_key(username):
    """Get a user's RSA public key. Returns (e, n) as integers or None."""
    conn = get_connection()
    row = conn.execute(
        "SELECT public_key_e, public_key_n FROM users WHERE username = ?",
        (username,)
    ).fetchone()
    conn.close()
    if row and row["public_key_e"] and row["public_key_n"]:
        return (int(row["public_key_e"]), int(row["public_key_n"]))
    return None


def get_private_key(username):
    """Get a user's RSA private key. Returns (d, n) as integers or None."""
    conn = get_connection()
    row = conn.execute(
        "SELECT private_key_d, private_key_n FROM users WHERE username = ?",
        (username,)
    ).fetchone()
    conn.close()
    if row and row["private_key_d"] and row["private_key_n"]:
        return (int(row["private_key_d"]), int(row["private_key_n"]))
    return None


def get_all_registered_usernames():
    """Get all registered usernames (for key rotation)."""
    conn = get_connection()
    rows = conn.execute("SELECT username FROM users").fetchall()
    conn.close()
    return [row["username"] for row in rows]


# ---- Message operations ----

def save_message(sender, receiver, content, is_image=False):
    """Save a chat message or image record."""
    conn = get_connection()
    conn.execute(
        "INSERT INTO messages (sender, receiver, content, is_image, timestamp) VALUES (?, ?, ?, ?, ?)",
        (sender, receiver, content, 1 if is_image else 0, time.time())
    )
    conn.commit()
    conn.close()


def get_message_count():
    """Get total number of messages."""
    conn = get_connection()
    row = conn.execute("SELECT COUNT(*) as cnt FROM messages").fetchone()
    conn.close()
    return row["cnt"]


def get_all_messages(limit=100):
    """Get all messages with encrypted content for admin viewing."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, sender, receiver, content, is_image, timestamp FROM messages ORDER BY timestamp DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


# ---- Image operations ----

def save_image_record(sender, receiver, filename, encrypted_key, signature):
    """Save an encrypted image record."""
    conn = get_connection()
    conn.execute(
        "INSERT INTO images (sender, receiver, filename, encrypted_key, signature, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
        (sender, receiver, filename, encrypted_key, signature, time.time())
    )
    conn.commit()
    conn.close()


def get_image_records(receiver):
    """Get image records for a receiver."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM images WHERE receiver = ? ORDER BY timestamp DESC",
        (receiver,)
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


# ---- Admin operations ----

def add_admin_log(event, details=""):
    """Add an admin log entry."""
    conn = get_connection()
    conn.execute(
        "INSERT INTO admin_logs (event, details, timestamp) VALUES (?, ?, ?)",
        (event, details, time.time())
    )
    conn.commit()
    conn.close()


def get_admin_logs(limit=50):
    """Get recent admin log entries."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM admin_logs ORDER BY timestamp DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_server_stats():
    """Get server statistics for admin dashboard."""
    conn = get_connection()
    total_users = conn.execute("SELECT COUNT(*) as cnt FROM users").fetchone()["cnt"]
    online_users = conn.execute("SELECT COUNT(*) as cnt FROM users WHERE is_online = 1").fetchone()["cnt"]
    total_messages = conn.execute("SELECT COUNT(*) as cnt FROM messages").fetchone()["cnt"]
    total_images = conn.execute("SELECT COUNT(*) as cnt FROM images").fetchone()["cnt"]
    conn.close()
    return {
        "total_users": total_users,
        "online_users": online_users,
        "total_messages": total_messages,
        "total_images": total_images,
    }


# ---- Session key operations ----

def store_session_key(user1, user2, encrypted_key_for_user2):
    """Store an encrypted session key."""
    conn = get_connection()
    # Remove old session keys between these users
    conn.execute(
        "DELETE FROM session_keys WHERE (user1 = ? AND user2 = ?) OR (user1 = ? AND user2 = ?)",
        (user1, user2, user2, user1)
    )
    conn.execute(
        "INSERT INTO session_keys (user1, user2, encrypted_key_for_user2, timestamp) VALUES (?, ?, ?, ?)",
        (user1, user2, encrypted_key_for_user2, time.time())
    )
    conn.commit()
    conn.close()


def get_session_key(user1, user2):
    """Get the encrypted session key sent from user1 to user2."""
    conn = get_connection()
    row = conn.execute(
        "SELECT encrypted_key_for_user2 FROM session_keys WHERE user1 = ? AND user2 = ?",
        (user1, user2)
    ).fetchone()
    conn.close()
    return row["encrypted_key_for_user2"] if row else None


if __name__ == "__main__":
    init_database()
    print("Database initialized successfully.")
