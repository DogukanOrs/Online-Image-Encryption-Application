"""
IEA Admin — Sysadmin Monitoring Client.

A Tkinter GUI for the sysadmin to monitor the IEA server.
Features:
- View connected users
- View server statistics (total users, messages, images)
- View admin logs (login/logout, key rotations, image transfers)
- Auto-refresh capability

No external dependencies — uses only Python built-in modules.
"""

import socket
import json
import time
import sys
import os
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import BUFFER_SIZE, ADMIN_USERNAME, ADMIN_PASSWORD


class AdminClient:
    """Admin client that connects to the IEA server."""

    def __init__(self):
        self.sock = None
        self.connected = False

    def connect(self, host, port):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((host, int(port)))
            self.connected = True
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False

    def disconnect(self):
        self.connected = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass

    def send_msg(self, msg_dict):
        try:
            data = json.dumps(msg_dict).encode("utf-8")
            length = len(data).to_bytes(4, "big")
            self.sock.sendall(length + data)
        except Exception as e:
            print(f"Send failed: {e}")
            self.connected = False

    def recv_msg(self):
        try:
            length_data = b""
            while len(length_data) < 4:
                chunk = self.sock.recv(4 - len(length_data))
                if not chunk:
                    return None
                length_data += chunk

            msg_length = int.from_bytes(length_data, "big")
            data = b""
            while len(data) < msg_length:
                chunk = self.sock.recv(min(BUFFER_SIZE, msg_length - len(data)))
                if not chunk:
                    return None
                data += chunk

            return json.loads(data.decode("utf-8"))
        except Exception as e:
            print(f"Receive failed: {e}")
            return None

    def login_admin(self):
        """Authenticate as admin."""
        self.send_msg({
            "type": "ADMIN_LOGIN",
            "username": ADMIN_USERNAME,
            "password": ADMIN_PASSWORD
        })
        response = self.recv_msg()
        return response and response.get("success", False)

    def get_stats(self):
        """Get server statistics."""
        self.send_msg({"type": "ADMIN_STATS"})
        return self.recv_msg()

    def get_logs(self):
        """Get admin logs."""
        self.send_msg({"type": "ADMIN_LOGS"})
        return self.recv_msg()

    def get_messages(self):
        """Get all stored messages with encrypted content."""
        self.send_msg({"type": "ADMIN_MESSAGES"})
        return self.recv_msg()


class AdminApp:
    """Tkinter GUI for admin monitoring."""

    def __init__(self):
        self.client = AdminClient()
        self.auto_refresh = False

        self.root = tk.Tk()
        self.root.title("IEA — Sysadmin Monitor")
        self.root.geometry("800x600")
        self.root.minsize(700, 500)

        self._build_login_screen()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_login_screen(self):
        """Build admin login screen."""
        self._clear_root()

        frame = tk.Frame(self.root, padx=30, pady=30)
        frame.place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(frame, text="IEA — Sysadmin Monitor", font=("Arial", 18, "bold")).grid(
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

        tk.Button(frame, text="Connect", font=("Arial", 11), width=15, command=self._on_connect).grid(
            row=3, column=0, columnspan=2, pady=15
        )

        self.status_label = tk.Label(frame, text="", font=("Arial", 10), fg="red")
        self.status_label.grid(row=4, column=0, columnspan=2)

    def _on_connect(self):
        """Connect to server and authenticate."""
        host = self.entry_host.get().strip()
        port = self.entry_port.get().strip()

        if not self.client.connect(host, port):
            self.status_label.config(text="Cannot connect to server", fg="red")
            return

        if not self.client.login_admin():
            self.status_label.config(text="Admin authentication failed", fg="red")
            self.client.disconnect()
            return

        self._build_dashboard()

    def _build_dashboard(self):
        """Build the admin monitoring dashboard."""
        self._clear_root()

        # Top bar
        top_frame = tk.Frame(self.root, pady=5, padx=10)
        top_frame.pack(fill="x")
        tk.Label(top_frame, text="IEA Server Monitor", font=("Arial", 14, "bold")).pack(side="left")
        tk.Button(top_frame, text="Refresh", command=self._refresh_all).pack(side="right", padx=5)
        tk.Button(top_frame, text="Disconnect", command=self._on_disconnect).pack(side="right", padx=5)

        self.auto_var = tk.BooleanVar(value=False)
        tk.Checkbutton(top_frame, text="Auto-refresh (10s)", variable=self.auto_var,
                       command=self._toggle_auto_refresh).pack(side="right", padx=5)

        # Stats frame
        stats_frame = tk.LabelFrame(self.root, text="Server Statistics", font=("Arial", 11, "bold"), padx=10, pady=5)
        stats_frame.pack(fill="x", padx=10, pady=5)

        self.stat_labels = {}
        stat_names = ["Uptime", "Total Users", "Online Users", "Total Messages", "Total Images", "Connected Clients"]
        for i, name in enumerate(stat_names):
            tk.Label(stats_frame, text=f"{name}:", font=("Arial", 10, "bold")).grid(row=i // 3, column=(i % 3) * 2, sticky="e", padx=5, pady=2)
            lbl = tk.Label(stats_frame, text="—", font=("Arial", 10))
            lbl.grid(row=i // 3, column=(i % 3) * 2 + 1, sticky="w", padx=5, pady=2)
            self.stat_labels[name] = lbl

        # Tabbed notebook for Logs and Messages
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=10, pady=5)

        # Tab 1: Admin Logs
        logs_tab = tk.Frame(notebook)
        notebook.add(logs_tab, text="Admin Logs")

        self.logs_text = scrolledtext.ScrolledText(logs_tab, font=("Courier", 9), state="disabled", wrap="word")
        self.logs_text.pack(fill="both", expand=True)

        # Tab 2: Message Logs (encrypted content)
        messages_tab = tk.Frame(notebook)
        notebook.add(messages_tab, text="Message Logs (Encrypted)")

        # Treeview table for messages
        columns = ("id", "sender", "receiver", "content", "sha256", "type", "timestamp")
        self.msg_tree = ttk.Treeview(messages_tab, columns=columns, show="headings", height=15)

        self.msg_tree.heading("id", text="ID")
        self.msg_tree.heading("sender", text="Sender")
        self.msg_tree.heading("receiver", text="Receiver")
        self.msg_tree.heading("content", text="Encrypted Content")
        self.msg_tree.heading("sha256", text="SHA-256 Hash")
        self.msg_tree.heading("type", text="Type")
        self.msg_tree.heading("timestamp", text="Timestamp")

        self.msg_tree.column("id", width=40, anchor="center")
        self.msg_tree.column("sender", width=80, anchor="center")
        self.msg_tree.column("receiver", width=80, anchor="center")
        self.msg_tree.column("content", width=220, anchor="w")
        self.msg_tree.column("sha256", width=180, anchor="w")
        self.msg_tree.column("type", width=50, anchor="center")
        self.msg_tree.column("timestamp", width=130, anchor="center")

        # Scrollbar for treeview
        msg_scrollbar = ttk.Scrollbar(messages_tab, orient="vertical", command=self.msg_tree.yview)
        self.msg_tree.configure(yscrollcommand=msg_scrollbar.set)

        self.msg_tree.pack(side="left", fill="both", expand=True)
        msg_scrollbar.pack(side="right", fill="y")

        # Initial refresh
        self._refresh_all()

    def _refresh_all(self):
        """Refresh stats and logs."""
        if not self.client.connected:
            return

        # Get stats
        stats_response = self.client.get_stats()
        if stats_response and stats_response.get("type") == "ADMIN_STATS_RESPONSE":
            stats = stats_response.get("stats", {})
            uptime_sec = stats.get("uptime", 0)
            hours = int(uptime_sec // 3600)
            mins = int((uptime_sec % 3600) // 60)
            secs = int(uptime_sec % 60)
            self.stat_labels["Uptime"].config(text=f"{hours}h {mins}m {secs}s")
            self.stat_labels["Total Users"].config(text=str(stats.get("total_users", 0)))
            self.stat_labels["Online Users"].config(text=str(stats.get("online_users", 0)))
            self.stat_labels["Total Messages"].config(text=str(stats.get("total_messages", 0)))
            self.stat_labels["Total Images"].config(text=str(stats.get("total_images", 0)))
            clients = stats.get("connected_clients", [])
            self.stat_labels["Connected Clients"].config(text=", ".join(clients) if clients else "None")

        # Get logs
        logs_response = self.client.get_logs()
        if logs_response and logs_response.get("type") == "ADMIN_LOGS_RESPONSE":
            logs = logs_response.get("logs", [])
            self.logs_text.config(state="normal")
            self.logs_text.delete("1.0", "end")
            for log in logs:
                ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(log.get("timestamp", 0)))
                event = log.get("event", "")
                details = log.get("details", "")
                self.logs_text.insert("end", f"[{ts}] {event}: {details}\n")
            self.logs_text.config(state="disabled")

        # Get messages (encrypted content)
        if hasattr(self, "msg_tree"):
            messages_response = self.client.get_messages()
            if messages_response and messages_response.get("type") == "ADMIN_MESSAGES_RESPONSE":
                # Clear existing rows
                for item in self.msg_tree.get_children():
                    self.msg_tree.delete(item)

                messages = messages_response.get("messages", [])
                for msg in messages:
                    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(msg.get("timestamp", 0)))
                    msg_type = "Image" if msg.get("is_image", 0) else "Text"
                    sha_hash = msg.get("sha256", "")
                    self.msg_tree.insert("", "end", values=(
                        msg.get("id", ""),
                        msg.get("sender", ""),
                        msg.get("receiver", ""),
                        msg.get("content", ""),
                        sha_hash,
                        msg_type,
                        ts
                    ))

    def _toggle_auto_refresh(self):
        """Toggle auto-refresh."""
        if self.auto_var.get():
            self.auto_refresh = True
            self._auto_refresh_loop()
        else:
            self.auto_refresh = False

    def _auto_refresh_loop(self):
        """Auto-refresh every 10 seconds."""
        if self.auto_refresh and self.client.connected:
            self._refresh_all()
            self.root.after(10000, self._auto_refresh_loop)

    def _on_disconnect(self):
        """Disconnect from server."""
        self.auto_refresh = False
        self.client.disconnect()
        self._build_login_screen()

    def _clear_root(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def _on_close(self):
        self.auto_refresh = False
        self.client.disconnect()
        self.root.destroy()

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = AdminApp()
    app.run()
