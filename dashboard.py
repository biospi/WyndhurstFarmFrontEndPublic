"""
dashboard_connector_paramiko.py

Dependencies:
    pip install ttkbootstrap paramiko
Place uob.png in same folder.

Usage:
    python dashboard_connector_paramiko.py
"""

import tkinter as tk
from tkinter import messagebox, filedialog
import threading
import webbrowser
import os
import json
import select
import socket
import sys
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

import paramiko

# ---------- Config ----------
SSH_GATEWAY_HOST = "IT106570.users.bris.ac.uk"
SSH_GATEWAY_PORT = 22
REMOTE_STREAMLIT_HOST = "127.0.0.1"
REMOTE_STREAMLIT_PORT = 8501
DEFAULT_LOCAL_PORT = 8501
ICON_FILENAME = "uob.png"
CONFIG_FILE = "dashboard_config.json"
# ----------------------------

# Globals
_tunnel_thread = None
_tunnel_active = False


def set_status(text, style="info"):
    def _update():
        status_label.config(text=text)
        if style == "success":
            status_label.configure(bootstyle="success")
        elif style == "danger":
            status_label.configure(bootstyle="danger")
        elif style == "warning":
            status_label.configure(bootstyle="warning")
        else:
            status_label.configure(bootstyle="info")
    root.after(0, _update)


def forward_tunnel(local_port, remote_host, remote_port, transport):
    """Forward local_port on localhost to remote_host:remote_port via transport."""
    class SubHandler(threading.Thread):
        daemon = True
        def __init__(self, client_socket):
            super().__init__()
            self.client_socket = client_socket

        def run(self):
            try:
                chan = transport.open_channel(
                    'direct-tcpip',
                    (remote_host, remote_port),
                    self.client_socket.getpeername()
                )
            except Exception as e:
                print(f"Forwarding request to {remote_host}:{remote_port} failed: {e}")
                self.client_socket.close()
                return
            if chan is None:
                self.client_socket.close()
                return

            while True:
                r, w, x = select.select([self.client_socket, chan], [], [])
                if self.client_socket in r:
                    data = self.client_socket.recv(1024)
                    if not data:
                        break
                    chan.send(data)
                if chan in r:
                    data = chan.recv(1024)
                    if not data:
                        break
                    self.client_socket.send(data)
            chan.close()
            self.client_socket.close()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('127.0.0.1', local_port))
    except Exception as e:
        set_status(f"Binding local port {local_port} failed: {e}", "danger")
        return

    sock.listen(100)
    set_status(f"Tunnel available at http://localhost:{local_port}", "success")
    while _tunnel_active:
        try:
            client_sock, addr = sock.accept()
        except Exception:
            break
        handler = SubHandler(client_sock)
        handler.start()
    sock.close()


def start_tunnel(username, password, key_filename, local_port, auto_open):
    global _tunnel_thread, _tunnel_active
    if _tunnel_active:
        set_status("Tunnel already running.", "warning")
        return

    set_status("Connecting…", "info")

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if key_filename:
            client.connect(
                SSH_GATEWAY_HOST, SSH_GATEWAY_PORT,
                username=username, key_filename=key_filename,
                password=password or None
            )
        else:
            client.connect(
                SSH_GATEWAY_HOST, SSH_GATEWAY_PORT,
                username=username, password=password or None
            )

        transport = client.get_transport()
        if not transport:
            raise Exception("SSH transport not available")

        _tunnel_active = True

        forward_thread = threading.Thread(
            target=forward_tunnel,
            args=(local_port, REMOTE_STREAMLIT_HOST, REMOTE_STREAMLIT_PORT, transport),
            daemon=True
        )
        forward_thread.start()

        _tunnel_thread = (client, transport, forward_thread)

        url = f"http://localhost:{local_port}"
        root.after(0, lambda: connect_btn.configure(text="Disconnect", bootstyle="danger", command=disconnect))
        root.after(0, lambda: username_entry.configure(state="disabled"))
        root.after(0, lambda: password_entry.configure(state="disabled"))
        root.after(0, lambda: key_entry.configure(state="disabled"))
        root.after(0, lambda: local_port_entry.configure(state="disabled"))

        set_status(f"Tunnel started → {url}", "success")
        root.clipboard_clear()
        root.clipboard_append(url)
        if auto_open:
            webbrowser.open(url)

    except Exception as e:
        set_status(f"Error connecting: {e}", "danger")
        messagebox.showerror("Connection error", str(e))
        _tunnel_active = False
        root.after(0, lambda: connect_btn.configure(text="Connect", bootstyle=SUCCESS, command=connect))
        root.after(0, lambda: username_entry.configure(state="normal"))
        root.after(0, lambda: password_entry.configure(state="normal"))
        root.after(0, lambda: key_entry.configure(state="normal"))
        root.after(0, lambda: local_port_entry.configure(state="normal"))


def disconnect():
    global _tunnel_active, _tunnel_thread
    if not _tunnel_active or not _tunnel_thread:
        set_status("No tunnel running.", "warning")
        return
    client, transport, fwd_thread = _tunnel_thread
    _tunnel_active = False
    try:
        transport.close()
        client.close()
    except Exception as e:
        print("Error closing tunnel:", e)
    _tunnel_thread = None
    set_status("Tunnel closed.", "info")
    root.after(0, lambda: connect_btn.configure(text="Connect", bootstyle=SUCCESS, command=connect))
    root.after(0, lambda: username_entry.configure(state="normal"))
    root.after(0, lambda: password_entry.configure(state="normal"))
    root.after(0, lambda: key_entry.configure(state="normal"))
    root.after(0, lambda: local_port_entry.configure(state="normal"))


def connect():
    username = username_var.get().strip()
    password = password_var.get()
    keyfile = keyfile_var.get().strip()
    local_port = local_port_var.get().strip()
    auto_open = open_check_var.get()

    if not username:
        set_status("Enter username.", "danger")
        return
    try:
        lp = int(local_port)
    except:
        set_status("Local port must be number.", "danger")
        return

    start_tunnel(username, password, keyfile, lp, auto_open)


# ---------- Config Helpers ----------

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_config(cfg):
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(cfg, f)
    except:
        pass


# ---------- GUI Setup ----------

root = ttk.Window(themename="cosmo")
root.title("Wyndhurst Dashboard")
root.geometry("500x300")
root.resizable(False, False)

# Icon
try:
    img = tk.PhotoImage(file=ICON_FILENAME)
    root.iconphoto(False, img)
except Exception:
    pass

padx = 12
pady = 6

title = ttk.Label(root, text="Wyndhurst Dashboard", font=("Segoe UI", 16, "bold"))
title.pack(pady=(20, 10))

form = ttk.Frame(root)
form.pack(padx=padx, pady=(0,10), fill="x")

username_var = tk.StringVar()
password_var = tk.StringVar()
keyfile_var = tk.StringVar()
local_port_var = tk.StringVar(value=str(DEFAULT_LOCAL_PORT))
open_check_var = tk.BooleanVar(value=True)

# Username
ttk.Label(form, text="Username:").grid(row=0, column=0, sticky="w", pady=4)
username_entry = ttk.Entry(form, textvariable=username_var, width=30)
username_entry.grid(row=0, column=1, sticky="w", padx=8)

# Password
ttk.Label(form, text="Password (or leave blank for SSH key):").grid(row=1, column=0, sticky="w", pady=4)
password_entry = ttk.Entry(form, textvariable=password_var, width=30, show="*")
password_entry.grid(row=1, column=1, sticky="w", padx=8)

pw_show_var = tk.BooleanVar(value=False)
def toggle_show_pw():
    password_entry.config(show="" if pw_show_var.get() else "*")
pw_cb = ttk.Checkbutton(form, text="Show", variable=pw_show_var, command=toggle_show_pw, bootstyle="toolbutton")
pw_cb.grid(row=1, column=2, padx=(6,0))

# Private key file
ttk.Label(form, text="Private key file (optional):").grid(row=2, column=0, sticky="w", pady=4)
key_entry = ttk.Entry(form, textvariable=keyfile_var, width=30)
key_entry.grid(row=2, column=1, sticky="w", padx=8)

# Local Port
ttk.Label(form, text="Local port:").grid(row=3, column=0, sticky="w", pady=4)
local_port_entry = ttk.Entry(form, textvariable=local_port_var, width=10)
local_port_entry.grid(row=3, column=1, sticky="w", padx=8)

# Auto open
open_check = ttk.Checkbutton(form, text="Open browser after connect", variable=open_check_var, bootstyle="success")
open_check.grid(row=4, column=1, sticky="w", pady=(6,2))

# Buttons
buttons = ttk.Frame(root)
buttons.pack(pady=(10,5))

connect_btn = ttk.Button(buttons, text="Connect", bootstyle=SUCCESS, width=16, command=connect)
connect_btn.grid(row=0, column=0, padx=5)

def copy_link():
    try:
        clip = root.clipboard_get()
        messagebox.showinfo("Link in clipboard", f"Copied link:\n{clip}")
    except:
        messagebox.showinfo("Link in clipboard", "No link in clipboard. Connect first.")

copy_btn = ttk.Button(buttons, text="Show link in clipboard", bootstyle=PRIMARY, width=20, command=copy_link)
copy_btn.grid(row=0, column=1, padx=5)

status_label = ttk.Label(root, text="Ready", font=("Segoe UI", 10), bootstyle="info", anchor="center")
status_label.pack(fill="x", padx=padx, pady=(5, 15))

def on_close():
    if _tunnel_active:
        if messagebox.askyesno("Exit", "Tunnel is running. Disconnect and exit?"):
            disconnect()
        else:
            return
    root.destroy()

root.protocol("WM_DELETE_WINDOW", on_close)

username_entry.focus_set()


# ---------- Startup Warning ----------

def show_vpn_warning():
    warn = tk.Toplevel(root)
    warn.title("VPN Requirement")
    warn.geometry("400x200")
    warn.resizable(False, False)

    lbl = ttk.Label(
        warn,
        text="⚠️ You must be connected to the UoB network\nor have the UoB VPN activated before using this dashboard.",
        font=("Segoe UI", 11),
        wraplength=360,
        justify="center"
    )
    lbl.pack(pady=20)

    dont_show_var = tk.BooleanVar(value=False)
    cb = ttk.Checkbutton(
        warn,
        text="Don't show this message again",
        variable=dont_show_var,
        bootstyle="secondary"
    )
    cb.pack(pady=10)

    def close_warning():
        if dont_show_var.get():
            cfg = load_config()
            cfg["skip_vpn_warning"] = True
            save_config(cfg)
        warn.destroy()

    ok_btn = ttk.Button(warn, text="OK", bootstyle=SUCCESS, command=close_warning)
    ok_btn.pack(pady=10)

    warn.transient(root)
    warn.grab_set()
    root.wait_window(warn)

cfg = load_config()
if not cfg.get("skip_vpn_warning", False):
    root.after(100, show_vpn_warning)

# ---------- Run ----------
root.mainloop()
