import tkinter as tk
from tkinter import messagebox
import threading, socket, select, webbrowser, paramiko, ttkbootstrap as ttk
from ttkbootstrap.constants import *
import itertools, os, subprocess, time, datetime
from tkinter import filedialog
from pathlib import Path

CHUNK_DURATION = 20 * 60  # 20 minutes

with Path("hanwha.txt").open("r") as file:
    HANWHA_IPS = [line.strip() for line in file if line.strip()]

with Path("hikvision.txt").open("r") as file:
    HIKVISION_IPS = [line.strip() for line in file if line.strip()]

HANWHA_IPS.sort(key=lambda ip: tuple(int(x) for x in ip.split(".")))
HIKVISION_IPS.sort(key=lambda ip: tuple(int(x) for x in ip.split(".")))

config = {
    "AUTH": {
        "password_hanwha": "Ocs881212",
        "password_hikvision": "ocs881212"
    }
}

# ---------- CONFIG ----------
SSH_GATEWAY = "IT107338.users.bris.ac.uk"
SSH_GATEWAY_PORT = 22
FARM_PC = "10.70.66.2"
FARM_PC_PORT = 22
START_PORT = 8080
LAST_USER_FILE = ".last_user.txt"
# ----------------------------


class TunnelManager:
    def __init__(self, gateway_user, gateway_pass=None, keyfile=None):
        self.gateway_user = gateway_user
        self.gateway_pass = gateway_pass
        self.keyfile = keyfile
        self.transport = None
        self.farm_transport = None
        self.client_chain = []
        self.active_tunnels = {}
        self.port_gen = itertools.count(START_PORT)

    def connect_chain(self):
        """Establish SSH chain: Laptop → Ubuntu Server → Farm PC"""
        gw_client = paramiko.SSHClient()
        gw_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        gw_client.connect(
            SSH_GATEWAY,
            port=SSH_GATEWAY_PORT,
            username=self.gateway_user,
            password=self.gateway_pass or None,
            key_filename=self.keyfile or None,
            allow_agent=True,
            look_for_keys=True,
        )
        print("[SSH] Connected to gateway")

        farm_sock = gw_client.get_transport().open_channel(
            "direct-tcpip", (FARM_PC, FARM_PC_PORT), ("127.0.0.1", 0)
        )

        farm_client = paramiko.SSHClient()
        farm_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        farm_client.connect(
            FARM_PC,
            username=self.gateway_user,
            password=self.gateway_pass or None,
            sock=farm_sock,
            allow_agent=True,
            look_for_keys=True,
        )
        print("[SSH] Connected to farm PC")

        self.transport = gw_client.get_transport()
        self.farm_transport = farm_client.get_transport()
        self.client_chain = [gw_client, farm_client]

    def forward_tunnel(self, local_port, remote_ip, remote_port):
        """Forward remote_ip:remote_port → localhost:local_port using Paramiko's port forwarding"""
        print(local_port, remote_ip, remote_port)
        stop_flag = threading.Event()
        self.active_tunnels[remote_ip] = (local_port, stop_flag)

        def server():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("127.0.0.1", local_port))
            sock.listen(5)
            print(f"[TUNNEL] localhost:{local_port} → {remote_ip}:{remote_port}")
            while not stop_flag.is_set():
                try:
                    client, _ = sock.accept()
                    chan = self.farm_transport.open_channel(
                        "direct-tcpip", (remote_ip, remote_port), client.getsockname()
                    )
                    threading.Thread(target=self._pipe, args=(client, chan), daemon=True).start()
                except Exception as e:
                    print(f"[TUNNEL] Accept error: {e}")
                    break
            sock.close()
            print(f"[TUNNEL] Closed tunnel for {remote_ip}")

        threading.Thread(target=server, daemon=True).start()
        return stop_flag

    @staticmethod
    def _pipe(client_sock, chan):
        """Pipe data between client socket and SSH channel"""
        try:
            while True:
                r, _, _ = select.select([client_sock, chan], [], [], 1)
                if client_sock in r:
                    data = client_sock.recv(1024)
                    if not data:
                        break
                    chan.send(data)
                if chan in r:
                    data = chan.recv(1024)
                    if not data:
                        break
                    client_sock.send(data)
        except Exception as e:
            print(f"[PIPE ERROR] {e}")
        finally:
            try:
                client_sock.close()
            except Exception:
                pass
            try:
                chan.close()
            except Exception:
                pass

    def open_camera(self, ip, port=80):
        local_port = next(self.port_gen)
        self.forward_tunnel(local_port, ip, port)
        url = f"http://localhost:{local_port}"
        webbrowser.open(url)
        return url

    def close_all(self):
        for c in self.client_chain:
            try:
                c.close()
            except Exception:
                pass
        self.active_tunnels.clear()


# ---------- Scrollable Frame (camera list only) ----------
class ScrollFrame(ttk.Frame):
    """A scrollable frame using a canvas + interior frame."""
    def __init__(self, parent, height=300, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)

        self.canvas = tk.Canvas(self, highlightthickness=0)
        self.vscroll = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vscroll.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.vscroll.pack(side="right", fill="y")

        # Interior frame that will actually hold widgets
        self.interior = ttk.Frame(self.canvas)
        self.interior_id = self.canvas.create_window((0, 0), window=self.interior, anchor="nw")

        # Bind to update scrollregion when interior changes
        self.interior.bind("<Configure>", self._on_frame_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)

        # Mousewheel bindings for convenience
        self.canvas.bind("<Enter>", lambda e: self._bind_mousewheel())
        self.canvas.bind("<Leave>", lambda e: self._unbind_mousewheel())

        # For platforms that use button-4/5
        self.canvas.bind_all("<Button-4>", self._on_mousewheel, add="+")
        self.canvas.bind_all("<Button-5>", self._on_mousewheel, add="+")

    def _on_frame_configure(self, event):
        # Update scroll region to match interior size
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_canvas_configure(self, event):
        # Make the interior frame width match the canvas width
        try:
            self.canvas.itemconfig(self.interior_id, width=event.width)
        except Exception:
            pass

    def _bind_mousewheel(self):
        # Windows / macOS
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

    def _unbind_mousewheel(self):
        self.canvas.unbind_all("<MouseWheel>")

    def _on_mousewheel(self, event):
        # Cross-platform mousewheel handler
        try:
            if hasattr(event, "delta"):  # Windows / macOS
                if event.delta < 0:
                    self.canvas.yview_scroll(1, "unit")
                elif event.delta > 0:
                    self.canvas.yview_scroll(-1, "unit")
            elif event.num == 5:  # X11 scroll down
                self.canvas.yview_scroll(1, "unit")
            elif event.num == 4:  # X11 scroll up
                self.canvas.yview_scroll(-1, "unit")
        except Exception:
            pass


# ---------- GUI ----------
class CCTVApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Wyndhurst Tunnel Dashboard")

        # ALLOW resizing so geometry("") can shrink/expand to fit content
        self.root.resizable(True, True)

        # Make the root window a sensible minimum size
        self.root.minsize(640, 360)

        self.manager = None
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.remember_user_var = tk.BooleanVar(value=True)

        self.load_last_username()
        self.setup_ui()

        # Force a layout calculation and auto-size window to content
        self.root.update_idletasks()
        # geometry("") instructs Tk to fit window to its requested size
        try:
            self.root.geometry("")   # auto-size to content
        except Exception:
            pass

        self.recording_threads = {}
        self.stop_flags = {}

    # ---------------- Recording Logic ----------------
    def start_recording(self, ip_var, port_var):
        ip = ip_var.get().strip()
        port = int(port_var.get().strip() or 80)
        if not ip:
            messagebox.showwarning("Missing IP", "Please enter camera IP first.")
            return

        if not self.manager:
            messagebox.showwarning("Not connected", "Connect SSH first.")
            return

        save_dir = filedialog.askdirectory(title=f"Select recording destination for {ip}")
        if not save_dir:
            return

        # Create tunnel if not already active
        local_port = next(self.manager.port_gen)
        self.manager.forward_tunnel(local_port, ip, 554)
        self.status.config(text=f"Recording from {ip}...", bootstyle="info")

        stop_flag = threading.Event()
        self.stop_flags[ip] = stop_flag

        def record_loop():
            while not stop_flag.is_set():
                start_time = datetime.datetime.now()
                end_time = start_time + datetime.timedelta(seconds=CHUNK_DURATION)

                start_str = start_time.strftime("%Y%m%d_%H%M%S")
                end_str = end_time.strftime("%Y%m%d_%H%M%S")
                output_file = Path(save_dir) / f"{ip.replace('.', '_')}_{start_str}_to_{end_str}.mp4"

                # Select format
                if ip in HANWHA_IPS:
                    rtsp_url = f"rtsp://admin:{config['AUTH']['password_hanwha']}@localhost:{local_port}/profile2/media.smp"
                if ip in HIKVISION_IPS:
                    rtsp_url = f"rtsp://admin:{config['AUTH']['password_hikvision']}@localhost:{local_port}/Streaming/channels/101"

                command = [
                    "ffmpeg", "-y",
                    "-rtsp_transport", "tcp",
                    "-i", rtsp_url,
                    "-t", str(CHUNK_DURATION),
                    "-c:v", "libx264",
                    "-preset", "fast",
                    "-crf", "28",
                    "-r", "16",
                    "-an",
                    output_file.as_posix()
                ]

                print(f"[RECORD] Running: {' '.join(command)}")
                try:
                    subprocess.run(command, check=True)
                except subprocess.CalledProcessError as e:
                    print(f"[ERROR] Recording {ip}: {e}")
                    break

            print(f"[STOP] Recording stopped for {ip}")

        t = threading.Thread(target=record_loop, daemon=True)
        self.recording_threads[ip] = t
        t.start()

    def stop_recording(self, ip_var):
        ip = ip_var.get().strip()
        if ip in self.stop_flags:
            self.stop_flags[ip].set()
            self.status.config(text=f"Stopped recording {ip}", bootstyle="warning")
        else:
            messagebox.showinfo("Not recording", f"No active recording for {ip}")

    def load_last_username(self):
        """Load the last saved username if it exists."""
        if os.path.exists(LAST_USER_FILE):
            try:
                with open(LAST_USER_FILE, "r") as f:
                    saved_user = f.read().strip()
                    if saved_user:
                        self.username_var.set(saved_user)
            except Exception:
                pass

    def save_last_username(self, username):
        """Save the username to a small file if checkbox ticked."""
        if self.remember_user_var.get():
            try:
                with open(LAST_USER_FILE, "w") as f:
                    f.write(username)
            except Exception as e:
                print(f"Failed to save username: {e}")
        else:
            if os.path.exists(LAST_USER_FILE):
                os.remove(LAST_USER_FILE)

    def setup_ui(self):
        # Outer frame holds header/login + scrollable camera area + status
        outer = ttk.Frame(self.root, padding=12)
        outer.pack(fill="both", expand=True)

        # --- Header / SSH login (fixed; not scrollable) ---
        header = ttk.Frame(outer)
        header.pack(fill="x", pady=(0, 8))

        # Row 0 (username)
        ttk.Label(header, text="SSH Username:").grid(row=0, column=0, sticky="w", padx=(0, 6))
        ttk.Entry(header, textvariable=self.username_var, width=25).grid(row=0, column=1, padx=5, pady=4, sticky="w")

        # Row 1 (password)
        ttk.Label(header, text="SSH Password (or key):").grid(row=1, column=0, sticky="w", padx=(0, 6))
        ttk.Entry(header, textvariable=self.password_var, width=25, show="*").grid(row=1, column=1, padx=5, pady=4, sticky="w")

        ttk.Checkbutton(
            header, text="Remember username", variable=self.remember_user_var, bootstyle="round-toggle"
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(0, 6))

        ttk.Button(header, text="Connect", bootstyle=SUCCESS, command=self.connect_ssh).grid(
            row=0, column=2, rowspan=2, padx=(10, 0)
        )

        # Separator
        ttk.Separator(outer).pack(fill="x", pady=6)

        # --- Scrollable camera list (this is Option A: only camera list scrolls) ---
        scroll = ScrollFrame(outer, height=300)
        scroll.pack(fill="both", expand=True, pady=(6, 6))
        self.cameras_frame = scroll.interior

        # Make columns expand within the interior frame
        # Note: we use groups of 3 columns (IP, Port, Actions) repeated across columns
        # Ensure the exterior scroll frame expands horizontally
        self.cameras_frame.grid_columnconfigure(0, weight=1)

        # Header row inside cameras_frame
        ttk.Label(self.cameras_frame, text="IP").grid(row=0, column=0, padx=5, pady=3)
        ttk.Label(self.cameras_frame, text="Port").grid(row=0, column=1, padx=5, pady=3)
        ttk.Label(self.cameras_frame, text="Actions").grid(row=0, column=2, padx=5, pady=3)

        self.cam_entries = []
        all_ips = HANWHA_IPS + HIKVISION_IPS
        max_rows_per_column = 2000  # we will place all in one continuous column since we scroll

        for idx, ip in enumerate(all_ips):
            row = idx + 1  # +1 to leave row 0 for headers

            ip_var = tk.StringVar(value=ip)
            port_var = tk.StringVar(value="80")

            ttk.Entry(self.cameras_frame, textvariable=ip_var, width=18).grid(row=row, column=0, padx=5, pady=3, sticky="w")
            ttk.Entry(self.cameras_frame, textvariable=port_var, width=6).grid(row=row, column=1, padx=5, pady=3, sticky="w")

            btn_frame = ttk.Frame(self.cameras_frame)
            btn_frame.grid(row=row, column=2, padx=5, pady=3, sticky="w")
            ttk.Button(btn_frame, text="Open", command=lambda iv=ip_var, pv=port_var: self.open_cam(iv, pv),
                       bootstyle=PRIMARY if ip in HANWHA_IPS else SECONDARY).pack(side="left", padx=2)
            ttk.Button(btn_frame, text="Record", command=lambda iv=ip_var, pv=port_var: self.start_recording(iv, pv),
                       bootstyle=SUCCESS).pack(side="left", padx=2)
            ttk.Button(btn_frame, text="Stop", command=lambda iv=ip_var: self.stop_recording(iv),
                       bootstyle=DANGER).pack(side="left", padx=2)

            self.cam_entries.append((ip_var, port_var))

        # --- Status bar (fixed) ---
        self.status = ttk.Label(outer, text="Disconnected.", bootstyle="danger")
        self.status.pack(fill="x", pady=(8, 0))

    def connect_ssh(self):
        user = self.username_var.get().strip()
        pwd = self.password_var.get().strip() or None
        if not user:
            messagebox.showerror("Missing Info", "Please enter your SSH username.")
            return
        self.save_last_username(user)
        try:
            self.manager = TunnelManager(user, pwd)
            self.manager.connect_chain()
            self.status.config(text="Connected via Ubuntu server → Farm PC", bootstyle="success")
        except Exception as e:
            print(e)
            messagebox.showerror("Connection failed", str(e))
            self.status.config(text="Connection failed.", bootstyle="danger")

    def open_cam(self, ip_var, port_var):
        print(ip_var.get(), port_var.get())
        if not self.manager:
            messagebox.showwarning("Not connected", "Connect SSH first.")
            return
        ip = ip_var.get().strip()
        try:
            port = int(port_var.get().strip())
        except:
            port = 80
        if not ip:
            messagebox.showwarning("Missing IP", "Please enter camera IP.")
            return
        try:
            url = self.manager.open_camera(ip, port)
            self.status.config(text=f"Opened {url}", bootstyle="info")
        except Exception as e:
            print(e)
            messagebox.showerror("Error", f"Failed to open {ip}: {e}")

    def on_close(self):
        if self.manager:
            self.manager.close_all()
        self.root.destroy()


if __name__ == "__main__":
    app = ttk.Window(themename="flatly")
    gui = CCTVApp(app)
    app.protocol("WM_DELETE_WINDOW", gui.on_close)
    app.mainloop()
