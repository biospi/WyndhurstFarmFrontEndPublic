import tkinter as tk
from tkinter import messagebox
import threading, socket, select, webbrowser, paramiko, ttkbootstrap as ttk
from ttkbootstrap.constants import *
import itertools, os
import subprocess, time, datetime, os
from tkinter import filedialog
from pathlib import Path

CHUNK_DURATION = 20 * 60  # 20 minutes

with Path("hanwha.txt").open("r") as file:
    HANWHA_IPS = [line.strip() for line in file if line.strip()]

with Path("hikvision.txt").open("r") as file:
    HIKVISION_IPS = [line.strip() for line in file if line.strip()]

# HANWHA_IPS = ["10.70.66.52", "10.70.66.53", "10.70.66.141", "10.70.66.50", "10.70.66.49", "10.70.66.47", "10.70.66.45",
#               "10.70.66.46", "10.70.66.54", "10.70.66.48", "10.70.66.26", "10.70.66.27", "10.70.66.25", "10.70.66.23",
#               "10.70.66.2", "10.70.66.2", "10.70.66.2", "10.70.66.2", "10.70.66.2", "10.70.66.2", "10.70.66.2",
#               "10.70.66.2", "10.70.66.2", "10.70.66.2", "10.70.66.2", "10.70.66.2", "10.70.66.2", "10.70.66.2"]

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

    # def forward_tunnel(self, local_port, remote_ip, remote_port, stop_flag=None):
    #     """Forward localhost:local_port → remote_ip:remote_port with optional stop control."""
    #     if stop_flag is None:
    #         stop_flag = threading.Event()  # default if no stop control needed
    #
    #     def handler(client_sock):
    #         try:
    #             chan = self.farm_transport.open_channel(
    #                 "direct-tcpip", (remote_ip, remote_port), client_sock.getsockname()
    #             )
    #             while True:
    #                 r, _, _ = select.select([client_sock, chan], [], [], 1)
    #                 if stop_flag.is_set():
    #                     break
    #                 if client_sock in r:
    #                     data = client_sock.recv(1024)
    #                     if not data:
    #                         break
    #                     chan.send(data)
    #                 if chan in r:
    #                     data = chan.recv(1024)
    #                     if not data:
    #                         break
    #                     client_sock.send(data)
    #         except Exception as e:
    #             print(f"[ERROR] Tunnel handler for {remote_ip}: {e}")
    #         finally:
    #             client_sock.close()
    #             chan.close()
    #
    #     def server(remote_ip=remote_ip):
    #         sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #         sock.bind(("127.0.0.1", local_port))
    #         sock.listen(10)
    #         print(f"[TUNNEL] RTSP tunnel active: localhost:{local_port} → {remote_ip}:{remote_port}")
    #         while not stop_flag.is_set():
    #             try:
    #                 client, _ = sock.accept()
    #                 threading.Thread(target=handler, args=(client,), daemon=True).start()
    #             except Exception:
    #                 break
    #         sock.close()
    #         print(f"[TUNNEL] Closed tunnel for {remote_ip}")
    #
    #     t = threading.Thread(target=server, daemon=True)
    #     t.start()
    #     self.active_tunnels[remote_ip] = (local_port, t)
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
            client_sock.close()
            chan.close()

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


# ---------- GUI ----------
class CCTVApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Wyndhurst Tunnel Dashboard")
        self.root.resizable(False, False)

        self.manager = None
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.remember_user_var = tk.BooleanVar(value=True)

        self.load_last_username()
        self.setup_ui()

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
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="SSH Username:").grid(row=0, column=0, sticky="w")
        ttk.Entry(frame, textvariable=self.username_var, width=25).grid(row=0, column=0, padx=5, pady=5)

        ttk.Label(frame, text="SSH Password (or key):").grid(row=1, column=0, sticky="w")
        ttk.Entry(frame, textvariable=self.password_var, width=25, show="*").grid(row=1, column=0, padx=5, pady=5)

        ttk.Checkbutton(
            frame, text="Remember username", variable=self.remember_user_var, bootstyle="round-toggle"
        ).grid(row=3, column=0, columnspan=2, sticky="w", pady=(0, 10))

        ttk.Button(frame, text="Connect", bootstyle=SUCCESS, command=self.connect_ssh).grid(
            row=3, column=0, rowspan=1, padx=10
        )

        ttk.Separator(frame).grid(row=4, columnspan=3, sticky="ew", pady=10)

        # Center camera list
        self.cameras_frame = ttk.Frame(frame)
        self.cameras_frame.grid(row=5, column=0, columnspan=3, sticky="nsew")
        self.cameras_frame.grid_columnconfigure((0, 1, 2), weight=1)

        ttk.Label(self.cameras_frame, text="Camera IP").grid(row=0, column=0, padx=8, pady=3, sticky="e")
        ttk.Label(self.cameras_frame, text="Port").grid(row=0, column=1, padx=8, pady=3, sticky="ew")

        self.cam_entries = []
        all_ips = HANWHA_IPS + HIKVISION_IPS
        num_columns = 4
        max_rows_per_column = 20

        ip_var_list = []
        for idx, ip in enumerate(all_ips):
            col = idx // max_rows_per_column
            row = (idx % max_rows_per_column) + 1  # +1 to leave row 0 for headers

            ip_var = tk.StringVar(value=ip)
            ip_var_list.append(ip_var)
            port_var = tk.StringVar(value=80)

            ttk.Entry(self.cameras_frame, textvariable=ip_var, width=18).grid(row=row, column=col * 3, padx=5, pady=3)
            ttk.Entry(self.cameras_frame, textvariable=port_var, width=6).grid(row=row, column=col * 3 + 1, padx=5,
                                                                               pady=3)

            btn_frame = ttk.Frame(self.cameras_frame)
            btn_frame.grid(row=row, column=col * 3 + 2, padx=5, pady=3)
            ttk.Button(btn_frame, text="Open", command=lambda iv=ip_var, pv=port_var: self.open_cam(iv, pv),
                       bootstyle=PRIMARY if ip in HANWHA_IPS else SECONDARY).pack(side="left", padx=2)
            ttk.Button(btn_frame, text="Record", command=lambda iv=ip_var, pv=port_var: self.start_recording(iv, pv),
                       bootstyle=SUCCESS).pack(side="left", padx=2)
            ttk.Button(btn_frame, text="Stop", command=lambda iv=ip_var: self.stop_recording(iv),
                       bootstyle=DANGER).pack(side="left", padx=2)

            self.cam_entries.append((ip_var, port_var))

        # Column headers
        for col in range(num_columns):
            ttk.Label(self.cameras_frame, text="IP").grid(row=0, column=col * 3, padx=5, pady=3)
            ttk.Label(self.cameras_frame, text="Port").grid(row=0, column=col * 3 + 1, padx=5, pady=3)
            ttk.Label(self.cameras_frame, text="Actions").grid(row=0, column=col * 3 + 2, padx=5, pady=3)

        # for i in range(10):
        #     ip_var = tk.StringVar(value="10.70.66.")
        #     port_var = tk.StringVar(value=f"{80+i}")
        #     ttk.Entry(self.cameras_frame, textvariable=ip_var, width=18).grid(
        #         row=i+1, column=0, padx=8, pady=3, sticky="e"
        #     )
        #     ttk.Entry(self.cameras_frame, textvariable=port_var, width=6).grid(
        #         row=i+1, column=1, padx=8, sticky="ew"
        #     )
        #     btn = ttk.Button(
        #         self.cameras_frame,
        #         text="Open Web UI",
        #         command=lambda iv=ip_var, pv=port_var: self.open_cam(iv, pv),
        #         bootstyle=PRIMARY
        #     )
        #
        #     ttk.Button(self.cameras_frame, text="Record",
        #                command=lambda iv=ip_var, pv=port_var: self.start_recording(iv, pv),
        #                bootstyle=SUCCESS).grid(row=i+1, column=3, padx=4)
        #
        #     ttk.Button(self.cameras_frame, text="Stop",
        #                command=lambda iv=ip_var: self.stop_recording(iv),
        #                bootstyle=DANGER).grid(row=i+1, column=4, padx=4)
        #
        #     btn.grid(row=i+1, column=2, padx=10, sticky="w")
        #     self.cam_entries.append((ip_var, port_var))

        self.status = ttk.Label(frame, text="Disconnected.", bootstyle="danger")
        self.status.grid(row=20, columnspan=3, pady=(20, 0))

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
