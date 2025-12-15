import shutil
import signal
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

with Path("raspberry.txt").open("r") as file:
    RASPBERRY_IPS = [line.strip() for line in file if line.strip()]

HANWHA_IPS.sort(key=lambda ip: tuple(int(x) for x in ip.split(".")))
HIKVISION_IPS.sort(key=lambda ip: tuple(int(x) for x in ip.split(".")))
RASPBERRY_IPS.sort(key=lambda ip: tuple(int(x) for x in ip.split(".")))


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
START_PORT = 9000
LAST_USER_FILE = ".last_user.txt"
# ----------------------------


# ---------- RASPBERRY PI TUNNEL CONFIG ----------
RPI_REMOTE_PORT = 8765

RPI_INTERMEDIATE_PORT = 30022
RPI_LOCAL_PORT = 38765
# ----------------------------------------------


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

    def forward_rtsp_paramiko(self, ip):
        local_port = next(self.port_gen)
        stop_flag = self.forward_tunnel(local_port, ip, 554)
        time.sleep(2)
        return local_port, stop_flag

    def open_raspberry_paramiko(self, raspberry_ip):
        local_port = RPI_LOCAL_PORT

        # Reuse existing farm_transport
        stop_flag = threading.Event()

        def server():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("127.0.0.1", local_port))
            sock.listen(5)

            print(f"[RPI] localhost:{local_port} → {raspberry_ip}:{RPI_REMOTE_PORT}")

            while not stop_flag.is_set():
                try:
                    client, _ = sock.accept()
                    chan = self.farm_transport.open_channel(
                        "direct-tcpip",
                        (raspberry_ip, RPI_REMOTE_PORT),
                        client.getsockname()
                    )
                    threading.Thread(
                        target=self._pipe,
                        args=(client, chan),
                        daemon=True
                    ).start()
                except Exception as e:
                    print("[RPI ERROR]", e)
                    break

            sock.close()

        threading.Thread(target=server, daemon=True).start()
        time.sleep(0.5)

        url = f"http://localhost:{local_port}/"
        webbrowser.open(url)
        return url

    def start_rtsp_tunnel(self, local_port, camera_ip):
        return subprocess.Popen(
            [
                "ssh",
                "-N",
                "-o", "ExitOnForwardFailure=yes",
                "-J", f"{self.gateway_user}@{SSH_GATEWAY}",
                "-L", f"{local_port}:{camera_ip}:554",
                f"{self.gateway_user}@{FARM_PC}",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

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

        # Press Enter to Connect
        self.root.bind('<Return>', lambda event: self.connect_ssh())

        self.recording_threads = {}
        self.recording_procs = {}
        self.stop_flags = {}
        self.ssh_tunnels = {}

        self.recording_procs = {}  # ip -> subprocess.Popen
        self.recording_ports = {}  # ip -> local rtsp port
        self.recording_flags = {}  # ip -> threading.Event

    def open_in_vlc(self, rtsp_url):
        """
        Launch VLC externally with the RTSP URL.
        User controls recording inside VLC.
        """
        vlc_candidates = []

        # Windows common paths
        if os.name == "nt":
            vlc_candidates = [
                r"C:\Program Files\VideoLAN\VLC\vlc.exe",
                r"C:\Program Files (x86)\VideoLAN\VLC\vlc.exe",
            ]

        # Fallback: PATH (Windows/Linux/macOS)
        vlc_in_path = shutil.which("vlc")
        if vlc_in_path:
            vlc_candidates.append(vlc_in_path)

        for vlc in vlc_candidates:
            try:
                subprocess.Popen([vlc, rtsp_url])
                return
            except Exception:
                continue

        messagebox.showerror(
            "VLC not found",
            "VLC is not installed or not found in PATH."
        )

    def open_cam_vlc(self, ip_var):
        ip = ip_var.get().strip()

        if not ip:
            messagebox.showwarning("Missing IP", "Please enter camera IP.")
            return

        if not self.manager:
            messagebox.showwarning("Not connected", "Connect SSH first.")
            return

        # --- Create RTSP tunnel ---
        local_port, _ = self.manager.forward_rtsp_paramiko(ip)
        time.sleep(1)

        # --- Build RTSP URL ---
        if ip in HANWHA_IPS:
            rtsp_url = (
                f"rtsp://admin:{config['AUTH']['password_hanwha']}"
                f"@localhost:{local_port}/profile2/media.smp"
            )
        elif ip in HIKVISION_IPS:
            rtsp_url = (
                f"rtsp://admin:{config['AUTH']['password_hikvision']}"
                f"@localhost:{local_port}/Streaming/channels/101"
            )
        else:
            messagebox.showerror("Unknown camera", ip)
            return

        print(f"[VLC] Opening {rtsp_url}")
        self.open_in_vlc(rtsp_url)

        self.status.config(text=f"Opened {ip} in VLC", bootstyle="info")


    # ---------------- Recording Logic ----------------
    # def start_recording(self, ip_var, port_var):
    #     ip = ip_var.get().strip()
    #     port = int(port_var.get().strip() or 80)
    #     if not ip:
    #         messagebox.showwarning("Missing IP", "Please enter camera IP first.")
    #         return
    #
    #     if not self.manager:
    #         messagebox.showwarning("Not connected", "Connect SSH first.")
    #         return
    #
    #     save_dir = filedialog.askdirectory(title=f"Select recording destination for {ip}")
    #     if not save_dir:
    #         return
    #
    #     if ip in self.recording_threads and self.recording_threads[ip].is_alive():
    #         messagebox.showinfo("Recording", f"{ip} is already being recorded.")
    #         return
    #
    #     # Create Paramiko tunnel for RTSP
    #     local_port, stop_flag = self.manager.forward_rtsp_paramiko(ip)
    #     self.stop_flags[ip] = stop_flag
    #     time.sleep(2)  # give tunnel time to establish
    #     self.status.config(text=f"Recording from {ip}...", bootstyle="info")
    #
    #     def record_loop():
    #         while not stop_flag.is_set():
    #             if stop_flag.is_set():
    #                 break
    #             start_time = datetime.datetime.now()
    #             end_time = start_time + datetime.timedelta(seconds=CHUNK_DURATION)
    #
    #             start_str = start_time.strftime("%Y%m%d_%H%M%S")
    #             end_str = end_time.strftime("%Y%m%d_%H%M%S")
    #             output_file = Path(save_dir) / f"{ip.replace('.', '_')}_{start_str}_to_{end_str}.mp4"
    #
    #             if ip in HANWHA_IPS:
    #                 rtsp_url = f"rtsp://admin:{config['AUTH']['password_hanwha']}@localhost:{local_port}/profile2/media.smp"
    #             elif ip in HIKVISION_IPS:
    #                 rtsp_url = f"rtsp://admin:{config['AUTH']['password_hikvision']}@localhost:{local_port}/Streaming/channels/101"
    #             else:
    #                 print(f"[WARN] Unknown camera type for {ip}")
    #                 break
    #
    #             command = [
    #                 "ffmpeg",
    #                 "-y",
    #                 "-rtsp_transport", "tcp",
    #                 "-timeout", "5000000",
    #                 "-i", rtsp_url,
    #                 "-c:v", "libx264",
    #                 "-preset", "fast",
    #                 "-crf", "28",
    #                 # "-t", str(CHUNK_DURATION),
    #                 output_file.as_posix()
    #             ]
    #
    #             print(f"[RECORD] Running: {' '.join(command)}")
    #             # proc = subprocess.Popen(command, stdin=subprocess.PIPE)
    #             proc = subprocess.Popen(
    #                 command,
    #                 stdin=subprocess.PIPE,
    #                 stdout=subprocess.PIPE,
    #                 stderr=subprocess.PIPE,
    #                 shell=False
    #             )
    #             self.recording_procs[ip] = proc
    #
    #             # Wait for FFmpeg to finish chunk or stop
    #             try:
    #                 # Wait until either chunk duration expires or stop_flag is set
    #                 start = time.time()
    #                 while proc.poll() is None:
    #                     elapsed = time.time() - start
    #                     if stop_flag.is_set() or elapsed >= CHUNK_DURATION:
    #                         try:
    #                             ##proc.send_signal(signal.SIGINT if os.name != "nt" else signal.CTRL_C_EVENT)
    #                             #proc.terminate()
    #                             # proc.send_signal(signal.CTRL_C_EVENT)
    #                             # proc.wait(timeout=10)
    #                             proc.stdin.write(b'q')
    #                             proc.stdin.flush()
    #                             proc.wait()
    #
    #                         except Exception:
    #                             proc.kill()
    #                         break
    #                     time.sleep(0.5)
    #                 # while proc.poll() is None:
    #                 #     if stop_flag.is_set():
    #                 #         try:
    #                 #             proc.send_signal(signal.SIGINT if os.name != "nt" else signal.CTRL_C_EVENT)
    #                 #             proc.wait(timeout=10)
    #                 #         except Exception:
    #                 #             proc.kill()
    #                 #
    #                 #         return
    #                 #     time.sleep(0.5)
    #             except Exception as e:
    #                 print(f"[ERROR] ffmpeg failed for {ip}: {e}")
    #                 # Stop recording completely when ffmpeg fails
    #                 break
    #
    #             if ip in self.recording_procs:
    #                 del self.recording_procs[ip]
    #
    #         print(f"[STOP] Recording stopped for {ip}")
    #     t = threading.Thread(target=record_loop, daemon=True)
    #     self.recording_threads[ip] = t
    #     t.start()
    #
    # def stop_recording(self, ip_var):
    #     ip = ip_var.get().strip()
    #     if ip not in self.stop_flags:
    #         messagebox.showinfo("Not recording", f"No active recording for {ip}")
    #         return
    #
    #     self.stop_flags[ip].set()  # signal thread to stop
    #     proc = self.recording_procs.get(ip)
    #     if proc.poll() is None:
    #         try:
    #             proc.communicate(input=b'q', timeout=5)  # send 'q' to stop FFmpeg gracefully
    #         except Exception:
    #             proc.kill()  # fallback if needed
    #
    #     # if ip in self.recording_procs:
    #     #     del self.recording_procs[ip]
    #     # self.status.config(text=f"Stopped recording {ip}", bootstyle="warning")
    #     # Clean up
    #     self.recording_procs.pop(ip, None)
    #     self.stop_flags.pop(ip, None)
    #     self.status.config(text=f"Stopped recording {ip}", bootstyle="warning")

    def start_recording(self, ip_var, port_var):
        ip = ip_var.get().strip()

        if not ip:
            messagebox.showwarning("Missing IP", "Please enter camera IP.")
            return

        if not self.manager:
            messagebox.showwarning("Not connected", "Connect SSH first.")
            return

        if ip in self.recording_procs:
            messagebox.showinfo("Recording", f"{ip} is already recording.")
            return

        save_dir = filedialog.askdirectory(
            title=f"Select recording destination for {ip}"
        )
        if not save_dir:
            return

        # --- RTSP tunnel ---
        local_port, stop_flag = self.manager.forward_rtsp_paramiko(ip)
        self.recording_ports[ip] = local_port
        self.recording_flags[ip] = stop_flag

        time.sleep(1)

        # --- RTSP URL ---
        if ip in HANWHA_IPS:
            rtsp_url = (
                f"rtsp://admin:{config['AUTH']['password_hanwha']}"
                f"@localhost:{local_port}/profile2/media.smp"
            )
        elif ip in HIKVISION_IPS:
            rtsp_url = (
                f"rtsp://admin:{config['AUTH']['password_hikvision']}"
                f"@localhost:{local_port}/Streaming/channels/101"
            )
        else:
            messagebox.showerror("Unknown camera", ip)
            return

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = Path(save_dir) / f"{ip.replace('.', '_')}_{timestamp}_%03d.mp4"

        # --- FFmpeg with native segmentation ---
        command = [
            "ffmpeg",
            "-loglevel", "debug",
            "-rtsp_transport", "tcp",
            "-timeout", "5000000",
            "-i", rtsp_url,
            "-c:v", "libx264",
            "-preset", "fast",
            "-crf", "28",
            "-f", "segment",
            "-segment_time", str(CHUNK_DURATION),
            "-reset_timestamps", "1",
            filename.as_posix(),
        ]

        print("[RECORD]", " ".join(command))

        proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        self.recording_procs[ip] = proc
        self.status.config(text=f"Recording {ip}", bootstyle="success")

    def stop_recording(self, ip_var):
        ip = ip_var.get().strip()

        proc = self.recording_procs.get(ip)
        if not proc:
            messagebox.showinfo("Not recording", f"{ip} is not recording.")
            return

        print(f"[STOP] Stopping recording for {ip}")

        try:
            proc.stdin.write(b"q\n")
            proc.stdin.flush()
            proc.wait(timeout=10)
        except Exception:
            proc.kill()

        # Stop tunnel
        flag = self.recording_flags.get(ip)
        if flag:
            flag.set()

        self.recording_procs.pop(ip, None)
        self.recording_ports.pop(ip, None)
        self.recording_flags.pop(ip, None)

        self.status.config(text=f"Stopped recording {ip}", bootstyle="warning")

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
        self.password_entry = ttk.Entry(header, textvariable=self.password_var, width=25, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, pady=4, sticky="w")
        self.password_entry.focus_set()

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
        all_ips = HANWHA_IPS + HIKVISION_IPS + RASPBERRY_IPS

        for idx, ip in enumerate(all_ips):
            row = idx + 1  # +1 to leave row 0 for headers

            ip_var = tk.StringVar(value=ip)
            port_var = tk.StringVar(value="80")

            ttk.Entry(self.cameras_frame, textvariable=ip_var, width=18).grid(row=row, column=0, padx=5, pady=3, sticky="w")
            ttk.Entry(self.cameras_frame, textvariable=port_var, width=6).grid(row=row, column=1, padx=5, pady=3, sticky="w")

            btn_frame = ttk.Frame(self.cameras_frame)
            btn_frame.grid(row=row, column=2, padx=5, pady=3, sticky="w")

            if ip in HANWHA_IPS:
                ttk.Button(btn_frame, text="Open Webview", command=lambda iv=ip_var, pv=port_var: self.open_cam(iv, pv),
                           bootstyle=PRIMARY).pack(side="left", padx=2)

            if ip in HIKVISION_IPS:
                ttk.Button(btn_frame, text="Open Webview", command=lambda iv=ip_var, pv=port_var: self.open_cam(iv, pv),
                           bootstyle=INFO).pack(side="left", padx=2)

            if ip in RASPBERRY_IPS:
                ttk.Button(btn_frame, text="Open Webview", command=lambda iv=ip_var, pv=port_var: self.open_cam(iv, pv),
                           bootstyle=WARNING).pack(side="left", padx=2)

            ttk.Button(
                btn_frame,
                text="Open in VLC",
                command=lambda iv=ip_var: self.open_cam_vlc(iv),
                bootstyle=PRIMARY
            ).pack(side="left", padx=2)

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
            self.status.config(text="Connected.", bootstyle="success")
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
            # url = self.manager.open_camera(ip, port)
            if ip in RASPBERRY_IPS:
                url = self.manager.open_raspberry_paramiko(ip)
            else:
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
