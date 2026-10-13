# Super Advanced Intelligent Network Threat Scanner (SAINTS) Module - John Stotler and Michael Kelley, 2026. All rights reserved.
# HISTORY:
#   - v0.1 (9/10/2026) - initial tkinter shell
#   - v0.2 (9/20/2026) - redesigned UI, integrated live ARP scan output into the main window
#   - v0.3 (10/07/2026) - added multithreaded TCP port scanning for a selected host

# ---- IMPORTS ---------------------------------------------------------------
import ipaddress
import socket
import threading
import time
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor, as_completed
from tkinter import ttk, messagebox

import scapy.all as scapy

# ---- COLORS / THEME --------------------------------------------------------
BG_DARK = "#0f1117"
BG_PANEL = "#161a23"
BG_PANEL_ALT = "#1c212d"
ACCENT = "#00e5a0"
ACCENT_DIM = "#0a3d30"
TEXT_MAIN = "#e6e8ee"
TEXT_MUTED = "#8891a3"
DANGER = "#ff5c5c"
BORDER = "#242938"

FONT_TITLE = ("Segoe UI", 22, "bold")
FONT_SUBTITLE = ("Segoe UI", 11)
FONT_LABEL = ("Segoe UI", 10, "bold")
FONT_MONO = ("Consolas", 10)
FONT_BTN = ("Segoe UI", 11, "bold")
FONT_STATUS = ("Segoe UI", 9)

# ---- PORT SCAN CONFIG -------------------------------------------------------
COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139,
    143, 161, 162, 389, 443, 445, 465, 514, 587, 631, 636, 993, 995, 1080,
    1433, 1521, 1723, 2049, 3306, 3389, 5060, 5432, 5900, 5985, 6379, 8000,
    8080, 8443, 8888, 9100, 9200, 27017,
]
PORT_TIMEOUT = 0.6     # seconds to wait per connection attempt
PORT_WORKERS = 200     # concurrent connection attempts


# ---- SCANNER LOGIC (from scanner.py, adapted for GUI callbacks) -----------
def run_scan(ip_range, on_result, on_status, on_done):
    """Runs an ARP scan and streams results back to the GUI via callbacks.
    on_result(ip, mac) is called for each device found.
    on_status(text) updates the status line.
    on_done(count) is called when finished (or on error, with count=-1).
    """
    try:
        on_status(f"Scanning {ip_range} ...")

        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request

        answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

        count = 0
        for element in answered_list:
            ip = element[1].psrc
            mac = element[1].hwsrc
            on_result(ip, mac)
            count += 1
            time.sleep(0.05)  # small delay so results visibly stream in

        on_done(count)

    except PermissionError:
        on_status("Permission denied: try running with admin/root privileges.")
        on_done(-1)
    except Exception as exc:  # noqa: BLE001
        on_status(f"Scan error: {exc}")
        on_done(-1)


def parse_ports(text):
    """Turns user input into a sorted list of ports.
    Accepts: 'common', 'all', or comma-separated ports/ranges like '22,80,8000-8100'.
    Raises ValueError with a readable message on bad input.
    """
    text = text.strip().lower()
    if not text or text == "common":
        return sorted(COMMON_PORTS)
    if text == "all":
        return list(range(1, 65536))

    ports = set()
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                lo, hi = (int(x) for x in part.split("-", 1))
                if lo > hi:
                    lo, hi = hi, lo
                candidates = range(lo, hi + 1)
            else:
                candidates = [int(part)]
        except ValueError:
            raise ValueError(f"Invalid port entry: '{part}'") from None

        for p in candidates:
            if not 1 <= p <= 65535:
                raise ValueError(f"Port out of range (1-65535): {p}")
            ports.add(p)

    if not ports:
        raise ValueError("No ports specified.")
    return sorted(ports)


def _check_port(host, port, timeout):
    """Returns True if a TCP connection to host:port succeeds."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except OSError:
        return False


def _service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def run_port_scan(host, ports, stop_event, on_result, on_progress, on_done):
    """TCP connect scan of `ports` on `host`, using a thread pool.
    on_result(port, service) is called for each open port.
    on_progress(done, total) is called periodically.
    on_done(open_count, stopped) is called when finished; open_count=-1 on error.
    """
    total = len(ports)
    done = 0
    open_count = 0

    def worker(port):
        if stop_event.is_set():
            return port, False
        return port, _check_port(host, port, PORT_TIMEOUT)

    try:
        executor = ThreadPoolExecutor(max_workers=PORT_WORKERS)
        futures = [executor.submit(worker, p) for p in ports]
        try:
            for fut in as_completed(futures):
                port, is_open = fut.result()
                done += 1
                if is_open:
                    open_count += 1
                    on_result(port, _service_name(port))
                if done % 25 == 0 or done == total:
                    on_progress(done, total)
                if stop_event.is_set():
                    break
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

        on_done(open_count, stop_event.is_set())

    except Exception:  # noqa: BLE001
        on_done(-1, False)


def get_self_info():
    """Reads this machine's own network info: hostname, local IP, MAC,
    active scapy interface, default gateway, and the /24 range that
    contains the local IP
    """
    info = {
        "hostname": None,
        "local_ip": None,
        "mac": None,
        "iface": None,
        "gateway": None,
        "suggested_range": None,
    }

    # Hostname + local IP (via udp)
    try:
        info["hostname"] = socket.gethostname()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            info["local_ip"] = s.getsockname()[0]
    except Exception:
        pass

    # Active scapy interface + its MAC
    try:
        iface = scapy.conf.iface
        info["iface"] = str(iface)
        info["mac"] = scapy.get_if_hwaddr(iface)
    except Exception:
        pass

    # Default gateway, via scapy's routing table
    try:
        for route in scapy.conf.route.routes:
            net, mask, gw, dev, addr, metric = route
            if net == 0 and mask == 0 and gw not in ("0.0.0.0", "::"):
                info["gateway"] = gw
                break
    except Exception:
        pass

    # Suggested /24 range based on local IP
    if info["local_ip"]:
        try:
            network = ipaddress.ip_network(f"{info['local_ip']}/24", strict=False)
            info["suggested_range"] = str(network)
        except Exception:
            pass

    return info


# ---- APP --------------------------------------------------------------------
class SaintsApp:
    def __init__(self, root):
        self.root = root
        self.scanning = False
        self.port_scanning = False
        self.port_stop_event = threading.Event()

        root.title("SAINTS - Super Advanced Intelligent Threat Scanner")
        root.geometry("980x780")
        root.minsize(760, 620)
        root.configure(bg=BG_DARK)

        self._build_style()
        self._build_header()
        self._build_controls()
        self._build_status_bar()     
        self._build_results_panel()

    # -- styling --------------------------------------------------------
    def _build_style(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(
            "Treeview",
            background=BG_PANEL_ALT,
            fieldbackground=BG_PANEL_ALT,
            foreground=TEXT_MAIN,
            rowheight=28,
            borderwidth=0,
            font=FONT_MONO,
        )
        style.configure(
            "Treeview.Heading",
            background=BG_PANEL,
            foreground=ACCENT,
            font=FONT_LABEL,
            borderwidth=0,
            relief="flat",
        )
        style.map(
            "Treeview",
            background=[("selected", ACCENT_DIM)],
            foreground=[("selected", ACCENT)],
        )
        style.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])

    # -- header -----------------------------------------------------------
    def _build_header(self):
        header = tk.Frame(self.root, bg=BG_DARK)
        header.pack(fill="x", padx=30, pady=(24, 10))

        badge = tk.Frame(header, bg=ACCENT, width=6)
        badge.pack(side="left", fill="y", padx=(0, 14))

        title_box = tk.Frame(header, bg=BG_DARK)
        title_box.pack(side="left", fill="x", expand=True)

        tk.Label(
            title_box, text="S A I N T S", font=FONT_TITLE, bg=BG_DARK, fg=TEXT_MAIN
        ).pack(anchor="w")
        tk.Label(
            title_box,
            text="Super Advanced Intelligent Threat Scanner",
            font=FONT_SUBTITLE,
            bg=BG_DARK,
            fg=TEXT_MUTED,
        ).pack(anchor="w")

        self.status_dot = tk.Canvas(
            header, width=14, height=14, bg=BG_DARK, highlightthickness=0
        )
        self.status_dot.pack(side="right", padx=(0, 8), pady=4)
        self._draw_dot(TEXT_MUTED)

    def _draw_dot(self, color):
        self.status_dot.delete("all")
        self.status_dot.create_oval(2, 2, 12, 12, fill=color, outline="")

    # -- controls -----------------------------------------------------------
    def _build_controls(self):
        panel = tk.Frame(self.root, bg=BG_PANEL, highlightbackground=BORDER, highlightthickness=1)
        panel.pack(fill="x", padx=30, pady=10)

        inner = tk.Frame(panel, bg=BG_PANEL)
        inner.pack(fill="x", padx=18, pady=16)

        tk.Label(
            inner, text="TARGET RANGE", font=FONT_LABEL, bg=BG_PANEL, fg=TEXT_MUTED
        ).grid(row=0, column=0, sticky="w", pady=(0, 6))

        entry_frame = tk.Frame(inner, bg=BG_PANEL_ALT, highlightbackground=BORDER, highlightthickness=1)
        entry_frame.grid(row=1, column=0, sticky="w")

        self.target_var = tk.StringVar(value="192.168.1.1/24")
        self.target_entry = tk.Entry(
            entry_frame,
            textvariable=self.target_var,
            font=FONT_MONO,
            bg=BG_PANEL_ALT,
            fg=TEXT_MAIN,
            insertbackground=ACCENT,
            relief="flat",
            width=28,
        )
        self.target_entry.pack(padx=10, pady=8)

        self.scan_button = tk.Button(
            inner,
            text="▶  BEGIN SCAN",
            font=FONT_BTN,
            bg=ACCENT,
            fg=BG_DARK,
            activebackground=ACCENT,
            activeforeground=BG_DARK,
            relief="flat",
            padx=22,
            pady=10,
            cursor="hand2",
            command=self.start_scan,
        )
        self.scan_button.grid(row=1, column=1, padx=(16, 0))

        self.self_scan_button = tk.Button(
            inner,
            text="⌂  SELF-SCAN",
            font=FONT_BTN,
            bg=BG_PANEL_ALT,
            fg=ACCENT,
            activebackground=BG_PANEL_ALT,
            activeforeground=ACCENT,
            relief="flat",
            padx=16,
            pady=10,
            cursor="hand2",
            command=self.run_self_scan,
        )
        self.self_scan_button.grid(row=1, column=2, padx=(10, 0))

        self.clear_button = tk.Button(
            inner,
            text="CLEAR",
            font=FONT_BTN,
            bg=BG_PANEL_ALT,
            fg=TEXT_MUTED,
            activebackground=BG_PANEL_ALT,
            activeforeground=TEXT_MAIN,
            relief="flat",
            padx=16,
            pady=10,
            cursor="hand2",
            command=self.clear_results,
        )
        self.clear_button.grid(row=1, column=3, padx=(10, 0))

        inner.grid_columnconfigure(4, weight=1)

        self.count_label = tk.Label(
            inner, text="0 devices found", font=FONT_SUBTITLE, bg=BG_PANEL, fg=TEXT_MUTED
        )
        self.count_label.grid(row=1, column=5, sticky="e")

        # -- port scan controls --
        tk.Label(
            inner,
            text="PORTS  (common · all · 22,80,443 · 1-1024)",
            font=FONT_LABEL,
            bg=BG_PANEL,
            fg=TEXT_MUTED,
        ).grid(row=2, column=0, columnspan=3, sticky="w", pady=(16, 6))

        port_entry_frame = tk.Frame(inner, bg=BG_PANEL_ALT, highlightbackground=BORDER, highlightthickness=1)
        port_entry_frame.grid(row=3, column=0, sticky="w")

        self.ports_var = tk.StringVar(value="common")
        self.ports_entry = tk.Entry(
            port_entry_frame,
            textvariable=self.ports_var,
            font=FONT_MONO,
            bg=BG_PANEL_ALT,
            fg=TEXT_MAIN,
            insertbackground=ACCENT,
            relief="flat",
            width=28,
        )
        self.ports_entry.pack(padx=10, pady=8)

        self.port_scan_button = tk.Button(
            inner,
            text="⚑  PORT SCAN",
            font=FONT_BTN,
            bg=ACCENT,
            fg=BG_DARK,
            activebackground=ACCENT,
            activeforeground=BG_DARK,
            relief="flat",
            padx=22,
            pady=10,
            cursor="hand2",
            command=self.start_port_scan,
        )
        self.port_scan_button.grid(row=3, column=1, padx=(16, 0))

        self.port_stop_button = tk.Button(
            inner,
            text="■  STOP",
            font=FONT_BTN,
            bg=BG_PANEL_ALT,
            fg=DANGER,
            activebackground=BG_PANEL_ALT,
            activeforeground=DANGER,
            relief="flat",
            padx=16,
            pady=10,
            cursor="hand2",
            state="disabled",
            command=self.stop_port_scan,
        )
        self.port_stop_button.grid(row=3, column=2, padx=(10, 0))

        self.port_count_label = tk.Label(
            inner, text="0 open ports", font=FONT_SUBTITLE, bg=BG_PANEL, fg=TEXT_MUTED
        )
        self.port_count_label.grid(row=3, column=5, sticky="e")

        # -- self-scan info strip (hidden until first used) --
        self.self_info_frame = tk.Frame(inner, bg=BG_PANEL_ALT, highlightbackground=BORDER, highlightthickness=1)
        self.self_info_label = tk.Label(
            self.self_info_frame,
            text="",
            font=FONT_MONO,
            bg=BG_PANEL_ALT,
            fg=TEXT_MAIN,
            justify="left",
            anchor="w",
            padx=12,
            pady=8,
        )
        self.self_info_label.pack(fill="x")
        self.use_range_button = tk.Button(
            self.self_info_frame,
            text="Use this range →",
            font=FONT_STATUS,
            bg=ACCENT,
            fg=BG_DARK,
            relief="flat",
            padx=10,
            pady=4,
            cursor="hand2",
            command=self._apply_suggested_range,
        )
        self._suggested_range = None

    # -- results tables -------------------------------------------------
    def _build_results_panel(self):
        container = tk.Frame(self.root, bg=BG_DARK)
        container.pack(fill="both", expand=True, padx=30, pady=(0, 10))

        paned = tk.PanedWindow(
            container, orient="vertical", bg=BG_DARK, sashwidth=6, bd=0, sashrelief="flat"
        )
        paned.pack(fill="both", expand=True)

        # -- hosts (ARP results) --
        host_panel = tk.Frame(paned, bg=BG_DARK)

        columns = ("ip", "mac")
        self.tree = ttk.Treeview(host_panel, columns=columns, show="headings", selectmode="browse")
        self.tree.heading("ip", text="IP ADDRESS")
        self.tree.heading("mac", text="MAC ADDRESS")
        self.tree.column("ip", width=220, anchor="w")
        self.tree.column("mac", width=260, anchor="w")
        self.tree.bind("<<TreeviewSelect>>", self._on_host_selected)
        self.tree.bind("<Double-1>", lambda _e: self.start_port_scan())

        scrollbar = ttk.Scrollbar(host_panel, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        paned.add(host_panel, minsize=120, stretch="always")

        # -- open ports --
        port_panel = tk.Frame(paned, bg=BG_DARK)

        self.port_header = tk.Label(
            port_panel,
            text="OPEN PORTS — select a host above (double-click to scan)",
            font=FONT_LABEL,
            bg=BG_DARK,
            fg=TEXT_MUTED,
            anchor="w",
        )
        self.port_header.pack(fill="x", pady=(8, 4))

        port_table = tk.Frame(port_panel, bg=BG_DARK)
        port_table.pack(fill="both", expand=True)

        self.port_tree = ttk.Treeview(
            port_table, columns=("port", "state", "service"), show="headings", selectmode="browse"
        )
        self.port_tree.heading("port", text="PORT")
        self.port_tree.heading("state", text="STATE")
        self.port_tree.heading("service", text="SERVICE")
        self.port_tree.column("port", width=120, anchor="w")
        self.port_tree.column("state", width=120, anchor="w")
        self.port_tree.column("service", width=260, anchor="w")
        self.port_tree.tag_configure("open", foreground=ACCENT)

        port_scrollbar = ttk.Scrollbar(port_table, orient="vertical", command=self.port_tree.yview)
        self.port_tree.configure(yscrollcommand=port_scrollbar.set)

        self.port_tree.pack(side="left", fill="both", expand=True)
        port_scrollbar.pack(side="right", fill="y")
        paned.add(port_panel, minsize=120, stretch="always")

    # -- status bar -------------------------------------------------------
    def _build_status_bar(self):
        bar = tk.Frame(self.root, bg=BG_PANEL, height=30)
        bar.pack(fill="x", side="bottom")

        self.status_label = tk.Label(
            bar,
            text="Idle — set a target range and begin scan.",
            font=FONT_STATUS,
            bg=BG_PANEL,
            fg=TEXT_MUTED,
            anchor="w",
        )
        self.status_label.pack(fill="x", padx=16, pady=6)

    # -- actions: ARP scan ----------------------------------------------------
    def start_scan(self):
        if self.scanning:
            return

        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning("SAINTS", "Please enter a target IP or range.")
            return

        self.clear_results()
        self.scanning = True
        self.scan_button.config(state="disabled", text="SCANNING...", bg=TEXT_MUTED)
        self._draw_dot(ACCENT)
        self.set_status(f"Scanning {target} ...")

        thread = threading.Thread(target=self._scan_thread, args=(target,), daemon=True)
        thread.start()

    def _scan_thread(self, target):
        run_scan(
            target,
            on_result=lambda ip, mac: self.root.after(0, self._add_result, ip, mac),
            on_status=lambda text: self.root.after(0, self.set_status, text),
            on_done=lambda count: self.root.after(0, self._scan_finished, count),
        )

    def _add_result(self, ip, mac):
        self.tree.insert("", "end", values=(ip, mac))
        n = len(self.tree.get_children())
        self.count_label.config(text=f"{n} device{'s' if n != 1 else ''} found")

    def _scan_finished(self, count):
        self.scanning = False
        self.scan_button.config(state="normal", text="▶  BEGIN SCAN", bg=ACCENT)
        if count >= 0:
            self._draw_dot(ACCENT)
            self.set_status(f"Scan complete. {count} device(s) found.")
        else:
            self._draw_dot(DANGER)
            self.set_status("Scan failed. See message above.")

    # -- actions: port scan ---------------------------------------------------
    def _on_host_selected(self, _event=None):
        if self.port_scanning:
            return
        host = self._selected_host()
        if host:
            self.port_header.config(text=f"OPEN PORTS — {host} (ready)")

    def _selected_host(self):
        sel = self.tree.selection()
        if sel:
            return str(self.tree.item(sel[0])["values"][0])
        return None

    def _resolve_port_target(self):
        """Selected host wins; otherwise fall back to a single IP typed in the target box."""
        host = self._selected_host()
        if host:
            return host
        typed = self.target_var.get().strip()
        try:
            ipaddress.ip_address(typed)
            return typed
        except ValueError:
            return None

    def start_port_scan(self):
        if self.port_scanning:
            return

        host = self._resolve_port_target()
        if not host:
            messagebox.showwarning(
                "SAINTS",
                "Select a device in the list (or enter a single IP as the target) to port scan.",
            )
            return

        try:
            ports = parse_ports(self.ports_var.get())
        except ValueError as exc:
            messagebox.showwarning("SAINTS", str(exc))
            return

        self._clear_ports()
        self.port_scanning = True
        self.port_stop_event.clear()
        self.port_scan_button.config(state="disabled", text="SCANNING...", bg=TEXT_MUTED)
        self.port_stop_button.config(state="normal")
        self.port_header.config(text=f"OPEN PORTS — {host}", fg=ACCENT)
        self._draw_dot(ACCENT)
        self.set_status(f"Port scanning {host} ({len(ports)} ports) ...")

        thread = threading.Thread(
            target=self._port_scan_thread, args=(host, ports), daemon=True
        )
        thread.start()

    def _port_scan_thread(self, host, ports):
        run_port_scan(
            host,
            ports,
            self.port_stop_event,
            on_result=lambda port, svc: self.root.after(0, self._add_port_result, port, svc),
            on_progress=lambda d, t: self.root.after(0, self._port_progress, host, d, t),
            on_done=lambda n, stopped: self.root.after(0, self._port_scan_finished, host, n, stopped),
        )

    def _add_port_result(self, port, service):
        self.port_tree.insert("", "end", values=(port, "open", service), tags=("open",))
        n = len(self.port_tree.get_children())
        self.port_count_label.config(text=f"{n} open port{'s' if n != 1 else ''}")

    def _port_progress(self, host, done, total):
        if self.port_scanning:
            self.set_status(f"Port scanning {host} ... {done}/{total} ports checked")

    def _port_scan_finished(self, host, open_count, stopped):
        self.port_scanning = False
        self.port_scan_button.config(state="normal", text="⚑  PORT SCAN", bg=ACCENT)
        self.port_stop_button.config(state="disabled")

        if open_count < 0:
            self._draw_dot(DANGER)
            self.set_status(f"Port scan of {host} failed.")
            return

        # results arrive out of order from the thread pool; sort them numerically
        rows = [self.port_tree.item(i)["values"] for i in self.port_tree.get_children()]
        rows.sort(key=lambda r: int(r[0]))
        self._clear_ports(reset_label=False)
        for port, state, service in rows:
            self.port_tree.insert("", "end", values=(port, state, service), tags=("open",))

        self._draw_dot(ACCENT)
        verb = "stopped" if stopped else "complete"
        self.set_status(f"Port scan {verb} for {host}. {open_count} open port(s) found.")

    def stop_port_scan(self):
        if self.port_scanning:
            self.port_stop_event.set()
            self.set_status("Stopping port scan ...")

    def _clear_ports(self, reset_label=True):
        for row in self.port_tree.get_children():
            self.port_tree.delete(row)
        if reset_label:
            self.port_count_label.config(text="0 open ports")

    # -- actions: self scan ---------------------------------------------------
    def run_self_scan(self):
        self.set_status("Reading local machine info...")
        self.self_scan_button.config(state="disabled", text="READING...")
        thread = threading.Thread(target=self._self_scan_thread, daemon=True)
        thread.start()

    def _self_scan_thread(self):
        info = get_self_info()
        self.root.after(0, self._show_self_info, info)

    def _show_self_info(self, info):
        self.self_scan_button.config(state="normal", text="⌂  SELF-SCAN")

        lines = [
            f"Hostname:    {info['hostname'] or 'unavailable'}",
            f"Local IP:    {info['local_ip'] or 'unavailable'}",
            f"MAC:         {info['mac'] or 'unavailable'}",
            f"Interface:   {info['iface'] or 'unavailable'}",
            f"Gateway:     {info['gateway'] or 'unavailable'}",
        ]
        self.self_info_label.config(text="\n".join(lines))
        self.self_info_frame.grid(row=4, column=0, columnspan=6, sticky="ew", pady=(12, 0))
        self.self_info_label.pack(side="left", fill="x", expand=True)

        self._suggested_range = info["suggested_range"]
        if self._suggested_range:
            self.use_range_button.pack(side="right", padx=12)
        else:
            self.use_range_button.pack_forget()

        if info["local_ip"] and info["gateway"]:
            self.set_status("Self-scan complete. Target range suggested below.")
        else:
            self.set_status(
                "Self-scan partially failed — try running as Administrator for full results."
            )

    def _apply_suggested_range(self):
        if self._suggested_range:
            self.target_var.set(self._suggested_range)
            self.set_status(f"Target range set to {self._suggested_range}")

    def clear_results(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        self.count_label.config(text="0 devices found")
        self._clear_ports()
        self.port_header.config(
            text="OPEN PORTS — select a host above (double-click to scan)", fg=TEXT_MUTED
        )

    def set_status(self, text):
        self.status_label.config(text=text)


# ---- ENTRY POINT ------------------------------------------------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = SaintsApp(root)
    root.mainloop()