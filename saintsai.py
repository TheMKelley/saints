# SAINTS AI module - Ollama integration (local LLM manager, agent, and GUI panel)
# All rights reserved, John Stotler and Michael Kelley. Ollama MIT license applies to all use.
#
#   OllamaManager - finds/starts/stops a local Ollama server and pulls the model.
#                   Uses a bundled copy (<app>/ollama/) when present, which is how you
#                   will ship it in the installer; otherwise falls back to the Ollama
#                   you already have installed.
#   AIAgent       - turns structured facts (open ports now; baseline stats/alerts later)
#                   into plain-language analysis. Talks to Ollama over its REST API,
#                   so there are no extra pip dependencies.
#   AIPanel       - a tkinter panel that plugs into the SAINTS window.

import json
import os
import shutil
import subprocess
import sys
import threading
import time
import tkinter as tk
import urllib.error
import urllib.request
from pathlib import Path

# ---- CONFIG -----------------------------------------------------------------
DEFAULT_MODEL = "llama3.2:3b"       # small enough for CPU-only machines
BUNDLED_HOST = "127.0.0.1:11500"    # private port used when we ship our own Ollama
SYSTEM_HOST = "127.0.0.1:11434"     # Ollama's default port (dev machine)
STARTUP_TIMEOUT = 25                # seconds to wait for the server to come up

# ---- Grounding facts for the ai to use ------------------------------------------------
PORT_NOTES = {
    21: "FTP - sends credentials in plain text",
    22: "SSH - encrypted remote login; check for weak passwords",
    23: "Telnet - unencrypted remote login, should almost never be open",
    25: "SMTP - mail server",
    53: "DNS",
    80: "HTTP - unencrypted web server",
    110: "POP3 - unencrypted mail retrieval",
    135: "Windows RPC - commonly abused for lateral movement",
    139: "NetBIOS - legacy Windows file sharing",
    143: "IMAP - mail retrieval",
    161: "SNMP - often exposed with default community strings",
    389: "LDAP - directory service",
    443: "HTTPS - encrypted web server",
    445: "SMB - Windows file sharing, frequent ransomware/worm target",
    1433: "Microsoft SQL Server - database should not be network-exposed",
    1723: "PPTP VPN - outdated and weak",
    3306: "MySQL - database should not be network-exposed",
    3389: "RDP - remote desktop, heavily targeted by attackers",
    5432: "PostgreSQL - database should not be network-exposed",
    5900: "VNC - remote desktop, often weakly protected",
    6379: "Redis - often has no authentication",
    9200: "Elasticsearch - often exposed without authentication",
    27017: "MongoDB - often exposed without authentication",
}

ANALYSIS_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "risk_level": {"type": "string", "enum": ["low", "medium", "high"]},
        "findings": {"type": "array", "items": {"type": "string"}},
        "next_steps": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["summary", "risk_level", "findings", "next_steps"],
}


def _app_dir():
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent


# ---- OLLAMA MANAGER -----------------------------------------------------------
class OllamaManager:
    def __init__(self, model=DEFAULT_MODEL):
        self.model = model
        self.host = SYSTEM_HOST
        self._proc = None            # only set if WE launched the server
        self._bundled = self._find_bundled()
        if self._bundled:
            self.host = BUNDLED_HOST

    @property
    def base_url(self):
        return f"http://{self.host}"

    @staticmethod
    def _find_bundled():
        exe = "ollama.exe" if sys.platform == "win32" else "ollama"
        path = _app_dir() / "ollama" / exe
        return path if path.exists() else None

    # -- server lifecycle -------------------------------------------------------
    def is_up(self):
        try:
            with urllib.request.urlopen(f"{self.base_url}/api/tags", timeout=1.5):
                return True
        except Exception:  # noqa: BLE001
            return False

    def start(self):
        if self.is_up():
            return

        binary = self._bundled or (shutil.which("ollama") and Path(shutil.which("ollama")))
        if not binary:
            raise RuntimeError(
                "Ollama was not found. Install it from ollama.com or bundle it in <app>/ollama/."
            )

        env = os.environ.copy()
        env["OLLAMA_HOST"] = self.host
        if self._bundled:
            env["OLLAMA_MODELS"] = str(_app_dir() / "models")

        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        self._proc = subprocess.Popen(
            [str(binary), "serve"],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=flags,
        )

        deadline = time.time() + STARTUP_TIMEOUT
        while time.time() < deadline:
            if self.is_up():
                return
            if self._proc.poll() is not None:
                break
            time.sleep(0.4)
        raise RuntimeError("Ollama server did not start.")

    def stop(self):
        """Stops the server only if this app started it."""
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None

    # -- models ------------------------------------------------------------------
    def has_model(self):
        with urllib.request.urlopen(f"{self.base_url}/api/tags", timeout=5) as r:
            names = {m["name"] for m in json.load(r).get("models", [])}
        return self.model in names or f"{self.model}:latest" in names

    def pull_model(self, on_progress=None):
        """Downloads the model, streaming progress. on_progress(text, fraction_or_None)."""
        body = json.dumps({"model": self.model, "stream": True}).encode()
        req = urllib.request.Request(
            f"{self.base_url}/api/pull", data=body, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=60) as r:
            for line in r:
                if not line.strip():
                    continue
                msg = json.loads(line)
                if "error" in msg:
                    raise RuntimeError(msg["error"])
                if on_progress:
                    total, done = msg.get("total"), msg.get("completed")
                    frac = (done / total) if total and done is not None else None
                    on_progress(msg.get("status", ""), frac)

    def prepare(self, on_status):
        """Start server -> ensure model is present -> warm it up. Call from a worker thread."""
        on_status("Starting local AI engine...")
        self.start()
        if not self.has_model():
            def prog(text, frac):
                pct = f" {frac * 100:.0f}%" if frac is not None else ""
                on_status(f"Downloading {self.model}: {text}{pct}")
            self.pull_model(prog)
        on_status("Loading model...")
        self.chat([{"role": "user", "content": "ok"}], fmt=None, max_tokens=1)  # warm-up

    # -- inference ---------------------------------------------------------------
    def chat(self, messages, fmt=None, max_tokens=None):
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "keep_alive": "10m",
            "options": {"temperature": 0.1, "num_ctx": 4096},
        }
        if fmt is not None:
            payload["format"] = fmt
        if max_tokens:
            payload["options"]["num_predict"] = max_tokens

        req = urllib.request.Request(
            f"{self.base_url}/api/chat",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=300) as r:
                return json.load(r)["message"]["content"]
        except urllib.error.URLError as exc:
            raise RuntimeError(f"AI engine unreachable: {exc}") from exc


# ---- AGENT --------------------------------------------------------------------
class AIAgent:
    """Turns structured findings into plain-language analysis.

    Keep the numeric work (baselines, anomaly scoring) in normal code and hand the
    results to this class for explanation. Swap the backend later without touching the GUI.
    """

    SYSTEM = (
        "You are the analyst inside SAINTS, a local network security scanner. "
        "Use ONLY the facts provided. Never invent ports, hosts or CVEs. "
        "Respond with JSON matching the requested schema."
    )

    AUDIENCE = {
        "technical": (
            "Audience: a network/security engineer. Be precise; mention protocols, "
            "hardening steps and verification commands where relevant."
        ),
        "simple": (
            "Audience: a non-technical home or small-office user. Use plain English, no jargon, "
            "short sentences. Say what it means and exactly what to do next."
        ),
    }

    def __init__(self, manager):
        self.manager = manager

    def _ask(self, facts, task, audience):
        user = f"{self.AUDIENCE[audience]}\n\nTask: {task}\n\nFacts:\n{json.dumps(facts, indent=2)}"
        raw = self.manager.chat(
            [{"role": "system", "content": self.SYSTEM}, {"role": "user", "content": user}],
            fmt=ANALYSIS_SCHEMA,
        )
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"summary": raw, "risk_level": "medium", "findings": [], "next_steps": []}

    def analyze_ports(self, host, open_ports, audience="simple"):
        """open_ports: list of (port, service_name)."""
        facts = {
            "host": host,
            "open_ports": [
                {"port": p, "service": s, "note": PORT_NOTES.get(int(p), "no extra notes")}
                for p, s in open_ports
            ],
        }
        task = "Assess the exposure of this host based on its open ports and list next steps."
        return self._ask(facts, task, audience)

    # -- hooks for the baseline / monitoring phase --------------------------------
    def describe_baseline(self, stats, audience="simple"):
        """stats: dict of computed baseline numbers (flows/hour, usual destinations, ports...)."""
        return self._ask(stats, "Describe what normal network behavior looks like here.", audience)

    def explain_alert(self, alert, audience="simple"):
        """alert: dict with what was detected, the baseline value, the observed value, host, time."""
        return self._ask(alert, "Explain this anomaly and what the user should do next.", audience)


# ---- GUI PANEL ----------------------------------------------------------------
class AIPanel(tk.Frame):

    RISK_COLORS = {"low": "#00e5a0", "medium": "#ffb84d", "high": "#ff5c5c"}

    def __init__(self, parent, agent, theme):
        super().__init__(parent, bg=theme["BG_DARK"])
        self.agent = agent
        self.t = theme
        self._ready = False
        self._busy = False
        self._context = None
        self.audience = tk.StringVar(value="simple")

        bar = tk.Frame(self, bg=theme["BG_DARK"])
        bar.pack(fill="x", pady=(8, 4))

        tk.Label(bar, text="AI ANALYST", font=theme["FONT_LABEL"],
                 bg=theme["BG_DARK"], fg=theme["TEXT_MUTED"]).pack(side="left")

        self.status = tk.Label(bar, text="starting...", font=theme["FONT_STATUS"],
                               bg=theme["BG_DARK"], fg=theme["TEXT_MUTED"])
        self.status.pack(side="left", padx=12)

        self.analyze_btn = tk.Button(
            bar, text="✦  ANALYZE", font=theme["FONT_BTN"], bg=theme["ACCENT"], fg=theme["BG_DARK"],
            activebackground=theme["ACCENT"], relief="flat", padx=14, pady=4, cursor="hand2",
            state="disabled", command=self.analyze,
        )
        self.analyze_btn.pack(side="right")

        for text, value in (("Technical", "technical"), ("Plain English", "simple")):
            tk.Radiobutton(
                bar, text=text, variable=self.audience, value=value,
                font=theme["FONT_STATUS"], bg=theme["BG_DARK"], fg=theme["TEXT_MAIN"],
                selectcolor=theme["BG_PANEL_ALT"], activebackground=theme["BG_DARK"],
                activeforeground=theme["ACCENT"], highlightthickness=0,
            ).pack(side="right", padx=6)

        body = tk.Frame(self, bg=theme["BG_DARK"])
        body.pack(fill="both", expand=True)
        self.text = tk.Text(
            body, wrap="word", font=theme["FONT_MONO"], bg=theme["BG_PANEL_ALT"],
            fg=theme["TEXT_MAIN"], relief="flat", padx=12, pady=10, state="disabled",
            highlightbackground=theme["BORDER"], highlightthickness=1,
        )
        sb = tk.Scrollbar(body, command=self.text.yview)
        self.text.configure(yscrollcommand=sb.set)
        self.text.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        self.text.tag_configure("h", foreground=theme["ACCENT"], font=theme["FONT_LABEL"])
        self.text.tag_configure("muted", foreground=theme["TEXT_MUTED"])
        for level, color in self.RISK_COLORS.items():
            self.text.tag_configure(level, foreground=color, font=theme["FONT_LABEL"])

        self._write_plain("Run a port scan, then press ANALYZE for an explanation and next steps.")

    # -- startup -----------------------------------------------------------------
    def boot(self):
        # ai agent ran in the background to prevent freezing.
        threading.Thread(target=self._boot_thread, daemon=True).start()

    def _boot_thread(self):
        try:
            self.agent.manager.prepare(lambda s: self.after(0, self._set_status, s))
            self.after(0, self._boot_done, None)
        except Exception as exc:  # noqa: BLE001
            self.after(0, self._boot_done, str(exc))

    def _boot_done(self, error):
        if error:
            self._set_status(f"AI unavailable: {error}", self.t["DANGER"])
            return
        self._ready = True
        self._set_status(f"ready ({self.agent.manager.model})", self.t["ACCENT"])
        self._refresh_button()

    # -- context from the scanner -------------------------------------------------
    def set_context(self, host, ports):
        self._context = (host, list(ports))
        self._refresh_button()

    def _refresh_button(self):
        ok = self._ready and self._context is not None and not self._busy
        self.analyze_btn.config(state="normal" if ok else "disabled")

    # -- analysis ------------------------------------------------------------------
    def analyze(self):
        if not (self._ready and self._context) or self._busy:
            return
        host, ports = self._context
        self._busy = True
        self._refresh_button()
        self._set_status(f"analyzing {host} ...")
        self._write_plain("Thinking...")
        audience = self.audience.get()
        threading.Thread(target=self._analyze_thread, args=(host, ports, audience), daemon=True).start()

    def _analyze_thread(self, host, ports, audience):
        try:
            result = self.agent.analyze_ports(host, ports, audience)
            self.after(0, self._show_result, host, result)
        except Exception as exc:  # noqa: BLE001
            self.after(0, self._show_error, str(exc))

    def _show_result(self, host, r):
        self._busy = False
        self._refresh_button()
        self._set_status(f"ready ({self.agent.manager.model})", self.t["ACCENT"])

        level = r.get("risk_level", "medium")
        self._clear()
        self._append(f"{host}   ", "h")
        self._append(f"RISK: {level.upper()}\n\n", level if level in self.RISK_COLORS else "h")
        self._append(r.get("summary", "") + "\n\n")
        if r.get("findings"):
            self._append("WHAT WE FOUND\n", "h")
            for item in r["findings"]:
                self._append(f"  • {item}\n")
            self._append("\n")
        if r.get("next_steps"):
            self._append("NEXT STEPS\n", "h")
            for i, item in enumerate(r["next_steps"], 1):
                self._append(f"  {i}. {item}\n")
        self._append("\nAI-generated guidance. Verify before making changes.", "muted")

    def _show_error(self, msg):
        self._busy = False
        self._refresh_button()
        self._set_status("error", self.t["DANGER"])
        self._write_plain(f"Analysis failed: {msg}")

    # -- text helpers ----------------------------------------------------------------
    def _set_status(self, text, color=None):
        self.status.config(text=text, fg=color or self.t["TEXT_MUTED"])

    def _clear(self):
        self.text.config(state="normal")
        self.text.delete("1.0", "end")
        self.text.config(state="disabled")

    def _append(self, text, tag=None):
        self.text.config(state="normal")
        self.text.insert("end", text, tag) if tag else self.text.insert("end", text)
        self.text.config(state="disabled")

    def _write_plain(self, text):
        self._clear()
        self._append(text, "muted")