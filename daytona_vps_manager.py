"""Dashboard setup and monitor for remote Daytona satellite workers.

Run on Windows:  python daytona_vps_manager.py
Paste lines such as: [vps-04] ssh token@ssh.app.daytona.io
"""
from __future__ import annotations

import base64
import json
import queue
import re
import subprocess
import threading
import tkinter as tk
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tkinter import ttk
from typing import Any

REPO = "https://github.com/HoangVanLuong2207/checkpass.git"
HEALTH_CODE = "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8765/healthz',timeout=4).read().decode())"


def parse_targets(text: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for number, line in enumerate(text.splitlines(), 1):
        target = re.search(r"ssh\s+([^\s]+@[^\s]+)", line)
        if not target:
            continue
        label = re.search(r"\[([^]]+)\]", line)
        found.append((label.group(1) if label else f"vps-{number:02}", target.group(1)))
    return found


def run_ssh(target: str, command: str, timeout: int = 900) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=20", target, command],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout,
        )
        return result.returncode == 0, result.stdout.strip()
    except subprocess.TimeoutExpired:
        return False, f"SSH không phản hồi trong {timeout}s"
    except Exception as exc:
        return False, str(exc)


class App:
    def __init__(self, root: tk.Tk) -> None:
        self.root, self.events = root, queue.Queue()
        root.title("Daytona Satellite Manager")
        root.geometry("1280x780")
        self.targets = tk.StringVar()
        self.master_url = tk.StringVar(value="http://160.236.192.49:8761")
        self.master_token = tk.StringVar()
        self.workers, self.chunks, self.gap = tk.StringVar(value="15"), tk.StringVar(value="5"), tk.StringVar(value="0")
        self.auto = tk.BooleanVar(value=True)
        self.status = tk.StringVar(value="Sẵn sàng")
        self.rows: dict[str, dict[str, Any]] = {}
        self.refreshing = False
        self.next_refresh: str | None = None
        self._build()
        self.root.after(200, self._drain)
        self.root.after(1000, self.refresh)

    def _build(self) -> None:
        tabs = ttk.Notebook(self.root); tabs.pack(fill="both", expand=True, padx=10, pady=10)
        setup, health = ttk.Frame(tabs, padding=12), ttk.Frame(tabs, padding=12)
        tabs.add(setup, text="Setup VPS"); tabs.add(health, text="Sức khỏe VPS")
        ttk.Label(setup, text="Dán danh sách SSH (mỗi dòng một VPS):").pack(anchor="w")
        self.input = tk.Text(setup, height=13, font=("Consolas", 10)); self.input.pack(fill="x", pady=(4, 10))
        form = ttk.Frame(setup); form.pack(fill="x")
        for col, (name, var, width, hidden) in enumerate((("Master URL", self.master_url, 38, False), ("Master token", self.master_token, 28, True), ("Workers", self.workers, 6, False), ("Chunks", self.chunks, 6, False), ("Gap", self.gap, 6, False))):
            ttk.Label(form, text=name).grid(row=0, column=col * 2, sticky="w", padx=(0, 4))
            ttk.Entry(form, textvariable=var, width=width, show="*" if hidden else "").grid(row=0, column=col * 2 + 1, padx=(0, 12))
        ttk.Button(setup, text="Setup + chạy tất cả", command=self.setup).pack(anchor="w", pady=15)
        ttk.Label(setup, textvariable=self.status).pack(anchor="w")
        ttk.Label(setup, text="Kết quả setup từng VPS:").pack(anchor="w", pady=(12, 3))
        self.setup_log = tk.Text(setup, height=13, font=("Consolas", 9), state="disabled")
        self.setup_log.pack(fill="both", expand=True)

        bar = ttk.Frame(health); bar.pack(fill="x")
        ttk.Button(bar, text="Quét ngay", command=self.refresh).pack(side="left")
        ttk.Checkbutton(bar, text="Tự quét 5 giây", variable=self.auto).pack(side="left", padx=12)
        ttk.Label(bar, textvariable=self.status).pack(side="right")
        columns = ("id", "state", "chunks", "accounts", "done", "active", "recent", "error")
        self.table = ttk.Treeview(health, columns=columns, show="headings", height=19)
        labels = {"id":"VPS", "state":"Trạng thái", "chunks":"Chunk nhận/xong", "accounts":"Acc nhận/xong", "done":"Đang xử lý", "active":"Acc còn lại", "recent":"Acc vừa check", "error":"Lỗi"}
        for col in columns:
            self.table.heading(col, text=labels[col]); self.table.column(col, width=150, anchor="w")
        self.table.column("error", width=300); self.table.column("recent", width=260); self.table.pack(fill="both", expand=True, pady=10)
        self.table.bind("<<TreeviewSelect>>", self.show_detail)
        self.detail = tk.Text(health, height=8, font=("Consolas", 9)); self.detail.pack(fill="x")

    def entries(self) -> list[tuple[str, str]]:
        return parse_targets(self.input.get("1.0", "end"))

    def setup(self) -> None:
        entries, token = self.entries(), self.master_token.get().strip()
        if not entries or not token:
            self.status.set("Cần danh sách SSH và MASTER_TOKEN"); return
        self.setup_log.configure(state="normal")
        self.setup_log.delete("1.0", "end")
        self.setup_log.configure(state="disabled")
        self.status.set(f"Đang setup {len(entries)} VPS...")
        def one(label: str, target: str) -> None:
            env = "\n".join((f"MASTER_URL={self.master_url.get().strip()}", f"MASTER_TOKEN={token}", f"SATELLITE_ID={label}", f"WORKERS={self.workers.get()}", f"CONCURRENT_CHUNKS={self.chunks.get()}", f"START_GAP={self.gap.get()}", "TIMEOUT=20", "LEASE_MINUTES=3", "POLL_INTERVAL=10", "HEALTH_HOST=127.0.0.1", "HEALTH_PORT=8765", ""))
            encoded = base64.b64encode(env.encode()).decode()
            command = ("set -e; apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq git python3 python3-venv; "
                f"if [ -d /opt/checkpass/.git ]; then cd /opt/checkpass && git pull --ff-only origin main; else git clone -q {REPO} /opt/checkpass; fi; "
                "cd /opt/checkpass; python3 -m venv .venv; .venv/bin/pip install -q -r requirements.txt; "
                f"printf '%s' '{encoded}' | base64 -d > /etc/checkpass-satellite.env; chmod 600 /etc/checkpass-satellite.env; "
                "set -a; . /etc/checkpass-satellite.env; set +a; pkill -f '[s]atellite_worker.py' || true; "
                "nohup .venv/bin/python satellite_worker.py > /var/log/checkpass-satellite.log 2>&1 < /dev/null & sleep 3; tail -n 4 /var/log/checkpass-satellite.log")
            ok, output = run_ssh(target, command); self.events.put(("setup", label, ok, output))
        threading.Thread(target=lambda: list(ThreadPoolExecutor(max_workers=8).map(lambda item: one(*item), entries)), daemon=True).start()

    def refresh(self) -> None:
        entries = self.entries()
        if not entries or self.refreshing:
            return
        self.refreshing = True
        self.status.set(f"Đang quét {len(entries)} VPS...")
        def one(label: str, target: str) -> None:
            command = (
                f"cd /opt/checkpass && if .venv/bin/python -c \"{HEALTH_CODE}\" 2>/dev/null; then true; "
                "else echo __HEALTH_UNAVAILABLE__; pgrep -af '[s]atellite_worker.py' || true; "
                "tail -n 12 /var/log/checkpass-satellite.log 2>&1 || true; fi"
            )
            ok, output = run_ssh(target, command, 45)
            try: data = json.loads(output) if ok else {"last_error": output}
            except json.JSONDecodeError: data = {"last_error": output}
            self.events.put(("health", label, bool(data.get("ok")), data))
        def scan() -> None:
            # Daytona may close or delay many simultaneous SSH sessions under load.
            with ThreadPoolExecutor(max_workers=min(4, len(entries))) as pool:
                list(pool.map(lambda item: one(*item), entries))
            self.events.put(("scan_done", "", True, {}))
        threading.Thread(target=scan, daemon=True).start()

    def _schedule_refresh(self) -> None:
        if self.auto.get() and self.next_refresh is None:
            self.next_refresh = self.root.after(5000, self._scheduled_refresh)

    def _scheduled_refresh(self) -> None:
        self.next_refresh = None
        self.refresh()

    def _drain(self) -> None:
        changed = False
        try:
            while True:
                kind, label, ok, data = self.events.get_nowait()
                if kind == "setup":
                    self.status.set(f"{label}: {'OK' if ok else 'lỗi'}")
                    self.setup_log.configure(state="normal")
                    self.setup_log.insert("end", f"\n[{label}] {'OK' if ok else 'LỖI'}\n{data[-1800:]}\n")
                    self.setup_log.see("end")
                    self.setup_log.configure(state="disabled")
                elif kind == "health":
                    self.rows[label] = data
                    changed = True
                elif kind == "scan_done":
                    self.refreshing = False
                    self.status.set(f"Đã quét {len(self.rows)} VPS")
                    self._schedule_refresh()
        except queue.Empty: pass
        if changed:
            self.render()
        self.root.after(200, self._drain)

    def render(self) -> None:
        for item in self.table.get_children(): self.table.delete(item)
        for label, data in self.rows.items():
            details = data.get("active_chunk_details") or []
            pending = ", ".join(account for chunk in details for account in chunk.get("pending_accounts", [])[:5])
            recent = ", ".join(data.get("recent_checked_accounts") or ["—"])
            self.table.insert("", "end", iid=label, values=(label, "Online" if data.get("ok") else "Offline", f"{data.get('chunks_claimed',0)}/{data.get('chunks_completed',0)}", f"{data.get('accounts_claimed',0)}/{data.get('accounts_completed',0)}", data.get("chunks_active",0), pending[:150] or "—", recent[:220], str(data.get("last_error", ""))[:200]))

    def show_detail(self, _event: Any) -> None:
        selected = self.table.selection()
        if selected:
            self.detail.delete("1.0", "end"); self.detail.insert("1.0", json.dumps(self.rows.get(selected[0], {}), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    root = tk.Tk(); App(root); root.mainloop()
