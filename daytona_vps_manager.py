"""Daytona satellite health monitor. Run: python daytona_vps_manager.py"""
from __future__ import annotations

import json
import queue
import re
import subprocess
import threading
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor
from tkinter import ttk
from typing import Any

HEALTH = "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8765/healthz',timeout=4).read().decode())"


def targets(text: str) -> list[tuple[str, str]]:
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        match = re.search(r"ssh\s+([^\s]+@[^\s]+)", line)
        if match:
            label = re.search(r"\[([^]]+)\]", line)
            found.append((label.group(1) if label else f"vps-{number:02}", match.group(1)))
    return found


def ssh(target: str) -> tuple[bool, str]:
    command = (f"cd /opt/checkpass && if .venv/bin/python -c \"{HEALTH}\" 2>/dev/null; then true; "
               "else echo __HEALTH_UNAVAILABLE__; pgrep -af '[s]atellite_worker.py' || true; "
               "tail -n 12 /var/log/checkpass-satellite.log 2>&1 || true; fi")
    try:
        run = subprocess.run(["ssh", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=15", target, command],
                             text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=45)
        return run.returncode == 0, run.stdout.strip()
    except subprocess.TimeoutExpired:
        return False, "SSH không phản hồi trong 45 giây"
    except Exception as exc:
        return False, str(exc)


class Monitor:
    def __init__(self, root: tk.Tk) -> None:
        self.root, self.events, self.rows = root, queue.Queue(), {}
        self.busy, self.timer = False, None
        self.auto, self.status = tk.BooleanVar(value=True), tk.StringVar(value="Sẵn sàng")
        root.title("Daytona VPS Health Monitor"); root.geometry("1320x780")
        frame = ttk.Frame(root, padding=12); frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Dán danh sách SSH (mỗi dòng một VPS):").pack(anchor="w")
        self.input = tk.Text(frame, height=8, font=("Consolas", 10)); self.input.pack(fill="x", pady=(4, 8))
        bar = ttk.Frame(frame); bar.pack(fill="x")
        ttk.Button(bar, text="Quét ngay", command=self.scan).pack(side="left")
        ttk.Checkbutton(bar, text="Tự quét 15 giây", variable=self.auto).pack(side="left", padx=12)
        ttk.Label(bar, textvariable=self.status).pack(side="right")
        columns = ("vps", "state", "chunks", "accounts", "active", "pending", "recent", "error")
        self.table = ttk.Treeview(frame, columns=columns, show="headings", height=18)
        heads = ("VPS", "Trạng thái", "Chunk nhận/xong", "Acc nhận/xong", "Chunk chạy", "Acc còn lại", "Acc vừa check", "Lỗi")
        for col, head in zip(columns, heads): self.table.heading(col, text=head); self.table.column(col, width=150, anchor="w")
        self.table.column("error", width=290); self.table.column("recent", width=250)
        self.table.pack(fill="both", expand=True, pady=8); self.table.bind("<<TreeviewSelect>>", self.detail)
        self.out = tk.Text(frame, height=10, font=("Consolas", 9)); self.out.pack(fill="x")
        root.after(200, self.drain)

    def scan(self) -> None:
        entries = targets(self.input.get("1.0", "end"))
        if not entries or self.busy: return
        self.busy = True; self.status.set(f"Đang quét {len(entries)} VPS...")
        def one(item: tuple[str, str]) -> None:
            label, host = item; ok, text = ssh(host)
            try: data = json.loads(text) if ok else {"_error": text}
            except json.JSONDecodeError: data = {"_error": text}
            self.events.put((label, data))
        def work() -> None:
            with ThreadPoolExecutor(max_workers=min(4, len(entries))) as pool: list(pool.map(one, entries))
            self.events.put(("", None))
        threading.Thread(target=work, daemon=True).start()

    def drain(self) -> None:
        changed = False
        try:
            while True:
                label, data = self.events.get_nowait()
                if not label:
                    self.busy = False; self.status.set(f"Đã quét {len(self.rows)} VPS"); self.schedule(); continue
                if data.get("ok"):
                    data["_error"] = ""; self.rows[label] = data
                else:
                    old = dict(self.rows.get(label, {})); old["_error"] = data.get("_error", "Không đọc được health"); self.rows[label] = old
                changed = True
        except queue.Empty: pass
        if changed: self.render()
        self.root.after(200, self.drain)

    def schedule(self) -> None:
        if self.auto.get() and self.timer is None: self.timer = self.root.after(15000, self.scheduled)

    def scheduled(self) -> None:
        self.timer = None; self.scan()

    def render(self) -> None:
        for item in self.table.get_children(): self.table.delete(item)
        for label, data in self.rows.items():
            details = data.get("active_chunk_details") or []
            pending = ", ".join(x for d in details for x in d.get("pending_accounts", [])[:5])
            state = "Online" if data.get("ok") else ("SSH chậm · dữ liệu cũ" if data else "SSH chậm")
            self.table.insert("", "end", iid=label, values=(label, state, f"{data.get('chunks_claimed',0)}/{data.get('chunks_completed',0)}", f"{data.get('accounts_claimed',0)}/{data.get('accounts_completed',0)}", data.get("chunks_active",0), pending[:150] or "—", ", ".join(data.get("recent_checked_accounts") or ["—"])[:220], str(data.get("_error") or data.get("last_error") or "")[:200]))

    def detail(self, _event: Any) -> None:
        selected = self.table.selection()
        if selected: self.out.delete("1.0", "end"); self.out.insert("1.0", json.dumps(self.rows.get(selected[0], {}), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    window = tk.Tk(); Monitor(window); window.mainloop()
