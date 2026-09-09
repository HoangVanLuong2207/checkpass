"""Monitor Render satellite /healthz endpoints."""
from __future__ import annotations

import json
import queue
import re
import threading
import tkinter as tk
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tkinter import ttk
from typing import Any


TARGETS_FILE = Path.home() / ".checkpass" / "render_health_urls.txt"
DEFAULT_TARGETS = "[checkpass3] https://checkpass3-wt3z.onrender.com/\n"


def load_saved_targets() -> str:
    try:
        saved = TARGETS_FILE.read_text(encoding="utf-8")
        return saved if parse_targets(saved) else DEFAULT_TARGETS
    except OSError:
        return DEFAULT_TARGETS


def save_targets(text: str) -> None:
    TARGETS_FILE.parent.mkdir(parents=True, exist_ok=True)
    TARGETS_FILE.write_text(text.strip() + "\n", encoding="utf-8")


def parse_targets(text: str) -> list[tuple[str, str]]:
    result = []
    seen_urls: set[str] = set()
    for number, line in enumerate(text.splitlines(), 1):
        match = re.search(r"https?://[^\s]+", line)
        if not match:
            continue
        url = match.group(0).rstrip("/.,;)")
        normalized_url = url.lower().rstrip("/")
        if normalized_url in seen_urls:
            continue
        seen_urls.add(normalized_url)
        named = re.search(r"\[([^]]+)\]", line)
        host = urllib.parse.urlsplit(url).hostname or f"render-{number:02}"
        result.append((named.group(1) if named else host, url))
    return result


def fetch_health(url: str) -> dict[str, Any]:
    request = urllib.request.Request(
        url.rstrip("/") + "/healthz",
        headers={"User-Agent": "Mozilla/5.0 CheckpassHealthMonitor/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            data = json.loads(response.read().decode("utf-8"))
        return data if isinstance(data, dict) else {"_error": "Health không trả JSON object"}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")[:300]
        return {"_error": f"HTTP {exc.code}: {body}"}
    except Exception as exc:
        return {"_error": str(exc)}


class Monitor:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.events: queue.Queue[tuple[str, dict[str, Any] | None]] = queue.Queue()
        self.rows: dict[str, dict[str, Any]] = {}
        self.busy = False
        self.timer: str | None = None
        self.auto = tk.BooleanVar(value=True)
        self.status = tk.StringVar(value="Sẵn sàng")
        root.title("Render Satellite Health Monitor")
        root.geometry("1320x780")
        frame = ttk.Frame(root, padding=12)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Dán URL Render, mỗi dòng một dịch vụ:").pack(anchor="w")
        self.input = tk.Text(frame, height=8, font=("Consolas", 10))
        self.input.pack(fill="x", pady=(4, 8))
        self.input.insert("1.0", load_saved_targets())
        bar = ttk.Frame(frame)
        bar.pack(fill="x")
        ttk.Button(bar, text="Quét ngay", command=self.scan).pack(side="left")
        ttk.Checkbutton(bar, text="Tự quét 15 giây", variable=self.auto).pack(side="left", padx=12)
        ttk.Label(bar, textvariable=self.status).pack(side="right")
        columns = ("service", "state", "chunks", "accounts", "active", "error")
        headings = ("Dịch vụ", "Trạng thái", "Chunk nhận/xong", "Acc nhận/xong", "Chunk chạy", "Lỗi")
        self.table = ttk.Treeview(frame, columns=columns, show="headings", height=18)
        for column, heading in zip(columns, headings):
            self.table.heading(column, text=heading)
            self.table.column(column, width=150, anchor="w")
        self.table.column("error", width=290)
        self.table.pack(fill="both", expand=True, pady=8)
        self.table.bind("<<TreeviewSelect>>", self.show_detail)
        self.detail = tk.Text(frame, height=10, font=("Consolas", 9))
        self.detail.pack(fill="x")
        root.after(200, self.drain)

    def scan(self) -> None:
        input_text = self.input.get("1.0", "end")
        entries = parse_targets(input_text)
        if not entries or self.busy:
            return
        try:
            save_targets(input_text)
        except OSError as exc:
            self.status.set(f"Không lưu được danh sách: {exc}")
            return
        self.busy = True
        active_labels = {label for label, _url in entries}
        self.rows = {label: data for label, data in self.rows.items() if label in active_labels}
        self.render()
        self.status.set(f"Đang quét {len(entries)} dịch vụ...")

        def one(item: tuple[str, str]) -> None:
            label, url = item
            self.events.put((label, fetch_health(url)))

        def work() -> None:
            with ThreadPoolExecutor(max_workers=min(12, len(entries))) as pool:
                list(pool.map(one, entries))
            self.events.put(("", None))

        threading.Thread(target=work, daemon=True).start()

    def drain(self) -> None:
        changed = False
        try:
            while True:
                label, data = self.events.get_nowait()
                if not label:
                    self.busy = False
                    self.status.set(f"Đã quét {len(self.rows)} dịch vụ")
                    self.schedule()
                elif data and data.get("ok"):
                    data["_monitor_error"] = ""
                    self.rows[label] = data
                    changed = True
                else:
                    old = dict(self.rows.get(label, {}))
                    old["_monitor_error"] = str((data or {}).get("_error") or "Không đọc được health")
                    self.rows[label] = old
                    changed = True
        except queue.Empty:
            pass
        if changed:
            self.render()
        self.root.after(200, self.drain)

    def schedule(self) -> None:
        if self.auto.get() and self.timer is None:
            self.timer = self.root.after(15000, self.scheduled_scan)

    def scheduled_scan(self) -> None:
        self.timer = None
        self.scan()

    def render(self) -> None:
        for item in self.table.get_children():
            self.table.delete(item)
        for label, data in self.rows.items():
            error = str(data.get("_monitor_error") or data.get("last_error") or "")
            state = "Online" if data.get("ok") else ("Không phản hồi · dữ liệu cũ" if data else "Không phản hồi")
            values = (
                label, state,
                f"{data.get('chunks_claimed', 0)}/{data.get('chunks_completed', 0)}",
                f"{data.get('accounts_claimed', 0)}/{data.get('accounts_completed', 0)}",
                data.get("chunks_active", 0), error[:200],
            )
            self.table.insert("", "end", iid=label, values=values)

    def show_detail(self, _event: Any) -> None:
        selected = self.table.selection()
        if selected:
            data = dict(self.rows.get(selected[0], {}))
            for field in ("accounts_active", "accounts_processed_active", "active_chunk_details", "recent_checked_accounts"):
                data.pop(field, None)
            self.detail.delete("1.0", "end")
            self.detail.insert("1.0", json.dumps(data, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    window = tk.Tk()
    Monitor(window)
    window.mainloop()
