"""Local GUI monitor for numbered satellite health ports.

Run this beside satellite_worker.py:
    python satellite_manager.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import tkinter as tk
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tkinter import ttk
from typing import Any


REFRESH_MS = 2_000


def fetch_health(port: int) -> tuple[int, dict[str, Any] | None, str]:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1.5) as response:
            payload = json.loads(response.read().decode("utf-8"))
        if not isinstance(payload, dict) or not payload.get("ok"):
            raise ValueError("health response không hợp lệ")
        return port, payload, ""
    except Exception as exc:
        return port, None, str(exc)


class SatelliteManager:
    columns = (
        "port", "id", "proxy", "state", "active_chunks", "claimed_chunks", "completed_chunks",
        "active_accounts", "processed_active", "claimed_accounts", "completed_accounts", "error",
    )

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Satellite Manager")
        self.root.geometry("1450x560")
        self.root.minsize(960, 360)
        self.port_start = tk.StringVar(value="9001")
        self.port_count = tk.StringVar(value="10")
        self.master_url = tk.StringVar(value=os.environ.get("MASTER_URL", ""))
        self.master_token = tk.StringVar(value=os.environ.get("MASTER_TOKEN", ""))
        self.workers = tk.StringVar(value=os.environ.get("WORKERS", "4"))
        self.concurrent_chunks = tk.StringVar(value=os.environ.get("CONCURRENT_CHUNKS", "1"))
        self.start_gap = tk.StringVar(value=os.environ.get("START_GAP", "1.5"))
        self.timeout = tk.StringVar(value=os.environ.get("TIMEOUT", "20"))
        self.poll_interval = tk.StringVar(value=os.environ.get("POLL_INTERVAL", "10"))
        self.proxies = tk.StringVar(value=os.environ.get("GARENA_PROXIES", ""))
        self.auto_refresh = tk.BooleanVar(value=True)
        self.status = tk.StringVar(value="Sẵn sàng")
        self.refreshing = False
        self.processes: dict[int, tuple[subprocess.Popen[bytes], Any]] = {}
        self._build()
        self.refresh()

    def _build(self) -> None:
        config = ttk.LabelFrame(self.root, text="Cấu hình worker", padding=10)
        config.pack(fill="x", padx=10, pady=(10, 4))
        fields = [
            ("MASTER_URL", self.master_url, 46, False),
            ("MASTER_TOKEN", self.master_token, 28, True),
            ("Workers", self.workers, 5, False),
            ("Chunk đồng thời", self.concurrent_chunks, 5, False),
            ("Gap (giây)", self.start_gap, 5, False),
            ("Timeout", self.timeout, 5, False),
            ("Poll", self.poll_interval, 5, False),
            ("Proxy SOCKS5 (; theo port)", self.proxies, 46, False),
        ]
        for index, (label, variable, width, hidden) in enumerate(fields):
            row, column = divmod(index, 4)
            ttk.Label(config, text=label + ":").grid(row=row, column=column * 2, sticky="w", padx=(0, 4), pady=3)
            ttk.Entry(config, textvariable=variable, width=width, show="*" if hidden else "").grid(
                row=row, column=column * 2 + 1, sticky="ew", padx=(0, 12), pady=3
            )
        ttk.Label(
            config,
            text="Proxy: socks5://user:pass@host:port; phân cách bằng dấu ; theo thứ tự port. Để trống vị trí nào thì port đó dùng IP gốc.",
        ).grid(row=2, column=0, columnspan=8, sticky="w", pady=(7, 0))

        top = ttk.Frame(self.root, padding=10)
        top.pack(fill="x")
        ttk.Label(top, text="Port bắt đầu:").pack(side="left")
        ttk.Entry(top, textvariable=self.port_start, width=8).pack(side="left", padx=(5, 12))
        ttk.Label(top, text="Số port:").pack(side="left")
        ttk.Entry(top, textvariable=self.port_count, width=5).pack(side="left", padx=(5, 12))
        ttk.Button(top, text="▶ Khởi chạy", command=self.start_workers).pack(side="left")
        ttk.Button(top, text="■ Dừng worker đã mở", command=self.stop_workers).pack(side="left", padx=(6, 12))
        ttk.Button(top, text="Quét ngay", command=self.refresh).pack(side="left")
        ttk.Checkbutton(top, text="Tự làm mới 2 giây", variable=self.auto_refresh).pack(side="left", padx=14)
        ttk.Label(top, textvariable=self.status).pack(side="right")

        table_frame = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        table_frame.pack(fill="both", expand=True)
        headings = {
            "port": "Port", "id": "Vệ tinh", "proxy": "Proxy", "state": "Trạng thái", "active_chunks": "Chunk đang chạy",
            "claimed_chunks": "Chunk đã nhận", "completed_chunks": "Chunk xong", "active_accounts": "Acc đang xử lý",
            "processed_active": "Acc xong (chunk đang chạy)", "claimed_accounts": "Tổng acc nhận",
            "completed_accounts": "Tổng acc xong", "error": "Lỗi gần nhất",
        }
        self.table = ttk.Treeview(table_frame, columns=self.columns, show="headings")
        for column in self.columns:
            self.table.heading(column, text=headings[column])
            self.table.column(column, width=110, anchor="center", stretch=column == "error")
        self.table.column("id", width=130)
        self.table.column("proxy", width=150)
        self.table.column("error", width=250, anchor="w")
        y_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        x_scroll = ttk.Scrollbar(table_frame, orient="horizontal", command=self.table.xview)
        self.table.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        self.table.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)

    def start_workers(self) -> None:
        ports = self._ports()
        master_url = self.master_url.get().strip()
        master_token = self.master_token.get().strip()
        if not ports or not master_url or not master_token:
            self.status.set("Cần nhập MASTER_URL, MASTER_TOKEN và port hợp lệ")
            return
        try:
            if int(self.workers.get()) < 1 or int(self.concurrent_chunks.get()) < 1:
                raise ValueError
            float(self.start_gap.get())
            float(self.timeout.get())
            float(self.poll_interval.get())
        except ValueError:
            self.status.set("Workers/chunk phải > 0; gap, timeout và poll phải là số")
            return
        worker_file = Path(__file__).with_name("satellite_worker.py")
        if not worker_file.is_file():
            self.status.set("Không tìm thấy satellite_worker.py")
            return
        logs_dir = worker_file.with_name("satellite_logs")
        logs_dir.mkdir(exist_ok=True)
        proxies = [item.strip() for item in self.proxies.get().split(";")]
        started = 0
        for number, port in enumerate(ports, 1):
            existing = self.processes.get(port)
            if existing is not None and existing[0].poll() is None:
                continue
            environment = os.environ.copy()
            environment.update({
                "MASTER_URL": master_url,
                "MASTER_TOKEN": master_token,
                "SATELLITE_ID": f"pc-local-{number}",
                "PORT": str(port),
                "WORKERS": self.workers.get().strip(),
                "CONCURRENT_CHUNKS": self.concurrent_chunks.get().strip(),
                "START_GAP": self.start_gap.get().strip(),
                "TIMEOUT": self.timeout.get().strip(),
                "POLL_INTERVAL": self.poll_interval.get().strip(),
                "GARENA_PROXY": proxies[number - 1] if number - 1 < len(proxies) else "",
            })
            log_file = (logs_dir / f"pc-local-{number}.log").open("a", encoding="utf-8")
            process = subprocess.Popen(
                [sys.executable, str(worker_file)], cwd=worker_file.parent, env=environment,
                stdout=log_file, stderr=subprocess.STDOUT,
            )
            self.processes[port] = (process, log_file)
            started += 1
        self.status.set(f"Đã khởi chạy {started} worker; log nằm trong satellite_logs")
        self.refresh()

    def stop_workers(self) -> None:
        stopped = 0
        for port, (process, log_file) in list(self.processes.items()):
            if process.poll() is None:
                process.terminate()
                stopped += 1
            log_file.close()
            self.processes.pop(port, None)
        self.status.set(f"Đã gửi lệnh dừng {stopped} worker do cửa sổ này mở")
        self.refresh()

    def _ports(self) -> list[int]:
        try:
            start = int(self.port_start.get())
            count = int(self.port_count.get())
            if not 1 <= start <= 65535 or not 1 <= count <= 100:
                raise ValueError
            return list(range(start, min(65536, start + count)))
        except ValueError:
            self.status.set("Port bắt đầu phải 1..65535; số port phải 1..100")
            return []

    def refresh(self) -> None:
        if self.refreshing:
            return
        ports = self._ports()
        if not ports:
            return
        self.refreshing = True
        self.status.set("Đang quét...")
        threading.Thread(target=self._fetch_all, args=(ports,), daemon=True).start()

    def _fetch_all(self, ports: list[int]) -> None:
        with ThreadPoolExecutor(max_workers=min(20, len(ports))) as pool:
            results = list(pool.map(fetch_health, ports))
        self.root.after(0, self._render, results)

    def _render(self, results: list[tuple[int, dict[str, Any] | None, str]]) -> None:
        self.refreshing = False
        for item in self.table.get_children():
            self.table.delete(item)
        online = 0
        for port, payload, error in results:
            if payload is None:
                values = (port, "—", "—", "Offline", "—", "—", "—", "—", "—", "—", "—", error[:100])
            else:
                online += 1
                values = (
                    port, payload.get("id", "—"), payload.get("proxy", "IP gốc"), "Online", payload.get("chunks_active", 0),
                    payload.get("chunks_claimed", 0), payload.get("chunks_completed", 0),
                    payload.get("accounts_active", 0), payload.get("accounts_processed_active", 0),
                    payload.get("accounts_claimed", 0), payload.get("accounts_completed", 0),
                    payload.get("last_error", ""),
                )
            self.table.insert("", "end", values=values)
        self.status.set(f"{online}/{len(results)} vệ tinh online · cập nhật {time.strftime('%H:%M:%S')}")
        if self.auto_refresh.get():
            self.root.after(REFRESH_MS, self.refresh)


def main() -> None:
    root = tk.Tk()
    SatelliteManager(root)
    root.mainloop()


if __name__ == "__main__":
    main()
