from __future__ import annotations

"""Vệ tinh check acc - claim chunk từ tổng bộ, chạy check, trả kết quả.

Vòng lặp: claim (<= 1000 acc/chunk) -> chạy qua engine cũng được dùng bởi
garena_api_test_chrome1 (bounded workers, sub-chunk <= 15) -> POST kết quả.
Nếu xử lý/net lỗi thì release chunk để tổng bộ giao lại cho vệ tinh khác.

Vệ tinh có một HTTP /healthz để Render không ngủ free tier trong lúc chạy dài.
"""

import json
import os
import socket
import threading
import time
import urllib.error
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import garena_api_test_chrome1 as api_test
import garena_tcp_login_chrome as tcp_ui


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


MASTER_URL = _env("MASTER_URL").rstrip("/") or "http://127.0.0.1:8761"
MASTER_TOKEN = _env("MASTER_TOKEN")
SATELLITE_ID = _env("SATELLITE_ID") or f"{socket.gethostname()}-{os.getpid()}"
WORKERS = int(_env("WORKERS", "8") or "8")
START_GAP = float(_env("START_GAP", "3.0") or "3.0")
TIMEOUT = float(_env("TIMEOUT", "20.0") or "20.0")
LEASE_MINUTES = float(_env("LEASE_MINUTES", "60") or "60")
POLL_INTERVAL = float(_env("POLL_INTERVAL", "15") or "15")
HEALTH_PORT = int(_env("HEALTH_PORT", "8765") or "8765")
HEALTH_HOST = _env("HEALTH_HOST", "0.0.0.0") or "0.0.0.0"


class _Client:
    def __init__(self, base_url: str, token: str) -> None:
        self.base_url = base_url
        self.token = token

    def _request(self, path: str, body: Any | None = None) -> dict:
        url = self.base_url + path
        data = None if body is None else json.dumps(body, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(url, data=data, method="POST" if body is not None else "GET")
        request.add_header("Content-Type", "application/json")
        request.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                payload = json.loads(exc.read().decode("utf-8"))
            except Exception:
                payload = {"ok": False, "error": f"HTTP {exc.code}"}
            raise RuntimeError(payload.get("error") or f"login HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"không kết nối được tổng bộ: {exc.reason}") from exc

    def claim(self) -> dict:
        return self._request("/api/claim", {
            "satellite_id": SATELLITE_ID,
            "lease_minutes": LEASE_MINUTES,
        })

    def report(self, chunk_id: int, rows: list[dict]) -> dict:
        return self._request("/api/report", {"chunk_id": chunk_id, "rows": rows})

    def release(self, chunk_id: int) -> dict:
        return self._request("/api/chunk/release", {
            "chunk_id": chunk_id,
            "satellite_id": SATELLITE_ID,
        })


class _Health(BaseHTTPRequestHandler):
    def log_message(self, _format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        body = b'{"ok":true,"role":"satellite","id":"' + SATELLITE_ID.encode() + b'"}'
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass


def _run_health_server() -> None:
    try:
        server = ThreadingHTTPServer((HEALTH_HOST, HEALTH_PORT), _Health)
        server.serve_forever(poll_interval=0.5)
    except Exception as exc:
        print(f"[satellite] lỗi health server: {exc}", flush=True)


def _one_chunk(client: _Client, tcp_module: Any) -> None:
    claim_resp = client.claim()
    claim = claim_resp.get("claim")
    if not claim:
        time.sleep(POLL_INTERVAL)
        return
    chunk_id = int(claim["chunk_id"])
    accounts = list(claim.get("accounts") or [])
    print(f"[satellite] {SATELLITE_ID}: claim chunk {chunk_id} ({len(accounts)} acc)", flush=True)

    credentials = []
    for index, raw in enumerate(accounts, 1):
        raw_str = str(raw).strip()
        if "|" in raw_str:
            parts = raw_str.split("|")
            account = parts[0].strip() if len(parts) >= 1 else ""
            password = parts[1].strip() if len(parts) >= 2 else ""
        elif raw_str.count(":") == 1:
            account, password = raw_str.split(":", 1)
            account = account.strip()
            password = password.strip()
        else:
            account = raw_str
            password = ""
        credentials.append(api_test.BatchAccount(index, account, password))

    rows: list[dict[str, str]] = []
    try:
        raw_rows = api_test.run_batch_core(
            credentials, tcp_module, WORKERS, START_GAP, TIMEOUT
        )
        rows = [api_test.public_batch_row(row) for row in raw_rows]
        client.report(chunk_id, rows)
        ok = sum(1 for r in rows if r.get("status") == "OK")
        print(
            f"[satellite] {SATELLITE_ID}: chunk {chunk_id} xong "
            f"{len(rows)} acc (ok={ok} fail={len(rows) - ok})",
            flush=True,
        )
    except Exception as exc:
        print(f"[satellite] {SATELLITE_ID}: chunk {chunk_id} lỗi, release để check lại: {exc}", flush=True)
        try:
            client.release(chunk_id)
        except Exception as release_exc:
            print(f"[satellite] release chunk {chunk_id} thất bại: {release_exc}", flush=True)
    finally:
        for credential in credentials:
            credential.password = ""


def _worker_loop() -> None:
    tcp_module = tcp_ui.load_verified_tcp_module()
    client = _Client(MASTER_URL, MASTER_TOKEN)
    print(
        f"[satellite] {SATELLITE_ID} khởi động: master={MASTER_URL} "
        f"workers={WORKERS} gap={START_GAP:g}s timeout={TIMEOUT:g}s",
        flush=True,
    )
    while True:
        try:
            _one_chunk(client, tcp_module)
        except Exception as exc:
            print(f"[satellite] lỗi vòng lặp: {exc}; chờ {POLL_INTERVAL}s", flush=True)
            time.sleep(POLL_INTERVAL)


def main() -> int:
    tcp_ui.configure_console_encoding()
    if not MASTER_TOKEN:
        print("[satellite] CẢNH BÁO: chưa đặt MASTER_TOKEN", flush=True)
    health_thread = threading.Thread(target=_run_health_server, daemon=True, name="health")
    health_thread.start()
    _worker_loop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
