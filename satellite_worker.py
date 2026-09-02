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
from concurrent.futures import ThreadPoolExecutor
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
CONCURRENT_CHUNKS = int(_env("CONCURRENT_CHUNKS", "3") or "3")
POLL_INTERVAL = float(_env("POLL_INTERVAL", "15") or "15")
# In thời gian của mỗi lần gọi master khi vượt ngưỡng này. Report luôn được in
# để có thể đối chiếu với thời gian xử lý phía master.
MASTER_REQUEST_WARN_SECONDS = float(_env("MASTER_REQUEST_WARN_SECONDS", "2.0") or "2.0")
# Render Web Service truyền PORT; fallback HEALTH_PORT cho local
HEALTH_PORT = int(_env("PORT", "") or _env("HEALTH_PORT", "8765") or "8765")
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
        started = time.perf_counter()
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                payload = json.loads(response.read().decode("utf-8"))
            elapsed_ms = (time.perf_counter() - started) * 1000
            # master_elapsed_ms là thời gian master xử lý request; phần chênh
            # lệch còn lại là upload/download + độ trễ mạng/proxy.
            server_elapsed_ms = payload.get("master_elapsed_ms")
            if path == "/api/report" or elapsed_ms >= MASTER_REQUEST_WARN_SECONDS * 1000:
                detail = f", master={server_elapsed_ms:.1f}ms" if isinstance(server_elapsed_ms, (int, float)) else ""
                print(f"[satellite] master {path}: round-trip={elapsed_ms:.1f}ms{detail}", flush=True)
            return payload
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

    def report(self, chunk_id: int, rows: list[dict], done: bool = True) -> dict:
        return self._request("/api/report", {
            "chunk_id": chunk_id,
            "satellite_id": SATELLITE_ID,
            "rows": rows,
            "done": done,
        })

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
        print(f"[satellite] health server listening on {HEALTH_HOST}:{HEALTH_PORT}", flush=True)
        server.serve_forever(poll_interval=0.5)
    except Exception as exc:
        print(f"[satellite] loi health server: {exc}", flush=True)


def _self_ping_loop() -> None:
    """Tự gửi request đến chính mình mỗi 10 phút để Render Free Web Service không bị spin down."""
    import urllib.request as _ur
    ping_url = f"http://127.0.0.1:{HEALTH_PORT}/healthz"
    while True:
        time.sleep(300)  # 5 phút
        try:
            with _ur.urlopen(ping_url, timeout=10):
                pass
        except Exception:
            pass


def _process_chunk(client: _Client, tcp_module: Any, claim: dict) -> None:
    """Xử lý 1 chunk trong thread riêng."""
    chunk_id = int(claim["chunk_id"])
    accounts = list(claim.get("accounts") or [])
    print(f"[satellite] {SATELLITE_ID}: chunk {chunk_id} ({len(accounts)} acc)", flush=True)

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

    try:
        buffer = []
        buffer_lock = threading.Lock()
        sent_count = [0]
        FLUSH_SIZE = 5

        def on_result(row):
            pub = api_test.public_batch_row(row)
            flush = None
            with buffer_lock:
                buffer.append(pub)
                if len(buffer) >= FLUSH_SIZE:
                    flush = list(buffer)
                    # không clear ngay — chỉ clear sau khi report thành công để tránh mất pack nhỏ
                else:
                    flush = None
            if flush:
                try:
                    client.report(chunk_id, flush, done=False)
                    sent_count[0] += len(flush)
                    with buffer_lock:
                        # xóa đúng số phần tử đã flush (đề phòng buffer đã tăng thêm trong lúc report)
                        del buffer[:len(flush)]
                except Exception as exc:
                    print(f"[satellite] stream report loi: {exc}", flush=True)
                    # giu buffer nguyen de retry o lan flush sau hoac o remaining

        api_test.run_batch_core(
            credentials, tcp_module, WORKERS, START_GAP, TIMEOUT,
            on_result=on_result,
        )
        # Gui phan con lai + danh dau done — dam bao gui het ke ca khi truoc do flush loi
        # Thu lai den khi thanh cong (toi da 3 lan) de tranh mat pack nho
        with buffer_lock:
            remaining = list(buffer)
            buffer.clear()
        # Neu so da gui + con lai < tong so acc, canh bao (pack nho de lo bug)
        expected = len(credentials)
        total_buffered = sent_count[0] + len(remaining)
        if total_buffered != expected:
            print(f"[satellite] canh bao: chunk {chunk_id} expected {expected} nhung buffered {total_buffered} (sent {sent_count[0]} + remaining {len(remaining)})", flush=True)
            # Neu thieu do flush loi truoc do, remaining da chua phan khoi phuc nen se du
        for attempt in range(3):
            try:
                client.report(chunk_id, remaining, done=True)
                break
            except Exception as exc:
                print(f"[satellite] report done loi lan {attempt+1}: {exc}", flush=True)
                if attempt == 2:
                    raise
                time.sleep(2)
        total = sent_count[0] + len(remaining)
        # Dam bao total phan anh dung so acc da check, khong phu thuoc kich thuoc pack
        if total != expected:
            print(f"[satellite] {SATELLITE_ID}: chunk {chunk_id} xong {total}/{expected} acc (da gui {sent_count[0]} + con lai {len(remaining)})", flush=True)
        else:
            print(f"[satellite] {SATELLITE_ID}: chunk {chunk_id} xong {total} acc", flush=True)
    except Exception as exc:
        print(f"[satellite] {SATELLITE_ID}: chunk {chunk_id} loi, release: {exc}", flush=True)
        try:
            client.release(chunk_id)
        except Exception as release_exc:
            print(f"[satellite] release chunk {chunk_id} that bai: {release_exc}", flush=True)
    finally:
        for credential in credentials:
            credential.password = ""


def _worker_loop() -> None:
    tcp_module = tcp_ui.load_verified_tcp_module()
    client = _Client(MASTER_URL, MASTER_TOKEN)
    print(
        f"[satellite] {SATELLITE_ID} khởi động: master={MASTER_URL} "
        f"workers={WORKERS} concurrent_chunks={CONCURRENT_CHUNKS} "
        f"gap={START_GAP:g}s timeout={TIMEOUT:g}s "
        f"master_warn={MASTER_REQUEST_WARN_SECONDS:g}s",
        flush=True,
    )

    # Đếm số chunk đang xử lý
    active_count = 0
    active_lock = threading.Lock()

    def on_chunk_done(future):
        nonlocal active_count
        with active_lock:
            active_count -= 1

    with ThreadPoolExecutor(max_workers=CONCURRENT_CHUNKS, thread_name_prefix="chunk") as pool:
        while True:
            try:
                # Chờ nếu đủ chunk đang chạy
                with active_lock:
                    if active_count >= CONCURRENT_CHUNKS:
                        time.sleep(1)
                        continue

                claim_resp = client.claim()
                claim = claim_resp.get("claim")
                if not claim:
                    time.sleep(POLL_INTERVAL)
                    continue

                with active_lock:
                    active_count += 1

                future = pool.submit(_process_chunk, client, tcp_module, claim)
                future.add_done_callback(on_chunk_done)

            except Exception as exc:
                err_msg = str(exc)
                # Phân biệt lỗi auth (401) với lỗi mạng thường — nếu auth fail thì chờ lâu hơn, không spam
                if "401" in err_msg or "token" in err_msg.lower() or "không hợp lệ" in err_msg.lower() or "unauthorized" in err_msg.lower():
                    print(f"[satellite] LỖI AUTH: {err_msg}", flush=True)
                    print(f"[satellite] Kiểm tra MASTER_TOKEN của vệ tinh có khớp với master server không!", flush=True)
                    print(f"[satellite] MASTER_TOKEN hiện tại: '{MASTER_TOKEN[:4]}***{MASTER_TOKEN[-2:]}' (len={len(MASTER_TOKEN)})", flush=True)
                    time.sleep(60)  # Chờ 60s trước khi thử lại, tránh spam
                else:
                    print(f"[satellite] loi vong lap: {err_msg}; cho {POLL_INTERVAL}s", flush=True)
                    time.sleep(POLL_INTERVAL)


def main() -> int:
    tcp_ui.configure_console_encoding()
    if not MASTER_TOKEN:
        print("[satellite] CẢNH BÁO: chưa đặt MASTER_TOKEN", flush=True)
    else:
        print(f"[satellite] MASTER_TOKEN = '{MASTER_TOKEN[:4]}***{MASTER_TOKEN[-2:]}' (len={len(MASTER_TOKEN)})", flush=True)
    health_thread = threading.Thread(target=_run_health_server, daemon=True, name="health")
    health_thread.start()
    # Self-ping để Render Free Web Service không spin down
    ping_thread = threading.Thread(target=_self_ping_loop, daemon=True, name="self-ping")
    ping_thread.start()
    _worker_loop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
