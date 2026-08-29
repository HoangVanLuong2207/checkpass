"""Bounded Garena TCP LOGIN health probe for accounts owned by the operator.

This intentionally does not request SSO/OAuth tokens and never prints or saves
the TCP session key.  It is a conservative production-health check, not a tool
for discovering or bypassing Garena's maximum rate.
"""

from __future__ import annotations

import argparse
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

import garena_api_test_chrome as api_test
import garena_tcp_login_chrome as tcp_ui


MAX_ACCOUNTS = 40
MAX_WORKERS = 9999999
MIN_START_GAP_SECONDS = 0.0
DEFAULT_CREDENTIALS_FILE = Path(__file__).resolve().with_name("accounts_probe.txt")
@dataclass(slots=True)
class Credential:
    index: int
    account: str
    password: str


@dataclass(slots=True)
class ProbeResult:
    index: int
    masked_account: str
    ok: bool
    uid: int = 0
    session_key_bytes: int = 0
    elapsed_ms: int = 0
    error: str = ""
    should_stop: bool = False


class StartGate:
    """Space LOGIN starts globally even when two requests overlap."""

    def __init__(self, gap_seconds: float) -> None:
        self.gap_seconds = gap_seconds
        self._lock = threading.Lock()
        self._next_start = 0.0

    def wait(self, stop_event: threading.Event) -> bool:
        with self._lock:
            while not stop_event.is_set():
                delay = self._next_start - time.monotonic()
                if delay <= 0:
                    self._next_start = time.monotonic() + self.gap_seconds
                    return True
                stop_event.wait(min(delay, 0.25))
        return False


def mask_account(account: str) -> str:
    if len(account) <= 2:
        return "*" * len(account)
    if len(account) <= 6:
        return account[0] + "*" * (len(account) - 2) + account[-1]
    return account[:2] + "*" * (len(account) - 4) + account[-2:]


def load_credentials(path: Path, limit: int) -> list[Credential]:
    if not path.is_file():
        raise ValueError(f"Không tìm thấy file: {path}")
    credentials: list[Credential] = []
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "|" in line:
            parts = line.split("|")
            if len(parts) < 2:
                raise ValueError(
                    f"Dòng {line_number}: cần định dạng user|pass, user|pass|mail hoặc user|pass|mail|passmail (hoặc user:pass)"
                )
            account = parts[0].strip()
            password = parts[1].strip()
        elif line.count(":") == 1:
            account, password = line.split(":", 1)
            account = account.strip()
            password = password.strip()
        else:
            raise ValueError(
                f"Dòng {line_number}: cần định dạng user|pass, user|pass|mail hoặc user|pass|mail|passmail (hoặc user:pass)"
            )
        if not account or not password or len(account) > 128 or len(password) > 1024:
            raise ValueError(f"Dòng {line_number}: tài khoản/mật khẩu không hợp lệ")
        credentials.append(Credential(len(credentials) + 1, account, password))
        if len(credentials) >= limit:
            break
    if not credentials:
        raise ValueError("File không có tài khoản hợp lệ")
    return credentials


def probe_one(
    tcp_module,
    credential: Credential,
    timeout: float,
    gate: StartGate,
    stop_event: threading.Event,
) -> ProbeResult:
    masked = mask_account(credential.account)
    if not gate.wait(stop_event):
        return ProbeResult(credential.index, masked, False, error="đã dừng trước khi gửi")

    started = time.monotonic()
    try:
        client_type = api_test.resilient_tcp_client_type(tcp_module)
        with client_type(timeout=timeout) as client:
            uid = int(client.login(credential.account, credential.password))
            key_size = len(client.session_key or b"")
        elapsed_ms = round((time.monotonic() - started) * 1000)
        if key_size != 16:
            stop_event.set()
            return ProbeResult(
                credential.index,
                masked,
                False,
                elapsed_ms=elapsed_ms,
                error="LOGIN thành công nhưng session key không đúng 16 byte",
                should_stop=True,
            )
        return ProbeResult(
            credential.index,
            masked,
            True,
            uid=uid,
            session_key_bytes=key_size,
            elapsed_ms=elapsed_ms,
        )
    except Exception as exc:
        elapsed_ms = round((time.monotonic() - started) * 1000)
        message = (str(exc).strip() or type(exc).__name__)[:300]
        # Any failed authentication makes the remaining sample ambiguous and
        # stops new starts. With two workers, at most one request may already
        # be in flight when this failure becomes visible.
        should_stop = True
        stop_event.set()
        return ProbeResult(
            credential.index,
            masked,
            False,
            elapsed_ms=elapsed_ms,
            error=message,
            should_stop=should_stop,
        )
    finally:
        credential.password = ""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Probe LOGIN TCP có giới hạn; không lấy SSO/OAuth và không xuất session key"
    )
    parser.add_argument(
        "credentials",
        type=Path,
        nargs="?",
        default=DEFAULT_CREDENTIALS_FILE,
        help="File UTF-8 dạng user|pass, user|pass|mail hoặc user|pass|mail|passmail (hoặc user:pass) (mặc định: accounts_probe.txt cạnh chương trình)",
    )
    parser.add_argument("--limit", type=int, default=5, help="Số tài khoản, 1..40 (mặc định 5)")
    parser.add_argument("--workers", type=int, choices=(20, 40), default=20)
    parser.add_argument(
        "--start-gap",
        type=float,
        default=5.0,
        help="Khoảng cách giữa hai lần bắt đầu LOGIN, tối thiểu 2 giây",
    )
    parser.add_argument("--timeout", type=float, default=20.0, help="Timeout mỗi LOGIN, 5..60 giây")
    return parser.parse_args()


def main() -> int:
    tcp_ui.configure_console_encoding()
    args = parse_args()
    if not 1 <= args.limit <= MAX_ACCOUNTS:
        raise SystemExit(f"--limit phải trong khoảng 1..{MAX_ACCOUNTS}")
    if not MIN_START_GAP_SECONDS <= args.start_gap <= 60:
        raise SystemExit("--start-gap phải trong khoảng 2..60 giây")
    if not 5 <= args.timeout <= 60:
        raise SystemExit("--timeout phải trong khoảng 5..60 giây")

    credentials = load_credentials(args.credentials.resolve(), args.limit)
    tcp_module = tcp_ui.load_verified_tcp_module()
    gate = StartGate(args.start_gap)
    stop_event = threading.Event()

    print(
        f"Probe {len(credentials)} tài khoản | workers={args.workers} | "
        f"start_gap={args.start_gap:g}s | không lưu session/token"
    )
    print("STT|ACCOUNT|STATUS|UID|SESSION_BYTES|ELAPSED_MS|ERROR")

    results: list[ProbeResult] = []
    try:
        with ThreadPoolExecutor(max_workers=args.workers, thread_name_prefix="tcp-probe") as executor:
            futures = [
                executor.submit(
                    probe_one,
                    tcp_module,
                    credential,
                    args.timeout,
                    gate,
                    stop_event,
                )
                for credential in credentials
            ]
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                status = "OK" if result.ok else "FAIL"
                safe_error = result.error.replace("|", "/").replace("\r", " ").replace("\n", " ")
                print(
                    f"{result.index}|{result.masked_account}|{status}|{result.uid or ''}|"
                    f"{result.session_key_bytes or ''}|{result.elapsed_ms}|{safe_error}"
                )
                if result.should_stop:
                    print("STOP|Phát hiện tín hiệu từ chối/giới hạn; không gửi thêm LOGIN mới.")
    finally:
        for credential in credentials:
            credential.password = ""

    attempted = [result for result in results if result.error != "đã dừng trước khi gửi"]
    succeeded = sum(result.ok for result in attempted)
    failed = len(attempted) - succeeded
    print(f"SUMMARY|attempted={len(attempted)}|ok={succeeded}|fail={failed}|stopped={stop_event.is_set()}")
    return 0 if failed == 0 and not stop_event.is_set() else 1


if __name__ == "__main__":
    raise SystemExit(main())
