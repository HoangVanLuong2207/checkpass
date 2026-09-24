"""Test Garena TCP token exchange and the Weekly Report profile API.

The password is read with ``getpass`` and is never written to disk or included
in the JSON output. OAuth credentials, cookies, and request tokens are omitted.
The Weekly Report response body itself is intentionally printed without
redaction so every field returned by ``/api/profile`` can be inspected.

This script reuses the verified Garena OAuth resources from the local upclone
project. It does not copy or print the embedded client secret.
"""

from __future__ import annotations

import argparse
import getpass
import importlib
import json
import os
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Any

import garena_api_test_chrome1 as garena


WEEKLY_BASE_URL = "https://weeklyreport.moba.garena.vn/"
WEEKLY_PROFILE_URL = f"{WEEKLY_BASE_URL}api/profile"
DEFAULT_UPCLONE_DIR = Path(r"C:\Users\ADMIN'\Downloads\upclone")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "TCP login Garena, đổi SSO thành access token game cho app 100054, "
            "sau đó gọi GET Weekly Report /api/profile"
        )
    )
    parser.add_argument(
        "--account",
        help="Tên tài khoản Garena; nếu bỏ trống chương trình sẽ hỏi khi chạy",
    )
    parser.add_argument(
        "--partition",
        default="1011",
        help="Partition gửi cho Weekly Report (mặc định: 1011)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=20.0,
        help="Timeout cho mỗi kết nối, tính bằng giây (mặc định: 20)",
    )
    parser.add_argument(
        "--upclone-dir",
        type=Path,
        default=DEFAULT_UPCLONE_DIR,
        help=f"Thư mục upclone chứa core/resources (mặc định: {DEFAULT_UPCLONE_DIR})",
    )
    parser.add_argument(
        "--device-serial",
        default="weeklyreport-profile-test",
        help="Chuỗi ổn định dùng tạo device_id OAuth",
    )
    parser.add_argument(
        "--android-id",
        default="weeklyreport-profile-test",
        help="Chuỗi ổn định dùng tạo device_id OAuth",
    )
    return parser.parse_args()


def load_upclone_game_login(upclone_dir: Path) -> ModuleType:
    root = upclone_dir.expanduser().resolve()
    module_path = root / "core" / "garena_tcp_game_login.py"
    if not module_path.is_file():
        raise RuntimeError(f"Không tìm thấy module OAuth upclone: {module_path}")

    root_text = str(root)
    if root_text not in sys.path:
        sys.path.insert(0, root_text)
    module = importlib.import_module("core.garena_tcp_game_login")
    loaded_path = Path(module.__file__ or "").resolve()
    if loaded_path != module_path:
        raise RuntimeError(f"Đã nạp nhầm module core từ: {loaded_path}")
    return module


def exchange_game_access_token(
    account: str,
    password: str,
    upclone_dir: Path,
    device_serial: str,
    android_id: str,
    timeout: float,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    started = time.monotonic()
    try:
        game_login = load_upclone_game_login(upclone_dir)
        bundle = game_login.exchange_game_token(
            account,
            password,
            device_serial,
            android_id,
            timeout=timeout,
            # One bounded attempt. Re-running manually is safer than silently
            # issuing multiple TCP logins when Garena is rate-limiting.
            reconnect_attempts=0,
        )
        access_token = str(bundle.access_token or "")
        tcp_result = {
            "ok": True,
            "uid": int(bundle.uid),
            "elapsed_ms": round((time.monotonic() - started) * 1000),
        }
        oauth_result = {
            "ok": bool(access_token),
            "access_token_received": bool(access_token),
            "access_token_length": len(access_token),
            "refresh_token_received": bool(bundle.refresh_token),
            "open_id_received": bool(bundle.open_id),
            "expiry_time": int(bundle.expiry_time),
            "refresh_expiry_time": int(bundle.refresh_expiry_time),
        }
        if not access_token:
            oauth_result["error"] = "missing_game_access_token"
        return tcp_result, oauth_result, access_token
    except Exception as exc:
        return ({
            "ok": False,
            "error": (str(exc).strip() or type(exc).__name__)[:500],
            "elapsed_ms": round((time.monotonic() - started) * 1000),
        }, {"ok": False, "error": "game_token_exchange_failed"}, "")


def weekly_profile(
    access_token: str,
    partition: str,
    timeout: float,
) -> dict[str, Any]:
    """Return the complete, unredacted Weekly Report profile response."""

    started = time.monotonic()
    session = garena.WebSession(timeout)
    try:
        status, final_url, content_type, body = session.request(
            WEEKLY_PROFILE_URL,
            headers={
                "Referer": WEEKLY_BASE_URL,
                "Content-Type": "application/json",
                "Access-Token": access_token,
                "Partition": partition,
            },
        )
        http_ok = 200 <= status < 300
        application_ok = not (
            isinstance(body, dict)
            and (body.get("error") not in (None, "", 0, False) or bool(body.get("errors")))
        )
        return {
            "ok": http_ok and application_ok,
            "http_ok": http_ok,
            "status": status,
            "url": final_url,
            "content_type": content_type,
            "elapsed_ms": round((time.monotonic() - started) * 1000),
            # Deliberately do not call garena.redact_tree here: this standalone
            # diagnostic script is intended to display every profile field.
            "body": body,
        }
    except Exception as exc:
        return {
            "ok": False,
            "status": 0,
            "url": WEEKLY_PROFILE_URL,
            "elapsed_ms": round((time.monotonic() - started) * 1000),
            "error": (str(exc).strip() or type(exc).__name__)[:500],
        }


def main() -> int:
    garena.tcp_ui.configure_console_encoding()
    args = parse_args()
    if not 1.0 <= args.timeout <= 60.0:
        raise SystemExit("--timeout phải nằm trong khoảng 1..60 giây")

    account = (args.account or input("Tài khoản Garena: ")).strip()
    if not account:
        raise SystemExit("Tài khoản không được để trống")
    password = getpass.getpass("Mật khẩu Garena: ")
    if not password:
        raise SystemExit("Mật khẩu không được để trống")

    tcp_result, oauth_result, access_token = exchange_game_access_token(
        account,
        password,
        args.upclone_dir,
        args.device_serial,
        args.android_id,
        args.timeout,
    )
    result: dict[str, Any] = {
        "tcp": tcp_result,
        "game_oauth": oauth_result,
        "profile": None,
    }

    if tcp_result.get("ok") and oauth_result.get("ok") and access_token:
        result["profile"] = weekly_profile(
            access_token,
            args.partition,
            args.timeout,
        )

    # Drop the last local references before serializing diagnostics.
    account = password = access_token = ""
    os.environ.pop("UPCLONE_GARENA_CLIENT_SECRET", None)
    print(json.dumps(result, ensure_ascii=False, indent=2))

    if not result["tcp"].get("ok"):
        return 2
    if not result["game_oauth"].get("ok"):
        return 3
    if not (result["profile"] or {}).get("ok"):
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
