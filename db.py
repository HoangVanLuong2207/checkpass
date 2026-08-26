"""Turso/libSQL database module for check history.
Uses libsql-client (pure Python HTTP, no Rust needed)."""

import asyncio
import os
import time
from typing import Any

_url: str = ""
_token: str = ""
_ready: bool = False
_initialized: bool = False


def _load_config() -> None:
    global _url, _token, _ready
    if _ready:
        return
    _url = os.environ.get("TURSO_URL", "").strip()
    _token = os.environ.get("TURSO_TOKEN", "").strip()
    _ready = bool(_url)


def _run(coro: Any) -> Any:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, coro).result()
    return asyncio.run(coro)


async def _execute(sql: str, args: tuple = ()) -> Any:
    from libsql_client import create_client
    client = create_client(_url, auth_token=_token or None)
    try:
        result = await client.execute(sql, args)
        return result
    finally:
        await client.close()


async def _execute_all(sql: str, args: tuple = ()) -> list:
    from libsql_client import create_client
    client = create_client(_url, auth_token=_token or None)
    try:
        result = await client.execute(sql, args)
        return result.rows if hasattr(result, "rows") else []
    finally:
        await client.close()


async def _batch(statements: list) -> Any:
    from libsql_client import create_client
    client = create_client(_url, auth_token=_token or None)
    try:
        return await client.batch(statements)
    finally:
        await client.close()


def _ensure_tables() -> None:
    global _initialized
    if _initialized:
        return
    _load_config()
    if not _url:
        return
    try:
        _run(_execute("""
            CREATE TABLE IF NOT EXISTS batch_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at REAL NOT NULL,
                total INTEGER DEFAULT 0,
                met INTEGER DEFAULT 0,
                not_met INTEGER DEFAULT 0,
                required_level INTEGER DEFAULT 12,
                elapsed_ms INTEGER DEFAULT 0
            )
        """))
        _run(_execute("""
            CREATE TABLE IF NOT EXISTS batch_rows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                stt TEXT DEFAULT '',
                account TEXT DEFAULT '',
                status TEXT DEFAULT '',
                uid TEXT DEFAULT '',
                email TEXT DEFAULT '',
                email_status TEXT DEFAULT '',
                mobile TEXT DEFAULT '',
                two_step TEXT DEFAULT '',
                authenticator TEXT DEFAULT '',
                session_key TEXT DEFAULT '',
                name TEXT DEFAULT '',
                level TEXT DEFAULT '',
                player_status TEXT DEFAULT '',
                deletion_status TEXT DEFAULT '',
                elapsed_ms TEXT DEFAULT '',
                error TEXT DEFAULT '',
                latest_login TEXT DEFAULT '',
                login_ip TEXT DEFAULT '',
                FOREIGN KEY (run_id) REFERENCES batch_runs(id) ON DELETE CASCADE
            )
        """))
        _initialized = True
    except Exception:
        pass


def _is_met(row: dict[str, str], required_level: int) -> bool:
    lv = row.get("level", "").strip()
    if lv.isdigit():
        return int(lv) >= required_level
    return False


def save_batch(rows: list[dict[str, str]], required_level: int = 12) -> int | None:
    _load_config()
    if not _url:
        return None
    _ensure_tables()
    met = sum(1 for r in rows if _is_met(r, required_level))
    not_met = len(rows) - met
    elapsed = max((int(r.get("elapsed_ms", "0") or "0") for r in rows), default=0)
    try:
        result = _run(_execute(
            "INSERT INTO batch_runs (created_at, total, met, not_met, required_level, elapsed_ms) VALUES (?,?,?,?,?,?)",
            (time.time(), len(rows), met, not_met, required_level, elapsed),
        ))
        run_id = result.last_insert_rowid if hasattr(result, "last_insert_rowid") else 0
        if not run_id:
            rows_result = _run(_execute("SELECT last_insert_rowid()"))
            if rows_result and hasattr(rows_result, "rows") and rows_result.rows:
                run_id = rows_result.rows[0][0]
        stmts = []
        for r in rows:
            stmts.append({
                "sql": "INSERT INTO batch_rows (run_id,stt,account,status,uid,email,email_status,mobile,two_step,authenticator,session_key,name,level,player_status,deletion_status,elapsed_ms,error,latest_login,login_ip) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                "args": [run_id, r.get("stt",""), r.get("account",""), r.get("status",""), r.get("uid",""), r.get("email",""), r.get("email_status",""), r.get("mobile",""), r.get("two_step",""), r.get("authenticator",""), r.get("session_key",""), r.get("name",""), r.get("level",""), r.get("player_status",""), r.get("deletion_status",""), r.get("elapsed_ms",""), r.get("error",""), r.get("latest_login",""), r.get("login_ip","")],
            })
        if stmts:
            _run(_batch(stmts))
        return run_id
    except Exception:
        return None


def list_runs(limit: int = 50) -> list[dict[str, Any]]:
    _load_config()
    if not _url:
        return []
    _ensure_tables()
    try:
        rows = _run(_execute_all(
            "SELECT id, created_at, total, met, not_met, required_level, elapsed_ms FROM batch_runs ORDER BY id DESC LIMIT ?",
            (limit,),
        ))
        return [
            {"id": r[0], "created_at": r[1], "total": r[2], "met": r[3], "not_met": r[4], "required_level": r[5], "elapsed_ms": r[6]}
            for r in rows
        ]
    except Exception:
        return []


def get_run_rows(run_id: int) -> list[dict[str, str]]:
    _load_config()
    if not _url:
        return []
    _ensure_tables()
    cols = ["stt","account","status","uid","email","email_status","mobile","two_step","authenticator","session_key","name","level","player_status","deletion_status","elapsed_ms","error","latest_login","login_ip"]
    try:
        rows = _run(_execute_all(
            "SELECT stt,account,status,uid,email,email_status,mobile,two_step,authenticator,session_key,name,level,player_status,deletion_status,elapsed_ms,error,latest_login,login_ip FROM batch_rows WHERE run_id=? ORDER BY id",
            (run_id,),
        ))
        return [{cols[i]: (row[i] or "") for i in range(len(cols))} for row in rows]
    except Exception:
        return []


def delete_run(run_id: int) -> bool:
    _load_config()
    if not _url:
        return False
    _ensure_tables()
    try:
        _run(_execute("DELETE FROM batch_rows WHERE run_id=?", (run_id,)))
        _run(_execute("DELETE FROM batch_runs WHERE id=?", (run_id,)))
        return True
    except Exception:
        return False


def delete_all_runs() -> bool:
    _load_config()
    if not _url:
        return False
    _ensure_tables()
    try:
        _run(_execute("DELETE FROM batch_rows"))
        _run(_execute("DELETE FROM batch_runs"))
        return True
    except Exception:
        return False


def is_available() -> bool:
    _load_config()
    return bool(_url)
