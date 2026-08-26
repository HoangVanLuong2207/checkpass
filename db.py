"""Turso/libSQL database module for check history."""

import json
import os
import time
from typing import Any

_conn: Any = None


def _get_conn() -> Any:
    global _conn
    if _conn is not None:
        return _conn
    url = os.environ.get("TURSO_URL", "").strip()
    token = os.environ.get("TURSO_TOKEN", "").strip()
    if not url:
        return None
    try:
        import libsql_experimental as libsql
        _conn = libsql.connect(url, auth_token=token or None)
        _init_tables(_conn)
        return _conn
    except Exception:
        return None


def _init_tables(conn: Any) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS batch_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at REAL NOT NULL,
            total INTEGER DEFAULT 0,
            met INTEGER DEFAULT 0,
            not_met INTEGER DEFAULT 0,
            required_level INTEGER DEFAULT 12,
            elapsed_ms INTEGER DEFAULT 0
        )
    """)
    conn.execute("""
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
    """)
    conn.commit()


def save_batch(rows: list[dict[str, str]], required_level: int = 12) -> int | None:
    conn = _get_conn()
    if conn is None:
        return None
    met = sum(1 for r in rows if _is_met(r, required_level))
    not_met = len(rows) - met
    elapsed = max((int(r.get("elapsed_ms", "0") or "0") for r in rows), default=0)
    cur = conn.execute(
        "INSERT INTO batch_runs (created_at, total, met, not_met, required_level, elapsed_ms) VALUES (?,?,?,?,?,?)",
        (time.time(), len(rows), met, not_met, required_level, elapsed),
    )
    run_id = cur.lastrowid
    for r in rows:
        conn.execute(
            "INSERT INTO batch_rows (run_id,stt,account,status,uid,email,email_status,mobile,two_step,authenticator,session_key,name,level,player_status,deletion_status,elapsed_ms,error,latest_login,login_ip) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (run_id, r.get("stt",""), r.get("account",""), r.get("status",""), r.get("uid",""), r.get("email",""), r.get("email_status",""), r.get("mobile",""), r.get("two_step",""), r.get("authenticator",""), r.get("session_key",""), r.get("name",""), r.get("level",""), r.get("player_status",""), r.get("deletion_status",""), r.get("elapsed_ms",""), r.get("error",""), r.get("latest_login",""), r.get("login_ip","")),
        )
    conn.commit()
    return run_id


def _is_met(row: dict[str, str], required_level: int) -> bool:
    lv = row.get("level", "").strip()
    if lv.isdigit():
        return int(lv) >= required_level
    return False


def list_runs(limit: int = 50) -> list[dict[str, Any]]:
    conn = _get_conn()
    if conn is None:
        return []
    cur = conn.execute(
        "SELECT id, created_at, total, met, not_met, required_level, elapsed_ms FROM batch_runs ORDER BY id DESC LIMIT ?",
        (limit,),
    )
    runs = []
    for row in cur.fetchall():
        runs.append({
            "id": row[0],
            "created_at": row[1],
            "total": row[2],
            "met": row[3],
            "not_met": row[4],
            "required_level": row[5],
            "elapsed_ms": row[6],
        })
    return runs


def get_run_rows(run_id: int) -> list[dict[str, str]]:
    conn = _get_conn()
    if conn is None:
        return []
    cur = conn.execute(
        "SELECT stt,account,status,uid,email,email_status,mobile,two_step,authenticator,session_key,name,level,player_status,deletion_status,elapsed_ms,error,latest_login,login_ip FROM batch_rows WHERE run_id=? ORDER BY id",
        (run_id,),
    )
    cols = ["stt","account","status","uid","email","email_status","mobile","two_step","authenticator","session_key","name","level","player_status","deletion_status","elapsed_ms","error","latest_login","login_ip"]
    return [{cols[i]: (row[i] or "") for i in range(len(cols))} for row in cur.fetchall()]


def delete_run(run_id: int) -> bool:
    conn = _get_conn()
    if conn is None:
        return False
    conn.execute("DELETE FROM batch_rows WHERE run_id=?", (run_id,))
    conn.execute("DELETE FROM batch_runs WHERE id=?", (run_id,))
    conn.commit()
    return True


def delete_all_runs() -> bool:
    conn = _get_conn()
    if conn is None:
        return False
    conn.execute("DELETE FROM batch_rows")
    conn.execute("DELETE FROM batch_runs")
    conn.commit()
    return True


def is_available() -> bool:
    return _get_conn() is not None
