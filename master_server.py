from __future__ import annotations

"""Tổng bộ (coordinator) - chỉ điều phối chứ KHÔNG tự check account.

Nhận acc (user|pass), chia thành các chunk <= 1000, cho vệ tinh claim,
nhận kết quả về và lưu. Máy này giữ RAM nhỏ bất kể số lượng acc vì nó
không chạy Garena check; dữ liệu nằm trong SQLite trên đĩa.
"""

import argparse
import csv
import io
import json
import os
import secrets
import sqlite3
import sys
import threading
import time
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

DEFAULT_CHUNK_LIMIT = 1000
MAX_CHUNK_LIMIT = 1000
DEFAULT_DB_PATH = Path(__file__).resolve().with_name("master.db")
DEFAULT_LEASE_MINUTES = 60
MAX_BODY = 16 * 1024 * 1024

_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    total INTEGER NOT NULL,
    chunk_size INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    finished_at REAL
);
CREATE TABLE IF NOT EXISTS chunks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL,
    idx INTEGER NOT NULL,
    account TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    satellite_id TEXT DEFAULT '',
    claimed_at REAL,
    lease_until REAL,
    reported_at REAL,
    UNIQUE(job_id, idx)
);
CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chunk_id INTEGER NOT NULL,
    job_id INTEGER NOT NULL,
    account TEXT NOT NULL,
    row_json TEXT NOT NULL,
    reported_at REAL NOT NULL,
    UNIQUE(chunk_id, account)
);
CREATE INDEX IF NOT EXISTS idx_chunks_claim ON chunks(status, lease_until);
CREATE INDEX IF NOT EXISTS idx_chunks_job ON chunks(job_id);
CREATE INDEX IF NOT EXISTS idx_results_chunk ON results(chunk_id);
CREATE INDEX IF NOT EXISTS idx_results_job ON results(job_id);
"""


def _now() -> float:
    return time.time()


class Store:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=10000")
        self._lock = threading.RLock()
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def _fetch(self, sql: str, args: tuple = ()) -> list[tuple]:
        with self._lock:
            cur = self._conn.execute(sql, args)
            return cur.fetchall()

    def _exec(self, sql: str, args: tuple = ()) -> int:
        with self._lock:
            cur = self._conn.execute(sql, args)
            self._conn.commit()
            return cur.lastrowid


@dataclass
class ParsedAccount:
    account: str
    password: str


def parse_accounts(text: str) -> list[ParsedAccount]:
    result: list[ParsedAccount] = []
    for line_number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "|" in line:
            parts = line.split("|")
            if len(parts) < 2:
                raise ValueError(f"Dòng {line_number}: cần định dạng user|pass, user|pass|mail hoặc user|pass|mail|passmail (hoặc user:pass)")
            account = parts[0].strip()
            password = parts[1].strip()
        elif line.count(":") == 1:
            account, password = line.split(":", 1)
            account = account.strip()
            password = password.strip()
        else:
            raise ValueError(f"Dòng {line_number}: cần định dạng user|pass, user|pass|mail hoặc user|pass|mail|passmail (hoặc user:pass)")
        if not account or not password or len(account) > 128 or len(password) > 1024:
            raise ValueError(f"Dòng {line_number}: tài khoản/mật khẩu không hợp lệ")
        result.append(ParsedAccount(account, password))
        if len(result) >= MAX_CHUNK_LIMIT * 10000:
            raise ValueError("Quá nhiều tài khoản trong một lần gửi")
    if not result:
        raise ValueError("Danh sách trống hoặc không có dòng hợp lệ")
    return result


def split_chunks(accounts: list[ParsedAccount], chunk_size: int) -> list[list[ParsedAccount]]:
    return [accounts[i : i + chunk_size] for i in range(0, len(accounts), chunk_size)]


_PAGE_HTML = """
<!doctype html>
<html lang="vi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Garena Check Tool</title>
<style>
:root{color-scheme:dark;font-family:'Segoe UI',system-ui,sans-serif}
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0e1117;color:#e6edf3;min-height:100vh;padding:18px}
.container{max-width:900px;margin:0 auto}
header{display:flex;align-items:center;gap:12px;margin-bottom:20px}
header h1{font-size:22px;color:#58a6ff}
header .badge{background:#238636;color:#fff;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:700}
.card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:20px;margin-bottom:16px}
.card h2{font-size:16px;margin-bottom:12px;color:#79c0ff}
textarea{width:100%;height:140px;background:#0d1117;color:#e6edf3;border:1px solid #30363d;border-radius:8px;padding:10px;font-family:monospace;font-size:13px;resize:vertical}
textarea:focus{border-color:#2f81f7;outline:none}
.row{display:flex;gap:12px;align-items:end;flex-wrap:wrap}
.field{flex:1;min-width:120px}
.field label{display:block;font-size:13px;color:#8b949e;margin-bottom:4px}
.field input,.field select{width:100%;padding:8px;background:#0d1117;color:#e6edf3;border:1px solid #30363d;border-radius:6px}
btn,button,.btn{padding:10px 20px;border:0;border-radius:8px;font-weight:700;cursor:pointer;font-size:14px}
.btn-primary{background:#238636;color:#fff}.btn-primary:hover{background:#2ea043}
.btn-primary:disabled{opacity:.5;cursor:wait}
.btn-sm{padding:6px 14px;font-size:12px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin:12px 0}
.stat{background:#0d1117;border-radius:8px;padding:12px;text-align:center}
.stat .num{font-size:28px;font-weight:800;color:#58a6ff}
.stat .lbl{font-size:11px;color:#8b949e;margin-top:2px}
.stat.ok .num{color:#56d364}
.stat.fail .num{color:#ff7b72}
.stat.pending .num{color:#d29922}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:10px}
th{text-align:left;padding:8px 6px;border-bottom:2px solid #30363d;color:#8b949e;font-size:11px;text-transform:uppercase}
td{padding:7px 6px;border-bottom:1px solid #21262d}
tr:hover{background:#1c2128}
.tag{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700}
.tag-ok{background:#23863633;color:#56d364}
.tag-fail{background:#da363333;color:#ff7b72}
.tag-run{background:#d2992233;color:#d29922}
.empty{color:#484f58;text-align:center;padding:30px}
#toast{position:fixed;bottom:20px;right:20px;background:#238636;color:#fff;padding:10px 18px;border-radius:8px;font-weight:600;display:none;z-index:99;box-shadow:0 4px 20px #0006}
.jobs-list{max-height:500px;overflow-y:auto}
</style>
</head>
<body>
<div class="container">
<header>
  <h1>🎮 Garena Check Tool</h1>
  <span class="badge">MASTER</span>
</header>

<div class="card">
  <h2>📋 Gửi danh sách tài khoản</h2>
  <textarea id="accInput" placeholder="Nhập tài khoản, mỗi dòng 1 acc&#10;Định dạng: user|pass  hoặc  user:pass&#10;&#10;Ví dụ:&#10;account1|password1&#10;account2|password2"></textarea>
  <div class="row" style="margin-top:12px">
    <div class="field"><label>Chunk size</label><input type="number" id="chunkSize" value="100" min="1" max="1000"></div>
    <div class="field"><label>&nbsp;</label><button class="btn btn-primary" id="btnSend" onclick="sendJob()">🚀 Gửi check</button></div>
  </div>
</div>

<div class="card">
  <h2>📊 Danh sách Jobs</h2>
  <div style="margin-bottom:10px"><button class="btn btn-sm btn-primary" onclick="loadJobs()">🔄 Refresh</button></div>
  <div id="jobsList" class="jobs-list"><div class="empty">Chưa có job nào</div></div>
</div>

<div class="card" id="detailCard" style="display:none">
  <h2>📝 Chi tiết Job #<span id="detailJobId"></span></h2>
  <div class="stats" id="detailStats"></div>
  <div style="margin:10px 0;display:flex;gap:8px">
    <button class="btn btn-sm btn-primary" onclick="refreshDetail()">🔄 Refresh</button>
    <button class="btn btn-sm btn-primary" onclick="exportCsv()" style="background:#1f6feb">📥 Export CSV</button>
  </div>
  <div id="detailRows"><div class="empty">Đang tải...</div></div>
</div>
</div>

<div id="toast"></div>

<script>
const TOKEN=localStorage.getItem('masterToken')||prompt('Nhập MASTER_TOKEN:','');
if(TOKEN)localStorage.setItem('masterToken',TOKEN);
const H={'Authorization':'Bearer '+TOKEN,'Content-Type':'application/json'};
let currentJobId=null;

function toast(msg,ms=3000){const t=document.getElementById('toast');t.textContent=msg;t.style.display='block';setTimeout(()=>t.style.display='none',ms)}

async function api(path,opt={}){const r=await fetch(path,{headers:H,...opt});return r.json()}

async function sendJob(){
  const text=document.getElementById('accInput').value.trim();
  if(!text){toast('Nhập danh sách tài khoản!');return}
  const btn=document.getElementById('btnSend');btn.disabled=true;btn.textContent='⏳ Đang gửi...';
  try{
    const chunk_size=parseInt(document.getElementById('chunkSize').value)||100;
    const d=await api('/api/jobs',{method:'POST',body:JSON.stringify({text,chunk_size})});
    if(d.ok){toast('✅ Tạo Job #'+d.job_id+' ('+d.total+' acc)');document.getElementById('accInput').value='';loadJobs();viewJob(d.job_id)}
    else toast('❌ '+d.error)
  }catch(e){toast('❌ Lỗi: '+e.message)}finally{btn.disabled=false;btn.textContent='🚀 Gửi check'}
}

async function loadJobs(){
  const el=document.getElementById('jobsList');
  try{
    const d=await api('/api/jobs_list');
    if(!d.ok||!d.jobs||d.jobs.length===0){el.innerHTML='<div class="empty">Chưa có job nào</div>';return}
    let h='<table><tr><th>ID</th><th>Tổng</th><th>Trạng thái</th><th>OK</th><th>Fail</th><th></th></tr>';
    d.jobs.forEach(j=>{
      const st=j.status==='done'?'<span class="tag tag-ok">Xong</span>':'<span class="tag tag-run">Đang chạy</span>';
      h+='<tr><td>#'+j.id+'</td><td>'+j.total+'</td><td>'+st+'</td><td style="color:#56d364">'+(j.ok||0)+'</td><td style="color:#ff7b72">'+(j.fail||0)+'</td>';
      h+='<td><button class="btn btn-sm btn-primary" onclick="viewJob('+j.id+')">Xem</button></td></tr>'
    });
    el.innerHTML=h+'</table>'
  }catch(e){el.innerHTML='<div class="empty">Lỗi: '+e.message+'</div>'}
}

async function viewJob(id){
  currentJobId=id;
  document.getElementById('detailCard').style.display='block';
  document.getElementById('detailJobId').textContent=id;
  refreshDetail();
}

async function refreshDetail(){
  if(!currentJobId)return;
  const id=currentJobId;
  try{
    const s=await api('/api/jobs/'+id);
    if(!s.ok){document.getElementById('detailStats').innerHTML='<div class="empty">'+s.error+'</div>';return}
    const c=s.chunks||{},r=s.results||{};
    document.getElementById('detailStats').innerHTML=
      '<div class="stat"><div class="num">'+s.total+'</div><div class="lbl">Tổng</div></div>'+
      '<div class="stat ok"><div class="num">'+(r.ok||0)+'</div><div class="lbl">OK</div></div>'+
      '<div class="stat fail"><div class="num">'+(r.fail||0)+'</div><div class="lbl">Fail</div></div>'+
      '<div class="stat pending"><div class="num">'+(c.pending||0)+'</div><div class="lbl">Chờ</div></div>'+
      '<div class="stat"><div class="num">'+(c.claimed||0)+'</div><div class="lbl">Đang check</div></div>';

    const rd=await api('/api/jobs/'+id+'/rows');
    if(!rd.ok||!rd.rows||rd.rows.length===0){document.getElementById('detailRows').innerHTML='<div class="empty">Chưa có kết quả</div>';return}
    let h='<table><tr><th>STT</th><th>Account</th><th>Status</th><th>UID</th><th>Tên</th><th>Level</th><th>Thời gian</th></tr>';
    rd.rows.forEach(r=>{
      const tag=r.status==='OK'?'tag-ok':'tag-fail';
      h+='<tr><td>'+r.stt+'</td><td><b>'+r.account+'</b></td><td><span class="tag '+tag+'">'+r.status+'</span></td>';
      h+='<td>'+r.uid+'</td><td>'+r.name+'</td><td>'+r.level+'</td><td>'+r.elapsed_ms+'ms</td></tr>'
    });
    document.getElementById('detailRows').innerHTML=h+'</table>';
    if(s.status!=='done')setTimeout(refreshDetail,5000)
  }catch(e){document.getElementById('detailRows').innerHTML='<div class="empty">Lỗi: '+e.message+'</div>'}
}

function exportCsv(){if(currentJobId)window.open('/api/jobs/'+currentJobId+'/export.csv?token='+TOKEN)}

loadJobs();setInterval(loadJobs,15000);
</script>
</body>
</html>
"""


class MasterHandler(BaseHTTPRequestHandler):
    server: "CoordinatorServer"

    def log_message(self, _format: str, *args: Any) -> None:
        return

    def _authorized(self) -> bool:
        token = self.server.master_token
        if not token:
            return True
        header = self.headers.get("Authorization", "")
        if header.startswith("Bearer "):
            return secrets.compare_digest(header[7:].strip(), token)
        # Hỗ trợ token qua query string cho export CSV
        if "?" in self.path:
            from urllib.parse import urlparse, parse_qs
            qs = parse_qs(urlparse(self.path).query)
            qt = qs.get("token", [""])[0]
            if qt and secrets.compare_digest(qt, token):
                return True
        return False

    def _security_headers(self, content_type: str) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Referrer-Policy", "no-referrer")

    def _json(self, status: HTTPStatus, value: Any) -> None:
        body = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self._security_headers("application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def _read_json(self) -> Any:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            raise ValueError("Kích thước request không hợp lệ")
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("JSON không hợp lệ") from exc

    def _html(self, html: str) -> None:
        body = html.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def _clean_path(self) -> str:
        """Return path without query string."""
        p = self.path
        if "?" in p:
            p = p.split("?", 1)[0]
        return p

    def do_GET(self) -> None:
        path = self._clean_path()
        if path == "/healthz":
            self._json(HTTPStatus.OK, {"ok": True, "role": "master", "now": _now()})
            return
        if path == "/" or path == "/index.html":
            self._html(_PAGE_HTML)
            return
        if not self._authorized():
            self._json(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": "token kh\u00f4ng h\u1ee3p l\u1ec7"})
            return
        if path == "/api/jobs_list":
            self._handle_jobs_list()
            return
        parts = path.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "api" and parts[1] == "jobs":
            job_id = self._int_or_none(parts[2])
            if job_id is None:
                self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "job_id không hợp lệ"})
                return
            self._handle_job_summary(job_id)
            return
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "jobs" and parts[3] == "rows":
            job_id = self._int_or_none(parts[2])
            if job_id is None:
                self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "job_id không hợp lệ"})
                return
            self._handle_job_rows(job_id)
            return
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "jobs" and parts[3] == "export.csv":
            job_id = self._int_or_none(parts[2])
            if job_id is None:
                self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "job_id không hợp lệ"})
                return
            self._handle_job_export(job_id)
            return
        self._json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Không tìm thấy"})

    @staticmethod
    def _int_or_none(value: str) -> int | None:
        try:
            number = int(value)
        except (TypeError, ValueError):
            return None
        return number

    def do_POST(self) -> None:
        if not self._authorized():
            self._json(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": "token không hợp lệ"})
            return
        if self.path == "/api/jobs":
            self._handle_create_job()
            return
        if self.path == "/api/claim":
            self._handle_claim()
            return
        if self.path == "/api/report":
            self._handle_report()
            return
        if self.path == "/api/chunk/release":
            self._handle_release()
            return
        self._json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Không tìm thấy"})

    # --- handlers -----------------------------------------------------

    def _handle_jobs_list(self) -> None:
        store = self.server.store
        with store._lock:
            jobs_raw = store._conn.execute(
                "SELECT id, created_at, total, chunk_size, status, finished_at FROM jobs ORDER BY id DESC LIMIT 50"
            ).fetchall()
            jobs = []
            for row in jobs_raw:
                job_id = row[0]
                results = store._conn.execute(
                    "SELECT COUNT(*), SUM(CASE WHEN json_extract(row_json,'$.status')='OK' THEN 1 ELSE 0 END) "
                    "FROM results WHERE job_id=?",
                    (job_id,),
                ).fetchone()
                results_count = results[0] or 0
                ok_count = results[1] or 0
                jobs.append({
                    "id": job_id,
                    "total": row[2],
                    "status": row[4],
                    "ok": ok_count,
                    "fail": results_count - ok_count,
                })
        self._json(HTTPStatus.OK, {"ok": True, "jobs": jobs})

    def _handle_create_job(self) -> None:
        try:
            body = self._read_json()
        except ValueError as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
            return
        accounts_raw = body.get("accounts")
        text = body.get("text")
        if isinstance(accounts_raw, list):
            joined = "\n".join(str(item) for item in accounts_raw if item is not None)
        elif isinstance(text, str):
            joined = text
        elif isinstance(accounts_raw, str):
            joined = accounts_raw
        else:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "cần 'accounts' hoặc 'text'"})
            return
        try:
            parsed = parse_accounts(joined)
        except ValueError as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
            return
        try:
            chunk_size = int(body.get("chunk_size", DEFAULT_CHUNK_LIMIT))
        except (TypeError, ValueError):
            chunk_size = DEFAULT_CHUNK_LIMIT
        chunk_size = max(1, min(chunk_size, MAX_CHUNK_LIMIT))

        store = self.server.store
        with store._lock:
            job_id = store._exec(
                "INSERT INTO jobs (created_at, total, chunk_size, status) VALUES (?,?,?,?)",
                (_now(), len(parsed), chunk_size, "open"),
            )
            chunks = split_chunks(parsed, chunk_size)
            for idx, chunk in enumerate(chunks):
                accounts_json = json.dumps(
                    [f"{acc.account}|{acc.password}" for acc in chunk],
                    ensure_ascii=False,
                )
                store._exec(
                    "INSERT INTO chunks (job_id, idx, account) VALUES (?,?,?)",
                    (job_id, idx, accounts_json),
                )
        self._json(HTTPStatus.OK, {
            "ok": True,
            "job_id": job_id,
            "total": len(parsed),
            "chunks": len(chunks),
            "chunk_size": chunk_size,
        })

    def _handle_claim(self) -> None:
        try:
            body = self._read_json()
        except ValueError as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
            return
        satellite_id = str(body.get("satellite_id") or "")
        if not satellite_id:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "cần satellite_id"})
            return
        try:
            lease_minutes = float(body.get("lease_minutes", DEFAULT_LEASE_MINUTES))
        except (TypeError, ValueError):
            lease_minutes = DEFAULT_LEASE_MINUTES
        if not 1 <= lease_minutes <= 60 * 8:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "lease_minutes không hợp lệ"})
            return
        # Số chunk muốn nhận cùng lúc (mặc định 1, tối đa 10)
        try:
            max_chunks = int(body.get("max_chunks", 1))
        except (TypeError, ValueError):
            max_chunks = 1
        max_chunks = max(1, min(max_chunks, 10))

        store = self.server.store
        now = _now()
        claims = []
        with store._lock:
            try:
                store._conn.execute("BEGIN IMMEDIATE")
                for _ in range(max_chunks):
                    row = store._conn.execute(
                        """
                        SELECT id, job_id, account FROM chunks
                        WHERE status='pending'
                           OR (status='claimed' AND lease_until IS NOT NULL AND lease_until < ?)
                        ORDER BY job_id, idx
                        LIMIT 1
                        """,
                        (now,),
                    ).fetchone()
                    if row is None:
                        break
                    chunk_id, job_id, account_data = row
                    # Atomic: đổi status ngay trong transaction
                    store._conn.execute(
                        "UPDATE chunks SET status='claimed', satellite_id=?, claimed_at=?, lease_until=? WHERE id=? AND (status='pending' OR (status='claimed' AND lease_until < ?))",
                        (satellite_id, now, now + lease_minutes * 60, chunk_id, now),
                    )
                    try:
                        accounts = json.loads(account_data)
                    except (json.JSONDecodeError, TypeError):
                        accounts = [account_data] if account_data else []
                    claims.append({
                        "chunk_id": chunk_id,
                        "job_id": job_id,
                        "lease_until": now + lease_minutes * 60,
                        "accounts": accounts,
                    })
                store._conn.commit()
            except Exception:
                store._conn.rollback()
                raise
            if not claims:
                self._check_finish_all_jobs(now)
        # Tương thích ngược: nếu chỉ claim 1 thì trả claim đơn
        if max_chunks == 1:
            self._json(HTTPStatus.OK, {"ok": True, "claim": claims[0] if claims else None})
        else:
            self._json(HTTPStatus.OK, {"ok": True, "claims": claims, "count": len(claims)})

    def _handle_report(self) -> None:
        try:
            body = self._read_json()
        except ValueError as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
            return
        try:
            chunk_id = int(body.get("chunk_id"))
        except (TypeError, ValueError):
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "cần chunk_id"})
            return
        rows = body.get("rows")
        if not isinstance(rows, list):
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "cần mảng rows"})
            return
        # done=true nghĩa là chunk đã check xong hoàn toàn
        is_done = bool(body.get("done", True))

        store = self.server.store
        now = _now()
        with store._lock:
            chunk = store._conn.execute(
                "SELECT job_id, status FROM chunks WHERE id=?", (chunk_id,)
            ).fetchone()
            if chunk is None:
                self._json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "chunk không tồn tại"})
                return
            job_id = chunk[0]
            try:
                store._conn.execute("BEGIN IMMEDIATE")
                for row in rows:
                    if not isinstance(row, dict):
                        continue
                    account = str(row.get("account", "") or "")
                    if not account:
                        continue
                    store._conn.execute(
                        """
                        INSERT INTO results (chunk_id, job_id, account, row_json, reported_at)
                        VALUES (?,?,?,?,?)
                        ON CONFLICT(chunk_id, account) DO UPDATE SET
                            row_json=excluded.row_json, reported_at=excluded.reported_at
                        """,
                        (chunk_id, job_id, account, json.dumps(row, ensure_ascii=False), now),
                    )
                if is_done:
                    store._conn.execute(
                        "UPDATE chunks SET status='done', reported_at=? WHERE id=?",
                        (now, chunk_id),
                    )
                store._conn.commit()
            except Exception:
                store._conn.rollback()
                raise
            if is_done:
                self._check_finish_all_jobs(now)
        self._json(HTTPStatus.OK, {"ok": True, "chunk_id": chunk_id, "rows": len(rows), "done": is_done})

    def _handle_release(self) -> None:
        try:
            body = self._read_json()
        except ValueError as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
            return
        try:
            chunk_id = int(body.get("chunk_id"))
        except (TypeError, ValueError):
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "cần chunk_id"})
            return
        satellite_id = str(body.get("satellite_id") or "")
        store = self.server.store
        with store._lock:
            store._conn.execute(
                """
                UPDATE chunks SET status='pending', satellite_id='', claimed_at=NULL, lease_until=NULL
                WHERE id=? AND status='claimed' AND (?='' OR satellite_id=?)
                """,
                (chunk_id, satellite_id, satellite_id),
            )
            store._conn.commit()
        self._json(HTTPStatus.OK, {"ok": True})

    def _check_finish_all_jobs(self, now: float) -> None:
        store = self.server.store
        open_jobs = [
            item[0]
            for item in store._conn.execute("SELECT id FROM jobs WHERE status='open'")
        ]
        for job_id in open_jobs:
            pending = store._conn.execute(
                "SELECT COUNT(*) FROM chunks WHERE job_id=? AND status!='done'", (job_id,)
            ).fetchone()[0]
            if pending == 0:
                store._conn.execute(
                    "UPDATE jobs SET status='done', finished_at=? WHERE id=?",
                    (now, job_id),
                )

    def _handle_job_summary(self, job_id: int) -> None:
        store = self.server.store
        with store._lock:
            job = store._conn.execute(
                "SELECT id, created_at, total, chunk_size, status, finished_at FROM jobs WHERE id=?",
                (job_id,),
            ).fetchone()
            if job is None:
                self._json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "job không tồn tại"})
                return
            pending = store._conn.execute(
                "SELECT COUNT(*) FROM chunks WHERE job_id=? AND status='pending'", (job_id,)
            ).fetchone()[0]
            claimed = store._conn.execute(
                "SELECT COUNT(*) FROM chunks WHERE job_id=? AND status='claimed'", (job_id,)
            ).fetchone()[0]
            done = store._conn.execute(
                "SELECT COUNT(*) FROM chunks WHERE job_id=? AND status='done'", (job_id,)
            ).fetchone()[0]
            results = store._conn.execute(
                "SELECT COUNT(*), SUM(CASE WHEN json_extract(row_json,'$.status')='OK' THEN 1 ELSE 0 END) "
                "FROM results WHERE job_id=?",
                (job_id,),
            ).fetchone()
            results_count = results[0] or 0
            ok_count = results[1] or 0
        self._json(HTTPStatus.OK, {
            "ok": True,
            "job_id": job_id,
            "created_at": job[1],
            "total": job[2],
            "chunk_size": job[3],
            "status": job[4],
            "finished_at": job[5],
            "chunks": {"pending": pending, "claimed": claimed, "done": done},
            "results": {"count": results_count, "ok": ok_count, "fail": results_count - ok_count},
        })

    def _handle_job_rows(self, job_id: int) -> None:
        store = self.server.store
        with store._lock:
            rows_raw = store._conn.execute(
                "SELECT row_json FROM results WHERE job_id=? ORDER BY id", (job_id,)
            ).fetchall()
        rows = [json.loads(item[0]) for item in rows_raw]
        self._json(HTTPStatus.OK, {"ok": True, "job_id": job_id, "rows": rows})

    def _handle_job_export(self, job_id: int) -> None:
        store = self.server.store
        with store._lock:
            rows_raw = store._conn.execute(
                "SELECT row_json FROM results WHERE job_id=? ORDER BY id", (job_id,)
            ).fetchall()
        rows = [json.loads(item[0]) for item in rows_raw]
        columns: list[str] = []
        for row in rows:
            for key in row:
                if key not in columns:
                    columns.append(key)
        if not columns:
            columns = ["account", "status"]
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
        body = buffer.getvalue()
        data = body.encode("utf-8-sig")
        self.send_response(HTTPStatus.OK)
        self._security_headers("text/csv; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="job_{job_id}.csv"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass


class CoordinatorServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], handler: type[BaseHTTPRequestHandler], store: Store, master_token: str) -> None:
        super().__init__(address, handler)
        self.store = store
        self.master_token = master_token


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Tổng bộ điều phối check acc; không tự check")
    parser.add_argument("--port", type=int, default=None, help="Port HTTP (env PORT)")
    parser.add_argument("--host", type=str, default=None, help="Host bind (env HOST, mặc định 0.0.0.0)")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB_PATH, help="File SQLite (env MASTER_DB)")
    parser.add_argument("--token", type=str, default=None, help="Token bí mật (env MASTER_TOKEN)")
    parser.add_argument("--self-test", action="store_true", help="Không mở server, chỉ kiểm tra")
    return parser.parse_args()


def configure_console_encoding() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="replace")


def main() -> int:
    configure_console_encoding()
    args = parse_args()
    host = (args.host or os.environ.get("HOST", "") or "0.0.0.0").strip() or "0.0.0.0"
    port = args.port or int(os.environ.get("PORT", "8761") or "8761")
    db_path = Path(args.db or os.environ.get("MASTER_DB", "") or DEFAULT_DB_PATH)
    token = args.token or os.environ.get("MASTER_TOKEN", "").strip()

    if args.self_test:
        accs = parse_accounts("a|1\nb:2\n# comment\nc|3")
        chunks = split_chunks(accs, 2)
        assert len(accs) == 3
        assert [len(c) for c in chunks] == [2, 1]
        dup = parse_accounts("a|1\na:2")
        assert len(dup) == 2
        print("SELF-TEST OK: master parse/split."); return 0

    store = Store(db_path)
    server = CoordinatorServer((host, port), MasterHandler, store, token)
    print(f"[master] Tổng bộ: http://{host}:{port}  role=coordinator  db={db_path}")
    if not token:
        print("[master] CẢNH BÁO: chưa đặt MASTER_TOKEN - các vệ tinh đều truy cập được. Hãy đặt trên Render.")
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\n[master] Đã dừng.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
