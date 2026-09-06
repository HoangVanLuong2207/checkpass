"""Copy master jobs, chunks and results from SQLite into PostgreSQL."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from master_server import LocalStore, PostgreSQLStore


TABLES = {
    "jobs": "id, created_at, total, chunk_size, status, finished_at, owner_hash, owner_preview",
    "chunks": "id, job_id, idx, account, status, satellite_id, claimed_at, lease_until, reported_at",
    "results": "id, chunk_id, job_id, account, row_json, reported_at",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Chuyển dữ liệu master SQLite sang PostgreSQL")
    parser.add_argument("--sqlite", type=Path, default=Path("master.db"), help="Đường dẫn master.db nguồn")
    parser.add_argument("--database-url", required=True, help="PostgreSQL DATABASE_URL đích")
    parser.add_argument("--replace", action="store_true", help="Xóa dữ liệu hiện có ở PostgreSQL trước khi copy")
    return parser.parse_args()


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="replace")
    args = parse_args()
    if not args.sqlite.is_file():
        raise SystemExit(f"Không tìm thấy SQLite source: {args.sqlite}")

    source = LocalStore(args.sqlite)
    target = PostgreSQLStore(args.database_url)
    existing = sum(int((target.fetchone(f"SELECT COUNT(*) FROM {table}") or [0])[0]) for table in TABLES)
    if existing and not args.replace:
        raise SystemExit("PostgreSQL đích đã có dữ liệu. Thêm --replace nếu muốn xóa và chép lại.")
    if args.replace:
        target.batch([
            {"sql": "DELETE FROM results"},
            {"sql": "DELETE FROM chunks"},
            {"sql": "DELETE FROM jobs"},
        ])

    for table, columns in TABLES.items():
        rows = source.fetch(f"SELECT {columns} FROM {table} ORDER BY id")
        field_count = len(columns.split(", "))
        placeholders = ",".join("?" for _ in range(field_count))
        statements = [
            {"sql": f"INSERT INTO {table} ({columns}) VALUES ({placeholders})", "args": row}
            for row in rows
        ]
        for offset in range(0, len(statements), 500):
            target.batch(statements[offset:offset + 500])
        print(f"{table}: {len(rows)} rows", flush=True)

    for table in TABLES:
        target.exec(
            f"SELECT setval(pg_get_serial_sequence('{table}', 'id'), COALESCE(MAX(id), 1), MAX(id) IS NOT NULL) FROM {table}"
        )
    print("Hoàn tất chuyển dữ liệu sang PostgreSQL.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
