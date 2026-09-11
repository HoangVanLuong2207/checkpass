from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path

from master_server import CoordinatorServer, LocalStore, MasterHandler


class _BlockingCreateStore:
    """Pause the create batch after the job row exists but before chunks exist."""

    def __init__(self, inner: LocalStore) -> None:
        self.inner = inner
        self.batch_entered = threading.Event()
        self.release_batch = threading.Event()
        self.block_once = True

    def __getattr__(self, name: str):
        return getattr(self.inner, name)

    def batch(self, statements: list) -> None:
        opens_job = any(
            isinstance(statement, dict)
            and "UPDATE jobs SET status='open'" in statement.get("sql", "")
            for statement in statements
        )
        if opens_job and self.block_once:
            self.block_once = False
            self.batch_entered.set()
            if not self.release_batch.wait(5):
                raise TimeoutError("test did not release create batch")
        self.inner.batch(statements)


class JobCreationRaceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.inner = LocalStore(Path(self.temp_dir.name) / "master-test.db")
        self.store = _BlockingCreateStore(self.inner)
        self.server = CoordinatorServer(("127.0.0.1", 0), MasterHandler, self.store, "secret")
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.store.release_batch.set()
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join(5)
        self.inner._conn.close()
        self.temp_dir.cleanup()

    def post(self, path: str, body: dict) -> tuple[int, dict]:
        request = urllib.request.Request(
            self.base_url + path,
            data=json.dumps(body).encode("utf-8"),
            method="POST",
            headers={"Authorization": "Bearer secret", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read().decode("utf-8"))

    def test_claim_cannot_finish_job_before_chunks_are_saved(self) -> None:
        created: dict = {}

        def create_job() -> None:
            try:
                text = "\n".join(f"user{index}|pass{index}" for index in range(31))
                created["response"] = self.post("/api/jobs", {"text": text})
            except Exception as exc:  # pragma: no cover - surfaced by assertion below
                created["error"] = exc

        create_thread = threading.Thread(target=create_job)
        create_thread.start()
        self.assertTrue(self.store.batch_entered.wait(5))

        job = self.inner.fetchone("SELECT id, status FROM jobs ORDER BY id DESC LIMIT 1")
        self.assertIsNotNone(job)
        self.assertEqual(job[1], "creating")

        status, claim = self.post("/api/claim", {"satellite_id": "race-satellite"})
        self.assertEqual(status, 200)
        self.assertIsNone(claim["claim"])
        self.assertEqual(
            self.inner.fetchone("SELECT status FROM jobs WHERE id=?", (job[0],))[0],
            "creating",
        )

        self.store.release_batch.set()
        create_thread.join(10)
        self.assertFalse(create_thread.is_alive())
        self.assertNotIn("error", created)
        self.assertEqual(created["response"][0], 200)

        job_id = created["response"][1]["job_id"]
        self.assertEqual(self.inner.fetchone("SELECT status FROM jobs WHERE id=?", (job_id,))[0], "open")
        self.assertEqual(self.inner.fetchone("SELECT COUNT(*) FROM chunks WHERE job_id=?", (job_id,))[0], 3)

        status, claim = self.post("/api/claim", {"satellite_id": "race-satellite"})
        self.assertEqual(status, 200)
        self.assertEqual(claim["claim"]["job_id"], job_id)

    def test_open_job_without_chunks_is_not_completed(self) -> None:
        orphan_id = self.inner.exec(
            "INSERT INTO jobs (created_at, total, chunk_size, status) VALUES (?,?,?,?)",
            (1, 1, 15, "open"),
        )
        handler = object.__new__(MasterHandler)
        handler.server = self.server
        handler._check_finish_all_jobs(2)
        self.assertEqual(
            self.inner.fetchone("SELECT status FROM jobs WHERE id=?", (orphan_id,))[0],
            "open",
        )

    def test_regular_key_gets_global_overview_but_only_its_job_list(self) -> None:
        owner_a_job = self.inner.exec(
            "INSERT INTO jobs (created_at, total, chunk_size, status, owner_hash, owner_preview) VALUES (?,?,?,?,?,?)",
            (1, 100, 15, "open", "owner-a", "key-a"),
        )
        owner_b_job = self.inner.exec(
            "INSERT INTO jobs (created_at, total, chunk_size, status, owner_hash, owner_preview) VALUES (?,?,?,?,?,?)",
            (2, 250, 15, "done", "owner-b", "key-b"),
        )
        self.inner.exec(
            "INSERT INTO results (chunk_id, job_id, account, row_json, reported_at) VALUES (?,?,?,?,?)",
            (101, owner_a_job, "account-a", '{"status":"OK"}', 3),
        )
        self.inner.exec(
            "INSERT INTO results (chunk_id, job_id, account, row_json, reported_at) VALUES (?,?,?,?,?)",
            (202, owner_b_job, "account-b", '{"status":"FAIL"}', 3),
        )
        handler = object.__new__(MasterHandler)
        handler.server = self.server
        captured: dict = {}

        def capture_json(status: int, payload: dict) -> None:
            captured["status"] = status
            captured["payload"] = payload

        handler._json = capture_json
        handler._handle_jobs_list({"owner_hash": "owner-a", "is_admin": False})

        self.assertEqual(captured["status"], 200)
        self.assertEqual([job["owner_preview"] for job in captured["payload"]["jobs"]], ["key-a"])
        self.assertEqual(captured["payload"]["overview"], {
            "total_jobs": 2,
            "running_jobs": 1,
            "done_jobs": 1,
            "total_accounts": 350,
            "processed_accounts": 2,
        })

    def test_notice_html_and_css_can_be_saved(self) -> None:
        handler = object.__new__(MasterHandler)
        handler.server = self.server
        captured: list[tuple[int, dict]] = []
        notice_html = '<div class="notice-title">Bảo trì</div><div>Thông báo mới</div>'
        notice_css = '#noticeBox { background: #fff; }'
        handler._read_json = lambda: {
            "notice": {"enabled": True, "html": notice_html, "css": notice_css},
        }
        handler._json = lambda status, payload: captured.append((status, payload))

        handler._handle_admin_settings_save()
        self.assertEqual(captured[-1][0], 200)
        handler._handle_admin_settings_get()

        returned = captured[-1][1]["notice"]
        self.assertEqual(returned["html"], notice_html)
        self.assertEqual(returned["css"], notice_css)
        self.assertTrue(returned["enabled"])


if __name__ == "__main__":
    unittest.main()
