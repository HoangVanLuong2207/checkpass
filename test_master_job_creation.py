from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from master_server import (
    CoordinatorServer,
    LocalStore,
    MasterHandler,
    _prune_completed_jobs_before_today,
    _today_start_timestamp,
)


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


class _CountingStore:
    """Record read calls while delegating storage to LocalStore."""

    def __init__(self, inner: LocalStore) -> None:
        self.inner = inner
        self.read_calls = 0

    def __getattr__(self, name: str):
        return getattr(self.inner, name)

    def fetch(self, sql: str, args: tuple = ()) -> list[tuple]:
        self.read_calls += 1
        return self.inner.fetch(sql, args)

    def fetchone(self, sql: str, args: tuple = ()) -> tuple | None:
        self.read_calls += 1
        return self.inner.fetchone(sql, args)


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

    def post(self, path: str, body: dict, token: str = "secret") -> tuple[int, dict]:
        request = urllib.request.Request(
            self.base_url + path,
            data=json.dumps(body).encode("utf-8"),
            method="POST",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read().decode("utf-8"))

    def post_error(self, path: str, body: dict, token: str = "secret") -> tuple[int, dict]:
        try:
            return self.post(path, body, token)
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read().decode("utf-8"))
            finally:
                exc.close()

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

    def test_jobs_list_uses_constant_number_of_database_reads(self) -> None:
        for index in range(12):
            job_id = self.inner.exec(
                "INSERT INTO jobs (created_at, total, chunk_size, status, owner_hash, owner_preview) VALUES (?,?,?,?,?,?)",
                (index, 1, 15, "done", "owner-a", "key-a"),
            )
            self.inner.exec(
                "INSERT INTO results (chunk_id, job_id, account, row_json, reported_at) VALUES (?,?,?,?,?)",
                (1000 + index, job_id, f"account-{index}", '{"status":"OK"}', index),
            )

        counting_store = _CountingStore(self.inner)
        handler = object.__new__(MasterHandler)
        handler.server = type("Server", (), {"store": counting_store})()
        captured: dict = {}
        handler._json = lambda status, payload: captured.update(status=status, payload=payload)

        handler._handle_jobs_list({"owner_hash": "owner-a", "is_admin": False})

        self.assertEqual(captured["status"], 200)
        self.assertEqual(len(captured["payload"]["jobs"]), 12)
        self.assertTrue(all(job["processed"] == 1 for job in captured["payload"]["jobs"]))
        self.assertEqual(counting_store.read_calls, 3)

    def test_job_summary_uses_one_database_read(self) -> None:
        job_id = self.inner.exec(
            "INSERT INTO jobs (created_at, total, chunk_size, status, owner_hash, owner_preview) VALUES (?,?,?,?,?,?)",
            (1, 3, 15, "open", "owner-a", "key-a"),
        )
        chunk_ids = [
            self.inner.exec(
                "INSERT INTO chunks (job_id, idx, account, status) VALUES (?,?,?,?)",
                (job_id, index, "[]", status),
            )
            for index, status in enumerate(("pending", "claimed", "done"))
        ]
        self.inner.exec(
            "INSERT INTO results (chunk_id, job_id, account, row_json, reported_at) VALUES (?,?,?,?,?)",
            (chunk_ids[-1], job_id, "account-ok", '{"status":"OK"}', 2),
        )

        counting_store = _CountingStore(self.inner)
        handler = object.__new__(MasterHandler)
        handler.server = type("Server", (), {"store": counting_store})()
        captured: dict = {}
        handler._json = lambda status, payload: captured.update(status=status, payload=payload)

        handler._handle_job_summary(job_id, {"owner_hash": "owner-a", "is_admin": False})

        self.assertEqual(captured["status"], 200)
        self.assertEqual(captured["payload"]["chunks"], {"pending": 1, "claimed": 1, "done": 1})
        self.assertEqual(captured["payload"]["results"]["count"], 1)
        self.assertEqual(counting_store.read_calls, 1)

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

    def test_admin_can_save_and_read_running_job_limit(self) -> None:
        handler = object.__new__(MasterHandler)
        handler.server = self.server
        captured: list[tuple[int, dict]] = []
        handler._read_json = lambda: {"max_running_jobs": 3}
        handler._json = lambda status, payload: captured.append((status, payload))

        handler._handle_admin_settings_save()
        self.assertEqual(captured[-1][0], 200)
        handler._handle_admin_settings_get()

        settings = captured[-1][1]
        self.assertEqual(settings["max_running_jobs"], 3)
        self.assertEqual(settings["running_jobs"], 0)
        self.assertEqual(settings["available_job_slots"], 3)

    def test_admin_can_save_and_read_account_limit_per_job(self) -> None:
        handler = object.__new__(MasterHandler)
        handler.server = self.server
        captured: list[tuple[int, dict]] = []
        handler._read_json = lambda: {"max_accounts_per_job": 2500}
        handler._json = lambda status, payload: captured.append((status, payload))

        handler._handle_admin_settings_save()
        self.assertEqual(captured[-1][0], 200)
        handler._handle_admin_settings_get()

        self.assertEqual(captured[-1][1]["max_accounts_per_job"], 2500)

    def test_account_limit_rejects_regular_key_but_not_admin_key(self) -> None:
        self.store.block_once = False
        self.inner.exec(
            "INSERT INTO app_settings (setting_key, setting_value) VALUES (?,?)",
            ("max_accounts_per_job", "1"),
        )
        text = "user1|pass1\nuser2|pass2"

        status, rejected = self.post_error("/api/jobs", {"text": text}, token="regular-key")
        self.assertEqual(status, 413)
        self.assertEqual(rejected["code"], "ACCOUNT_LIMIT_REACHED")
        self.assertEqual(rejected["submitted_accounts"], 2)
        self.assertEqual(rejected["max_accounts_per_job"], 1)
        self.assertEqual(self.inner.fetchone("SELECT COUNT(*) FROM jobs")[0], 0)

        status, created = self.post("/api/jobs", {"text": text}, token="secret")
        self.assertEqual(status, 200)
        self.assertEqual(created["total"], 2)

    def test_each_regular_key_can_only_have_one_running_job(self) -> None:
        self.store.block_once = False

        status, first = self.post("/api/jobs", {"text": "user1|pass1"}, token="key-a")
        self.assertEqual(status, 200)

        status, rejected = self.post_error("/api/jobs", {"text": "user2|pass2"}, token="key-a")
        self.assertEqual(status, 409)
        self.assertEqual(rejected["code"], "KEY_RUNNING_JOB_LIMIT_REACHED")
        self.assertEqual(rejected["active_job_id"], first["job_id"])

        status, other_key_job = self.post("/api/jobs", {"text": "user3|pass3"}, token="key-b")
        self.assertEqual(status, 200)
        self.assertNotEqual(other_key_job["job_id"], first["job_id"])

    def test_admin_key_is_exempt_from_running_job_limit_per_key(self) -> None:
        self.store.block_once = False

        status, first = self.post("/api/jobs", {"text": "admin1|pass1"})
        self.assertEqual(status, 200)

        status, second = self.post("/api/jobs", {"text": "admin2|pass2"})
        self.assertEqual(status, 200)
        self.assertNotEqual(second["job_id"], first["job_id"])

    def test_retention_keeps_old_running_job_until_it_finishes(self) -> None:
        cutoff = _today_start_timestamp()

        def add_job(created_at: float, status: str, account: str, chunk_status: str) -> tuple[int, int]:
            job_id = self.inner.exec(
                "INSERT INTO jobs (created_at, total, chunk_size, status, finished_at) VALUES (?,?,?,?,?)",
                (created_at, 1, 15, status, created_at if status == "done" else None),
            )
            chunk_id = self.inner.exec(
                "INSERT INTO chunks (job_id, idx, account, status) VALUES (?,?,?,?)",
                (job_id, 0, json.dumps([f"{account}|pass"]), chunk_status),
            )
            self.inner.exec(
                "INSERT INTO results (chunk_id, job_id, account, row_json, reported_at) VALUES (?,?,?,?,?)",
                (chunk_id, job_id, account, '{}', created_at),
            )
            return job_id, chunk_id

        old_done, _ = add_job(cutoff - 7200, "done", "old-done", "done")
        old_running, old_running_chunk = add_job(cutoff - 3600, "open", "old-running", "pending")
        today_done, _ = add_job(cutoff + 60, "done", "today-done", "done")

        deleted = _prune_completed_jobs_before_today(self.inner, cutoff)
        self.assertEqual(deleted, {"jobs": 1, "chunks": 1, "results": 1})
        self.assertIsNone(self.inner.fetchone("SELECT id FROM jobs WHERE id=?", (old_done,)))
        self.assertEqual(self.inner.fetchone("SELECT status FROM jobs WHERE id=?", (old_running,))[0], "open")
        self.assertIsNotNone(self.inner.fetchone("SELECT id FROM jobs WHERE id=?", (today_done,)))

        self.inner.exec("UPDATE chunks SET status='done' WHERE id=?", (old_running_chunk,))
        handler = object.__new__(MasterHandler)
        handler.server = self.server
        handler._check_finish_all_jobs(cutoff + 120)

        self.assertIsNone(self.inner.fetchone("SELECT id FROM jobs WHERE id=?", (old_running,)))
        self.assertIsNotNone(self.inner.fetchone("SELECT id FROM jobs WHERE id=?", (today_done,)))

    def test_rejects_new_job_at_limit_and_accepts_after_a_job_stops(self) -> None:
        # This test exercises normal creation; the blocking wrapper is only needed
        # by the separate race test above.
        self.store.block_once = False
        self.inner.exec(
            "INSERT INTO app_settings (setting_key, setting_value) VALUES (?,?)",
            ("max_running_jobs", "1"),
        )

        status, first = self.post("/api/jobs", {"text": "user1|pass1"}, token="key-a")
        self.assertEqual(status, 200)

        status, rejected = self.post_error("/api/jobs", {"text": "user2|pass2"}, token="key-b")
        self.assertEqual(status, 429)
        self.assertEqual(rejected["code"], "JOB_LIMIT_REACHED")
        self.assertEqual(rejected["running_jobs"], 1)
        self.assertEqual(rejected["max_running_jobs"], 1)
        self.assertEqual(self.inner.fetchone("SELECT COUNT(*) FROM jobs")[0], 1)

        status, stopped = self.post(f"/api/jobs/{first['job_id']}/stop", {})
        self.assertEqual(status, 200)
        self.assertEqual(stopped["status"], "done")

        status, second = self.post("/api/jobs", {"text": "user2|pass2"}, token="key-b")
        self.assertEqual(status, 200)
        self.assertNotEqual(second["job_id"], first["job_id"])


if __name__ == "__main__":
    unittest.main()
