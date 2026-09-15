from __future__ import annotations

import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from satellite_keepawake import keepawake_loop, parse_satellite_targets


class _Store:
    def __init__(self) -> None:
        self.value = ""
        self.lock = threading.Lock()

    def fetchone(self, _sql: str, _args: tuple) -> tuple[str]:
        with self.lock:
            return (self.value,)


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.server.paths.append(self.path)
        self.send_response(200)
        self.end_headers()

    def log_message(self, _format: str, *_args: object) -> None:
        pass


class SatelliteKeepawakeTest(unittest.TestCase):
    def test_saved_list_changes_are_used_on_next_round(self) -> None:
        servers = []
        threads = []
        store = _Store()
        stop = threading.Event()
        loop_thread = None
        try:
            for _ in range(2):
                server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
                server.paths = []
                servers.append(server)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                threads.append(thread)
            with store.lock:
                store.value = f"[first] http://127.0.0.1:{servers[0].server_port}\n"
            loop_thread = threading.Thread(
                target=keepawake_loop, args=(store, stop), kwargs={"interval": 0.1}, daemon=True
            )
            loop_thread.start()
            deadline = time.monotonic() + 3
            while not servers[0].paths and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertIn("/healthz", servers[0].paths)

            with store.lock:
                store.value = f"[second] http://127.0.0.1:{servers[1].server_port}\n"
            deadline = time.monotonic() + 3
            while not servers[1].paths and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertIn("/healthz", servers[1].paths)
        finally:
            stop.set()
            if loop_thread:
                loop_thread.join(2)
            for server in servers:
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join(2)

    def test_duplicate_urls_are_only_called_once_per_round(self) -> None:
        targets = parse_satellite_targets(
            "[one] https://example.onrender.com/\nhttps://EXAMPLE.onrender.com\n"
        )
        self.assertEqual(len(targets), 1)


if __name__ == "__main__":
    unittest.main()
