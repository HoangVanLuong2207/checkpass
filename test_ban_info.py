from __future__ import annotations

import io
import json
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import garena_api_test_chrome1 as api
from openpyxl import load_workbook


def test_player_ban_fields_formats_vietnam_time() -> None:
    player = {
        "banInfo": {
            "banTime": 1789461980,
            "reason": "",
            "unbanTime": 1884099599,
        }
    }

    assert api.player_ban_fields(player) == {
        "banTime": "15/09/2026 15:46:20 GMT+7",
        "unbanTime": "14/09/2029 23:59:59 GMT+7",
    }


def test_player_ban_fields_are_empty_for_non_banned_player() -> None:
    expected = {"banTime": "", "unbanTime": ""}

    assert api.player_ban_fields({"name": "Normal"}) == expected
    assert api.player_ban_fields({"banInfo": {}}) == expected


def test_public_batch_row_omits_ban_fields_for_non_banned_player() -> None:
    public = api.public_batch_row({
        "account": "normal",
        "player_status": "Bình thường",
        **api.player_ban_fields({"name": "Normal"}),
    })

    assert not set(api.BATCH_BAN_FIELDNAMES).intersection(public)


def test_public_batch_row_keeps_ban_fields_for_satellite_report() -> None:
    row = {
        "account": "sample",
        "player_status": "Bị khóa",
        **api.player_ban_fields({
            "banInfo": {"banTime": 1789461980, "unbanTime": 1884099599}
        }),
    }

    public = api.public_batch_row(row)

    assert public["banTime"] == "15/09/2026 15:46:20 GMT+7"
    assert public["unbanTime"] == "14/09/2029 23:59:59 GMT+7"


def test_batch_check_extracts_ban_info_from_player_api(monkeypatch) -> None:
    class Credential:
        index = 1
        account = "sample"
        password = "secret"

    class Gate:
        @staticmethod
        def wait(_stop_event) -> bool:
            return True

    result = {
        "tcp": {"ok": True, "uid": 123},
        "apis": {
            "kientuong_player": {
                "ok": True,
                "body": {
                    "player": {
                        "name": "mMmu15003",
                        "level": 12,
                        "banInfo": {
                            "banTime": 1789461980,
                            "unbanTime": 1884099599,
                        },
                    },
                    "playerStatus": "NO_DELETION_REQUEST",
                },
            }
        },
        "web_auth": {},
        "tcp_to_web_probe": {},
    }
    monkeypatch.setattr(api, "run_api_tests", lambda *_args, **_kwargs: result)

    row = api.batch_check_one(Credential(), object(), 8, Gate(), threading.Event())

    assert row["status"] == "OK"
    assert row["player_status"] == "Bị khóa"
    assert row["banTime"] == "15/09/2026 15:46:20 GMT+7"
    assert row["unbanTime"] == "14/09/2029 23:59:59 GMT+7"


def test_master_xlsx_adds_ban_columns_only_to_locked_sheet() -> None:
    from master_server import MasterHandler

    normal = {
        "stt": "1", "account": "normal", "status": "OK", "level": "12",
        "player_status": "Bình thường",
    }
    locked = {
        "stt": "2", "account": "locked", "status": "OK", "level": "12",
        "player_status": "Bị khóa",
        "banTime": "15/09/2026 15:46:20 GMT+7",
        "unbanTime": "14/09/2029 23:59:59 GMT+7",
    }
    handler = object.__new__(MasterHandler)
    handler.path = "/api/jobs/1/export.xlsx?min_level=12"
    handler.wfile = io.BytesIO()
    handler.send_response = Mock()
    handler.send_header = Mock()
    handler.end_headers = Mock()
    handler._json = Mock()
    handler._check_job_access = Mock(return_value=(True, {"id": 1}))
    store = Mock()
    store.fetch.side_effect = [
        [(1, json.dumps(normal)), (1, json.dumps(locked))],
        [],
    ]
    handler.server = SimpleNamespace(store=store)

    handler._handle_job_export_xlsx(1, {})

    workbook = load_workbook(io.BytesIO(handler.wfile.getvalue()))
    normal_headers = [cell.value for cell in workbook["Đạt từ LV 12"][1]]
    locked_headers = [cell.value for cell in workbook["Bị khóa"][1]]
    assert "Thời gian ban" not in normal_headers
    assert "Thời gian mở ban" not in normal_headers
    assert locked_headers[-2:] == ["Thời gian ban", "Thời gian mở ban"]
