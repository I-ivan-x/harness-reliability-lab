"""Real MCP races exercise one bound write slot and separate process/DB grants."""

import asyncio
import json
import sqlite3
import time

import pytest
from mcp.shared.exceptions import McpError
from mcp.types import CancelledNotification, CancelledNotificationParams, ClientNotification

from harness_lab.mcp_port import MCPToolPort
from harness_lab.storage import initialize_environment


def prepare(directory, run_id="run-race", *, delay_s=0.6):
    directory.mkdir(parents=True)
    database = directory / "environment.sqlite"
    initialize_environment(database, {
        "target_ref": "change-X", "revision": 1, "queue_options": ["ops"],
        "write_policy": "allow", "facts": {},
    })
    config = {
        "db_path": str(database), "run_id": run_id, "principal": "operator",
        "operation_id": f"{run_id}:write-0", "idempotency_key": f"{run_id}:write-0",
        "target_ref": "change-X", "can_read": True, "can_write": True,
    }
    if delay_s:
        config["fault"] = {"kind": "pre_commit_delay", "attempts": [1], "delay_s": delay_s}
    path = directory / "server.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    events = []

    def trace(event, data):
        events.append((event, data))
        with (directory / "wire.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"event": event, "data": data}) + "\n")

    port = MCPToolPort(path, directory / "stderr.log", trace)
    return port, database, config, events


def arguments(config, attempt=1, **changes):
    return {
        "target_ref": "change-X", "expected_revision": 1, "queue": "ops", "priority": "normal",
        "envelope": {key: config[key] for key in (
            "run_id", "principal", "operation_id", "idempotency_key"
        )} | {"attempt": attempt, "stage": "write-0"}, **changes,
    }


def effects(database):
    with sqlite3.connect(database) as connection:
        tickets = connection.execute("SELECT run_id, params_json FROM tickets").fetchall()
        receipts = connection.execute("SELECT payload_json FROM receipts").fetchall()
    return tickets, [json.loads(row[0]) for row in receipts]


async def fault_event(port, name="pre_commit_delay_entered"):
    # The fault records this after authorize + inflight registration, before the
    # actual pre-transaction await. A sent client request alone cannot prove that.
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        text = port.stderr_path.read_text(encoding="utf-8")
        for line in text.splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("event") == name:
                assert entry["attempt"] == 1
                return
        await asyncio.sleep(0.005)
    pytest.fail(f"the real MCP server did not reach fault barrier {name}")


def payload(reply):
    return reply["structuredContent"]


@pytest.mark.parametrize("different", [False, True], ids=["same-parameters", "conflict"])
def test_same_session_competing_writes_have_one_immutable_effect(tmp_path, different):
    port, database, config, events = prepare(tmp_path / "race")

    async def check():
        async with port:
            first = asyncio.create_task(port.call("create_ticket", arguments(config), 3))
            await fault_event(port)
            assert not first.done() and effects(database) == ([], [])
            second = await port.call("create_ticket", arguments(
                config, attempt=2, priority="urgent" if different else "normal",
            ), 3)
            assert not first.done(), "the two real server requests must overlap"
            replies = [payload(await first), payload(second)]
            successful = [reply["receipt"] for reply in replies if reply["ok"]]
            failed = [reply["error"] for reply in replies if not reply["ok"]]
            if different:
                assert len(successful) == len(failed) == 1
                assert failed[0]["code"] == "IDEMPOTENCY_CONFLICT"
                assert not any(failed[0][flag] for flag in (
                    "repairable", "not_executed", "unbound"
                ))
            else:
                assert len(successful) == 2 and successful[0] == successful[1]
            tickets, receipts = effects(database)
            assert len(tickets) == len(receipts) == 1
            assert all(receipt == receipts[0] for receipt in successful)
            assert json.loads(tickets[0][1]) == receipts[0]["params"]
        requests = [data for event, data in events if event == "wire_send"
                    and data.get("method") == "tools/call"]
        assert len(requests) == 2 and requests[0]["id"] != requests[1]["id"]
        assert port.cleanup_completed

    asyncio.run(check())


def test_live_precommit_request_prevents_a_false_slot_wide_repair_proof(tmp_path):
    port, database, config, _events = prepare(tmp_path / "live")

    async def check():
        async with port:
            old = asyncio.create_task(port.call("create_ticket", arguments(config), 3))
            await fault_event(port)
            stale = payload(await port.call("create_ticket", arguments(
                config, attempt=2, expected_revision=0,
            ), 3))
            assert not old.done() and effects(database) == ([], [])
            assert stale["error"]["code"] == "STALE_REVISION"
            assert all(stale["error"][flag] is False for flag in (
                "repairable", "not_executed", "unbound"
            ))
            assert payload(await old)["ok"]
        assert len(effects(database)[0]) == len(effects(database)[1]) == 1

    asyncio.run(check())


def test_explicit_mcp_cancellation_removes_precommit_request_without_late_effect(tmp_path):
    delay_s = 0.6
    port, database, config, events = prepare(tmp_path / "cancel", delay_s=delay_s)

    async def check():
        async with port:
            old = asyncio.create_task(port.call("create_ticket", arguments(config), 3))
            await fault_event(port)
            request = next(data for event, data in events if event == "wire_send"
                           and data.get("method") == "tools/call")
            # SDK 1.30 timeout/local task cancellation does not itself emit this
            # protocol notification. Exercise explicit MCP cancellation honestly.
            assert port._session is not None
            await port._session.send_notification(ClientNotification(CancelledNotification(
                params=CancelledNotificationParams(requestId=request["id"], reason="G2 test"),
            )))
            with pytest.raises(McpError) as caught:
                await old
            assert caught.value.error.message == "Request cancelled"
            await fault_event(port, "pre_commit_delay_exited")
            assert effects(database) == ([], [])
            stale = payload(await port.call("create_ticket", arguments(
                config, attempt=2, expected_revision=0,
            ), 3))
            assert stale["error"]["code"] == "STALE_REVISION"
            assert all(stale["error"][flag] is True for flag in (
                "repairable", "not_executed", "unbound"
            ))
            # Exceed the original delay horizon while the same server remains
            # alive; closing its process immediately would hide a late commit.
            await asyncio.sleep(delay_s + 0.05)
            assert effects(database) == ([], [])
            committed = payload(await port.call("create_ticket", arguments(config, attempt=3), 3))
            assert committed["ok"]
            assert effects(database)[1] == [committed["receipt"]]
        assert port.cleanup_completed

    asyncio.run(check())


def test_two_live_mcp_processes_reject_cross_run_grants_and_keep_separate_worlds(tmp_path):
    port_a, db_a, config_a, _ = prepare(tmp_path / "a", "run-A", delay_s=0)
    port_b, db_b, config_b, _ = prepare(tmp_path / "b", "run-B", delay_s=0)

    async def check():
        async with port_a, port_b:
            rejected = await asyncio.gather(
                port_a.call("create_ticket", arguments(config_b), 3),
                port_b.call("create_ticket", arguments(config_a), 3),
            )
            assert all(payload(reply)["error"]["code"] == "PERMISSION_DENIED"
                       for reply in rejected)
            assert effects(db_a) == effects(db_b) == ([], [])
            # Change one protected field at a time: swapping a whole grant can
            # conceal a missing check on an individual ownership/scope field.
            for port, own, other in ((port_a, config_a, config_b), (port_b, config_b, config_a)):
                for field in (
                    "run_id", "principal", "operation_id", "idempotency_key", "target_ref",
                ):
                    forged = arguments(own)
                    if field == "target_ref":
                        forged[field] = "change-Y"
                    else:
                        forged["envelope"][field] = (
                            "outsider" if field == "principal" else other[field]
                        )
                    read = {key: forged[key] for key in ("target_ref", "envelope")}
                    read["envelope"] = read["envelope"] | {"stage": "initial_read"}
                    denied = await asyncio.gather(
                        port.call("read_state", read, 3), port.call("create_ticket", forged, 3),
                    )
                    assert all(payload(reply)["error"]["code"] == "PERMISSION_DENIED"
                               for reply in denied), field
                    assert effects(db_a) == effects(db_b) == ([], [])
            written_b = payload(await port_b.call("create_ticket", arguments(
                config_b, priority="urgent",
            ), 3))
            assert written_b["ok"] and effects(db_a) == ([], [])
            snapshot_b = effects(db_b)
            written_a = payload(await port_a.call("create_ticket", arguments(config_a), 3))
            assert written_a["ok"] and effects(db_b) == snapshot_b
            assert effects(db_a)[1] == [written_a["receipt"]]
            assert written_a["receipt"]["run_id"] == "run-A"
            assert written_b["receipt"]["run_id"] == "run-B"
            assert written_a["receipt"]["ticket_id"] != written_b["receipt"]["ticket_id"]
        assert port_a.cleanup_completed and port_b.cleanup_completed

    asyncio.run(check())
