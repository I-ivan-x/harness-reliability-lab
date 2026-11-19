"""Integration checks cross a real MCP stdio subprocess, including a lost receipt."""

import asyncio
import json
import sqlite3
import sys
from contextlib import asynccontextmanager, closing
from datetime import timedelta

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.exceptions import McpError
from pydantic import ValidationError

from harness_lab.mcp_port import MCPToolPort
from harness_lab.storage import initialize_environment
from harness_lab.tool_server import Envelope, ServerConfig, ToolService


@pytest.fixture
def environment(tmp_path):
    db_path = tmp_path / "environment.sqlite"
    world = {"target_ref": "change-X", "revision": 1, "queue_options": ["ops"],
             "write_policy": "allow", "facts": {"customer_impact": False}}
    initialize_environment(db_path, world)
    config = {"db_path": str(db_path), "run_id": "run-test", "principal": "operator",
              "operation_id": "run-test:write-0", "idempotency_key": "run-test:write-0",
              "target_ref": "change-X", "can_read": True, "can_write": True}
    return tmp_path, db_path, config


@asynccontextmanager
async def session_for(tmp_path, config):
    config_path = tmp_path / "server.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "harness_lab.tool_server", str(config_path)],
    )
    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            yield session


def arguments(config, *, attempt=1):
    return {
        "target_ref": "change-X", "expected_revision": 1, "queue": "ops", "priority": "normal",
        "envelope": {name: config[name] for name in (
            "run_id", "principal", "operation_id", "idempotency_key"
        )} | {"attempt": attempt, "stage": "write-0"},
    }


def read_arguments(params):
    return {"target_ref": params["target_ref"],
            "envelope": params["envelope"] | {"stage": "initial_read"}}


@pytest.mark.parametrize("can_read,can_write", [(True, False), (False, True)])
def test_trusted_grant_separates_read_and_write_permissions(environment, can_read, can_write):
    tmp_path, database, config = environment
    config.update(can_read=can_read, can_write=can_write)
    config_path = tmp_path / "server.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    events = []
    port = MCPToolPort(config_path, tmp_path / "stderr.log",
                       lambda event, data: events.append({"event": event, "data": data}))

    async def check():
        async with port:
            params = arguments(config)
            read = (await port.call("read_state", read_arguments(params), 3))["structuredContent"]
            assert read["ok"] is can_read
            if not can_read:
                assert read["error"]["code"] == "PERMISSION_DENIED"
            write = (await port.call("create_ticket", params, 3))["structuredContent"]
            assert not write["ok"] and write["error"]["code"] == "PERMISSION_DENIED"
        assert port.cleanup_completed

    asyncio.run(check())
    attempts = [item["data"] for item in events if item["event"] == "wire_send"
                and item["data"].get("method") == "tools/call"]
    assert [item["params"]["name"] for item in attempts] == ["read_state", "create_ticket"]
    assert len({item["id"] for item in attempts}) == 2
    (tmp_path / "wire.jsonl").write_text("\n".join(map(json.dumps, events)), encoding="utf-8")
    with closing(sqlite3.connect(database)) as db:
        assert db.execute("SELECT count(*) FROM tickets").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM receipts").fetchone()[0] == 0


@pytest.mark.parametrize("patch", [
    {"attempts": []}, {"attempts": [0]}, {"attempts": [True]}, {"attempts": [1.5]},
    {"kind": "commit_response_delay", "stage": "initial_read", "delay_s": 0.1},
    {"kind": "pre_commit_delay", "delay_s": float("nan")},
])
def test_fault_plan_rejects_invalid_attempts_and_committed_read_delays(environment, patch):
    config = environment[2] | {"fault": {"kind": "temporary_unavailable"} | patch}
    with pytest.raises(ValidationError):
        ServerConfig.model_validate(config)


def test_read_protocol_fault_is_a_real_rpc_error_and_stage_scoped(environment):
    tmp_path, _, config = environment
    config["fault"] = {"kind": "protocol_error", "stage": "initial_read", "attempts": [1]}

    async def check():
        async with session_for(tmp_path, config) as session:
            params = arguments(config)
            with pytest.raises(McpError) as caught:
                await session.call_tool("read_state", read_arguments(params))
            assert caught.value.error.code == -32603
            wrong_stage = await session.call_tool("read_state", {
                "target_ref": params["target_ref"], "envelope": params["envelope"],
            })
            assert wrong_stage.structuredContent["error"]["code"] == "INVALID_REQUEST"
            assert not (await session.call_tool("create_ticket", params)).isError

    asyncio.run(check())


def test_real_mcp_write_replay_and_strict_inputs(environment):
    tmp_path, db_path, config = environment

    async def check():
        async with session_for(tmp_path, config) as session:
            tools = await session.list_tools()
            assert {tool.name for tool in tools.tools} == {"read_state", "create_ticket"}
            assert all(tool.inputSchema["additionalProperties"] is False for tool in tools.tools)
            params = arguments(config)
            read = await session.call_tool("read_state", read_arguments(params))
            assert read.structuredContent["state"]["revision"] == 1
            invalid = await session.call_tool("create_ticket", params | {"untrusted": True})
            assert invalid.isError
            assert invalid.structuredContent["error"]["code"] == "INVALID_REQUEST"
            invalid = await session.call_tool("create_ticket", params | {
                "envelope": params["envelope"] | {"untrusted": True}
            })
            assert invalid.isError
            first = await session.call_tool("create_ticket", params)
            replay = await session.call_tool("create_ticket", arguments(config, attempt=2))
            assert not first.isError and replay.structuredContent == first.structuredContent
            conflict = await session.call_tool("create_ticket", params | {"priority": "urgent"})
            assert conflict.isError
            assert conflict.structuredContent["error"]["code"] == "IDEMPOTENCY_CONFLICT"

    asyncio.run(check())
    with sqlite3.connect(db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM tickets").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM receipts").fetchone()[0] == 1


def test_server_independently_rejects_identity_and_policy(environment):
    tmp_path, db_path, config = environment
    with sqlite3.connect(db_path) as db:
        world = json.loads(db.execute("SELECT payload_json FROM state").fetchone()[0])
        world["write_policy"] = "forbid"
        db.execute("UPDATE state SET payload_json = ?", (json.dumps(world),))

    async def check():
        async with session_for(tmp_path, config) as session:
            params = arguments(config)
            forged = params | {"envelope": params["envelope"] | {"principal": "administrator"}}
            denied = await session.call_tool("create_ticket", forged)
            assert denied.isError
            assert denied.structuredContent["error"]["code"] == "PERMISSION_DENIED"
            denied = await session.call_tool("create_ticket", params)
            assert denied.isError and not denied.structuredContent["error"]["repairable"]

    asyncio.run(check())
    with sqlite3.connect(db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM tickets").fetchone()[0] == 0


def test_post_commit_timeout_replays_original_receipt(environment):
    tmp_path, db_path, config = environment
    config["fault"] = {"kind": "commit_response_delay", "attempts": [1], "delay_s": 0.4}

    async def check():
        async with session_for(tmp_path, config) as session:
            with pytest.raises(McpError):
                await session.call_tool(
                    "create_ticket", arguments(config), read_timeout_seconds=timedelta(seconds=0.08)
                )
            # This is test-owned truth, never supplied to the Host after its timeout.
            with sqlite3.connect(db_path) as db:
                receipt = json.loads(db.execute("SELECT payload_json FROM receipts").fetchone()[0])
                world = json.loads(db.execute("SELECT payload_json FROM state").fetchone()[0])
                world["revision"] = 2
                world["write_policy"] = "forbid"
                db.execute("UPDATE state SET payload_json = ?", (json.dumps(world),))
            replay = await session.call_tool("create_ticket", arguments(config, attempt=2))
            assert not replay.isError
            assert replay.structuredContent["receipt"] == receipt

    asyncio.run(check())
    with sqlite3.connect(db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM tickets").fetchone()[0] == 1


def state_change_config(config):
    config["fault"] = {
        "kind": "state_change", "attempt": 1,
        "state_patch": {"revision": 2, "facts": {"customer_impact": True}},
    }
    return config


def test_state_change_persists_and_repair_uses_same_unbound_slot(environment):
    tmp_path, db_path, config = environment
    state_change_config(config)

    async def check():
        async with session_for(tmp_path, config) as session:
            params = arguments(config)
            read_params = read_arguments(params)
            initial = await session.call_tool("read_state", read_params)
            assert initial.structuredContent["state"]["revision"] == 1
            rejected = await session.call_tool("create_ticket", params | {"untrusted": True})
            assert rejected.structuredContent["error"]["code"] == "INVALID_REQUEST"
            forged = params | {"envelope": params["envelope"] | {"principal": "other"}}
            rejected = await session.call_tool("create_ticket", forged)
            assert rejected.structuredContent["error"]["code"] == "PERMISSION_DENIED"
            unchanged = await session.call_tool("read_state", read_params)
            assert unchanged.structuredContent["state"]["revision"] == 1

            failed = await session.call_tool("create_ticket", params)
            assert failed.isError
            assert failed.structuredContent["error"] == {
                "code": "STALE_REVISION", "message": "Refresh current state",
                "repairable": True, "not_executed": True, "unbound": True,
            }
            with sqlite3.connect(db_path) as db:
                state = json.loads(db.execute("SELECT payload_json FROM state").fetchone()[0])
                assert state["revision"] == 2 and state["facts"]["customer_impact"] is True
                assert db.execute("SELECT COUNT(*) FROM receipts").fetchone()[0] == 0
                assert db.execute("SELECT COUNT(*) FROM tickets").fetchone()[0] == 0
            # Retrying unchanged parameters does not make a business error disappear.
            again = await session.call_tool("create_ticket", arguments(config, attempt=2))
            assert again.structuredContent["error"]["code"] == "STALE_REVISION"
            refreshed = await session.call_tool("read_state", read_params)
            assert refreshed.structuredContent["state"]["revision"] == 2
            assert refreshed.structuredContent["state"]["facts"]["customer_impact"] is True
            corrected = arguments(config, attempt=3) | {
                "expected_revision": 2, "priority": "urgent",
            }
            written = await session.call_tool("create_ticket", corrected)
            assert not written.isError
            assert written.structuredContent["receipt"]["params"] == {
                key: value for key, value in corrected.items() if key != "envelope"
            }
            replay = await session.call_tool("create_ticket", corrected)
            assert replay.structuredContent == written.structuredContent

    asyncio.run(check())
    with sqlite3.connect(db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM tickets").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM receipts").fetchone()[0] == 1


def test_state_change_never_reapplies_to_an_unbound_slot(environment):
    tmp_path, db_path, config = environment
    state_change_config(config)

    async def check():
        async with session_for(tmp_path, config) as session:
            params = arguments(config)
            await session.call_tool("read_state", read_arguments(params))
            failed = await session.call_tool("create_ticket", params)
            assert failed.structuredContent["error"]["code"] == "STALE_REVISION"
            with sqlite3.connect(db_path) as db:
                state = json.loads(db.execute("SELECT payload_json FROM state").fetchone()[0])
                state["revision"] = 3
                state["facts"] = {"customer_impact": False}
                db.execute("UPDATE state SET payload_json = ?", (json.dumps(state),))
            # Even a reused attempt value cannot reset a previously applied private change.
            failed = await session.call_tool("create_ticket", params)
            assert failed.structuredContent["error"]["code"] == "STALE_REVISION"
            state = await session.call_tool("read_state", read_arguments(params))
            assert state.structuredContent["state"]["revision"] == 3
            assert state.structuredContent["state"]["facts"]["customer_impact"] is False

    asyncio.run(check())


def test_state_change_needs_initial_read_and_cannot_mutate_committed_replay(environment):
    tmp_path, db_path, config = environment
    state_change_config(config)

    async def check():
        async with session_for(tmp_path, config) as session:
            params = arguments(config)
            # No initial read means the phase condition has not been reached.
            committed = await session.call_tool("create_ticket", params)
            assert not committed.isError
            read_params = read_arguments(params)
            state = await session.call_tool("read_state", read_params)
            assert state.structuredContent["state"]["revision"] == 1
            replay = await session.call_tool("create_ticket", params)
            assert replay.structuredContent == committed.structuredContent
            state = await session.call_tool("read_state", read_params)
            assert state.structuredContent["state"]["revision"] == 1

    asyncio.run(check())
    with sqlite3.connect(db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM tickets").fetchone()[0] == 1


def test_repair_proof_is_withheld_while_another_slot_request_can_continue(environment):
    _, db_path, config = environment

    async def check():
        service = ToolService(ServerConfig.model_validate(config))
        try:
            first = arguments(config) | {"expected_revision": 0}
            second = arguments(config, attempt=2) | {"expected_revision": 0}
            # A deterministic in-process mutex barrier tests slot-wide proof issuance;
            # it does not claim to cover MCP cancellation or the complete G2 race matrix.
            async with service.lock:
                pending = [asyncio.create_task(service.create_ticket(
                    {key: value for key, value in request.items() if key != "envelope"},
                    Envelope.model_validate(request["envelope"]),
                )) for request in (first, second)]
                await asyncio.sleep(0)
                assert len(service.inflight) == 2
            replies = await asyncio.gather(*pending)
            flags = ("repairable", "not_executed", "unbound")
            first_error, last_error = [reply.structuredContent["error"] for reply in replies]
            assert first_error["code"] == last_error["code"] == "STALE_REVISION"
            assert all(first_error[flag] is False for flag in flags)
            assert all(last_error[flag] is True for flag in flags)
            assert not service.inflight
        finally:
            service.store.close()

    asyncio.run(check())
    with sqlite3.connect(db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM tickets").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM receipts").fetchone()[0] == 0


def test_pre_commit_wait_is_unlocked_cancellable_and_withholds_repair_proof(
    environment, monkeypatch, capsys,
):
    _, db_path, config = environment
    config["fault"] = {"kind": "pre_commit_delay", "attempts": [1], "delay_s": 0.4}

    async def check():
        entered = asyncio.Event()
        release = asyncio.Event()

        async def wait_at_fault(delay_s):
            assert delay_s == 0.4
            entered.set()
            await release.wait()

        monkeypatch.setattr("harness_lab.tool_server.asyncio.sleep", wait_at_fault)
        service = ToolService(ServerConfig.model_validate(config))
        pending = None
        try:
            request = arguments(config)
            params = {key: value for key, value in request.items() if key != "envelope"}
            envelope = Envelope.model_validate(request["envelope"])
            forged = envelope.model_copy(update={"principal": "other"})
            rejected = await service.create_ticket(params, forged)
            assert rejected.structuredContent["error"]["code"] == "PERMISSION_DENIED"
            assert not entered.is_set() and not service.inflight

            pending = asyncio.create_task(service.create_ticket(params, envelope))
            await asyncio.wait_for(entered.wait(), timeout=1)
            assert len(service.inflight) == 1 and not service.lock.locked()
            state = await asyncio.wait_for(
                service.read_state("change-X", envelope.model_copy(
                    update={"stage": "initial_read"},
                )), timeout=1,
            )
            assert state.structuredContent["state"]["revision"] == 1
            with sqlite3.connect(db_path) as db:
                assert db.execute("SELECT COUNT(*) FROM tickets").fetchone()[0] == 0
                assert db.execute("SELECT COUNT(*) FROM receipts").fetchone()[0] == 0

            second = await service.create_ticket(
                params | {"expected_revision": 0}, envelope.model_copy(update={"attempt": 2}),
            )
            assert second.structuredContent["error"]["code"] == "STALE_REVISION"
            flags = ("repairable", "not_executed", "unbound")
            assert all(second.structuredContent["error"][flag] is False for flag in flags)
            assert not pending.done() and len(service.inflight) == 1

            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending
            assert not service.inflight
            after_cancel = await service.create_ticket(
                params | {"expected_revision": 0}, envelope.model_copy(update={"attempt": 3}),
            )
            assert all(after_cancel.structuredContent["error"][flag] is True for flag in flags)
        finally:
            if pending is not None and not pending.done():
                pending.cancel()
                await asyncio.gather(pending, return_exceptions=True)
            service.store.close()

    asyncio.run(check())
    assert [json.loads(line) for line in capsys.readouterr().err.splitlines()] == [
        {"event": "pre_commit_delay_entered", "attempt": 1},
        {"event": "pre_commit_delay_exited", "attempt": 1},
    ]
    with sqlite3.connect(db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM tickets").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM receipts").fetchone()[0] == 0


def test_pre_commit_delay_produces_receipt_only_after_wait(environment, monkeypatch):
    _, db_path, config = environment
    config["fault"] = {"kind": "pre_commit_delay", "attempts": [1], "delay_s": 0.4}

    async def check():
        entered = asyncio.Event()
        release = asyncio.Event()

        async def wait_at_fault(_delay_s):
            entered.set()
            await release.wait()

        monkeypatch.setattr("harness_lab.tool_server.asyncio.sleep", wait_at_fault)
        service = ToolService(ServerConfig.model_validate(config))
        request = arguments(config)
        pending = asyncio.create_task(service.create_ticket(
            {key: value for key, value in request.items() if key != "envelope"},
            Envelope.model_validate(request["envelope"]),
        ))
        try:
            await asyncio.wait_for(entered.wait(), timeout=1)
            assert not pending.done()
            release.set()
            reply = await asyncio.wait_for(pending, timeout=1)
            assert not reply.isError and reply.structuredContent["kind"] == "receipt"
            assert not service.inflight
        finally:
            if not pending.done():
                pending.cancel()
                await asyncio.gather(pending, return_exceptions=True)
            service.store.close()

    asyncio.run(check())
    with sqlite3.connect(db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM tickets").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM receipts").fetchone()[0] == 1
