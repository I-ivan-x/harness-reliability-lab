"""Real MCP lifecycle checks preserve Host failures and join trace producers."""

import asyncio
import json
import time
from types import SimpleNamespace

import pytest
from anyio import BrokenResourceError

from harness_lab.mcp_port import MCPToolPort
from harness_lab.storage import initialize_environment


def test_body_exception_preserved_after_real_mcp_cleanup(tmp_path):
    db_path = tmp_path / "environment.sqlite"
    initialize_environment(db_path, {
        "target_ref": "X", "revision": 1, "queue_options": ["ops"],
        "write_policy": "allow", "facts": {},
    })
    config_path = tmp_path / "server.json"
    config_path.write_text(json.dumps({
        "db_path": str(db_path), "run_id": "R", "principal": "operator",
        "operation_id": "R:write-0", "idempotency_key": "R:write-0",
        "target_ref": "X", "can_read": True, "can_write": True,
    }), encoding="utf-8")
    events = []
    trace_closed = False

    def trace(event, data):
        assert not trace_closed, "SDK trace producer survived port cleanup"
        events.append((event, data))

    class HostStop(ValueError):
        pass

    original = HostStop("ordinary host stop")
    port = MCPToolPort(config_path, tmp_path / "stderr.log", trace)

    async def check():
        nonlocal trace_closed
        with pytest.raises(HostStop) as caught:
            async with port:
                assert port.tools
                raise original
        assert caught.value is original
        assert port.cleanup_completed
        assert events[-1][0] == "mcp_cleanup"
        assert events[-1][1]["completed"] is True
        assert any(event == "wire_send" for event, _ in events)
        trace_closed = True
        count = len(events)
        await asyncio.sleep(0.05)
        assert len(events) == count

    asyncio.run(check())


def test_unrelated_broken_resource_during_cleanup_is_not_silenced(tmp_path):
    class FailingClose:
        async def aclose(self):
            raise BrokenResourceError("unrelated cleanup failure")

    async def check():
        port = MCPToolPort(tmp_path / "unused.json", tmp_path / "stderr.log")
        port._owner_task = asyncio.current_task()
        port._stack = FailingClose()
        with pytest.raises(ExceptionGroup) as caught:
            await port.__aexit__(None, None, None)
        assert isinstance(caught.value.exceptions[0], BrokenResourceError)
        assert not port.cleanup_completed

    asyncio.run(check())


def test_port_deadline_owns_cancellation_before_sdk_fallback(tmp_path, monkeypatch):
    calls = []

    class BlockedSession:
        async def call_tool(self, name, args, *, read_timeout_seconds):
            calls.append(read_timeout_seconds.total_seconds())
            await asyncio.Future()

    async def check():
        port = MCPToolPort(tmp_path / "unused.json", tmp_path / "stderr.log")
        port._session = BlockedSession()
        monkeypatch.setattr(time, "get_clock_info", lambda _: SimpleNamespace(resolution=.015625))
        started = time.perf_counter()
        with pytest.raises(TimeoutError):
            await port.call("read_state", {}, .025)
        assert time.perf_counter() - started >= .025
        assert calls == [.025 + 2 * .015625]
        assert asyncio.current_task().cancelling() == 0

    asyncio.run(check())
