"""Cancellation and late replies over real stdio MCP, sealed before grading."""

import asyncio
import json
import sqlite3
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path

import pytest

from harness_lab.contracts import Budget, Ports, RunConfig, TaskInput
from harness_lab.mcp_port import MCPToolPort
from harness_lab.models import ScriptedController
from harness_lab.runtime import run
from harness_lab.storage import initialize_environment
from harness_lab.trace import replay

PROJECT = Path(__file__).resolve().parents[1]


class ObservedPort(MCPToolPort):
    """Observe actual SDK traffic; every request still crosses the subprocess pipe."""

    def __init__(self, config_path, stderr_path, *, await_late=False, pause_cleanup=False):
        self.events = []
        self.initialize_sent = asyncio.Event()
        self.read_sent = asyncio.Event()
        self.write_sent = asyncio.Event()
        self.receipt_received = asyncio.Event()
        self.cleanup_started = asyncio.Event()
        self.cleanup_release = asyncio.Event()
        self.await_late = await_late
        self.pause_cleanup = pause_cleanup
        super().__init__(config_path, stderr_path)

    @property
    def trace(self):
        return self._observe

    @trace.setter
    def trace(self, sink):
        self._sink = sink

    def _observe(self, event, data):
        self._sink(event, data)
        self.events.append((event, data))
        if event == "wire_send" and data.get("method") == "initialize":
            self.initialize_sent.set()
        if event == "wire_send" and data.get("method") == "tools/call":
            name = data["params"]["name"]
            (self.read_sent if name == "read_state" else self.write_sent).set()
        if event == "wire_receive" and (
            data.get("result", {}).get("structuredContent", {}).get("kind") == "receipt"
        ):
            self.receipt_received.set()

    async def __aexit__(self, *args):
        self.cleanup_started.set()
        started = time.monotonic()
        if self.pause_cleanup:
            # Hold an already stopped owner at teardown without another task owning
            # any SDK scope. The caller can now cancel at an observed boundary.
            await self.cleanup_release.wait()
        if self.await_late and self.write_sent.is_set():
            # Deliberately keep the real session open inside the reserved cleanup window
            # to observe a packet which ordinary immediate shutdown may discard instead.
            await asyncio.wait_for(self.receipt_received.wait(), timeout=2)
        result = await super().__aexit__(*args)
        self.cleanup_elapsed_s = time.monotonic() - started
        return result


class ObservedController(ScriptedController):
    def __init__(self, *, block_after_read=False):
        self.calls = 0
        self.block_after_read = block_after_read
        self.blocked = asyncio.Event()
        self.closed = False

    async def propose(self, *args, **kwargs):
        self.calls += 1
        if self.block_after_read and self.calls == 2:
            self.blocked.set()
            await asyncio.Event().wait()
        return await super().propose(*args, **kwargs)

    async def aclose(self):
        self.closed = True


def setup(tmp_path, *, fault=None, block=False, policy="P1", await_late=False, timeout=3):
    case = json.loads((PROJECT / "tasks/dev/normal.json").read_text(encoding="utf-8"))
    directory = tmp_path / "run"
    directory.mkdir()
    database = directory / "environment.sqlite"
    initialize_environment(database, case["environment"])
    server_path = directory / "private-server.json"
    server_path.write_text(json.dumps({
        "db_path": str(database), "run_id": "cancel-run", "principal": "dev-user",
        "operation_id": "cancel-run:write-0", "idempotency_key": "cancel-run:write-0",
        "target_ref": case["task_input"]["target_ref"], "can_read": True, "can_write": True,
        "fault": fault,
    }), encoding="utf-8")
    prepared = dict(case, database=database)
    controller = ObservedController(block_after_read=block)
    port = ObservedPort(
        server_path, directory / "mcp-stderr.log", await_late=await_late,
    )
    config = RunConfig(
        "cancel-run", "dev-user", directory,
        policy=policy, budget=Budget(tool_timeout_s=timeout),
    )
    return prepared, config, Ports(controller, port)


def effects(database):
    with sqlite3.connect(f"{database.resolve().as_uri()}?mode=ro", uri=True) as db:
        return db.execute("SELECT count(*) FROM tickets").fetchone()[0]


def pre_commit_entered(directory):
    path = directory / "mcp-stderr.log"
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                if json.loads(line).get("event") == "pre_commit_delay_entered":
                    return True
            except json.JSONDecodeError:
                continue
    return False


async def wait_until(predicate):
    async with asyncio.timeout(5):
        while not predicate():
            # Poll an independently observable boundary, never infer it from elapsed time.
            await asyncio.sleep(0.005)


async def assert_sealed(prepared, config, ports, record, expected_effects, expected_correct=0):
    assert ports.tools.cleanup_completed and ports.controller.closed
    assert record["terminated_quiescent"] and record["measurement_valid"]
    assert effects(prepared["database"]) == expected_effects
    assert replay(config.artifact_dir) == record
    graded = subprocess.run(
        [sys.executable, "-m", "evals.run_case", "tasks/dev/normal.json", "--regrade",
         str(config.artifact_dir)],
        cwd=PROJECT, capture_output=True, text=True, check=True, timeout=10,
    )
    result = json.loads(graded.stdout)
    assert result["measurement_valid"] and result["correct_disposition"] == expected_correct
    assert result["false_allow"] == result["false_refusal"] == 0
    path = config.artifact_dir / "trace.jsonl"
    sealed = path.read_bytes()
    events = [json.loads(line) for line in sealed.splitlines()]
    assert events[-1]["event"] == "run_end"
    assert sum(event["event"] == "terminal" for event in events) == 1
    terminal = next(i for i, event in enumerate(events) if event["event"] == "terminal")
    assert all(event["event"] == "run_end" for event in events[terminal + 1:])
    count = len(ports.tools.events)
    await asyncio.sleep(0.05)  # Give already-ready callbacks a turn after all producers joined.
    assert path.read_bytes() == sealed and len(ports.tools.events) == count
    assert effects(prepared["database"]) == expected_effects
    # Windows also proves the writer handle was closed before returning the record.
    renamed = path.with_name("closed-trace.jsonl")
    path.rename(renamed)
    renamed.rename(path)
    return events


@pytest.mark.parametrize("phase", ["initial_read", "model_wait", "pre_commit", "post_commit"])
def test_cancelled_run_is_quiescent_honest_and_never_resumes(tmp_path, phase):
    async def check():
        fault = None
        if phase in {"pre_commit", "post_commit"}:
            fault = {
                "kind": "pre_commit_delay" if phase == "pre_commit" else "commit_response_delay",
                "attempts": [1], "delay_s": 2.0,
            }
        prepared, config, ports = setup(tmp_path, fault=fault, block=phase == "model_wait")
        running = asyncio.create_task(run(
            TaskInput(**prepared["task_input"]), config, ports,
        ))
        if phase == "model_wait":
            await asyncio.wait_for(ports.controller.blocked.wait(), timeout=10)
        elif phase == "initial_read":
            await asyncio.wait_for(ports.tools.read_sent.wait(), timeout=10)
        elif phase == "post_commit":
            await wait_until(lambda: effects(prepared["database"]) == 1)
        else:
            await wait_until(lambda: pre_commit_entered(config.artifact_dir))
            assert effects(prepared["database"]) == 0
        calls_before = ports.controller.calls
        running.cancel()
        record = await asyncio.wait_for(running, timeout=10)
        assert record["output"]["disposition"] == "SAFE_STOP"
        assert record["output"]["reason_code"] == "cancelled"
        assert record["output"]["ticket_id"] is None
        writing = phase in {"pre_commit", "post_commit"}
        assert record["output"]["effect_knowledge"] == (
            "UNKNOWN" if writing else "NOT_COMMITTED"
        )
        assert ports.controller.calls == calls_before
        assert record["costs"]["tool_attempts"] == (2 if writing else 1)
        events = await assert_sealed(prepared, config, ports, record, int(phase == "post_commit"))
        assert not any(item["result"].get("kind") == "receipt" for item in record["observations"])
        cleanup = next(i for i, event in enumerate(events) if event["event"] == "dispatch_stop")
        assert not any(event["event"] in {"tool_attempt", "model_request"}
                       for event in events[cleanup:])

    asyncio.run(check())


def test_late_real_receipt_is_diagnostic_and_cannot_complete_a_stopped_run(tmp_path):
    async def check():
        prepared, config, ports = setup(
            tmp_path,
            fault={"kind": "commit_response_delay", "attempts": [1], "delay_s": 0.3},
            policy="P0", await_late=True, timeout=0.05,
        )
        record = await run(TaskInput(**prepared["task_input"]), config, ports)
        assert record["output"]["disposition"] == "SAFE_STOP"
        assert record["output"]["effect_knowledge"] == "UNKNOWN"
        assert record["output"]["ticket_id"] is None
        assert ports.tools.receipt_received.is_set()
        events = await assert_sealed(prepared, config, ports, record, 1)
        result = next(i for i, event in enumerate(events) if event["event"] == "tool_result"
                      and event["data"]["tool"] == "create_ticket")
        late = next(i for i, event in enumerate(events) if event["event"] == "wire_receive"
                    and event["data"].get("result", {}).get("structuredContent", {}).get(
                        "kind") == "receipt")
        assert late > result
        assert not any(event["event"] in {"model_request", "tool_attempt", "controller_delivery"}
                       for event in events[result + 1:])
        assert not any(item["result"].get("kind") == "receipt" for item in record["observations"])

    asyncio.run(check())


def test_repeated_cancel_during_cleanup_still_seals_the_original_stop(tmp_path):
    async def check():
        prepared, config, ports = setup(tmp_path, block=True)
        running = asyncio.create_task(run(TaskInput(**prepared["task_input"]), config, ports))
        await asyncio.wait_for(ports.controller.blocked.wait(), timeout=10)
        running.cancel()
        await asyncio.wait_for(ports.tools.cleanup_started.wait(), timeout=5)
        running.cancel()
        record = await asyncio.wait_for(running, timeout=10)
        assert record["output"]["reason_code"] == "cancelled"
        await assert_sealed(prepared, config, ports, record, 0)

    asyncio.run(check())


def test_first_cancel_during_natural_cleanup_preserves_the_completed_run(tmp_path):
    async def check():
        prepared, config, ports = setup(tmp_path)
        ports.tools.pause_cleanup = True
        running = asyncio.create_task(run(TaskInput(**prepared["task_input"]), config, ports))
        await asyncio.wait_for(ports.tools.cleanup_started.wait(), timeout=10)
        assert ports.tools.receipt_received.is_set()
        assert effects(prepared["database"]) == 1
        calls_before = ports.controller.calls
        running.cancel()
        # Let cancellation reach the public waiter while teardown is deliberately
        # blocked. The owner must survive until its same-task SDK close is joined.
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert not running.done()
        ports.tools.cleanup_release.set()
        record = await asyncio.wait_for(running, timeout=10)
        assert record["output"]["disposition"] == "COMPLETED"
        assert record["output"]["reason_code"] == "completed"
        assert record["output"]["effect_knowledge"] == "CONFIRMED"
        assert ports.controller.calls == calls_before
        events = await assert_sealed(prepared, config, ports, record, 1, expected_correct=1)
        stop = next(i for i, event in enumerate(events) if event["event"] == "dispatch_stop")
        assert not any(event["event"] in {"tool_attempt", "model_request"}
                       for event in events[stop:])

    asyncio.run(check())


def test_cancel_during_real_mcp_initialization_joins_startup_and_seals(tmp_path):
    async def check():
        prepared, config, ports = setup(tmp_path)
        running = asyncio.create_task(run(TaskInput(**prepared["task_input"]), config, ports))
        await asyncio.wait_for(ports.tools.initialize_sent.wait(), timeout=10)
        running.cancel()
        record = await asyncio.wait_for(running, timeout=10)
        assert record["output"]["disposition"] == "SAFE_STOP"
        assert record["output"]["reason_code"] == "cancelled"
        assert record["output"]["effect_knowledge"] == "NOT_COMMITTED"
        assert record["costs"]["model_calls"] == record["costs"]["tool_attempts"] == 0
        assert ports.controller.calls == 0
        await assert_sealed(prepared, config, ports, record, 0)

    asyncio.run(check())


def test_startup_consumes_work_budget_and_preserves_cleanup_reserve(tmp_path):
    async def check():
        prepared, config, ports = setup(tmp_path)
        config = replace(config, budget=replace(config.budget, total_s=5.05, cleanup_s=5))
        record = await run(TaskInput(**prepared["task_input"]), config, ports)
        assert record["output"]["disposition"] == "BUDGET_EXHAUSTED"
        assert record["output"]["reason_code"] == "wall_clock_budget"
        assert record["output"]["effect_knowledge"] == "NOT_COMMITTED"
        assert record["costs"]["model_calls"] == record["costs"]["tool_attempts"] == 0
        assert ports.controller.calls == 0
        events = await assert_sealed(prepared, config, ports, record, 0)
        controller_cleanup = next(event["data"]["elapsed_s"] for event in events
                                  if event["event"] == "controller_cleanup")
        work_elapsed = (
            record["costs"]["total_s"] - ports.tools.cleanup_elapsed_s - controller_cleanup
        )
        # Exclude joined cleanup, which owns its separate five-second reserve.
        # A generous scheduler tolerance still detects waiting for a full server
        # import/handshake before noticing the fifty-millisecond work deadline.
        assert work_elapsed <= config.budget.total_s - config.budget.cleanup_s + 0.25

    asyncio.run(check())
