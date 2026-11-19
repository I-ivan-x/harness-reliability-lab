"""Boundary assertions over the Host; protocol faults are tested separately."""

import asyncio
import json
import runpy
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest
from tests.test_reproposal import ScriptedPort, state

from harness_lab.contracts import Budget, Ports, RunConfig, TaskInput
from harness_lab.models import ScriptedController
from harness_lab.runtime import run
from harness_lab.storage import initialize_environment
from harness_lab.trace import replay


def execute(tmp_path, *, budget=None, controller=None, tools=None, **config):
    tools = tools or ScriptedPort([("read_state", state()), ("create_ticket", "receipt")])
    config = RunConfig("run-budget", "user", tmp_path, budget=budget or Budget(), **config)
    record = asyncio.run(run(TaskInput("budget", "Create one ticket.", "change-X", "2026-11-07"),
                             config, Ports(controller or ScriptedController(), tools)))
    assert record["measurement_valid"] and replay(tmp_path) == record
    return record


@pytest.mark.parametrize("limits,reason,models,tools", [
    ({"decision_steps": 1}, "model_or_decision_budget", 1, 1),
    ({"input_tokens_per_call": 1}, "input_estimate_limit", 0, 0),
    ({"tool_result_bytes": 1}, "invalid_result", 1, 1),
])
def test_stop_before_the_next_action(tmp_path, limits, reason, models, tools):
    record = execute(tmp_path, budget=Budget(**limits))
    assert record["output"]["reason_code"] == reason
    assert (record["costs"]["model_calls"], record["costs"]["tool_attempts"]) == (models, tools)


@pytest.mark.parametrize("field", ["input_tokens", "output_tokens"])
def test_provider_usage_overrun_prevents_tool_dispatch(tmp_path, field):
    class ReportedUsage(ScriptedController):
        async def propose(self, *args, **kwargs):
            reply = await super().propose(*args, **kwargs)
            return replace(reply, usage={"input_tokens": 0, "output_tokens": 0,
                                         field: getattr(Budget(), field + "_per_call") + 1})
    record = execute(tmp_path, controller=ReportedUsage())
    assert record["output"]["disposition"] == "BUDGET_EXHAUSTED"
    assert record["costs"]["model_calls"] == 1 and record["costs"]["tool_attempts"] == 0
    assert record["maxima"][field] > record["limits"][field + "_per_call"]


def test_host_bounds_a_port_that_ignores_its_timeout(tmp_path):
    class BlockedPort(ScriptedPort):
        async def call(self, *_args):
            await asyncio.sleep(10)
            raise AssertionError("Host did not enforce timeout")
    record = execute(tmp_path, tools=BlockedPort([]), policy="P0",
                     budget=Budget(tool_timeout_s=0.01))
    assert record["output"]["reason_code"] == "timeout"
    assert record["costs"]["tool_attempts"] == 1 and record["costs"]["total_s"] < 1


def test_backoff_does_not_spend_the_cleanup_reserve(tmp_path):
    record = execute(tmp_path, backoff_s=1000, tools=ScriptedPort([
        ("read_state", TimeoutError()),
    ]))
    assert record["output"]["reason_code"] == "backoff_budget"
    assert record["costs"]["tool_attempts"] == 1
    assert '"event": "backoff"' not in (tmp_path / "trace.jsonl").read_text(encoding="utf-8")


@pytest.mark.parametrize("policy,disposition", [("P0", "SAFE_STOP"), ("P1", "COMPLETED")])
def test_oversized_write_receipt_is_unknown_until_valid_replay(tmp_path, policy, disposition):
    class OversizedOnce(ScriptedPort):
        async def call(self, tool, *args):
            raw = await super().call(tool, *args)
            if tool == "create_ticket" and len(self.calls) == 2:
                raw["padding"] = "x" * 2000
            return raw
    tools = OversizedOnce([("read_state", state()), ("create_ticket", "receipt"),
                           ("create_ticket", "receipt")])
    record = execute(tmp_path, policy=policy, tools=tools, budget=Budget(tool_result_bytes=1000))
    assert record["output"]["disposition"] == disposition
    assert record["output"]["effect_knowledge"] == ("UNKNOWN" if policy == "P0" else "CONFIRMED")
    assert record["maxima"]["tool_result_bytes"] <= 1000
    if policy == "P1":
        assert tools.calls[1][1] | {"envelope": None} == tools.calls[2][1] | {"envelope": None}


@pytest.mark.parametrize("field", ["maxima", "counters", "costs"])
def test_replay_rejects_changed_budget_evidence_even_in_both_files(tmp_path, field):
    execute(tmp_path)
    manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    events = [json.loads(line) for line in (tmp_path / "trace.jsonl").read_text().splitlines()]
    key = {"maxima": "input_tokens", "counters": "decision_steps", "costs": "input_tokens"}[field]
    manifest["record"][field][key] = events[-1]["data"][field][key] = 99
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (tmp_path / "trace.jsonl").write_text("\n".join(map(json.dumps, events)), encoding="utf-8")
    with pytest.raises(ValueError, match="Budget evidence disagrees"):
        replay(tmp_path)


def test_initializer_and_offline_reader_close_connections(tmp_path, monkeypatch):
    closed, connect = [], sqlite3.connect
    class TrackedConnection(sqlite3.Connection):
        def close(self):
            closed.append(self)
            super().close()
    monkeypatch.setattr(sqlite3, "connect", lambda *args, **kwargs: connect(
        *args, factory=TrackedConnection, **kwargs,
    ))
    database = tmp_path / "world.sqlite"
    initialize_environment(database, state()["state"])
    reader = runpy.run_path(str(Path(__file__).parents[1] / "evals/grader.py"))["_load_state"]
    reader(database)
    assert len(closed) == 2
