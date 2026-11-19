"""Vertical integration over the installed package and an actual stdio MCP process."""

import asyncio
import json
import sqlite3
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from harness_lab.contracts import Budget, Ports, RunConfig, TaskInput
from harness_lab.mcp_port import MCPToolPort
from harness_lab.models import ModelError, ScriptedController
from harness_lab.runtime import run
from harness_lab.storage import initialize_environment
from harness_lab.trace import replay

PROJECT = Path(__file__).resolve().parents[1]


def prepare(tmp_path, case="normal", *, controller=None, budget=None, policy="P1"):
    source = json.loads((PROJECT / "tasks" / "dev" / f"{case}.json").read_text(encoding="utf-8"))
    run_id = "run-" + uuid.uuid4().hex
    directory = tmp_path / "run"
    directory.mkdir()
    initialize_environment(directory / "environment.sqlite", source["environment"])
    operation = f"{run_id}:write-0"
    server = {
        "db_path": str(directory / "environment.sqlite"),
        "run_id": run_id,
        "principal": "dev-user",
        "operation_id": operation,
        "idempotency_key": operation,
        "target_ref": source["task_input"]["target_ref"],
        "can_read": True,
        "can_write": True,
        "fault": source["fault_plan"] or None,
    }
    server_path = directory / "private-server.json"
    server_path.write_text(json.dumps(server), encoding="utf-8")
    task = TaskInput(**source["task_input"])
    config = RunConfig(run_id, "dev-user", directory, policy=policy, budget=budget or Budget())
    port = MCPToolPort(server_path, directory / "mcp-stderr.log")
    return task, config, Ports(controller or ScriptedController(), port)


def execute(prepared):
    task, config, ports = prepared
    record = asyncio.run(run(task, config, ports))
    assert record["measurement_valid"]
    assert record["terminated_quiescent"]
    assert replay(config.artifact_dir) == record
    return record


@pytest.mark.parametrize(
    ("case", "policy", "terminal", "attempts", "effects"),
    [
        ("normal", "P1", "COMPLETED", 2, 1),
        ("refused", "P1", "REFUSED", 1, 0),
        ("lost-response", "P1", "COMPLETED", 3, 1),
        ("lost-response", "P0", "SAFE_STOP", 2, 1),
    ],
)
def test_three_paths_and_unconfirmed_committed_write(
    tmp_path, case, policy, terminal, attempts, effects
):
    prepared = prepare(tmp_path, case, policy=policy)
    record = execute(prepared)
    assert record["output"]["disposition"] == terminal
    assert record["costs"]["tool_attempts"] == attempts
    if policy == "P0":
        assert record["output"]["effect_knowledge"] == "UNKNOWN"
        assert record["output"]["ticket_id"] is None
    directory = prepared[1].artifact_dir
    with sqlite3.connect(directory / "environment.sqlite") as db:
        assert db.execute("SELECT count(*) FROM tickets").fetchone()[0] == effects
    trace = [
        json.loads(line)
        for line in (directory / "trace.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    writes = [
        e["data"]
        for e in trace
        if e["event"] == "tool_attempt" and e["data"]["tool"] == "create_ticket"
    ]
    if len(writes) == 2:
        assert writes[0]["arguments"] == writes[1]["arguments"]
        assert writes[0]["envelope"]["idempotency_key"] == writes[1]["envelope"]["idempotency_key"]
    assert trace[-1]["event"] == "run_end"
    assert len([e for e in trace if e["event"] == "terminal"]) == 1
    assert any(e["event"] == "wire_send" and e["data"].get("method") == "initialize" for e in trace)


def test_global_model_budget_stops_before_a_write(tmp_path):
    record = execute(prepare(tmp_path, budget=Budget(model_calls=1)))
    assert record["output"]["disposition"] == "BUDGET_EXHAUSTED"
    assert record["costs"]["model_calls"] == 1
    assert record["costs"]["tool_attempts"] == 1
    assert record["observations"][0]["host_observed"] is True
    assert record["observations"][0]["delivered"] is False


class MalformedFinal(ScriptedController):
    def __init__(self, python_literal):
        self.python_literal = python_literal

    async def propose(self, *args, **kwargs):
        reply = await super().propose(*args, **kwargs)
        if reply.finish_reason == "stop":
            content = reply.message["content"]
            reply.message["content"] = (str(json.loads(content)) if self.python_literal
                                        else "```json\n" + content + "\n```")
        return reply


@pytest.mark.parametrize("python_literal", [False, True])
@pytest.mark.parametrize("case,knowledge,tools,models", [
    ("normal", "CONFIRMED", 2, 3), ("refused", "NOT_COMMITTED", 1, 2),
])
def test_invalid_final_never_becomes_success(
    tmp_path, python_literal, case, knowledge, tools, models,
):
    record = execute(prepare(tmp_path, case, controller=MalformedFinal(python_literal)))
    assert record["output"]["disposition"] == "SYSTEM_FAILURE"
    assert record["output"]["reason_code"] == "invalid_response"
    assert record["output"]["effect_knowledge"] == knowledge
    assert record["costs"]["tool_attempts"] == tools
    assert record["costs"]["model_calls"] == models


class RepeatedWrite(ScriptedController):
    async def propose(self, messages, *args, **kwargs):
        last = next(
            (json.loads(m["content"]) for m in reversed(messages) if m["role"] == "tool"), None
        )
        if last and last["result"].get("kind") == "receipt":
            params = dict(last["result"]["receipt"]["params"], priority="urgent")
            return self._call("create_ticket", params)
        return await super().propose(messages, *args, **kwargs)


def test_model_cannot_start_another_write_after_commit(tmp_path):
    record = execute(prepare(tmp_path, controller=RepeatedWrite()))
    assert record["output"]["disposition"] == "SYSTEM_FAILURE"
    assert record["output"]["reason_code"] == "action_not_allowed"
    assert record["costs"]["tool_attempts"] == 2


class FailedProvider(ScriptedController):
    async def propose(self, *args, **kwargs):
        raise ModelError("HTTP_429")


def test_failed_model_call_is_counted_and_usage_is_unknown(tmp_path):
    record = execute(prepare(tmp_path, controller=FailedProvider()))
    assert record["output"]["disposition"] == "SYSTEM_FAILURE"
    assert record["costs"]["model_calls"] == 1
    assert record["costs"]["input_tokens"] is None
    assert record["costs"]["output_tokens"] is None
    assert record["costs"]["tool_attempts"] == 0


class FailedClose(ScriptedController):
    async def aclose(self):
        raise OSError("simulated client close failure")


def test_client_close_failure_still_seals_an_honest_record(tmp_path):
    task, config, ports = prepare(tmp_path, controller=FailedClose())
    record = asyncio.run(run(task, config, ports))
    assert record["measurement_valid"] is False
    assert record["terminated_quiescent"] is True
    assert record["output"]["disposition"] == "COMPLETED"
    assert record["output"]["effect_knowledge"] == "CONFIRMED"
    assert replay(config.artifact_dir) == record
    # Windows rejects this rename if the trace writer is still open.
    path = config.artifact_dir / "trace.jsonl"
    path.rename(config.artifact_dir / "closed-trace.jsonl")


def test_installed_cli_and_offline_replay_share_the_record(tmp_path):
    task, config, _ports = prepare(tmp_path)
    task_path = tmp_path / "public-task.json"
    from dataclasses import asdict

    task_path.write_text(json.dumps(asdict(task)), encoding="utf-8")
    base = [sys.executable, "-I", "-m", "harness_lab"]
    executed = subprocess.run(
        base
        + [
            "run",
            str(task_path),
            "--run-id",
            config.run_id,
            "--server-config",
            str(config.artifact_dir / "private-server.json"),
            "--output",
            str(config.artifact_dir),
            "--model",
            "scripted",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert executed.returncode == 0, executed.stderr
    replayed = subprocess.run(
        base + ["replay", str(config.artifact_dir)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert replayed.returncode == 0, replayed.stderr
    assert json.loads(executed.stdout) == json.loads(replayed.stdout)


@pytest.mark.parametrize("kwargs", [{"model_calls": 1.5}, {"total_s": float("nan")}])
def test_invalid_budget_cannot_start_a_run(kwargs):
    with pytest.raises(ValueError):
        Budget(**kwargs)
