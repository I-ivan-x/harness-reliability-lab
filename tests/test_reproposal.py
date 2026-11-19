"""P2 authority boundaries and attempt accounting, plus real MCP state recovery."""

import asyncio
import copy
import json
import sqlite3
import subprocess
import sys
from collections import deque
from pathlib import Path

import pytest

from harness_lab.contracts import Budget, Ports, RunConfig, TaskInput
from harness_lab.models import ScriptedController
from harness_lab.runtime import run
from harness_lab.trace import replay

OLD = {"target_ref": "change-X", "expected_revision": 1, "queue": "ops", "priority": "normal"}
NEW = dict(OLD, expected_revision=2, priority="urgent")
PROJECT = Path(__file__).resolve().parents[1]


def state(revision=1):
    return {"ok": True, "kind": "state", "state": {
        "target_ref": "change-X", "revision": revision,
        "queue_options": ["ops", "platform"], "write_policy": "allow",
        "facts": {"customer_impact": revision == 2},
    }}


def error(code="STALE_REVISION", **changes):
    return {"ok": False, "error": {
        "code": code, "message": "Current business parameters are invalid.",
        "repairable": True, "not_executed": True, "unbound": True, **changes,
    }}


class PlannedController(ScriptedController):
    """Test proposals are explicit; no Gate/business helper chooses expected answers."""

    def __init__(self, *actions):
        self.actions = deque(actions)
        self.requests = []

    async def propose(self, messages, *_args, **_kwargs):
        self.requests.append(copy.deepcopy(messages))
        action = self.actions.popleft()
        if isinstance(action, dict):
            return self._call("create_ticket", action)
        if action == "read":
            return self._call("read_state", {"target_ref": "change-X"})
        last = next(json.loads(m["content"]) for m in reversed(messages) if m["role"] == "tool")
        if action == "stop":
            return self._final(
                "SAFE_STOP", "change-X", last["ref"], "stale_revision", "NOT_COMMITTED"
            )
        assert action == "finish"
        return self._final(
            "COMPLETED", "change-X", last["ref"], "completed", "CONFIRMED",
            last["result"]["receipt"]["ticket_id"],
        )


class ScriptedPort:
    """Delivers declared observations only; it does not emulate database semantics."""

    def __init__(self, responses):
        self.responses = deque(responses)
        self.calls = []
        self.cleanup_completed = False
        self.cleanup_elapsed_s = 0
        self.tools = [
            {"name": tool, "inputSchema": {"type": "object", "properties": {
                **{key: {} for key in fields}, "envelope": {},
            }, "required": [*fields, "envelope"]}}
            for tool, fields in (("read_state", ["target_ref"]), ("create_ticket", list(OLD)))
        ]

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        self.cleanup_completed = True

    async def call(self, tool, arguments, _timeout):
        self.calls.append((tool, copy.deepcopy(arguments)))
        expected_tool, response = self.responses.popleft()
        assert tool == expected_tool
        if isinstance(response, Exception):
            raise response
        if response == "receipt":
            envelope = arguments["envelope"]
            response = {"ok": True, "kind": "receipt", "receipt": {
                "receipt_id": "receipt-test", "ticket_id": "ticket-test",
                "run_id": envelope["run_id"], "operation_id": envelope["operation_id"],
                "target_ref": arguments["target_ref"],
                "params": {key: value for key, value in arguments.items() if key != "envelope"},
            }}
        return {"isError": not response["ok"], "structuredContent": copy.deepcopy(response)}


def execute(tmp_path, responses, *actions, policy="P2", budget=None):
    task = TaskInput(
        "repair-boundary", "Create one ticket using current facts.", "change-X", "2026-11-06"
    )
    controller, tools = PlannedController(*actions), ScriptedPort(responses)
    config = RunConfig("run-repair", "operator", tmp_path, policy=policy,
                       budget=budget or Budget(), backoff_s=0, jitter_s=0)
    record = asyncio.run(run(task, config, Ports(controller, tools)))
    assert record["measurement_valid"] and record["terminated_quiescent"]
    assert replay(tmp_path) == record
    assert record["costs"]["tool_attempts"] == len(tools.calls)
    return record, tools.calls, controller.requests


def writes(calls):
    return [args for tool, args in calls if tool == "create_ticket"]


def test_stale_refresh_and_repair_share_identity_and_remaining_retry_allowance(tmp_path):
    record, calls, _requests = execute(tmp_path, [
        ("read_state", state()), ("create_ticket", error()), ("read_state", state(2)),
        ("create_ticket", TimeoutError()), ("create_ticket", "receipt"),
    ], "read", OLD, NEW, "finish")
    assert record["output"]["disposition"] == "COMPLETED"
    attempts = writes(calls)
    assert [args["envelope"]["attempt"] for args in attempts] == [1, 2, 3]
    assert {args["envelope"]["idempotency_key"] for args in attempts} == {"run-repair:write-0"}
    assert {args["envelope"]["operation_id"] for args in attempts} == {"run-repair:write-0"}
    assert attempts[0]["expected_revision"] == 1
    assert attempts[1] | {"envelope": None} == attempts[2] | {"envelope": None}
    assert attempts[1]["expected_revision"] == 2 and attempts[1]["priority"] == "urgent"
    assert [args["envelope"]["attempt"] for tool, args in calls if tool == "read_state"] == [1, 1]


@pytest.mark.parametrize("policy", ["P0", "P1"])
def test_other_policies_do_not_receive_a_reproposal_window(tmp_path, policy):
    record, calls, requests = execute(tmp_path, [
        ("read_state", state()), ("create_ticket", error()),
    ], "read", OLD, NEW, policy=policy)
    assert record["output"]["disposition"] == "SAFE_STOP"
    assert len(calls) == 2 and len(requests) == 2


def test_queue_repair_does_not_spend_a_refresh_read(tmp_path):
    changed = dict(OLD, queue="platform")
    record, calls, _ = execute(tmp_path, [
        ("read_state", state()), ("create_ticket", error("INVALID_QUEUE")),
        ("create_ticket", "receipt"),
    ], "read", OLD, changed, "finish")
    assert record["output"]["disposition"] == "COMPLETED"
    assert [tool for tool, _args in calls] == ["read_state", "create_ticket", "create_ticket"]
    assert writes(calls)[1]["envelope"]["attempt"] == 2


@pytest.mark.parametrize("mutation", [
    {"repairable": "true"}, {"not_executed": 1}, {"unbound": None}, {"unbound": "missing"},
])
def test_malformed_repair_claim_never_authorizes_parameter_changes(tmp_path, mutation):
    bad = error(**mutation)
    if mutation == {"unbound": "missing"}:
        del bad["error"]["unbound"]
    record, calls, requests = execute(tmp_path, [
        ("read_state", state()), *[("create_ticket", bad)] * 3,
    ], "read", OLD, NEW)
    assert record["output"]["disposition"] != "COMPLETED"
    assert len(requests) == 2
    assert len(writes(calls)) <= 3
    assert all({key: args[key] for key in OLD} == OLD for args in writes(calls))
    assert sum(tool == "read_state" for tool, _args in calls) == 1


@pytest.mark.parametrize("changes", [
    {"repairable": False}, {"not_executed": False}, {"unbound": False},
])
def test_all_three_slot_wide_authorizations_are_required(tmp_path, changes):
    bad = error(**changes)
    record, calls, requests = execute(tmp_path, [
        ("read_state", state()), *[("create_ticket", bad)] * 3,
    ], "read", OLD, NEW)
    assert record["output"]["disposition"] == "SAFE_STOP"
    assert len(requests) == 2
    assert sum(tool == "read_state" for tool, _args in calls) == 1
    assert all({key: args[key] for key in OLD} == OLD for args in writes(calls))


def test_new_slot_wide_proof_can_resolve_unknown_but_never_reset_the_attempts(tmp_path):
    record, calls, requests = execute(tmp_path, [
        ("read_state", state()), ("create_ticket", TimeoutError()),
        ("create_ticket", error()), ("read_state", state(2)),
        ("create_ticket", TimeoutError()),
    ], "read", OLD, NEW)
    assert record["output"]["effect_knowledge"] == "UNKNOWN"
    assert record["output"]["disposition"] == "SAFE_STOP"
    attempts = writes(calls)
    assert len(requests) == 3 and len(attempts) == 3
    assert [args["envelope"]["attempt"] for args in attempts] == [1, 2, 3]
    assert [{key: args[key] for key in OLD} for args in attempts] == [OLD, OLD, NEW]
    assert {args["envelope"]["idempotency_key"] for args in attempts} == {"run-repair:write-0"}
    events = [
        json.loads(line)
        for line in (tmp_path / "trace.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    transition = next(event["data"] for event in events if event["event"] == "knowledge_transition")
    assert (transition["from"], transition["to"], transition["attempt"]) == (
        "UNKNOWN", "NOT_COMMITTED", 2
    )
    assert transition["basis"] == "certified_slot_unbound"


@pytest.mark.parametrize("changes", [
    {"repairable": False}, {"not_executed": False}, {"unbound": False},
    {"repairable": "true"}, {"not_executed": None}, {"unbound": "missing"},
])
def test_incomplete_proof_cannot_resolve_unknown_or_authorize_changes(tmp_path, changes):
    bad = error(**changes)
    if changes == {"unbound": "missing"}:
        del bad["error"]["unbound"]
    record, calls, requests = execute(tmp_path, [
        ("read_state", state()), ("create_ticket", TimeoutError()),
        *[("create_ticket", bad)] * 2,
    ], "read", OLD, NEW)
    assert record["output"]["effect_knowledge"] == "UNKNOWN"
    assert record["output"]["disposition"] == "SAFE_STOP"
    assert len(requests) == 2
    assert sum(tool == "read_state" for tool, _args in calls) == 1
    assert all({key: args[key] for key in OLD} == OLD for args in writes(calls))


@pytest.mark.parametrize("code", ["PERMISSION_DENIED", "APPROVAL_REQUIRED", "INVALID_REQUEST"])
def test_repair_flags_do_not_override_error_allowlist(tmp_path, code):
    record, calls, requests = execute(tmp_path, [
        ("read_state", state()), *[("create_ticket", error(code))] * 3,
    ], "read", OLD, NEW)
    assert record["output"]["disposition"] != "COMPLETED"
    assert len(requests) == 2
    assert sum(tool == "read_state" for tool, _args in calls) == 1
    assert all({key: args[key] for key in OLD} == OLD for args in writes(calls))


@pytest.mark.parametrize(("code", "disposition"), [
    ("PERMISSION_DENIED", "REFUSED"), ("APPROVAL_REQUIRED", "HANDOFF_HUMAN"),
])
def test_permission_and_approval_are_terminal_without_reproposal(tmp_path, code, disposition):
    record, calls, requests = execute(tmp_path, [
        ("read_state", state()), ("create_ticket", error(code, repairable=False)),
    ], "read", OLD, NEW)
    assert record["output"]["disposition"] == disposition
    assert len(calls) == 2 and len(requests) == 2


def test_refresh_failure_is_not_retried_and_never_permits_another_write(tmp_path):
    record, calls, _ = execute(tmp_path, [
        ("read_state", state()), ("create_ticket", error()),
        ("read_state", TimeoutError()),
    ], "read", OLD, NEW)
    assert record["output"]["disposition"] == "SAFE_STOP"
    assert record["output"]["effect_knowledge"] == "NOT_COMMITTED"
    assert len(calls) == 3 and len(writes(calls)) == 1


def test_a_second_repairable_failure_does_not_reopen_the_window(tmp_path):
    record, calls, requests = execute(tmp_path, [
        ("read_state", state()), ("create_ticket", error()), ("read_state", state(2)),
        ("create_ticket", error()),
    ], "read", OLD, NEW, NEW)
    assert record["output"]["disposition"] == "SAFE_STOP"
    assert record["output"]["effect_knowledge"] == "NOT_COMMITTED"
    assert len(requests) == 3 and len(calls) == 4


def test_parameter_change_does_not_create_a_fresh_attempt_budget(tmp_path):
    record, calls, _ = execute(tmp_path, [
        ("read_state", state()), ("create_ticket", error()), ("read_state", state(2)),
        ("create_ticket", TimeoutError()), ("create_ticket", TimeoutError()),
    ], "read", OLD, NEW, NEW)
    assert record["output"]["disposition"] == "SAFE_STOP"
    assert [args["envelope"]["attempt"] for args in writes(calls)] == [1, 2, 3]
    assert len(calls) == 5


@pytest.mark.parametrize("limit", [2, 3])
def test_global_budget_never_allows_an_extra_write_for_repair(tmp_path, limit):
    record, calls, _ = execute(tmp_path, [
        ("read_state", state()), ("create_ticket", error()), ("read_state", state(2)),
    ], "read", OLD, NEW, budget=Budget(tool_attempts=limit))
    assert record["output"]["disposition"] == "BUDGET_EXHAUSTED"
    assert len(calls) <= limit and len(writes(calls)) == 1


def test_reproposal_cannot_change_the_host_bound_target(tmp_path):
    record, calls, _ = execute(tmp_path, [
        ("read_state", state()), ("create_ticket", error("INVALID_QUEUE")),
    ], "read", OLD, dict(NEW, target_ref="change-Y"))
    assert record["output"]["disposition"] == "REFUSED"
    assert record["output"]["reason_code"] == "scope_denied"
    assert len(writes(calls)) == 1


def test_controller_can_stop_instead_of_repairing_without_losing_known_state(tmp_path):
    record, calls, _ = execute(tmp_path, [
        ("read_state", state()), ("create_ticket", error()), ("read_state", state(2)),
    ], "read", OLD, "stop")
    assert record["output"]["disposition"] == "SAFE_STOP"
    assert record["output"]["effect_knowledge"] == "NOT_COMMITTED"
    assert len(writes(calls)) == 1


@pytest.mark.parametrize(("case_name", "policy", "disposition", "params", "write_count"), [
    ("state-change", "P1", "SAFE_STOP", None, 1),
    ("state-change", "P2", "COMPLETED", NEW, 2),
    ("normal", "P2", "COMPLETED", OLD, 1),
    ("refused", "P2", "REFUSED", None, 0),
    ("lost-response", "P2", "COMPLETED", dict(OLD, priority="urgent"), 2),
])
def test_real_mcp_reproposal_and_existing_paths(
    tmp_path, case_name, policy, disposition, params, write_count,
):
    directory = tmp_path / "run"
    case = PROJECT / "tasks" / "dev" / f"{case_name}.json"
    subprocess.run(
        [sys.executable, "-m", "evals.run_case", str(case), "--output", str(directory),
         "--policy", policy],
        cwd=PROJECT, capture_output=True, text=True, check=True, timeout=30,
    )
    record = replay(directory)
    assert record["output"]["disposition"] == disposition
    assert record["measurement_valid"] and record["terminated_quiescent"]
    grade = json.loads((directory / "grade.json").read_text(encoding="utf-8"))
    assert grade["correct_disposition"] == (0 if disposition == "SAFE_STOP" else 1)
    expected_effects = int(params is not None)
    with sqlite3.connect(directory / "environment.sqlite") as db:
        effects = db.execute("SELECT params_json FROM tickets").fetchall()
        assert len(effects) == expected_effects
        assert db.execute("SELECT count(*) FROM receipts").fetchone()[0] == expected_effects
        if effects:
            assert json.loads(effects[0][0]) == params
    events = [
        json.loads(line)
        for line in (directory / "trace.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert any(
        event["event"] == "wire_send" and event["data"].get("method") == "initialize"
        for event in events
    )
    attempts = [
        event["data"] for event in events
        if event["event"] == "tool_attempt" and event["data"]["tool"] == "create_ticket"
    ]
    assert [attempt["envelope"]["attempt"] for attempt in attempts] == list(
        range(1, write_count + 1)
    )
    if attempts:
        assert len({attempt["envelope"]["idempotency_key"] for attempt in attempts}) == 1
    if case_name == "lost-response":
        assert attempts[0]["arguments"] == attempts[1]["arguments"]
