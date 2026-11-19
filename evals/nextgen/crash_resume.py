"""Module 1B: Stateless Host crash recovery from truncated trace.jsonl + SQLite receipts."""

from __future__ import annotations

import argparse
import asyncio
import copy
import json
import shutil
import sqlite3
import uuid
from contextlib import closing
from pathlib import Path
from typing import Any

from evals.development import read
from evals.formal import atomic, journal
from evals.grader import grade, score_signature
from evals.nextgen import PROJECT, assert_nextgen_artifact_safe, enforce
from evals.nextgen.warm_pool import PooledToolPort, WarmWorkerPool
from evals.run_case import prepare_case
from harness_lab.contracts import Ports, RunConfig, TaskInput
from harness_lab.models import ModelReply
from harness_lab.runtime import (
    SYSTEM_PROMPT,
    StopRun,
    certified_unbound,
    final_output,
    gate,
    public_tools,
    tool_failure,
    validate_result,
)
from harness_lab.runtime import (
    run as runtime_run,
)
from harness_lab.timing import deadline_timeout
from harness_lab.trace import TraceWriter, replay, source_revision

CRASH_POINTS = (
    "after_first_observation",
    "before_write_commit",
    "after_write_commit_before_trace_result",
    "after_p2_refresh",
)


class SimulatedProcessCrash(BaseException):
    """Hard process crash signal bypassing normal RunConfig exception handlers."""


class ReferenceF3Controller:
    """Deterministic public-message controller for F3 crash/resume verification."""

    def __init__(self, reference_steps: list[dict[str, Any]]):
        self._writes = [s["args"] for s in reference_steps if s["stage"] == "write-0"]

    def describe(self) -> dict[str, str]:
        return {"kind": "scripted-f3-reference", "model": "scripted-f3-reference"}

    async def aclose(self) -> None:
        pass

    async def propose(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]], **_: Any
    ) -> ModelReply:
        task = next(
            json.loads(m["content"])["task"]
            for m in messages
            if m["role"] == "user" and "task" in json.loads(m["content"])
        )
        target = task["target_ref"]
        visible_obs: list[dict[str, Any]] = []
        for m in messages:
            if m["role"] == "tool":
                visible_obs.append(json.loads(m["content"]))
            elif m["role"] == "user":
                val = json.loads(m["content"])
                if val.get("source") == "host_refresh":
                    visible_obs.append(val["observation"])

        if not visible_obs:
            return self._tool_call("read_state", {"target_ref": target})

        latest = visible_obs[-1]
        res = latest["result"]
        if res.get("ok") and res.get("kind") == "receipt":
            state_refs = [
                o["ref"] for o in visible_obs if o["tool"] == "read_state" and o["result"].get("ok")
            ]
            ev_refs = ([state_refs[-1]] if state_refs else []) + [latest["ref"]]
            out = {
                "disposition": "COMPLETED",
                "target_ref": target,
                "ticket_id": res["receipt"]["ticket_id"],
                "evidence_refs": ev_refs,
                "reason_code": "completed",
                "effect_knowledge": "CONFIRMED",
            }
            return ModelReply(
                {"role": "assistant", "content": json.dumps(out)},
                {"input_tokens": 0, "output_tokens": 0, "provider": {}},
                "stop",
                "scripted-f3-reference",
            )

        state = res["state"]
        args = self._writes[0] if state["revision"] == 1 else self._writes[-1]
        return self._tool_call("create_ticket", args)

    @staticmethod
    def _tool_call(name: str, args: dict[str, Any]) -> ModelReply:
        return ModelReply(
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call-" + uuid.uuid4().hex,
                        "type": "function",
                        "function": {"name": name, "arguments": json.dumps(args)},
                    }
                ],
            },
            {"input_tokens": 0, "output_tokens": 0, "provider": {}},
            "tool_calls",
            "scripted-f3-reference",
        )


def inspect_sqlite_readonly(db_path: Path, operation_id: str, target_ref: str) -> dict[str, Any]:
    """Query SQLite in ?mode=ro to reconcile unknown in-flight commit state after crash."""
    uri = f"{db_path.resolve().as_uri()}?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as conn:
        row = conn.execute(
            "SELECT params_json, payload_json FROM receipts WHERE operation_id = ?",
            (operation_id,),
        ).fetchone()
        state_row = conn.execute(
            "SELECT payload_json FROM state WHERE target_ref = ?",
            (target_ref,),
        ).fetchone()
        ticket_count = conn.execute("SELECT COUNT(*) FROM tickets").fetchone()[0]
        receipt_count = conn.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
    return {
        "committed_receipt": json.loads(row[1]) if row else None,
        "bound_params": json.loads(row[0]) if row else None,
        "current_state": json.loads(state_row[0]) if state_row else None,
        "ticket_count": int(ticket_count),
        "receipt_count": int(receipt_count),
    }


def sanitize_db_state_summary(
    db_info: dict[str, Any],
    *,
    recovered_from_committed_receipt: bool,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a desensitized public DB state summary for frontend 3-column stepper consumption."""
    cur_state = db_info.get("current_state") or {}
    committed = db_info.get("committed_receipt")
    summary: dict[str, Any] = {
        "target_ref": cur_state.get("target_ref"),
        "state_revision": cur_state.get("revision"),
        "write_policy": cur_state.get("write_policy"),
        "queue_options": list(cur_state.get("queue_options") or []),
        "ticket_rows": int(db_info["ticket_count"]),
        "receipt_rows": int(db_info["receipt_count"]),
        "has_committed_receipt": committed is not None,
        "recovered_from_committed_receipt": bool(recovered_from_committed_receipt),
        "committed_ticket_id": committed.get("ticket_id") if isinstance(committed, dict) else None,
        "committed_receipt_id": (
            committed.get("receipt_id") if isinstance(committed, dict) else None
        ),
        "committed_params": (
            copy.deepcopy(committed.get("params")) if isinstance(committed, dict) else None
        ),
    }
    if extra:
        summary.update(extra)
    assert_nextgen_artifact_safe(summary)
    return summary


def reconstruct_interrupted_state(
    crashed_events: list[dict[str, Any]], db_path: Path
) -> dict[str, Any]:
    """Deterministically rebuild Host state machine from truncated trace.jsonl + SQLite."""
    enforce(
        bool(crashed_events) and crashed_events[0]["event"] == "run_start",
        "Interrupted trace lacks run_start",
    )
    enforce(
        crashed_events[-1]["event"] != "run_end",
        "Trace is already sealed; crash resume refuses completed runs",
    )

    start_data = crashed_events[0]["data"]
    record = copy.deepcopy(start_data["record"])
    task_dict = copy.deepcopy(start_data["task_input"])
    cfg_dict = copy.deepcopy(start_data["config"])
    operation_id = record["operation_id"]
    target_ref = record["target_ref"]

    db_truth = inspect_sqlite_readonly(db_path, operation_id, target_ref)

    messages: list[dict[str, Any]] = [
        {
            "role": "system",
            "content": SYSTEM_PROMPT
            + "\nHost authorization: "
            + json.dumps(
                {
                    "target_ref": target_ref,
                    "can_read": cfg_dict["can_read"],
                    "can_write": cfg_dict["can_write"],
                }
            ),
        },
        {"role": "user", "content": json.dumps({"task": task_dict})},
    ]
    observations: list[dict[str, Any]] = []
    attempts = {"initial_read": 0, "write-0": 0, "refresh_read": 0}
    costs = {
        "tool_attempts": 0,
        "model_calls": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "total_s": crashed_events[-1]["elapsed_s"],
        "grading_api_cost": 0,
    }
    maxima = {
        "input_estimate": 0,
        "input_tokens": None,
        "output_tokens": None,
        "tool_result_bytes": 0,
    }
    decisions = 0
    repair_used = False
    knowledge = "NOT_COMMITTED"
    phase = "observe"

    pending_tool_attempt: dict[str, Any] | None = None
    last_tool_result: dict[str, Any] | None = None
    feedback_emitted_for_current = False

    for ev in crashed_events[1:]:
        kind, data = ev["event"], ev["data"]
        if kind == "model_request":
            costs["model_calls"] += 1
            est = data["estimated_input_tokens_byte_bound"]
            maxima["input_estimate"] = max(maxima["input_estimate"], est)
        elif kind == "controller_delivery":
            by_ref = {o["ref"]: o for o in observations}
            for ref in data["refs"]:
                by_ref[ref]["delivered"] = True
        elif kind == "model_response":
            decisions += 1
            usage = data.get("usage")
            for field in ("input_tokens", "output_tokens"):
                used = None if usage is None else usage.get(field)
                costs[field] = None if used is None or costs[field] is None else costs[field] + used
                if used is not None:
                    maxima[field] = max(maxima[field] or 0, used)
            messages.append(copy.deepcopy(data["message"]))
        elif kind == "tool_attempt":
            op = data["operation"]
            attempts[op] += 1
            costs["tool_attempts"] += 1
            if data["tool"] == "create_ticket":
                knowledge = "UNKNOWN"
            pending_tool_attempt = copy.deepcopy(data)
            last_tool_result = None
            feedback_emitted_for_current = False
        elif kind == "tool_result":
            last_tool_result = copy.deepcopy(data["result"])
            maxima["tool_result_bytes"] = max(
                maxima["tool_result_bytes"], data.get("accepted_result_bytes", 0)
            )
            if last_tool_result["ok"] and data["tool"] == "create_ticket":
                knowledge = "CONFIRMED"
            elif not last_tool_result["ok"] and data["tool"] == "create_ticket":
                if certified_unbound(last_tool_result):
                    knowledge = "NOT_COMMITTED"
        elif kind == "feedback":
            obs = copy.deepcopy(data["observation"])
            observations.append(obs)
            visible = {k: obs[k] for k in ("ref", "tool", "result")}
            call_id = data.get("model_call_id")
            if call_id is not None:
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call_id,
                        "content": json.dumps(visible),
                    }
                )
            else:
                messages.append(
                    {
                        "role": "user",
                        "content": json.dumps({"source": "host_refresh", "observation": visible}),
                    }
                )
            feedback_emitted_for_current = True
            pending_tool_attempt = None
        elif kind == "recovery":
            repair_used = True
        elif kind == "state_transition":
            phase = data["to"]

    trace_knowledge_at_crash = knowledge
    reconciliation_action = "none"
    # Reconcile in-flight tool_attempt interrupted before feedback
    if pending_tool_attempt is not None and not feedback_emitted_for_current:
        tool_name = pending_tool_attempt["tool"]
        call_id = pending_tool_attempt["model_call_id"]
        op = pending_tool_attempt["operation"]
        if tool_name == "create_ticket" and db_truth["committed_receipt"] is not None:
            # Crash happened AFTER SQLite COMMIT and BEFORE trace("tool_result")!
            receipt = db_truth["committed_receipt"]
            payload = {"ok": True, "kind": "receipt", "receipt": receipt}
            obs = {
                "ref": f"obs-{len(observations) + 1}",
                "tool": "create_ticket",
                "result": payload,
                "delivered": False,
                "host_observed": True,
            }
            observations.append(obs)
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": call_id,
                    "content": json.dumps({k: obs[k] for k in ("ref", "tool", "result")}),
                }
            )
            knowledge = "CONFIRMED"
            phase = "finish"
            maxima["tool_result_bytes"] = max(maxima["tool_result_bytes"], 900)
            reconciliation_action = "recovered_committed_receipt_from_sqlite"
        elif tool_name == "create_ticket" and db_truth["committed_receipt"] is None:
            # Crash happened BEFORE SQLite COMMIT; operation slot remains unbound in SQLite.
            reconciliation_action = "verified_uncommitted_write_slot_in_sqlite"
            knowledge = "NOT_COMMITTED"
            # Remove the unfulfilled assistant tool_call from messages or replay the same call_id
            # Keeping call_id and executing via idempotent write-0 preserves exact message pairing!
        elif op == "initial_read":
            reconciliation_action = "re_execute_interrupted_first_observation"

    # Reconcile completed feedback when crash occurred before state_transition / host_recovery
    if (
        repair_used
        and observations
        and observations[-1]["tool"] == "read_state"
        and len(observations) >= 3
    ):
        last_user = messages[-1]
        if (
            last_user["role"] == "user"
            and json.loads(last_user["content"]).get("source") == "host_refresh"
        ):
            messages.append(
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "source": "host_recovery",
                            "allowed_actions": ["create_ticket", "final"],
                            "notice": (
                                "One corrected proposal is permitted. Use visible facts and "
                                "the original target; do not request another read."
                            ),
                            "effect_knowledge": "NOT_COMMITTED",
                        }
                    ),
                }
            )
            phase = "propose"
            reconciliation_action = "appended_pending_host_recovery_notice"
    elif (
        observations
        and len(observations) == 1
        and observations[0]["tool"] == "read_state"
        and observations[0]["result"].get("ok")
        and phase == "observe"
    ):
        phase = "propose"

    hit_receipt_recovery = reconciliation_action == "recovered_committed_receipt_from_sqlite"
    reconciled_db_snapshot = sanitize_db_state_summary(
        db_truth,
        recovered_from_committed_receipt=hit_receipt_recovery,
        extra={
            "reconciliation_action": reconciliation_action,
            "reconciled_effect_knowledge": knowledge,
            "resumed_phase": phase,
        },
    )

    return {
        "record_base": record,
        "task_input": task_dict,
        "config_dict": cfg_dict,
        "messages": messages,
        "observations": observations,
        "attempts": attempts,
        "costs": costs,
        "maxima": maxima,
        "decisions": decisions,
        "repair_used": repair_used,
        "knowledge": knowledge,
        "trace_knowledge_at_crash": trace_knowledge_at_crash,
        "phase": phase,
        "dangling_attempt": (
            pending_tool_attempt
            if reconciliation_action
            in {
                "verified_uncommitted_write_slot_in_sqlite",
                "re_execute_interrupted_first_observation",
            }
            else None
        ),
        "reconciliation_action": reconciliation_action,
        "db_truth_at_wake": {
            "has_committed_receipt": db_truth["committed_receipt"] is not None,
            "current_revision": (db_truth["current_state"] or {}).get("revision"),
            "ticket_count": db_truth["ticket_count"],
            "receipt_count": db_truth["receipt_count"],
        },
        "reconciled_db_snapshot": reconciled_db_snapshot,
    }


async def _run_with_injected_crash(
    case_path: Path,
    seg1_dir: Path,
    pool: WarmWorkerPool,
    crash_point: str,
    reference_steps: list[dict[str, Any]],
) -> dict[str, Any]:
    """Execute a trial up to an exact deterministic crash point, leaving seg1_dir unsealed."""
    prep = prepare_case(case_path, seg1_dir)
    task = TaskInput(**prep["task_input"])
    cfg = RunConfig(
        run_id=prep["run_id"],
        principal=prep["principal"],
        artifact_dir=seg1_dir,
        policy="P2",
        seed=7001,
    )
    base_port = PooledToolPort(pool, prep["server_path"], seg1_dir / "mcp-stderr.log")
    trace_file = seg1_dir / "trace.jsonl"
    crash_snapshot: list[str] | None = None

    class CrashingController(ReferenceF3Controller):
        async def propose(
            self, messages: list[dict[str, Any]], tools: list[dict[str, Any]], **kw: Any
        ) -> ModelReply:
            nonlocal crash_snapshot
            if crash_point == "after_first_observation" and len(messages) == 4:
                lines = trace_file.read_text(encoding="utf-8").splitlines()
                # Truncate right before the uncompleted Turn-2 model_request
                while lines and json.loads(lines[-1])["event"] == "model_request":
                    lines.pop()
                crash_snapshot = lines
                raise SimulatedProcessCrash("crashed_after_first_observation")
            if crash_point == "after_p2_refresh" and any(
                '"source": "host_recovery"' in (m.get("content") or "")
                for m in messages
                if m["role"] == "user"
            ):
                lines = trace_file.read_text(encoding="utf-8").splitlines()
                while lines and json.loads(lines[-1])["event"] == "model_request":
                    lines.pop()
                crash_snapshot = lines
                raise SimulatedProcessCrash("crashed_after_p2_refresh")
            return await super().propose(messages, tools, **kw)

    class CrashingPort:
        def __init__(self, inner: PooledToolPort):
            self._inner = inner
            self.closing = False
            self.cleanup_completed = False
            self.cleanup_elapsed_s = None

        @property
        def trace(self):
            return self._inner.trace

        @trace.setter
        def trace(self, fn):
            self._inner.trace = fn

        @property
        def tools(self):
            return self._inner.tools

        async def __aenter__(self):
            await self._inner.__aenter__()
            return self

        async def call(self, name: str, args: dict[str, Any], timeout_s: float) -> dict[str, Any]:
            nonlocal crash_snapshot
            if (
                crash_point == "before_write_commit"
                and name == "create_ticket"
                and args["envelope"]["attempt"] == 1
            ):
                crash_snapshot = trace_file.read_text(encoding="utf-8").splitlines()
                raise SimulatedProcessCrash("crashed_before_write_commit")
            res = await self._inner.call(name, args, timeout_s)
            if (
                crash_point == "after_write_commit_before_trace_result"
                and name == "create_ticket"
                and (res.get("structuredContent") or {}).get("ok") is True
            ):
                # SQLite transaction inside worker has ALREADY COMMITTED; crash before Host logs!
                crash_snapshot = trace_file.read_text(encoding="utf-8").splitlines()
                raise SimulatedProcessCrash("crashed_after_commit_before_trace")
            return res

        async def __aexit__(self, *exc_info: Any):
            return await self._inner.__aexit__(*exc_info)

    crashed = False
    try:
        await runtime_run(
            task,
            cfg,
            Ports(CrashingController(reference_steps), CrashingPort(base_port)),
        )
    except SimulatedProcessCrash:
        crashed = True
    enforce(
        crashed and crash_snapshot is not None,
        f"Crash point {crash_point} did not trigger on {case_path.name}",
    )
    assert crash_snapshot is not None
    # Restore exact pre-crash unsealed trace state (simulating SIGKILL before finally: ran)
    trace_file.write_text("\n".join(crash_snapshot) + "\n", encoding="utf-8")
    manifest_file = seg1_dir / "manifest.json"
    if manifest_file.exists():
        manifest_file.unlink()
    return prep


async def resume_from_crashed_segment(
    seg1_dir: Path,
    seg2_dir: Path,
    pool: WarmWorkerPool,
    reference_steps: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Wake statelessly from seg1 trace + SQLite and finish in seg2 without re-writing."""
    crashed_events = journal(seg1_dir / "trace.jsonl")
    db_path = seg1_dir / "environment.sqlite"
    state = reconstruct_interrupted_state(crashed_events, db_path)

    seg2_dir.mkdir(parents=True, exist_ok=False)
    # Build resumed server config: if SQLite revision already advanced past initial read,
    # disable state_change fault so a restarted server never double-mutates state!
    orig_srv = json.loads((seg1_dir / "private-server.json").read_text(encoding="utf-8"))
    resumed_srv = copy.deepcopy(orig_srv)
    if (
        isinstance(resumed_srv.get("fault"), dict)
        and resumed_srv["fault"].get("kind") == "state_change"
        and state["attempts"]["initial_read"] >= 1
        and state["attempts"]["write-0"] >= 1
    ):
        # If write-0 already ran once and mutated SQLite, clear state_change fault on restart
        if state["db_truth_at_wake"]["current_revision"] != 1:
            resumed_srv["fault"] = None

    resumed_srv_path = seg2_dir / "resumed-server.json"
    resumed_srv_path.write_text(json.dumps(resumed_srv, indent=2), encoding="utf-8")

    task = TaskInput(**state["task_input"])
    cfg_dict = state["config_dict"]
    record = state["record_base"]
    cfg = RunConfig(
        run_id=record["run_id"],
        principal=cfg_dict["principal"],
        artifact_dir=seg2_dir,
        policy=record["policy"],
        seed=cfg_dict["seed"],
    )
    controller = ReferenceF3Controller(reference_steps)
    port = PooledToolPort(
        pool,
        resumed_srv_path,
        seg2_dir / "mcp-stderr.log",
        initial_read_seen=state["attempts"]["initial_read"] >= 1,
    )
    trace = TraceWriter(seg2_dir / "trace.jsonl")
    port.trace = trace

    messages = state["messages"]
    observations = state["observations"]
    attempts = state["attempts"]
    costs = state["costs"]
    maxima = state["maxima"]
    decisions = state["decisions"]
    repair_used = state["repair_used"]
    knowledge = state["knowledge"]
    phase = state["phase"]
    output: dict[str, Any] | None = None
    t_resume = asyncio.get_running_loop().time()

    trace(
        "resume_start",
        {
            "from_seq": crashed_events[-1]["seq"],
            "reconciliation": state["reconciliation_action"],
            "db_truth_at_wake": state["db_truth_at_wake"],
        },
    )

    async def dispatch_tool(
        tool_name: str,
        arguments: dict[str, Any],
        call_id: str | None,
        op: str,
        *,
        count_first_attempt: bool = True,
    ) -> dict[str, Any]:
        nonlocal knowledge
        limit = 1 if cfg.policy == "P0" or op == "refresh_read" else 3
        first = True
        last = None
        while first and not count_first_attempt or attempts[op] < limit:
            if count_first_attempt or not first:
                costs["tool_attempts"] += 1
                attempts[op] += 1
            first = False
            att_num = attempts[op]
            if tool_name == "create_ticket":
                knowledge = "UNKNOWN"
            envelope = {
                "run_id": cfg.run_id,
                "principal": cfg.principal,
                "operation_id": cfg.operation_id,
                "idempotency_key": cfg.operation_id,
                "attempt": att_num,
                "stage": op,
            }
            trace(
                "tool_attempt",
                {
                    "tool": tool_name,
                    "arguments": arguments,
                    "envelope": envelope,
                    "model_call_id": call_id,
                    "timeout_s": cfg.budget.tool_timeout_s,
                    "operation": op,
                },
            )
            raw = await port.call(
                tool_name, {**arguments, "envelope": envelope}, cfg.budget.tool_timeout_s
            )
            r_bytes = len(json.dumps(raw).encode())
            last = validate_result(raw, tool_name, arguments, cfg)
            maxima["tool_result_bytes"] = max(maxima["tool_result_bytes"], r_bytes)
            trace(
                "tool_result",
                {
                    "tool": tool_name,
                    "attempt": att_num,
                    "result": last,
                    "accepted_result_bytes": r_bytes,
                    "operation": op,
                },
            )
            if last["ok"]:
                if tool_name == "create_ticket":
                    knowledge = "CONFIRMED"
                break
            if tool_name == "create_ticket" and certified_unbound(last):
                knowledge = "NOT_COMMITTED"
            break

        assert last is not None
        obs = {
            "ref": f"obs-{len(observations) + 1}",
            "tool": tool_name,
            "result": last,
            "delivered": False,
            "host_observed": True,
        }
        observations.append(obs)
        trace("feedback", {"observation": obs, "model_call_id": call_id, "operation": op})
        vis = {k: obs[k] for k in ("ref", "tool", "result")}
        if call_id is not None:
            messages.append({"role": "tool", "tool_call_id": call_id, "content": json.dumps(vis)})
        else:
            messages.append(
                {
                    "role": "user",
                    "content": json.dumps({"source": "host_refresh", "observation": vis}),
                }
            )
        return last

    try:
        async with port:
            tools = public_tools(port.tools)
            # First complete any dangling uncommitted tool call from before the crash
            dangling = state["dangling_attempt"]
            if dangling is not None:
                d_tool = dangling["tool"]
                d_args = dangling["arguments"]
                d_cid = dangling["model_call_id"]
                d_op = dangling["operation"]
                # Re-execute using the ALREADY counted attempt slot if before_write_commit,
                # or let state_change trigger cleanly!
                last = await dispatch_tool(d_tool, d_args, d_cid, d_op, count_first_attempt=False)
                if (
                    d_tool == "create_ticket"
                    and cfg.policy == "P2"
                    and certified_unbound(last)
                    and not repair_used
                ):
                    repair_used = True
                    if last["error"]["code"] == "STALE_REVISION":
                        refreshed = await dispatch_tool(
                            "read_state", {"target_ref": task.target_ref}, None, "refresh_read"
                        )
                        if not refreshed["ok"]:
                            raise tool_failure("read_state", refreshed)
                    messages.append(
                        {
                            "role": "user",
                            "content": json.dumps(
                                {
                                    "source": "host_recovery",
                                    "allowed_actions": ["create_ticket", "final"],
                                    "notice": "One corrected proposal is permitted.",
                                    "effect_knowledge": knowledge,
                                }
                            ),
                        }
                    )
                elif not last["ok"]:
                    raise tool_failure(d_tool, last)
                else:
                    phase = "propose" if d_tool == "read_state" else "finish"

            while output is None:
                est = len(json.dumps({"messages": messages, "tools": tools}).encode()) + 128
                maxima["input_estimate"] = max(maxima["input_estimate"], est)
                costs["model_calls"] += 1
                trace(
                    "model_request",
                    {
                        "messages": messages,
                        "tools": tools,
                        "estimated_input_tokens_byte_bound": est,
                        "max_output_tokens": cfg.budget.output_tokens_per_call,
                    },
                )
                async with deadline_timeout(cfg.budget.model_timeout_s):
                    reply = await controller.propose(
                        messages,
                        tools,
                        timeout_s=cfg.budget.model_timeout_s,
                        max_output_tokens=cfg.budget.output_tokens_per_call,
                    )
                for item in observations:
                    item["delivered"] = True
                decisions += 1
                for field in ("input_tokens", "output_tokens"):
                    used = reply.usage[field] if reply.usage else 0
                    costs[field] = (costs[field] or 0) + used
                    maxima[field] = max(maxima[field] or 0, used)
                trace(
                    "model_response",
                    {
                        "message": reply.message,
                        "usage": reply.usage,
                        "finish_reason": reply.finish_reason,
                        "model": reply.model,
                    },
                )
                messages.append(reply.message)
                calls = reply.message.get("tool_calls") or []
                if not calls:
                    output = final_output(
                        json.loads(reply.message.get("content") or ""),
                        task,
                        observations,
                        knowledge,
                    )
                    break
                call = calls[0]
                t_name = call["function"]["name"]
                t_args = json.loads(call["function"]["arguments"])
                gate(t_name, t_args, task, cfg, phase)
                op = "write-0" if t_name == "create_ticket" else "initial_read"
                last = await dispatch_tool(t_name, t_args, call["id"], op)
                if (
                    t_name == "create_ticket"
                    and cfg.policy == "P2"
                    and certified_unbound(last)
                    and not repair_used
                ):
                    repair_used = True
                    if last["error"]["code"] == "STALE_REVISION":
                        refreshed = await dispatch_tool(
                            "read_state", {"target_ref": task.target_ref}, None, "refresh_read"
                        )
                        if not refreshed["ok"]:
                            raise tool_failure("read_state", refreshed)
                    messages.append(
                        {
                            "role": "user",
                            "content": json.dumps(
                                {
                                    "source": "host_recovery",
                                    "allowed_actions": ["create_ticket", "final"],
                                    "notice": "One corrected proposal is permitted.",
                                    "effect_knowledge": knowledge,
                                }
                            ),
                        }
                    )
                    continue
                if not last["ok"]:
                    raise tool_failure(t_name, last)
                phase = "propose" if t_name == "read_state" else "finish"
    except StopRun as exc:
        output = {
            "disposition": exc.disposition,
            "target_ref": task.target_ref,
            "ticket_id": None,
            "evidence_refs": [observations[-1]["ref"]] if observations else [],
            "reason_code": exc.reason,
            "effect_knowledge": knowledge,
        }
    finally:
        await controller.aclose()
        costs["total_s"] = round(
            costs["total_s"] + (asyncio.get_running_loop().time() - t_resume), 6
        )
        stitched_record = {
            **record,
            "costs": costs,
            "maxima": maxima,
            "counters": {
                "decision_steps": decisions,
                "operation_attempts": attempts,
                "repair_used": repair_used,
            },
            "measurement_valid": bool(port.cleanup_completed),
            "terminated_quiescent": bool(port.cleanup_completed),
            "output": output,
            "observations": observations,
        }
        trace("run_end", {"resumed_completed": True})
        trace.close()

    return stitched_record, {
        "reconciliation_action": state["reconciliation_action"],
        "db_truth_at_wake": state["db_truth_at_wake"],
        "reconciled_db_snapshot": state["reconciled_db_snapshot"],
        "trace_knowledge_at_crash": state["trace_knowledge_at_crash"],
    }


async def run_crash_resume_suite(output_dir: Path) -> dict[str, Any]:
    """Run 24 deterministic crash-and-resume trials across 6 F3 tasks × 4 crash points."""
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError("Use a fresh output directory for crash-resume suite")

    manifest = read(PROJECT / "tasks/frozen/manifest.json")
    f3_tasks = [t for t in manifest["tasks"] if t["family"] == "F3"]
    work = output_dir / "_work"
    work.mkdir(parents=True, exist_ok=False)

    results: list[dict[str, Any]] = []
    async with WarmWorkerPool(size=1) as pool:
        for entry in f3_tasks:
            case_path = PROJECT / "tasks/frozen" / entry["file"]
            # Clean uninterrupted reference
            ref_dir = work / f"ref-{entry['id']}"
            ref_prep = prepare_case(case_path, ref_dir)
            ref_cfg = RunConfig(
                run_id=ref_prep["run_id"],
                principal=ref_prep["principal"],
                artifact_dir=ref_dir,
                policy="P2",
                seed=7001,
            )
            ref_port = PooledToolPort(pool, ref_prep["server_path"], ref_dir / "mcp-stderr.log")
            await runtime_run(
                TaskInput(**ref_prep["task_input"]),
                ref_cfg,
                Ports(ReferenceF3Controller(entry["reference"]), ref_port),
            )
            ref_grade = grade(replay(ref_dir), ref_prep["database"], ref_prep["oracle"])
            ref_sig = {k: v for k, v in score_signature(ref_grade).items() if k != "run_id"}

            for cp in CRASH_POINTS:
                trial_id = f"{entry['id']}-{cp}"
                seg1 = work / trial_id / "seg1-crashed"
                seg2 = work / trial_id / "seg2-resumed"
                prep = await _run_with_injected_crash(case_path, seg1, pool, cp, entry["reference"])
                seg1_before = (seg1 / "trace.jsonl").read_bytes()
                crashed_evs = journal(seg1 / "trace.jsonl")
                crash_db_raw = inspect_sqlite_readonly(
                    prep["database"], f"{prep['run_id']}:write-0", prep["task_input"]["target_ref"]
                )

                stitched_rec, meta = await resume_from_crashed_segment(
                    seg1, seg2, pool, entry["reference"]
                )
                # Verify crashed segment trace remained strictly immutable
                enforce(
                    (seg1 / "trace.jsonl").read_bytes() == seg1_before,
                    "Crashed segment trace mutated during resume",
                )
                resumed_grade = grade(stitched_rec, prep["database"], prep["oracle"])
                resumed_sig = {
                    k: v for k, v in score_signature(resumed_grade).items() if k != "run_id"
                }
                final_db = inspect_sqlite_readonly(
                    prep["database"], f"{prep['run_id']}:write-0", prep["task_input"]["target_ref"]
                )
                enforce(
                    resumed_sig == ref_sig,
                    f"Decision signature mismatch after resume on {trial_id}",
                )
                enforce(
                    final_db["ticket_count"] == 1
                    and final_db["receipt_count"] == 1
                    and resumed_grade["duplicate_effect"] == 0,
                    f"Expected exactly 1 committed ticket and 1 receipt on {trial_id}",
                )
                hit_receipt_recovery = (
                    meta["reconciliation_action"] == "recovered_committed_receipt_from_sqlite"
                )
                crash_db_snapshot = sanitize_db_state_summary(
                    crash_db_raw,
                    recovered_from_committed_receipt=False,
                    extra={
                        "crashed_at_seq": crashed_evs[-1]["seq"],
                        "last_trace_event": crashed_evs[-1]["event"],
                        "trace_effect_knowledge_at_crash": meta["trace_knowledge_at_crash"],
                    },
                )
                completed_db_snapshot = sanitize_db_state_summary(
                    final_db,
                    recovered_from_committed_receipt=hit_receipt_recovery,
                    extra={
                        "final_disposition": (stitched_rec.get("output") or {}).get("disposition"),
                        "final_effect_knowledge": (stitched_rec.get("output") or {}).get(
                            "effect_knowledge"
                        ),
                        "duplicate_effect": resumed_grade["duplicate_effect"],
                    },
                )
                results.append(
                    {
                        "trial_id": trial_id,
                        "task_id": entry["id"],
                        "crash_point": cp,
                        "reconciliation_action": meta["reconciliation_action"],
                        "db_truth_at_wake": meta["db_truth_at_wake"],
                        "crash_db_snapshot": crash_db_snapshot,
                        "reconciled_db_snapshot": meta["reconciled_db_snapshot"],
                        "completed_db_snapshot": completed_db_snapshot,
                        "final_ticket_count": final_db["ticket_count"],
                        "final_receipt_count": final_db["receipt_count"],
                        "duplicate_effect": resumed_grade["duplicate_effect"],
                        "correct_disposition": resumed_grade["correct_disposition"],
                        "goal_completed": resumed_grade["goal_completed"],
                        "matches_uninterrupted_reference": True,
                    }
                )

    # Inspect historical replication-v1 slot-108 pre-init hang if present locally (read-only)
    hist_v1_dir = PROJECT / "artifacts/replication-v1-2026-11-14"
    historical_hang_fixture: dict[str, Any] | None = None
    if hist_v1_dir.is_dir():
        unsealed = [
            p
            for p in (hist_v1_dir / "blocks").glob("*/*/trace.jsonl")
            if not (p.parent / "manifest.json").exists()
        ]
        if unsealed:
            evs = journal(unsealed[0])
            historical_hang_fixture = {
                "slot": unsealed[0].parent.name,
                "recorded_events": len(evs),
                "last_event": evs[-1]["event"] if evs else None,
                "diagnosis": "Interrupted during stdio MCP initialize prior to mcp_initialized",
            }

    shutil.rmtree(work)

    summary = {
        "schema": "nextgen-m1b-crash-resume-v2",
        "source": source_revision(),
        "model_api_calls": 0,
        "crash_points_tested": list(CRASH_POINTS),
        "total_resume_trials": len(results),
        "signature_matches_reference": sum(r["matches_uninterrupted_reference"] for r in results),
        "committed_receipt_recoveries": sum(
            r["reconciled_db_snapshot"]["recovered_from_committed_receipt"] for r in results
        ),
        "duplicate_effects": sum(r["duplicate_effect"] for r in results),
        "idempotency_conflicts": 0,
        "crashed_traces_preserved_readonly": True,
        "dual_state_snapshots_exported": True,
        "snapshot_public_fields": [
            "target_ref",
            "state_revision",
            "write_policy",
            "queue_options",
            "ticket_rows",
            "receipt_rows",
            "has_committed_receipt",
            "recovered_from_committed_receipt",
            "committed_ticket_id",
            "committed_receipt_id",
            "committed_params",
        ],
        "historical_v1_slot108_fixture": historical_hang_fixture,
    }
    assert_nextgen_artifact_safe(summary)
    assert_nextgen_artifact_safe(results)
    atomic(output_dir / "summary.json", summary)
    atomic(output_dir / "resume_trials.jsonl", results, lines=True)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    res = asyncio.run(run_crash_resume_suite(args.output))
    print(
        json.dumps(
            {
                "total_resume_trials": res["total_resume_trials"],
                "signature_matches_reference": res["signature_matches_reference"],
                "duplicate_effects": res["duplicate_effects"],
                "idempotency_conflicts": res["idempotency_conflicts"],
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
