"""Offline unit tests for post-v2 latency/protocol diagnostics and secure trajectory export."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parents[1]

FIXTURE_AND_EXPORT_SCRIPT = r'''
import copy, json, subprocess, sys
from pathlib import Path
import pytest
from evals import diagnostics, post_training
from evals.evidence_audit import fingerprint
from evals.formal import atomic, journal
from evals.post_training import (
    SecurityViolationError,
    assert_preference_pair_safe,
    assert_sft_sample_safe,
)
from evals.replication_v2 import validate as validate_v2_contract
from harness_lab.runtime import SYSTEM_PROMPT, public_tools

RAW_MCP_TOOLS = [
    {
        "name": "read_state",
        "description": "Read the current target state inside this isolated run.",
        "inputSchema": {
            "$defs": {"Envelope": {"type": "object"}},
            "properties": {
                "target_ref": {"title": "Target Ref", "type": "string"},
                "envelope": {"$ref": "#/$defs/Envelope"},
            },
            "required": ["target_ref", "envelope"],
            "type": "object",
            "additionalProperties": False,
        },
    },
    {
        "name": "create_ticket",
        "description": "Create at most one ticket using the Host-bound operation.",
        "inputSchema": {
            "$defs": {"Envelope": {"type": "object"}},
            "properties": {
                "target_ref": {"title": "Target Ref", "type": "string"},
                "expected_revision": {"title": "Expected Revision", "type": "integer"},
                "queue": {"title": "Queue", "type": "string"},
                "priority": {
                    "enum": ["normal", "urgent"],
                    "title": "Priority",
                    "type": "string",
                },
                "envelope": {"$ref": "#/$defs/Envelope"},
            },
            "required": [
                "target_ref",
                "expected_revision",
                "queue",
                "priority",
                "envelope",
            ],
            "type": "object",
            "additionalProperties": False,
        },
    },
]


def make_sealed_run(
    run_dir,
    *,
    run_id,
    task_id,
    target_ref,
    policy,
    turns,
    observations,
    repair_used=False,
    output,
    include_backoff=False,
    host_error=False,
):
    run_dir.mkdir(parents=True, exist_ok=False)
    tools = public_tools(RAW_MCP_TOOLS)
    limits = {
        "model_calls": 6,
        "tool_attempts": 6,
        "decision_steps": 6,
        "output_tokens_per_call": 800,
        "input_tokens_per_call": 16000,
        "tool_result_bytes": 16000,
        "total_s": 120.0,
        "cleanup_s": 6.0,
        "tool_timeout_s": 0.18,
        "model_timeout_s": 30.0,
    }
    record_base = {
        "run_id": run_id,
        "operation_id": f"{run_id}:write-0",
        "task_id": task_id,
        "target_ref": target_ref,
        "policy": policy,
        "source": {"commit": "synthetic-commit", "dirty": False},
        "limits": limits,
        "timing": {"clock": "perf_counter"},
        "budget": {"tool_attempts": 6, "model_calls": 6, "total_s": 120.0},
    }
    task_input = {
        "task_id": task_id,
        "instruction": f"Synthetic instruction for {target_ref}.",
        "target_ref": target_ref,
        "as_of": "2026-11-17T00:00:00Z",
    }
    events = []
    t = 0.001

    def emit(event, data, dt=0.001):
        nonlocal t
        t = round(t + dt, 6)
        events.append({
            "seq": len(events) + 1,
            "elapsed_s": t,
            "event": event,
            "data": data,
        })

    emit("run_start", {"record": copy.deepcopy(record_base), "task_input": task_input}, dt=0.0)
    emit("mcp_initialized", {"protocolVersion": "2025-11-25"}, dt=0.200)
    emit("mcp_tools", {"tools": RAW_MCP_TOOLS}, dt=0.010)

    max_est = in_tok_total = out_tok_total = max_in_tok = max_out_tok = max_res_bytes = 0
    op_counts = {"initial_read": 0, "write-0": 0, "refresh_read": 0}
    delivered_idx = obs_cursor = 0

    for turn_idx, (req_msgs, resp_msg, finish_reason) in enumerate(turns):
        est = len(json.dumps({"messages": req_msgs, "tools": tools}).encode()) + 128
        max_est = max(max_est, est)
        emit(
            "model_request",
            {
                "messages": copy.deepcopy(req_msgs),
                "tools": copy.deepcopy(tools),
                "estimated_input_tokens_byte_bound": est,
                "max_output_tokens": 800,
            },
            dt=0.001,
        )
        if delivered_idx < obs_cursor:
            refs = [observations[i]["ref"] for i in range(delivered_idx, obs_cursor)]
            emit("controller_delivery", {"refs": refs}, dt=0.499)
            delivered_idx = obs_cursor
            resp_dt = 0.001
        else:
            resp_dt = 0.500
        in_tok, out_tok = 100 + 20 * turn_idx, 30 + 5 * turn_idx
        in_tok_total += in_tok
        out_tok_total += out_tok
        max_in_tok = max(max_in_tok, in_tok)
        max_out_tok = max(max_out_tok, out_tok)
        emit(
            "model_response",
            {
                "message": copy.deepcopy(resp_msg),
                "usage": {
                    "input_tokens": in_tok,
                    "output_tokens": out_tok,
                    "provider": {
                        "prompt_tokens_details": {"cached_tokens": 64},
                        "completion_tokens_details": {"reasoning_tokens": 10},
                    },
                },
                "finish_reason": finish_reason,
                "model": "synthetic-model",
            },
            dt=resp_dt,
        )
        calls = resp_msg.get("tool_calls") or []
        if calls:
            call = calls[0]
            tool_name = call["function"]["name"]
            args = json.loads(call["function"]["arguments"])
            op = "initial_read" if tool_name == "read_state" else "write-0"
            if include_backoff and op == "write-0" and op_counts[op] == 0:
                op_counts[op] += 1
                env = {
                    "run_id": run_id,
                    "principal": "dev-user",
                    "operation_id": f"{run_id}:write-0",
                    "idempotency_key": f"{run_id}:write-0",
                    "attempt": op_counts[op],
                    "stage": op,
                }
                emit(
                    "tool_attempt",
                    {
                        "tool": tool_name,
                        "arguments": args,
                        "envelope": env,
                        "model_call_id": call["id"],
                        "timeout_s": 0.18,
                        "operation": op,
                    },
                    dt=0.001,
                )
                emit(
                    "tool_result",
                    {
                        "tool": tool_name,
                        "attempt": op_counts[op],
                        "result": {"ok": False, "error": {"code": "TIMEOUT"}},
                        "accepted_result_bytes": 0,
                        "operation": op,
                    },
                    dt=0.180,
                )
                emit("backoff", {"delay_s": 0.025}, dt=0.001)
                emit("wire_receive", {"jsonrpc": "2.0", "id": 99, "result": {}}, dt=0.010)
            op_counts[op] += 1
            obs = copy.deepcopy(observations[obs_cursor])
            obs_cursor += 1
            env = {
                "run_id": run_id,
                "principal": "dev-user",
                "operation_id": f"{run_id}:write-0",
                "idempotency_key": f"{run_id}:write-0",
                "attempt": op_counts[op],
                "stage": op,
            }
            emit(
                "tool_attempt",
                {
                    "tool": tool_name,
                    "arguments": args,
                    "envelope": env,
                    "model_call_id": call["id"],
                    "timeout_s": 0.18,
                    "operation": op,
                },
                dt=0.020 if include_backoff and op == "write-0" else 0.001,
            )
            max_res_bytes = max(max_res_bytes, 256)
            emit(
                "tool_result",
                {
                    "tool": tool_name,
                    "attempt": op_counts[op],
                    "result": obs["result"],
                    "accepted_result_bytes": 256,
                    "operation": op,
                },
                dt=0.005,
            )
            emit(
                "feedback",
                {
                    "observation": {**obs, "delivered": False, "host_observed": True},
                    "model_call_id": call["id"],
                    "operation": op,
                },
                dt=0.001,
            )
            if repair_used and op == "write-0" and not obs["result"]["ok"]:
                emit(
                    "recovery",
                    {
                        "action": "reproposal",
                        "reason": "STALE_REVISION",
                        "write_attempts_used": 1,
                        "operation_id": f"{run_id}:write-0",
                    },
                    dt=0.001,
                )
                op_counts["refresh_read"] += 1
                ref_obs = copy.deepcopy(observations[obs_cursor])
                obs_cursor += 1
                ref_env = {
                    "run_id": run_id,
                    "principal": "dev-user",
                    "operation_id": f"{run_id}:write-0",
                    "idempotency_key": f"{run_id}:write-0",
                    "attempt": 1,
                    "stage": "refresh_read",
                }
                emit(
                    "tool_attempt",
                    {
                        "tool": "read_state",
                        "arguments": {"target_ref": target_ref},
                        "envelope": ref_env,
                        "model_call_id": None,
                        "timeout_s": 0.18,
                        "operation": "refresh_read",
                    },
                    dt=0.001,
                )
                emit(
                    "tool_result",
                    {
                        "tool": "read_state",
                        "attempt": 1,
                        "result": ref_obs["result"],
                        "accepted_result_bytes": 256,
                        "operation": "refresh_read",
                    },
                    dt=0.005,
                )
                emit(
                    "feedback",
                    {
                        "observation": {
                            **ref_obs,
                            "delivered": False,
                            "host_observed": True,
                        },
                        "model_call_id": None,
                        "operation": "refresh_read",
                    },
                    dt=0.001,
                )

    emit("dispatch_stop", {"effect_knowledge": output["effect_knowledge"]}, dt=0.001)
    emit("mcp_cleanup", {"completed": True, "elapsed_s": 0.080}, dt=0.080)
    if host_error:
        emit("host_error", {"exception_type": "JSONDecodeError", "reason": "invalid_response"})
    emit("controller_cleanup", {"completed": True, "elapsed_s": 0.003}, dt=0.003)
    emit("terminal", {"output": output}, dt=0.001)
    ending = {
        "costs": {
            "tool_attempts": sum(op_counts.values()),
            "model_calls": len(turns),
            "input_tokens": in_tok_total,
            "output_tokens": out_tok_total,
            "total_s": round(t, 6),
            "grading_api_cost": 0,
        },
        "maxima": {
            "input_estimate": max_est,
            "input_tokens": max_in_tok,
            "output_tokens": max_out_tok,
            "tool_result_bytes": max_res_bytes,
        },
        "counters": {
            "decision_steps": len(turns),
            "operation_attempts": op_counts,
            "repair_used": repair_used,
        },
        "measurement_valid": True,
        "terminated_quiescent": True,
    }
    emit("run_end", ending, dt=0.001)
    final_obs = [
        {**copy.deepcopy(o), "delivered": idx < delivered_idx, "host_observed": True}
        for idx, o in enumerate(observations)
    ]
    atomic(run_dir / "trace.jsonl", events, lines=True)
    atomic(
        run_dir / "manifest.json",
        {
            "schema": "g1-v1",
            "package_version": "0.1.0",
            "mcp_sdk": "1.30.0",
            "task_input": task_input,
            "controller": {"kind": "openai-compatible", "model": "synthetic-model"},
            "record": {**record_base, **ending, "output": output, "observations": final_obs},
        },
    )


def build_batch(source):
    source.mkdir(parents=True, exist_ok=False)
    atomic(
        source / "experiment.json",
        {
            "models": {
                "A": {"model": "deepseek-flash"},
                "B": {"model": "doubao-seed-2-1-lite-260915"},
            }
        },
    )
    sys_msg = {
        "role": "system",
        "content": SYSTEM_PROMPT + '\nHost authorization: {"target_ref": "rel-15"}',
    }
    user_msg = {
        "role": "user",
        "content": json.dumps({"task": {"task_id": "acc-05", "target_ref": "rel-15"}}),
    }
    obs1 = {
        "ref": "obs-1",
        "tool": "read_state",
        "result": {
            "ok": True,
            "kind": "state",
            "state": {
                "target_ref": "rel-15",
                "revision": 1,
                "write_policy": "allow",
                "queue_options": ["ops"],
                "facts": {"active_faults": 2},
                "tickets": [],
            },
        },
    }
    obs2 = {
        "ref": "obs-2",
        "tool": "create_ticket",
        "result": {
            "ok": False,
            "error": {
                "code": "STALE_REVISION",
                "message": "Refresh",
                "repairable": True,
                "not_executed": True,
                "unbound": True,
            },
        },
    }
    obs3 = {
        "ref": "obs-3",
        "tool": "read_state",
        "result": {
            "ok": True,
            "kind": "state",
            "state": {
                "target_ref": "rel-15",
                "revision": 2,
                "write_policy": "allow",
                "queue_options": ["ops"],
                "facts": {"active_faults": 0},
                "tickets": [],
            },
        },
    }
    rid = "run-11112222333344445555666677778888"
    obs4 = {
        "ref": "obs-4",
        "tool": "create_ticket",
        "result": {
            "ok": True,
            "kind": "receipt",
            "receipt": {
                "receipt_id": "rec-1",
                "run_id": rid,
                "operation_id": f"{rid}:write-0",
                "target_ref": "rel-15",
                "ticket_id": "tkt-1",
                "params": {
                    "target_ref": "rel-15",
                    "expected_revision": 2,
                    "queue": "ops",
                    "priority": "normal",
                },
            },
        },
    }
    a1 = {
        "role": "assistant",
        "content": "    ",
        "encrypted_content": "opaque-1",
        "tool_calls": [{
            "index": 0,
            "id": "ca",
            "type": "function",
            "function": {"name": "read_state", "arguments": '{"target_ref": "rel-15"}'},
        }],
    }
    t1 = {"role": "tool", "tool_call_id": "ca", "content": json.dumps(obs1)}
    a2_args = json.dumps({
        "target_ref": "rel-15",
        "expected_revision": 1,
        "queue": "ops",
        "priority": "urgent",
    })
    a2 = {
        "role": "assistant",
        "content": "",
        "encrypted_content": "opaque-2",
        "tool_calls": [{
            "id": "cb",
            "type": "function",
            "function": {"name": "create_ticket", "arguments": a2_args},
        }],
    }
    t2 = {"role": "tool", "tool_call_id": "cb", "content": json.dumps(obs2)}
    u_ref = {
        "role": "user",
        "content": json.dumps({"source": "host_refresh", "observation": obs3}),
    }
    u_rec = {
        "role": "user",
        "content": json.dumps({"source": "host_recovery", "effect_knowledge": "NOT_COMMITTED"}),
    }
    a3_args = json.dumps({
        "target_ref": "rel-15",
        "expected_revision": 2,
        "queue": "ops",
        "priority": "normal",
    })
    a3 = {
        "role": "assistant",
        "content": "",
        "tool_calls": [{
            "id": "cc",
            "type": "function",
            "function": {"name": "create_ticket", "arguments": a3_args},
        }],
    }
    t3 = {"role": "tool", "tool_call_id": "cc", "content": json.dumps(obs4)}
    out_ok = {
        "disposition": "COMPLETED",
        "target_ref": "rel-15",
        "ticket_id": "tkt-1",
        "evidence_refs": ["obs-3", "obs-4"],
        "reason_code": "completed",
        "effect_knowledge": "CONFIRMED",
    }
    a4 = {"role": "assistant", "content": json.dumps(out_ok)}

    make_sealed_run(
        source / "runs/acc-05-r1-B-P2",
        run_id=rid,
        task_id="acc-05",
        target_ref="rel-15",
        policy="P2",
        turns=[
            ([sys_msg, user_msg], a1, "tool_calls"),
            ([sys_msg, user_msg, a1, t1], a2, "tool_calls"),
            ([sys_msg, user_msg, a1, t1, a2, t2, u_ref, u_rec], a3, "tool_calls"),
            ([sys_msg, user_msg, a1, t1, a2, t2, u_ref, u_rec, a3, t3], a4, "stop"),
        ],
        observations=[obs1, obs2, obs3, obs4],
        repair_used=True,
        output=out_ok,
        include_backoff=True,
    )
    rows = [{
        "slot": "acc-05-r1-B-P2",
        "task_id": "acc-05",
        "family": "F3",
        "repeat": 1,
        "model": "B",
        "policy": "P2",
        "path": "runs/acc-05-r1-B-P2",
        "grade": {"correct_disposition": 1, "goal_completed": 1},
        "output": out_ok,
    }]

    sys15 = {"role": "system", "content": SYSTEM_PROMPT}
    user15 = {
        "role": "user",
        "content": json.dumps({"task": {"task_id": "acc-15", "target_ref": "key-k48"}}),
    }
    obs15 = {
        "ref": "obs-1",
        "tool": "read_state",
        "result": {
            "ok": True,
            "kind": "state",
            "state": {
                "target_ref": "key-k48",
                "revision": 12,
                "write_policy": "approval",
                "queue_options": ["key_ops"],
                "facts": {"recorded_approvers": 1},
                "tickets": [],
            },
        },
    }
    valid_h = {
        "disposition": "HANDOFF_HUMAN",
        "target_ref": "key-k48",
        "ticket_id": None,
        "evidence_refs": ["obs-1"],
        "reason_code": "approval_required",
        "effect_knowledge": "NOT_COMMITTED",
    }
    bad_py = (
        "{'disposition': 'HANDOFF_HUMAN', 'target_ref': 'key-k48', 'ticket_id': None, "
        "'evidence_refs': ['obs-1'], 'reason_code': 'approval_required', "
        "'effect_knowledge': 'NOT_COMMITTED'}"
    )

    for rep, valid in ((1, True), (2, False), (3, True)):
        slot = f"acc-15-r{rep}-B-P2"
        cid = f"prov_{rep}"
        t1a = {
            "role": "assistant",
            "content": "",
            "encrypted_content": f"e{rep}",
            "tool_calls": [{
                "id": cid,
                "type": "function",
                "function": {"name": "read_state", "arguments": '{"target_ref": "key-k48"}'},
            }],
        }
        t1t = {"role": "tool", "tool_call_id": cid, "content": json.dumps(obs15)}
        t2a = {
            "role": "assistant",
            "content": json.dumps(valid_h) if valid else bad_py,
            "encrypted_content": f"ef{rep}",
        }
        term = valid_h if valid else {
            "disposition": "SYSTEM_FAILURE",
            "target_ref": "key-k48",
            "ticket_id": None,
            "evidence_refs": [],
            "reason_code": "invalid_response",
            "effect_knowledge": "NOT_COMMITTED",
        }
        make_sealed_run(
            source / "runs" / slot,
            run_id=f"run-aaaa0000bbbb1111cccc2222dddd000{rep}",
            task_id="acc-15",
            target_ref="key-k48",
            policy="P2",
            turns=[
                ([sys15, user15], t1a, "tool_calls"),
                ([sys15, user15, t1a, t1t], t2a, "stop"),
            ],
            observations=[obs15],
            repair_used=False,
            output=term,
            host_error=not valid,
        )
        rows.append({
            "slot": slot,
            "task_id": "acc-15",
            "family": "F5",
            "repeat": rep,
            "model": "B",
            "policy": "P2",
            "path": f"runs/{slot}",
            "grade": {"correct_disposition": int(valid), "goal_completed": 0},
            "output": term,
        })
    atomic(source / "results.jsonl", rows, lines=True)


mode = sys.argv[1]
root = Path(sys.argv[2])

if mode == "contract":
    manifest, contract = validate_v2_contract()
    assert len(manifest["tasks"]) == 18
    assert len(contract["replication"]["code_sha256"]) == 31

elif mode == "latency_and_protocol":
    events = [
        {"seq": 1, "elapsed_s": 0.001, "event": "run_start", "data": {}},
        {"seq": 2, "elapsed_s": 1.501, "event": "mcp_tools", "data": {}},
        {"seq": 3, "elapsed_s": 1.502, "event": "model_request", "data": {}},
        {"seq": 4, "elapsed_s": 1.800, "event": "wire_receive", "data": {"id": 9}},
        {
            "seq": 5,
            "elapsed_s": 2.502,
            "event": "model_response",
            "data": {
                "message": {
                    "role": "assistant",
                    "content": json.dumps({
                        "disposition": "REFUSED",
                        "target_ref": "t-1",
                        "ticket_id": None,
                        "evidence_refs": [],
                        "reason_code": "policy_forbidden",
                        "effect_knowledge": "NOT_COMMITTED",
                    }),
                },
                "usage": {"input_tokens": 100, "output_tokens": 20, "provider": {}},
                "finish_reason": "stop",
            },
        },
        {
            "seq": 6,
            "elapsed_s": 2.503,
            "event": "tool_attempt",
            "data": {"tool": "create_ticket", "operation": "write-0"},
        },
        {"seq": 7, "elapsed_s": 2.683, "event": "tool_result", "data": {"result": {"ok": False}}},
        {"seq": 8, "elapsed_s": 2.684, "event": "backoff", "data": {"delay_s": 0.025}},
        {"seq": 9, "elapsed_s": 2.690, "event": "wire_receive", "data": {"id": 10}},
        {
            "seq": 10,
            "elapsed_s": 2.714,
            "event": "tool_attempt",
            "data": {"tool": "create_ticket", "operation": "write-0"},
        },
        {"seq": 11, "elapsed_s": 2.724, "event": "tool_result", "data": {"result": {"ok": True}}},
        {"seq": 12, "elapsed_s": 2.725, "event": "dispatch_stop", "data": {}},
        {"seq": 13, "elapsed_s": 2.825, "event": "mcp_cleanup", "data": {"elapsed_s": 0.100}},
        {"seq": 14, "elapsed_s": 2.826, "event": "host_stop", "data": {}},
        {
            "seq": 15,
            "elapsed_s": 2.829,
            "event": "controller_cleanup",
            "data": {"elapsed_s": 0.003},
        },
        {"seq": 16, "elapsed_s": 2.830, "event": "run_end", "data": {"costs": {"total_s": 2.829}}},
    ]
    lat = diagnostics.decompose_run_latency(events)
    assert lat["stages_s"]["model_inference_s"] == pytest.approx(1.000)
    assert lat["stages_s"]["mcp_comm_s"] == pytest.approx(1.690)
    assert lat["stages_s"]["backoff_wait_s"] == pytest.approx(0.030)
    assert lat["stages_s"]["cleanup_s"] == pytest.approx(0.103)
    reconstructed_span = sum(lat["stages_s"].values()) + lat["host_overhead_s"]
    assert reconstructed_span == pytest.approx(lat["trace_span_s"])
    agg = diagnostics._aggregate_group([{"latency": lat}])
    assert agg["persisted_token_telemetry"]["reasoning_tokens_sum"] is None
    assert agg["persisted_token_telemetry"]["cached_tokens_sum"] is None
    assert all(v is None for v in agg["unrecorded_in_nonstreaming_trace"].values())

    bad_args = diagnostics.classify_response_protocol(
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [{
                "id": "c1",
                "type": "function",
                "function": {"name": "read_state", "arguments": "{'target_ref': 'k1'}"},
            }],
        },
        "tool_calls",
        expected_tool_phase=True,
    )
    assert bad_args["protocol_field"] == "choices[0].message.tool_calls[].function.arguments"
    assert bad_args["anomaly"] == "tool_arguments_python_dict"

    acc15_style = diagnostics.classify_response_protocol(
        {
            "role": "assistant",
            "content": (
                "{'disposition': 'HANDOFF_HUMAN', 'target_ref': 'k', 'ticket_id': None, "
                "'evidence_refs': ['obs-1'], 'reason_code': 'approval_required', "
                "'effect_knowledge': 'NOT_COMMITTED'}"
            ),
        },
        "stop",
        expected_tool_phase=False,
    )
    assert acc15_style["protocol_field"] == "choices[0].message.content"
    assert acc15_style["anomaly"] == "terminal_content_python_dict"

    fallback = diagnostics.classify_response_protocol(
        {"role": "assistant", "content": "Calling read_state now..."},
        "stop",
        expected_tool_phase=True,
    )
    assert fallback["anomaly"] == "degraded_plain_text_when_tool_expected"

elif mode == "end_to_end_and_security":
    source = root / "batch"
    build_batch(source)
    before = fingerprint(source)
    for unsafe in (source, source / "nested"):
        with pytest.raises(ValueError, match="separate"):
            diagnostics.run(source, unsafe)
        with pytest.raises(ValueError, match="separate"):
            post_training.run(source, unsafe)

    diag_out = root / "diag-out"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "evals.diagnostics",
            "--input",
            str(source),
            "--output",
            str(diag_out),
        ],
        check=True,
    )
    diag_summary = json.loads((diag_out / "summary.json").read_text("utf-8"))
    assert diag_summary["runs"] == 4 and diag_summary["input_unchanged"] is True
    anom = diag_summary["acc15_protocol_summary"]["anomalies"]
    assert len(anom) == 1 and anom[0]["slot"] == "acc-15-r2-B-P2"
    assert anom[0]["protocol_field"] == "choices[0].message.content"
    assert anom[0]["anomaly"] == "terminal_content_python_dict"

    export_out = root / "export-out"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "evals.post_training",
            "--input",
            str(source),
            "--output",
            str(export_out),
        ],
        check=True,
    )
    assert fingerprint(source) == before
    with pytest.raises(FileExistsError):
        post_training.run(source, export_out)

    sft_rows = journal(export_out / "sft_masked_reproposal.jsonl")
    assert len(sft_rows) == 1
    sft = sft_rows[0]
    assert [m["loss_mask"] for m in sft["messages"]] == [0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1]
    assert sft["messages"][2]["content"] == ""
    obs4_rec = json.loads(sft["messages"][9]["content"])["result"]["receipt"]
    assert obs4_rec["ticket_id"] == "tkt-1"
    assert "run_id" not in obs4_rec and "operation_id" not in obs4_rec

    pref_rows = journal(export_out / "preference_acc15_pairs.jsonl")
    assert [p["pair_id"] for p in pref_rows] == [
        "pref-acc-15-B-P2-r1-vs-r2",
        "pref-acc-15-B-P2-r3-vs-r2",
    ]
    assert pref_rows[0]["prompt"] == pref_rows[1]["prompt"]
    assert all(m["loss_mask"] == 0 for m in pref_rows[0]["prompt"])

    sft_mutations = [
        lambda s: s["tools"][0]["function"]["parameters"]["properties"].update(
            envelope={"type": "object"}
        ),
        lambda s: s["tools"][0]["function"]["parameters"].update({"$defs": {"Envelope": {}}}),
        lambda s: s["messages"][2]["tool_calls"][0]["function"].update(
            arguments=json.dumps({"target_ref": "rel-15", "envelope": {"principal": "dev-user"}})
        ),
        lambda s: s["messages"][3].update(
            content=json.dumps({
                "ref": "obs-1",
                "result": {"receipt": {"run_id": "run-abcdef1234"}},
            })
        ),
        lambda s: s.update(fault_plan={"kind": "pre_commit_delay", "delay_s": 0.3}),
        lambda s: s["messages"][1].update(content=json.dumps({"state_patch": {"revision": 9}})),
        lambda s: s.update(oracle={"completable": True}),
        lambda s: s["messages"][2].update(encrypted_content="djEsecret"),
        lambda s: s["messages"][0].update(content="LAB_MODEL_API_KEY=secret"),
        lambda s: s["messages"][0].update(content="Path D:\\workspace\\project\\private.json"),
        lambda s: s["messages"][0].update(loss_mask=1),
        lambda s: s["messages"][2].update(loss_mask=0),
    ]
    for mut in sft_mutations:
        bad = copy.deepcopy(sft)
        mut(bad)
        with pytest.raises((AssertionError, SecurityViolationError)):
            assert_sft_sample_safe(bad)

    pref_mutations = [
        lambda p: p["prompt"][0].update(loss_mask=1),
        lambda p: p["rejected"].update(
            content="{'disposition': 'HANDOFF_HUMAN', 'envelope': {'principal': 'dev-user'}}"
        ),
        lambda p: p["chosen"].update(encrypted_content="opaque"),
        lambda p: p.update(db_path="/Users/alice/environment.sqlite"),
    ]
    for mut in pref_mutations:
        bad_p = copy.deepcopy(pref_rows[0])
        mut(bad_p)
        with pytest.raises((AssertionError, SecurityViolationError)):
            assert_preference_pair_safe(bad_p)
else:
    raise ValueError(mode)
'''


@pytest.mark.parametrize("mode", ["contract", "latency_and_protocol", "end_to_end_and_security"])
def test_post_v2_diagnostics_and_trajectory_export(tmp_path: Path, mode: str) -> None:
    subprocess.run(
        [sys.executable, "-c", FIXTURE_AND_EXPORT_SCRIPT, mode, str(tmp_path)],
        cwd=PROJECT,
        check=True,
        timeout=30,
    )
