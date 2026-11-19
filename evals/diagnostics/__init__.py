"""Read-only 4-stage monotonic latency decomposition and protocol-field anomaly locator."""

from __future__ import annotations

import ast
import json
import math
import statistics
from pathlib import Path
from typing import Any

from evals.development import read
from evals.evidence_audit import fingerprint
from evals.formal import atomic, journal
from harness_lab.trace import replay, source_revision

PROJECT = Path(__file__).resolve().parents[2]
DISPOSITION_KEYS = {
    "disposition",
    "target_ref",
    "ticket_id",
    "evidence_refs",
    "reason_code",
    "effect_knowledge",
}
UNRECORDED_TELEMETRY = {
    "ttft_s": None,
    "thinking_phase_s": None,
    "visible_generation_s": None,
    "network_rtt_s": None,
    "plaintext_reasoning_content": None,
}


def rel_posix(path: Path) -> str:
    resolved = path.resolve()
    if resolved.is_relative_to(PROJECT):
        return resolved.relative_to(PROJECT).as_posix()
    return resolved.name


def dist_stats(values: list[float]) -> dict[str, float | int | None]:
    if not values:
        return {"count": 0, "sum_s": 0.0, "mean_s": None, "median_s": None,
                "p90_s": None, "min_s": None, "max_s": None}
    ordered = sorted(values)
    idx90 = min(len(ordered) - 1, max(0, math.ceil(0.9 * len(ordered)) - 1))
    return {
        "count": len(ordered),
        "sum_s": round(sum(ordered), 6),
        "mean_s": round(statistics.fmean(ordered), 6),
        "median_s": round(statistics.median(ordered), 6),
        "p90_s": round(ordered[idx90], 6),
        "min_s": round(ordered[0], 6),
        "max_s": round(ordered[-1], 6),
    }


def classify_response_protocol(
    message: dict[str, Any], finish_reason: str, *, expected_tool_phase: bool = False
) -> dict[str, Any]:
    """Identify the exact protocol field and syntax class of a recorded model response."""
    calls = message.get("tool_calls") or []
    if calls:
        errors = []
        for idx, call in enumerate(calls):
            raw_args = (call.get("function") or {}).get("arguments", "")
            try:
                parsed = json.loads(raw_args)
                if not isinstance(parsed, dict):
                    errors.append({"index": idx, "kind": "tool_arguments_non_object"})
            except json.JSONDecodeError as exc:
                kind = "tool_arguments_invalid_json"
                try:
                    if isinstance(ast.literal_eval(raw_args), dict):
                        kind = "tool_arguments_python_dict"
                except (ValueError, SyntaxError):
                    pass
                errors.append({"index": idx, "kind": kind, "error": exc.msg, "pos": exc.pos})
        return {
            "finish_reason": finish_reason,
            "protocol_field": "choices[0].message.tool_calls[].function.arguments",
            "has_tool_calls": True,
            "valid_json": not errors,
            "anomaly": errors[0]["kind"] if errors else None,
            "errors": errors,
        }

    raw_content = message.get("content") if isinstance(message.get("content"), str) else ""
    try:
        parsed = json.loads(raw_content)
        if isinstance(parsed, dict) and set(parsed) == DISPOSITION_KEYS:
            return {
                "finish_reason": finish_reason,
                "protocol_field": "choices[0].message.content",
                "has_tool_calls": False,
                "valid_json": True,
                "anomaly": "unexpected_terminal_in_observe_phase" if expected_tool_phase else None,
            }
        return {
            "finish_reason": finish_reason,
            "protocol_field": "choices[0].message.content",
            "has_tool_calls": False,
            "valid_json": True,
            "anomaly": "terminal_content_schema_mismatch",
        }
    except json.JSONDecodeError as exc:
        anomaly = (
            "degraded_plain_text_when_tool_expected"
            if expected_tool_phase
            else "terminal_content_invalid_json"
        )
        python_literal_keys: list[str] | None = None
        try:
            literal = ast.literal_eval(raw_content)
            if isinstance(literal, dict):
                python_literal_keys = sorted(str(k) for k in literal)
                if set(literal) == DISPOSITION_KEYS:
                    anomaly = "terminal_content_python_dict"
                elif {"name", "arguments"} <= set(literal) or "target_ref" in literal:
                    anomaly = "degraded_tool_call_dict_in_content"
        except (ValueError, SyntaxError):
            pass
        return {
            "finish_reason": finish_reason,
            "protocol_field": "choices[0].message.content",
            "has_tool_calls": False,
            "valid_json": False,
            "anomaly": anomaly,
            "json_decode_error": f"{exc.msg} (line {exc.lineno}, col {exc.colno})",
            "python_literal_keys": python_literal_keys,
        }


def _extract_provider_token_details(usage: dict[str, Any] | None) -> dict[str, int | None]:
    if not isinstance(usage, dict):
        return {"input_tokens": None, "output_tokens": None,
                "cached_tokens": None, "reasoning_tokens": None}
    provider = usage.get("provider")
    provider = provider if isinstance(provider, dict) else {}
    prompt_details = provider.get("prompt_tokens_details")
    comp_details = provider.get("completion_tokens_details")
    cached = prompt_details.get("cached_tokens") if isinstance(prompt_details, dict) else None
    reasoning = comp_details.get("reasoning_tokens") if isinstance(comp_details, dict) else None
    in_tok = usage.get("input_tokens")
    out_tok = usage.get("output_tokens")
    return {
        "input_tokens": in_tok if type(in_tok) is int else None,
        "output_tokens": out_tok if type(out_tok) is int else None,
        "cached_tokens": cached if type(cached) is int else None,
        "reasoning_tokens": reasoning if type(reasoning) is int else None,
    }


def decompose_run_latency(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Split one sealed run's monotonic clock into 4 non-overlapping stages + Host residual."""
    if not events or events[0]["event"] != "run_start" or events[-1]["event"] != "run_end":
        raise ValueError("Trace must begin with run_start and end with run_end")
    previous = -1.0
    for idx, ev in enumerate(events, 1):
        if ev["seq"] != idx or ev["elapsed_s"] < previous:
            raise ValueError("Non-monotonic trace sequence or timestamp")
        previous = ev["elapsed_s"]

    t_start = events[0]["elapsed_s"]
    t_end = events[-1]["elapsed_s"]
    startup_end_ev = next(
        (e for e in events if e["event"] in {"mcp_tools", "dispatch_stop"}), events[-1]
    )
    mcp_startup_s = startup_end_ev["elapsed_s"] - t_start

    model_calls: list[dict[str, Any]] = []
    tool_calls: list[dict[str, Any]] = []
    backoffs: list[dict[str, Any]] = []
    seen_initial_read = False

    for idx, ev in enumerate(events):
        kind = ev["event"]
        if kind == "model_request":
            end_ev = next(
                events[j] for j in range(idx + 1, len(events))
                if events[j]["event"] in {"model_response", "model_failed", "dispatch_stop"}
            )
            dur = end_ev["elapsed_s"] - ev["elapsed_s"]
            info: dict[str, Any] = {
                "turn": len(model_calls) + 1,
                "elapsed_s": dur,
                "outcome_event": end_ev["event"],
            }
            if end_ev["event"] == "model_response":
                msg = end_ev["data"]["message"]
                proto = classify_response_protocol(
                    msg, end_ev["data"]["finish_reason"], expected_tool_phase=not seen_initial_read
                )
                info["protocol"] = proto
                info["tokens"] = _extract_provider_token_details(end_ev["data"].get("usage"))
            else:
                info["protocol"] = None
                info["tokens"] = _extract_provider_token_details(None)
            model_calls.append(info)
        elif kind == "tool_attempt":
            end_ev = next(
                events[j] for j in range(idx + 1, len(events))
                if events[j]["event"] in {"tool_result", "dispatch_stop"}
            )
            if ev["data"].get("operation") == "initial_read" and end_ev["event"] == "tool_result":
                seen_initial_read |= bool(end_ev["data"]["result"].get("ok"))
            tool_calls.append({
                "attempt_index": len(tool_calls) + 1,
                "tool": ev["data"]["tool"],
                "operation": ev["data"]["operation"],
                "elapsed_s": end_ev["elapsed_s"] - ev["elapsed_s"],
            })
        elif kind == "backoff":
            # Skip async wire_receive events arriving on the background stdio reader task.
            end_ev = next(
                events[j] for j in range(idx + 1, len(events))
                if events[j]["event"] in {"tool_attempt", "dispatch_stop"}
            )
            backoffs.append({
                "scheduled_s": ev["data"]["delay_s"],
                "elapsed_s": end_ev["elapsed_s"] - ev["elapsed_s"],
            })

    disp_idx = next(i for i, e in enumerate(events) if e["event"] == "dispatch_stop")
    mcp_clean_idx = next(i for i, e in enumerate(events) if e["event"] == "mcp_cleanup")
    ctrl_clean_idx = next(i for i, e in enumerate(events) if e["event"] == "controller_cleanup")
    mcp_cleanup_span_s = events[mcp_clean_idx]["elapsed_s"] - events[disp_idx]["elapsed_s"]
    ctrl_anchor_idx = next(
        (
            j for j in range(mcp_clean_idx + 1, ctrl_clean_idx)
            if events[j]["event"] in {"host_stop", "host_error"}
        ),
        mcp_clean_idx,
    )
    ctrl_cleanup_span_s = events[ctrl_clean_idx]["elapsed_s"] - events[ctrl_anchor_idx]["elapsed_s"]

    model_inference_s = sum(item["elapsed_s"] for item in model_calls)
    mcp_tool_calls_s = sum(item["elapsed_s"] for item in tool_calls)
    mcp_comm_s = mcp_startup_s + mcp_tool_calls_s
    backoff_wait_s = sum(item["elapsed_s"] for item in backoffs)
    backoff_scheduled_s = sum(item["scheduled_s"] for item in backoffs)
    cleanup_s = mcp_cleanup_span_s + ctrl_cleanup_span_s
    recorded_cleanup_s = (
        events[mcp_clean_idx]["data"]["elapsed_s"] + events[ctrl_clean_idx]["data"]["elapsed_s"]
    )
    four_stage_s = model_inference_s + mcp_comm_s + backoff_wait_s + cleanup_s
    host_overhead_s = t_end - four_stage_s
    if host_overhead_s < -1e-9:
        raise ValueError(f"Overlapping stage intervals detected: residual={host_overhead_s}")
    host_overhead_s = max(0.0, host_overhead_s)

    return {
        "trace_span_s": t_end,
        "recorded_total_s": events[-1]["data"]["costs"]["total_s"],
        "stages_s": {
            "model_inference_s": model_inference_s,
            "mcp_comm_s": mcp_comm_s,
            "backoff_wait_s": backoff_wait_s,
            "cleanup_s": cleanup_s,
        },
        "mcp_breakdown_s": {
            "mcp_startup_s": mcp_startup_s,
            "mcp_tool_calls_s": mcp_tool_calls_s,
        },
        "backoff_scheduled_s": backoff_scheduled_s,
        "recorded_cleanup_s": recorded_cleanup_s,
        "host_overhead_s": host_overhead_s,
        "model_calls": model_calls,
        "tool_calls": tool_calls,
    }


def _aggregate_group(records: list[dict[str, Any]]) -> dict[str, Any]:
    span_total = sum(r["latency"]["trace_span_s"] for r in records)
    stage_keys = ("model_inference_s", "mcp_comm_s", "backoff_wait_s", "cleanup_s")
    stages = {}
    for key in stage_keys:
        vals = [r["latency"]["stages_s"][key] for r in records]
        total = sum(vals)
        stages[key] = {
            **dist_stats(vals),
            "share_of_trace_span": round(total / span_total, 6) if span_total > 0 else None,
        }
    mcp_init_vals = [r["latency"]["mcp_breakdown_s"]["mcp_startup_s"] for r in records]
    mcp_rpc_vals = [r["latency"]["mcp_breakdown_s"]["mcp_tool_calls_s"] for r in records]
    overhead_vals = [r["latency"]["host_overhead_s"] for r in records]
    call_vals = [c["elapsed_s"] for r in records for c in r["latency"]["model_calls"]]

    token_rows = [
        c["tokens"] for r in records for c in r["latency"]["model_calls"]
        if c["outcome_event"] == "model_response"
    ]
    n_resp = len(token_rows)
    in_known = [t["input_tokens"] for t in token_rows if t["input_tokens"] is not None]
    out_known = [t["output_tokens"] for t in token_rows if t["output_tokens"] is not None]
    cache_known = [t["cached_tokens"] for t in token_rows if t["cached_tokens"] is not None]
    reas_known = [t["reasoning_tokens"] for t in token_rows if t["reasoning_tokens"] is not None]

    in_sum = sum(in_known) if len(in_known) == n_resp else None
    out_sum = sum(out_known) if len(out_known) == n_resp else None
    cache_sum = sum(cache_known) if len(cache_known) == n_resp else None
    reas_sum = sum(reas_known) if len(reas_known) == n_resp else None

    return {
        "runs": len(records),
        "recorded_total_s": round(sum(r["latency"]["recorded_total_s"] for r in records), 6),
        "trace_span_s": round(span_total, 6),
        "stages": stages,
        "mcp_sub_stages": {
            "mcp_startup_s": dist_stats(mcp_init_vals),
            "mcp_tool_calls_s": dist_stats(mcp_rpc_vals),
        },
        "host_overhead_s": {
            **dist_stats(overhead_vals),
            "share_of_trace_span": (
                round(sum(overhead_vals) / span_total, 6) if span_total else None
            ),
        },
        "per_model_call_inference_s": dist_stats(call_vals),
        "persisted_token_telemetry": {
            "responses_total": n_resp,
            "reasoning_tokens_recorded_calls": len(reas_known),
            "cached_tokens_recorded_calls": len(cache_known),
            "input_tokens_sum": in_sum,
            "cached_tokens_sum": cache_sum,
            "cache_hit_ratio": (
                round(cache_sum / in_sum, 6)
                if in_sum and cache_sum is not None
                else None
            ),
            "output_tokens_sum": out_sum,
            "reasoning_tokens_sum": reas_sum,
            "visible_output_tokens_sum": (
                out_sum - reas_sum if out_sum is not None and reas_sum is not None else None
            ),
            "reasoning_share_of_output": (
                round(reas_sum / out_sum, 6)
                if out_sum and reas_sum is not None
                else None
            ),
            "positive_reasoning_calls": (
                sum(x > 0 for x in reas_known) if len(reas_known) == n_resp else None
            ),
        },
        "unrecorded_in_nonstreaming_trace": dict(UNRECORDED_TELEMETRY),
    }


def extract_acc15_inspection(directory: Path, rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Extract raw assistant payloads and exact protocol-field diagnosis for acc-15."""
    acc15_rows = sorted(
        (r for r in rows if r["task_id"] == "acc-15"),
        key=lambda r: (r["model"], r["policy"], r["repeat"]),
    )
    b_p2_runs = []
    anomalies = []
    for row in acc15_rows:
        events = journal(directory / row["path"] / "trace.jsonl")
        seen_read = False
        turns = []
        for ev in events:
            if ev["event"] == "tool_result" and ev["data"].get("operation") == "initial_read":
                seen_read |= bool(ev["data"]["result"].get("ok"))
            elif ev["event"] == "model_response":
                msg = ev["data"]["message"]
                proto = classify_response_protocol(
                    msg, ev["data"]["finish_reason"], expected_tool_phase=not seen_read
                )
                sanitized_calls = [
                    {
                        "id": c.get("id"),
                        "type": c.get("type"),
                        "function": c.get("function"),
                    }
                    for c in (msg.get("tool_calls") or [])
                ]
                turn_entry = {
                    "turn": len(turns) + 1,
                    "seq": ev["seq"],
                    "finish_reason": ev["data"]["finish_reason"],
                    "raw_content": msg.get("content"),
                    "tool_calls": sanitized_calls,
                    "has_opaque_encrypted_content": "encrypted_content" in msg,
                    "tokens": _extract_provider_token_details(ev["data"].get("usage")),
                    "protocol_check": proto,
                }
                turns.append(turn_entry)
                if proto["anomaly"] is not None:
                    anomalies.append({
                        "slot": row["slot"],
                        "model": row["model"],
                        "policy": row["policy"],
                        "repeat": row["repeat"],
                        "turn": turn_entry["turn"],
                        "seq": ev["seq"],
                        **proto,
                        "raw_content": msg.get("content"),
                    })
        host_err = next((e["data"] for e in events if e["event"] == "host_error"), None)
        entry = {
            "slot": row["slot"],
            "repeat": row["repeat"],
            "model": row["model"],
            "policy": row["policy"],
            "correct_disposition": row["grade"]["correct_disposition"],
            "terminal_output": row["output"],
            "host_error": host_err,
            "turns": turns,
        }
        if row["model"] == "B" and row["policy"] == "P2":
            b_p2_runs.append(entry)

    return {
        "task_id": "acc-15",
        "total_slots_inspected": len(acc15_rows),
        "passed_slots": sum(r["grade"]["correct_disposition"] for r in acc15_rows),
        "failed_slots": sum(not r["grade"]["correct_disposition"] for r in acc15_rows),
        "anomalies_found": anomalies,
        "model_b_p2_three_repeats": b_p2_runs,
    }


def run(directory: Path, output: Path) -> dict[str, Any]:
    """Run read-only latency & protocol-field diagnostics without mutating input evidence."""
    directory, output = directory.resolve(), output.resolve()
    if directory == output or output.is_relative_to(directory) or directory.is_relative_to(output):
        raise ValueError("Diagnostic output must be separate from the recorded input directory")
    if output.exists():
        raise FileExistsError("Use a fresh diagnostic output directory; existing files are kept")

    before = fingerprint(directory)
    rows = journal(directory / "results.jsonl")
    contract = read(directory / "experiment.json")
    per_run = []
    by_model: dict[str, list[dict[str, Any]]] = {}
    by_group: dict[str, list[dict[str, Any]]] = {}

    for row in rows:
        run_dir = directory / row["path"]
        replay(run_dir)
        events = journal(run_dir / "trace.jsonl")
        latency = decompose_run_latency(events)
        item = {
            "slot": row["slot"],
            "task_id": row["task_id"],
            "family": row["family"],
            "repeat": row["repeat"],
            "model": row["model"],
            "policy": row["policy"],
            "correct_disposition": row["grade"]["correct_disposition"],
            "latency": latency,
        }
        per_run.append(item)
        by_model.setdefault(row["model"], []).append(item)
        by_group.setdefault(f"{row['model']}-{row['policy']}", []).append(item)

    acc15 = extract_acc15_inspection(directory, rows)
    if fingerprint(directory) != before:
        raise ValueError("Recorded input changed during read-only diagnostics")

    models_summary = {
        label: {
            "model_name": contract["models"][label]["model"],
            **_aggregate_group(items),
        }
        for label, items in sorted(by_model.items())
    }
    summary = {
        "schema": "diagnostics-latency-and-protocol-v1",
        "audit_source": source_revision(),
        "input": rel_posix(directory),
        "runs": len(per_run),
        "model_api_calls": 0,
        "input_unchanged": True,
        "telemetry_note": (
            "Stage durations decompose recorded monotonic perf_counter timestamps only. "
            "Sub-request streaming phases (TTFT, internal thinking duration vs answer generation) "
            "and plaintext reasoning were not persisted under stream=false and are kept null."
        ),
        "models": models_summary,
        "groups": {key: _aggregate_group(items) for key, items in sorted(by_group.items())},
        "acc15_protocol_summary": {
            "total_slots": acc15["total_slots_inspected"],
            "passed_slots": acc15["passed_slots"],
            "failed_slots": acc15["failed_slots"],
            "anomalies": acc15["anomalies_found"],
        },
    }

    output.mkdir(parents=True, exist_ok=False)
    atomic(output / "summary.json", summary)
    atomic(output / "acc15_raw_inspection.json", acc15)
    atomic(output / "runs_latency.jsonl", per_run, lines=True)
    return summary
