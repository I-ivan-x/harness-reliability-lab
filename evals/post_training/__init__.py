"""Read-only post-training SFT and preference exporter with hard Host-envelope security gates."""

from __future__ import annotations

import ast
import copy
import json
import re
from pathlib import Path
from typing import Any

from evals.development import read
from evals.diagnostics import DISPOSITION_KEYS, classify_response_protocol, rel_posix
from evals.evidence_audit import fingerprint
from evals.formal import atomic, journal
from harness_lab.trace import replay, source_revision

PUBLIC_TOOL_PARAMS: dict[str, set[str]] = {
    "read_state": {"target_ref"},
    "create_ticket": {"target_ref", "expected_revision", "queue", "priority"},
}
FORBIDDEN_KEYS = {
    # Wire-level Host security envelope & slot credentials
    "envelope",
    "$defs",
    "Envelope",
    "run_id",
    "principal",
    "operation_id",
    "idempotency_key",
    "attempt",
    "stage",
    # Private server & fault injection configuration
    "fault",
    "fault_plan",
    "state_patch",
    "delay_s",
    "attempts",
    "db_path",
    "server_path",
    # Private evaluation oracle
    "oracle",
    "completable",
    "write_allowed",
    "final_state",
    "expected_params",
    "handoff_reason",
    "required_facts",
    # Provider opaque state & credentials
    "encrypted_content",
    "reasoning_content",
    "reasoning",
    "api_key",
    "LAB_MODEL_API_KEY",
    "LAB_MODEL_BASE_URL",
    "LAB_MODEL_NAME",
    "LAB_MODEL_TOKEN_LIMIT_FIELD",
}
FORBIDDEN_SUBSTRINGS = (
    "idempotency_key",
    "operation_id",
    "dev-user",
    ":write-0",
    "initial_read",
    "refresh_read",
    "run_id",
    "fault_plan",
    "state_patch",
    "state_change",
    "pre_commit_delay",
    "commit_response_delay",
    "malformed_result",
    "protocol_error",
    "private-server.json",
    "environment.sqlite",
    "db_path",
    "LAB_MODEL_",
    "Bearer ",
    "encrypted_content",
)
LOCAL_PATH_MARKERS = ("d:\\", "d:/", "c:\\", "c:/", "\\users\\", "/users/")
RUN_ID_PATTERN = re.compile(r"\brun-[0-9a-f]{8,}\b")


class SecurityViolationError(AssertionError):
    """Raised when any Host envelope, private fault/oracle, credential, or mask rule fails."""


def enforce(condition: bool, message: str) -> None:
    if not condition:
        raise SecurityViolationError(message)


def _scan_no_leaks(value: Any, path: str = "root") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            enforce(
                key not in FORBIDDEN_KEYS,
                f"Forbidden Host/private field '{key}' leaked at {path}",
            )
            _scan_no_leaks(item, f"{path}.{key}")
    elif isinstance(value, list):
        for idx, item in enumerate(value):
            _scan_no_leaks(item, f"{path}[{idx}]")
    elif isinstance(value, str):
        for marker in FORBIDDEN_SUBSTRINGS:
            enforce(marker not in value, f"Forbidden token '{marker}' leaked at {path}")
        lowered = value.lower()
        for marker in LOCAL_PATH_MARKERS:
            enforce(marker not in lowered, f"Local filesystem path '{marker}' leaked at {path}")
        enforce(
            RUN_ID_PATTERN.search(value) is None,
            f"Host run_id identifier leaked inside string at {path}",
        )
        stripped = value.strip()
        if stripped[:1] in {"{", "["}:
            try:
                nested = json.loads(stripped)
            except json.JSONDecodeError:
                try:
                    nested = ast.literal_eval(stripped)
                except (ValueError, SyntaxError):
                    nested = None
            if isinstance(nested, (dict, list)):
                _scan_no_leaks(nested, f"{path}<parsed>")


def assert_public_tools(tools: Any) -> None:
    enforce(isinstance(tools, list) and len(tools) == 2, "Expected exactly 2 public tools")
    seen_names: set[str] = set()
    for tool in tools:
        enforce(isinstance(tool, dict) and tool.get("type") == "function", "Invalid tool wrapper")
        fn = tool.get("function")
        enforce(isinstance(fn, dict), "Missing tool function spec")
        name = fn.get("name")
        enforce(name in PUBLIC_TOOL_PARAMS, f"Unexpected tool name: {name}")
        seen_names.add(name)
        params = fn.get("parameters")
        enforce(isinstance(params, dict), f"Missing parameters schema for {name}")
        enforce("$defs" not in params, f"Wire $defs leaked in {name} schema")
        enforce(params.get("additionalProperties") is False, f"{name} must forbid extra properties")
        props = params.get("properties")
        expected = PUBLIC_TOOL_PARAMS[name]
        enforce(
            isinstance(props, dict) and set(props) == expected,
            f"Tool {name} properties mismatch public contract",
        )
        enforce(
            set(params.get("required") or []) == expected,
            f"Tool {name} required fields mismatch public contract",
        )
    enforce(seen_names == set(PUBLIC_TOOL_PARAMS), "Missing required public tools")


def _validate_assistant_action(msg: dict[str, Any], *, require_valid_target: bool) -> None:
    allowed_keys = {"role", "content", "tool_calls", "loss_mask"}
    enforce(set(msg) <= allowed_keys, f"Unexpected assistant keys: {set(msg) - allowed_keys}")
    calls = msg.get("tool_calls")
    if calls is not None:
        enforce(isinstance(calls, list) and len(calls) == 1, "Assistant tool_calls must have len 1")
        call = calls[0]
        enforce(
            set(call) == {"id", "type", "function"} and call.get("type") == "function",
            "Malformed assistant tool_call entry",
        )
        fn = call["function"]
        name = fn.get("name")
        enforce(name in PUBLIC_TOOL_PARAMS, f"Unknown tool call name: {name}")
        parsed_args = json.loads(fn["arguments"])
        enforce(
            isinstance(parsed_args, dict) and set(parsed_args) == PUBLIC_TOOL_PARAMS[name],
            f"Tool arguments violate public contract for {name}",
        )
    elif require_valid_target:
        parsed = json.loads(msg.get("content") or "")
        enforce(
            isinstance(parsed, dict) and set(parsed) == DISPOSITION_KEYS,
            "Terminal assistant JSON does not match public disposition contract",
        )


def assert_sft_sample_safe(sample: dict[str, Any]) -> None:
    """Enforce zero Host/fault/oracle leakage and strict assistant-only loss masking on SFT."""
    _scan_no_leaks(sample)
    assert_public_tools(sample.get("tools"))
    messages = sample.get("messages")
    enforce(isinstance(messages, list) and len(messages) >= 3, "SFT sample requires >=3 messages")
    enforce(messages[0].get("role") == "system", "First SFT message must be system")
    enforce(messages[1].get("role") == "user", "Second SFT message must be user")
    enforce(messages[-1].get("role") == "assistant", "Last SFT message must be assistant")

    supervised_count = 0
    for idx, msg in enumerate(messages):
        role = msg.get("role")
        mask = msg.get("loss_mask")
        enforce(type(mask) is int and mask in {0, 1}, f"Invalid loss_mask at message[{idx}]")
        if role == "assistant":
            enforce(mask == 1, f"Assistant message[{idx}] must have loss_mask=1")
            _validate_assistant_action(msg, require_valid_target=True)
            supervised_count += 1
        else:
            enforce(
                role in {"system", "user", "tool"},
                f"Unknown message role '{role}' at message[{idx}]",
            )
            enforce(
                mask == 0,
                f"Non-assistant role '{role}' at message[{idx}] must have loss_mask=0",
            )
    enforce(supervised_count >= 1, "SFT sample must supervise at least one assistant action")


def assert_preference_pair_safe(pair: dict[str, Any]) -> None:
    """Enforce zero Host/fault/oracle leakage and shared unmasked prompt on preference pairs."""
    _scan_no_leaks(pair)
    assert_public_tools(pair.get("tools"))
    prompt = pair.get("prompt")
    enforce(isinstance(prompt, list) and len(prompt) >= 2, "Preference prompt requires >=2 turns")
    for idx, msg in enumerate(prompt):
        enforce(
            type(msg.get("loss_mask")) is int and msg["loss_mask"] == 0,
            f"Preference prompt[{idx}] must have loss_mask=0",
        )
        if msg.get("role") == "assistant":
            _validate_assistant_action(msg, require_valid_target=True)
    chosen = pair.get("chosen")
    rejected = pair.get("rejected")
    enforce(isinstance(chosen, dict) and chosen.get("role") == "assistant", "Invalid chosen turn")
    enforce(
        isinstance(rejected, dict) and rejected.get("role") == "assistant", "Invalid rejected turn"
    )
    enforce("loss_mask" not in chosen and "loss_mask" not in rejected, "Targets omit loss_mask")
    _validate_assistant_action(chosen, require_valid_target=True)
    _validate_assistant_action(rejected, require_valid_target=False)
    enforce(chosen != rejected, "Chosen and rejected responses must differ")


def _sanitize_tool_observation(raw_content: str) -> str:
    payload = json.loads(raw_content)
    result = payload.get("result")
    if isinstance(result, dict) and result.get("kind") == "receipt":
        receipt = result.get("receipt")
        if isinstance(receipt, dict):
            cleaned_receipt = {
                k: v for k, v in receipt.items() if k not in {"run_id", "operation_id"}
            }
            payload = {**payload, "result": {**result, "receipt": cleaned_receipt}}
    return json.dumps(payload, ensure_ascii=False)


def _extract_sanitized_turns(
    events: list[dict[str, Any]], *, allow_invalid_final_assistant: bool = False
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    req_events = [e["data"] for e in events if e["event"] == "model_request"]
    resp_events = [e["data"] for e in events if e["event"] == "model_response"]
    enforce(
        len(req_events) >= 1 and len(req_events) == len(resp_events),
        "Trajectory must have matched model_request and model_response turns",
    )
    # Verify every earlier request/response is an exact prefix of the final request history.
    final_history = req_events[-1]["messages"]
    for idx in range(len(req_events) - 1):
        prefix = req_events[idx]["messages"] + [resp_events[idx]["message"]]
        enforce(
            final_history[: len(prefix)] == prefix,
            f"Turn {idx + 1} history is not a prefix of final request history",
        )

    raw_messages = [*copy.deepcopy(final_history), copy.deepcopy(resp_events[-1]["message"])]
    tools = copy.deepcopy(req_events[-1]["tools"])
    call_id_map: dict[str, str] = {}
    sanitized: list[dict[str, Any]] = []

    for idx, msg in enumerate(raw_messages):
        role = msg["role"]
        is_last = idx == len(raw_messages) - 1
        if role == "assistant":
            calls = msg.get("tool_calls") or []
            if calls:
                enforce(len(calls) == 1, "Parallel tool calls are outside public contract")
                raw_call = calls[0]
                old_id = raw_call["id"]
                new_id = call_id_map.setdefault(old_id, f"call_{len(call_id_map) + 1}")
                name = raw_call["function"]["name"]
                parsed_args = json.loads(raw_call["function"]["arguments"])
                raw_text = msg.get("content") if isinstance(msg.get("content"), str) else ""
                sanitized.append({
                    "role": "assistant",
                    "content": "" if not raw_text.strip() else raw_text,
                    "tool_calls": [{
                        "id": new_id,
                        "type": "function",
                        "function": {
                            "name": name,
                            "arguments": json.dumps(parsed_args, ensure_ascii=False),
                        },
                    }],
                    "loss_mask": 1,
                })
            else:
                content = msg.get("content") if isinstance(msg.get("content"), str) else ""
                if not (is_last and allow_invalid_final_assistant):
                    parsed = json.loads(content)
                    enforce(
                        isinstance(parsed, dict) and set(parsed) == DISPOSITION_KEYS,
                        "Invalid assistant disposition JSON",
                    )
                sanitized.append({
                    "role": "assistant",
                    "content": content,
                    "loss_mask": 1,
                })
        elif role == "tool":
            mapped_id = call_id_map.get(msg["tool_call_id"])
            enforce(mapped_id is not None, "Tool observation references unknown tool_call_id")
            sanitized.append({
                "role": "tool",
                "tool_call_id": mapped_id,
                "content": _sanitize_tool_observation(msg["content"]),
                "loss_mask": 0,
            })
        elif role in {"system", "user"}:
            sanitized.append({
                "role": role,
                "content": msg["content"],
                "loss_mask": 0,
            })
        else:
            raise SecurityViolationError(f"Unsupported role in trajectory: {role}")

    return tools, sanitized


def build_sft_samples(
    directory: Path,
    rows: list[dict[str, Any]],
    contract: dict[str, Any],
    *,
    include_host_retry: bool = False,
) -> list[dict[str, Any]]:
    """Convert recovery-succeeded runs into assistant-masked public-contract SFT samples."""
    samples: list[dict[str, Any]] = []
    for row in sorted(rows, key=lambda r: r["slot"]):
        if not row["grade"]["correct_disposition"]:
            continue
        run_dir = directory / row["path"]
        record = replay(run_dir)
        if not record.get("measurement_valid"):
            continue
        events = journal(run_dir / "trace.jsonl")
        has_reproposal = bool(record["counters"]["repair_used"])
        has_backoff = any(e["event"] == "backoff" for e in events)
        if has_reproposal:
            recovery_kind = "certified_reproposal"
        elif include_host_retry and has_backoff and record["counters"]["decision_steps"] >= 2:
            recovery_kind = "host_retry"
        else:
            continue

        tools, messages = _extract_sanitized_turns(events)
        sample = {
            "schema": "harness-sft-masked-v1",
            "sample_id": f"sft-{row['slot']}",
            "slot": row["slot"],
            "task_id": row["task_id"],
            "family": row["family"],
            "repeat": row["repeat"],
            "model": row["model"],
            "model_name": contract["models"][row["model"]]["model"],
            "policy": row["policy"],
            "recovery_kind": recovery_kind,
            "supervised_assistant_turns": sum(m["loss_mask"] == 1 for m in messages),
            "masked_context_turns": sum(m["loss_mask"] == 0 for m in messages),
            "tools": tools,
            "messages": messages,
        }
        assert_sft_sample_safe(sample)
        samples.append(sample)
    return samples


def build_acc15_preference_pairs(
    directory: Path, rows: list[dict[str, Any]], contract: dict[str, Any]
) -> list[dict[str, Any]]:
    """Pair same-model, same-policy acc-15 successes (r1, r3) against valid format failure (r2)."""
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in rows:
        if row["task_id"] == "acc-15":
            grouped.setdefault((row["model"], row["policy"]), []).append(row)

    pairs: list[dict[str, Any]] = []
    for (model_label, policy), group in sorted(grouped.items()):
        ordered = sorted(group, key=lambda r: r["repeat"])
        passed = [r for r in ordered if r["grade"]["correct_disposition"] == 1]
        failed = [r for r in ordered if r["grade"]["correct_disposition"] == 0]
        if not passed or not failed:
            continue
        for fail_row in failed:
            fail_dir = directory / fail_row["path"]
            replay(fail_dir)
            fail_events = journal(fail_dir / "trace.jsonl")
            enforce(
                not any(e["event"] == "model_failed" for e in fail_events),
                f"Cannot use API transport failure {fail_row['slot']} as content preference target",
            )
            rej_tools, rej_msgs = _extract_sanitized_turns(
                fail_events, allow_invalid_final_assistant=True
            )
            rej_prompt = [{**m, "loss_mask": 0} for m in rej_msgs[:-1]]
            rej_target = {k: v for k, v in rej_msgs[-1].items() if k != "loss_mask"}
            last_resp = [e["data"] for e in fail_events if e["event"] == "model_response"][-1]
            proto = classify_response_protocol(
                last_resp["message"], last_resp["finish_reason"], expected_tool_phase=False
            )

            for win_row in passed:
                win_dir = directory / win_row["path"]
                replay(win_dir)
                win_events = journal(win_dir / "trace.jsonl")
                win_tools, win_msgs = _extract_sanitized_turns(win_events)
                win_prompt = [{**m, "loss_mask": 0} for m in win_msgs[:-1]]
                win_target = {k: v for k, v in win_msgs[-1].items() if k != "loss_mask"}

                enforce(
                    win_tools == rej_tools and win_prompt == rej_prompt,
                    f"Prompt prefix mismatch between {win_row['slot']} and {fail_row['slot']}",
                )
                pair = {
                    "schema": "harness-preference-pair-v1",
                    "pair_id": (
                        f"pref-acc-15-{model_label}-{policy}-"
                        f"r{win_row['repeat']}-vs-r{fail_row['repeat']}"
                    ),
                    "task_id": "acc-15",
                    "model": model_label,
                    "model_name": contract["models"][model_label]["model"],
                    "policy": policy,
                    "chosen_slot": win_row["slot"],
                    "rejected_slot": fail_row["slot"],
                    "rejection_anomaly": proto["anomaly"],
                    "rejection_protocol_field": proto["protocol_field"],
                    "tools": win_tools,
                    "prompt": win_prompt,
                    "chosen": win_target,
                    "rejected": rej_target,
                }
                assert_preference_pair_safe(pair)
                pairs.append(pair)
    return pairs


def run(
    directory: Path, output: Path, *, include_host_retry: bool = False
) -> dict[str, Any]:
    """Export security-verified SFT and acc-15 preference datasets without touching input."""
    directory, output = directory.resolve(), output.resolve()
    if directory == output or output.is_relative_to(directory) or directory.is_relative_to(output):
        raise ValueError("Export output must be separate from the recorded input directory")
    if output.exists():
        raise FileExistsError("Use a fresh export output directory; existing files are kept")

    before = fingerprint(directory)
    rows = journal(directory / "results.jsonl")
    contract = read(directory / "experiment.json")

    sft_samples = build_sft_samples(
        directory, rows, contract, include_host_retry=include_host_retry
    )
    preference_pairs = build_acc15_preference_pairs(directory, rows, contract)

    if fingerprint(directory) != before:
        raise ValueError("Recorded input changed during read-only trajectory export")

    summary = {
        "schema": "post-training-export-summary-v1",
        "export_source": source_revision(),
        "input": rel_posix(directory),
        "model_api_calls": 0,
        "input_unchanged": True,
        "sft": {
            "include_host_retry": include_host_retry,
            "samples": len(sft_samples),
            "by_model": {
                m: sum(s["model"] == m for s in sft_samples) for m in sorted(contract["models"])
            },
            "supervised_assistant_turns_total": sum(
                s["supervised_assistant_turns"] for s in sft_samples
            ),
            "masked_context_turns_total": sum(
                s["masked_context_turns"] for s in sft_samples
            ),
            "file": "sft_masked_reproposal.jsonl",
        },
        "preference": {
            "pairs": len(preference_pairs),
            "pair_ids": [p["pair_id"] for p in preference_pairs],
            "file": "preference_acc15_pairs.jsonl",
        },
        "security_assertions": {
            "all_passed": True,
            "sanitized_surfaces": [
                "assistant_opaque_context_and_call_index_removed",
                "receipt_internal_slot_identifiers_removed",
                "tool_call_ids_canonicalized",
            ],
            "blocked_categories": [
                "wire_host_envelope",
                "private_fault_config",
                "private_task_oracle",
                "provider_opaque_and_credentials",
                "local_filesystem_paths",
                "non_assistant_loss_mask_supervision",
            ],
        },
    }
    _scan_no_leaks(summary)

    output.mkdir(parents=True, exist_ok=False)
    atomic(output / "sft_masked_reproposal.jsonl", sft_samples, lines=True)
    atomic(output / "preference_acc15_pairs.jsonl", preference_pairs, lines=True)
    atomic(output / "summary.json", summary)
    return summary
