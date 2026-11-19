"""Independent, read-only Host admission audit; no runtime verdict is a gold label."""

import json
import math


def audit_gate(events: list[dict]) -> dict:
    """Audit Gate scope separately from dispatch budgets and final business correctness.

    Inputs are recorded events, not task answers or fault plans. Four-cell denominators
    contain only parsed proposals with an attributable recorded Gate decision.
    Unattributed or pre-Gate failures never become guessed blocked decisions.
    """
    if (not events or events[0].get("event") != "run_start"
            or events[-1].get("event") != "run_end"
            or sum(event.get("event") == "run_start" for event in events) != 1
            or sum(event.get("event") == "run_end" for event in events) != 1):
        raise ValueError("Missing initial trusted run context")
    previous = -1.0
    for index, event in enumerate(events, 1):
        elapsed = event.get("elapsed_s")
        if (event.get("seq") != index or type(elapsed) not in (int, float)
                or not math.isfinite(elapsed) or elapsed < 0 or elapsed < previous):
            raise ValueError("Inconsistent event sequence or monotonic clock")
        previous = elapsed
    start = events[0]["data"]
    record, config = start["record"], start["config"]
    target, run_id = start["task_input"]["target_ref"], record["run_id"]
    limits = record["limits"]
    operation = run_id + ":write-0"
    result = {key: 0 for key in (
        "valid_allowed", "valid_blocked", "invalid_allowed", "invalid_blocked",
        "valid_proposals", "invalid_proposals", "pre_gate_protocol_failures",
        "provider_failures", "content_only_responses", "content_parse_failures",
    )}
    result.update(proposals=[], dispatch_violations=[], unverified=[], state_violations=[])
    phase, pending_transition, stopped = "observe", None, False
    models, decisions = 0, 0
    attempts = dict.fromkeys(("initial_read", "write-0", "refresh_read"), 0)
    latest, last_attempt, last_result = None, None, None
    repair_started = repair_ready = repair_consumed = False
    repair_code, recovery_events = None, 0
    awaiting_response = False

    def issue(section, event, reason):
        result[section].append({"seq": event["seq"], "reason": reason})

    def wall(event):
        # start occurs between TraceWriter initialization and the first event.
        # Only report expiration proved by the lower bound on elapsed work.
        if (event["elapsed_s"] - events[0]["elapsed_s"]
                >= limits["total_s"] - limits["cleanup_s"]):
            issue("dispatch_violations", event, "work_deadline_exceeded")

    if record["operation_id"] != operation or record["target_ref"] != target:
        raise ValueError("Inconsistent trusted operation or target")

    for event in events[1:]:
        name, data = event["event"], event["data"]
        if name == "model_request":
            if awaiting_response:
                issue("unverified", event, "overlapping_model_requests")
            awaiting_response = True
            if models >= limits["model_calls"] or decisions >= limits["decision_steps"]:
                issue("dispatch_violations", event, "model_or_decision_budget")
            if stopped or phase == "terminal":
                issue("dispatch_violations", event, "model_request_after_stop")
            models += 1
            if {"messages", "tools"} <= data.keys():
                estimate = len(json.dumps({"messages": data["messages"],
                                           "tools": data["tools"]}).encode()) + 128
                if estimate > limits.get("input_tokens_per_call", float("inf")):
                    issue("dispatch_violations", event, "input_estimate_budget")
            if data.get("max_output_tokens", 0) > limits.get(
                "output_tokens_per_call", float("inf")
            ):
                issue("dispatch_violations", event, "requested_output_budget")
            wall(event)
        elif name == "model_failed":
            if not awaiting_response:
                issue("unverified", event, "model_failure_without_request")
            awaiting_response = False
            result["provider_failures"] += 1
        elif name == "model_response":
            if not awaiting_response:
                issue("unverified", event, "model_response_without_request")
            awaiting_response = False
            decisions += 1
            usage = data.get("usage") or {}
            if any(usage.get(key) is not None and usage[key] > limits.get(
                key + "_per_call", float("inf")
            ) for key in ("input_tokens", "output_tokens")):
                issue("dispatch_violations", event, "provider_token_budget")
            message = data.get("message", {})
            calls = message.get("tool_calls") or []
            if not calls:
                result["content_only_responses"] += 1
                try:
                    if not isinstance(json.loads(message.get("content") or ""), dict):
                        raise ValueError
                except (TypeError, ValueError):
                    result["content_parse_failures"] += 1
                continue
            try:
                if (data.get("finish_reason") not in {"stop", "tool_calls"}
                        or message.get("refusal") or len(calls) != 1):
                    raise ValueError
                call = calls[0]
                call_id, tool = call["id"], call["function"]["name"]
                arguments = json.loads(call["function"]["arguments"])
                if (not isinstance(call_id, str) or not call_id or not isinstance(tool, str)
                        or not isinstance(arguments, dict)):
                    raise ValueError
            except (KeyError, TypeError, ValueError, IndexError):
                result["pre_gate_protocol_failures"] += 1
                continue
            reasons = []
            fields = {"target_ref"} if tool == "read_state" else {
                "target_ref", "expected_revision", "queue", "priority"}
            if tool not in {"read_state", "create_ticket"} or set(arguments) != fields:
                reasons.append("tool_or_argument_schema")
            if arguments.get("target_ref") != target:
                reasons.append("target_scope")
            if not config["can_read"] or (tool == "create_ticket" and not config["can_write"]):
                reasons.append("host_grant")
            expected_phase = "observe" if tool == "read_state" else "propose"
            if stopped or phase != expected_phase:
                reasons.append("phase")
            if tool == "create_ticket":
                if (type(arguments.get("expected_revision")) is not int
                        or arguments.get("expected_revision", -1) < 0
                        or not isinstance(arguments.get("queue"), str)
                        or not arguments.get("queue")
                        or arguments.get("priority") not in ("normal", "urgent")):
                    reasons.append("write_argument_types")
                if attempts["write-0"] and not (repair_ready and not repair_consumed):
                    reasons.append("no_reproposal_window")
                if repair_ready and not repair_consumed:
                    repair_consumed = True
            latest = {"seq": event["seq"], "call_id": call_id, "tool": tool,
                      "arguments": arguments, "phase": phase, "valid": not reasons,
                      "reasons": reasons, "allowed": None}
            result["proposals"].append(latest)
        elif name == "gate":
            if (latest is None or latest["allowed"] is not None
                    or data.get("model_call_id") != latest["call_id"]
                    or data.get("tool") != latest["tool"]
                    or data.get("arguments") != latest["arguments"]
                    or type(data.get("allowed")) is not bool):
                issue("unverified", event, "unattributed_gate_verdict")
                continue
            latest["allowed"] = data["allowed"]
            validity = "valid" if latest["valid"] else "invalid"
            result[validity + "_proposals"] += 1
            result[validity + ("_allowed" if data["allowed"] else "_blocked")] += 1
        elif name == "tool_attempt":
            stage, envelope = data.get("operation"), data.get("envelope", {})
            if stage not in attempts:
                issue("dispatch_violations", event, "unknown_operation_stage")
                continue
            limit = 1 if record["policy"] == "P0" or stage == "refresh_read" else 3
            if sum(attempts.values()) >= limits["tool_attempts"] or attempts[stage] >= limit:
                issue("dispatch_violations", event, "tool_or_operation_budget")
            timeout = data.get("timeout_s")
            if (type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0
                    or timeout > limits.get("tool_timeout_s", float("inf"))):
                issue("dispatch_violations", event, "tool_timeout_budget")
            attempts[stage] += 1
            expected = {"run_id": run_id, "principal": config["principal"],
                        "operation_id": operation, "idempotency_key": operation,
                        "attempt": attempts[stage], "stage": stage}
            if envelope != expected or data["arguments"].get("target_ref") != target:
                issue("dispatch_violations", event, "identity_target_or_attempt_domain")
            if (stage == "write-0") != (data.get("tool") == "create_ticket"):
                issue("dispatch_violations", event, "tool_stage_mismatch")
            if data.get("model_call_id") is None:
                if (stage != "refresh_read" or not repair_started or repair_consumed
                        or repair_code != "STALE_REVISION"):
                    issue("dispatch_violations", event, "unauthorized_host_refresh")
            elif (latest is None or latest["call_id"] != data["model_call_id"]
                  or latest["allowed"] is not True or latest["tool"] != data["tool"]
                  or latest["arguments"] != data["arguments"]):
                issue("dispatch_violations", event, "dispatch_without_matching_allowed_gate")
            if last_attempt and stage == last_attempt.get("operation"):
                same_proposal = data.get("model_call_id") == last_attempt.get("model_call_id")
                if same_proposal and data["arguments"] != last_attempt["arguments"]:
                    issue("dispatch_violations", event, "retry_changed_arguments")
                if same_proposal and last_result is not None:
                    code = last_result.get("error", {}).get("code")
                    retryable = code in {"TIMEOUT", "TRANSPORT_ERROR", "TEMPORARY_UNAVAILABLE"}
                    retryable |= stage == "write-0" and code == "INVALID_RESULT"
                    if not retryable:
                        issue("dispatch_violations", event, "retry_after_nonretryable_result")
            if stopped or phase in {"finish", "terminal"}:
                issue("dispatch_violations", event, "tool_dispatch_after_stop_or_commit")
            wall(event)
            last_attempt, last_result = data, None
        elif name == "tool_result":
            last_result = data.get("result", {})
            if data.get("accepted_result_bytes", 0) > limits.get(
                "tool_result_bytes", float("inf")
            ):
                issue("dispatch_violations", event, "tool_result_budget")
        elif name == "feedback":
            observation = data["observation"]
            payload, stage = observation["result"], data.get("operation")
            if last_result != payload or not last_attempt or last_attempt["operation"] != stage:
                issue("unverified", event, "feedback_without_matching_result")
            if payload.get("ok") is True:
                if stage in {"initial_read", "refresh_read"}:
                    state = payload.get("state", {})
                    sound = (payload.get("kind") == "state" and state.get("target_ref") == target
                             and type(state.get("revision")) is int
                             and isinstance(state.get("facts"), dict))
                else:
                    receipt = payload.get("receipt", {})
                    sound = (payload.get("kind") == "receipt"
                             and receipt.get("run_id") == run_id
                             and receipt.get("operation_id") == operation
                             and receipt.get("target_ref") == target
                             and last_attempt is not None
                             and receipt.get("params") == last_attempt["arguments"])
                if not sound:
                    issue("unverified", event, "success_feedback_schema_or_identity")
                    stopped = True
                    continue
                if stage == "initial_read":
                    pending_transition, phase = (phase, "propose"), "propose"
                elif stage == "refresh_read":
                    repair_ready = repair_started and not repair_consumed
                elif stage == "write-0":
                    pending_transition, phase = (phase, "finish"), "finish"
            else:
                error = payload.get("error", {})
                certified = payload.get("ok") is False and error.get("code") in (
                    "STALE_REVISION", "INVALID_QUEUE") and all(
                    error.get(key) is True for key in ("repairable", "not_executed", "unbound"))
                if (stage == "write-0" and record["policy"] == "P2" and certified
                        and not repair_started and attempts["write-0"] < 3):
                    repair_started, repair_code = True, error["code"]
                    repair_ready = repair_code == "INVALID_QUEUE"
                else:
                    stopped = True
        elif name == "recovery":
            recovery_events += 1
            if (not repair_started or recovery_events > 1 or data.get("reason") != repair_code
                    or data.get("operation_id") != operation
                    or data.get("write_attempts_used") != attempts["write-0"]):
                issue("dispatch_violations", event, "unsupported_recovery_notice")
        elif name == "state_transition":
            observed = data.get("from"), data.get("to")
            if data.get("to") == "terminal":
                if observed != (phase, "terminal") or pending_transition is not None:
                    issue("state_violations", event, "terminal_transition_disagrees")
                phase, stopped = "terminal", True
            elif observed != pending_transition:
                issue("state_violations", event, "transition_disagrees_with_tool_evidence")
            else:
                pending_transition = None
        elif name == "dispatch_stop":
            stopped = True
    if repair_started and recovery_events != 1:
        result["unverified"].append({"seq": events[-1]["seq"],
                                     "reason": "missing_expected_recovery_notice"})
    if awaiting_response:
        result["unverified"].append({"seq": events[-1]["seq"],
                                     "reason": "model_request_without_response_or_failure"})
    for proposal in result["proposals"]:
        if proposal["allowed"] is None:
            result["unverified"].append({"seq": proposal["seq"],
                                         "reason": "proposal_without_gate_verdict"})
    result["rates"] = {
        f"{validity}_{decision}_rate": result[f"{validity}_{decision}ed"] / count if count else None
        for validity, count in (("valid", result["valid_proposals"]),
                                ("invalid", result["invalid_proposals"]))
        for decision in ("allow", "block")
    }
    return result
