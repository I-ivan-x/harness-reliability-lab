"""Offline Host/MCP evidence reconciliation; no execution or task-oracle access."""

import json
import math

from mcp.types import CallToolResult, InitializeResult, ListToolsResult


def require(condition, reason):
    if not condition:
        raise ValueError("Protocol evidence: " + reason)


def _application_result(raw, attempt):
    """Independent assertions over the fixed two-tool application contract."""
    payload = raw.get("structuredContent")
    if not isinstance(payload, dict) or type(payload.get("ok")) is not bool:
        return False
    if raw.get("isError") is not (not payload["ok"]):
        return False
    args, envelope = attempt["arguments"], attempt["envelope"]
    if not payload["ok"]:
        error = payload.get("error", {})
        return isinstance(error, dict) and all(
            isinstance(error.get(key), str) and error[key] for key in ("code", "message")
        ) and all(type(error.get(key)) is bool for key in (
            "repairable", "not_executed", "unbound"
        )) and (not error["repairable"] or (
            error["code"] in {"STALE_REVISION", "INVALID_QUEUE"}
            and error["not_executed"] and error["unbound"]
        ))
    if attempt["tool"] == "read_state":
        state = payload.get("state", {})
        return (payload.get("kind") == "state" and isinstance(state, dict)
                and state.get("target_ref") == args["target_ref"]
                and type(state.get("revision")) is int and isinstance(state.get("facts"), dict))
    receipt = payload.get("receipt", {})
    return (payload.get("kind") == "receipt" and isinstance(receipt, dict)
            and all(isinstance(receipt.get(key), str) and receipt[key] for key in (
                "receipt_id", "ticket_id", "run_id", "operation_id", "target_ref"
            )) and receipt.get("params") == args
            and receipt["target_ref"] == args["target_ref"]
            and all(receipt[key] == envelope[key] for key in ("run_id", "operation_id")))


def _result_evidence(current, data, limit, counts, elapsed_s):
    result, response = data["result"], current.get("response")
    require(type(data.get("accepted_result_bytes")) is int
            and data["accepted_result_bytes"] >= 0, "invalid accepted-result size")
    require(isinstance(result, dict) and type(result.get("ok")) is bool, "bad Host result")
    accepted = data["accepted_result_bytes"]
    code = result.get("error", {}).get("code")
    if response and "error" in response:
        expected = "TIMEOUT" if response["error"]["code"] == 408 else "PROTOCOL_ERROR"
        require(result == {"ok": False, "error": {"code": expected}} and accepted == 0,
                "JSON-RPC error disagrees with Host result")
        counts["timeouts"] += expected == "TIMEOUT"
        return
    if not result["ok"] and code in {"TIMEOUT", "TRANSPORT_ERROR"} and accepted == 0:
        if code == "TIMEOUT":
            require(elapsed_s - current["elapsed_s"] + .001 >= current["attempt"]["timeout_s"],
                    "local timeout precedes its deadline")
            counts["timeouts"] += 1
        else:
            # Historical traces contain no typed, request-bound transport-failure proof.
            # An arbitrary diagnostic exception name cannot certify the local cause.
            counts["unverified_outcomes"] += 1
        return
    require(response is not None and "result" in response, "Host result lacks wire response")
    try:
        raw = CallToolResult.model_validate(response["result"]).model_dump(
            mode="json", by_alias=True
        )
        size = len(json.dumps(raw).encode())
        valid = _application_result(raw, current["attempt"]) and size <= limit
    except (ValueError, TypeError, KeyError):
        raw, size, valid = {}, 0, False
    if valid:
        require(result == raw["structuredContent"] and accepted == size,
                "application response or byte count disagrees with Host result")
    else:
        require(result == {"ok": False, "error": {"code": "INVALID_RESULT"}} and accepted == 0,
                "invalid wire result was accepted or misclassified")


def verify_protocol(events: list[dict]) -> dict:
    """Check fixed stdio-tool evidence. Missing-send attempts are explicitly unverified.

    wire_send is recorded before the stream send completes: it proves a send attempt,
    never remote delivery. A response may arrive after a local timeout or cancellation.
    """
    counts = dict.fromkeys(("attempts", "requests", "responses", "timeouts", "late_responses",
                           "interrupted", "unverified_attempts", "unverified_outcomes",
                           "feedbacks"), 0)
    requests, observations, delivered = {}, {}, set()
    current, listed, initialized, last_request_refs = None, None, None, set()
    stop = closed = initialized_notice = False
    cleanup_completed = None
    previous, limits, pending_delivery = -1, {}, None
    for index, event in enumerate(events, 1):
        require(event["seq"] == index and event["elapsed_s"] >= previous,
                "event sequence or time is inconsistent")
        previous = event["elapsed_s"]
        kind, data = event["event"], event["data"]
        if kind == "run_start":
            require(index == 1, "misplaced run start")
            limits = data["record"]["limits"]
        elif kind == "tool_attempt":
            require(not stop and not closed, "tool attempt after dispatch stopped")
            require(current is None or "result" in current, "overlapping Host attempts")
            timeout = data["timeout_s"]
            expected_timeout = min(limits["tool_timeout_s"],
                                   limits["total_s"] - limits["cleanup_s"] - previous)
            require(type(timeout) in (int, float) and math.isfinite(timeout) and timeout > 0
                    and abs(timeout - expected_timeout) <= .001,
                    "tool timeout disagrees with recorded engineering budget")
            current = {"attempt": data, "elapsed_s": previous}
            counts["attempts"] += 1
        elif kind == "wire_send":
            require(not closed, "wire send after MCP cleanup")
            method = data.get("method")
            if "id" not in data:
                if method == "notifications/initialized":
                    require(initialized is not None and not initialized_notice,
                            "initialized notice without successful initialization")
                    initialized_notice = True
                if method == "notifications/cancelled":
                    require(data.get("params", {}).get("requestId") in requests,
                            "cancellation references an unknown request")
                continue
            request_id = data["id"]
            require(type(request_id) in (str, int) and request_id not in requests,
                    "invalid or duplicate request ID")
            require(data.get("jsonrpc") == "2.0", "bad JSON-RPC request")
            request = {"wire": data, "current": None}
            requests[request_id] = request
            if method == "tools/call":
                require(not stop and current is not None and "result" not in current
                        and "request" not in current, "unmatched or repeated tool request")
                attempt = current["attempt"]
                require(data.get("params") == {"name": attempt["tool"], "arguments": {
                    **attempt["arguments"], "envelope": attempt["envelope"]
                }}, "tool request arguments disagree with Host attempt")
                current["request"], request["current"] = request_id, current
                counts["requests"] += 1
            elif method == "initialize":
                require(len(requests) == 1, "initialize was not the first request")
            else:
                require(method == "tools/list" and initialized_notice,
                        "unexpected request or discovery before initialization")
        elif kind == "wire_receive":
            require(not closed, "wire response after MCP cleanup")
            if "transport_error_type" in data:
                continue
            if "method" in data:
                require("id" not in data, "unexpected server-initiated request")
                continue
            request_id = data.get("id")
            require(type(request_id) in (str, int) and request_id in requests,
                    "response references an unknown request")
            request = requests[request_id]
            require("response" not in request and ("result" in data) != ("error" in data)
                    and data.get("jsonrpc") == "2.0", "duplicate or malformed response")
            request["response"] = data
            if "error" in data:
                require(type(data["error"].get("code")) is int
                        and isinstance(data["error"].get("message"), str), "bad protocol error")
            method, matched = request["wire"]["method"], request["current"]
            if matched is not None:
                counts["responses"] += 1
                if "result" in matched or stop:
                    counts["late_responses"] += 1
                else:
                    matched["response"] = data
            elif method == "initialize" and "result" in data:
                initialized = InitializeResult.model_validate(data["result"]).model_dump(
                    mode="json", by_alias=True)
            elif method == "tools/list" and "result" in data:
                require(listed is None, "duplicate tool discovery")
                listed = [tool.model_dump(mode="json", by_alias=True)
                          for tool in ListToolsResult.model_validate(data["result"]).tools]
        elif kind in {"mcp_initialized", "mcp_tools"}:
            expected = initialized if kind == "mcp_initialized" else {"tools": listed}
            require(expected is not None and data == expected,
                    "Host discovery metadata lacks matching wire evidence")
        elif kind == "tool_result":
            require(current is not None and "result" not in current, "unmatched Host result")
            attempt = current["attempt"]
            require(all(data[key] == attempt[key] for key in ("tool", "operation"))
                    and data["attempt"] == attempt["envelope"]["attempt"],
                    "Host result identity disagrees with attempt")
            if "request" not in current:
                counts["unverified_attempts"] += 1
            _result_evidence(current, data, limits["tool_result_bytes"], counts, previous)
            current["result"] = data["result"]
        elif kind == "feedback":
            require(current is not None and "result" in current and not current.get("feedback"),
                    "feedback lacks a unique final attempt result")
            observation, attempt = data["observation"], current["attempt"]
            require(observation["ref"] not in observations
                    and observation["result"] == current["result"]
                    and observation["tool"] == attempt["tool"]
                    and observation.get("host_observed") is True
                    and observation.get("delivered") is False
                    and all(data.get(key) == attempt.get(key)
                            for key in ("operation", "model_call_id")),
                    "feedback content or identity disagrees with final result")
            observations[observation["ref"]] = (observation, data.get("model_call_id"))
            current["feedback"] = True
            counts["feedbacks"] += 1
        elif kind == "model_request":
            require(not stop and not closed and initialized_notice and listed is not None,
                    "model request without live discovered MCP session")
            require(pending_delivery is None, "overlapping model requests")
            pending_delivery = set(observations) - delivered
            last_request_refs = set()
            for message in data["messages"]:
                if message["role"] not in {"user", "tool"}:
                    continue
                value = json.loads(message["content"])
                if message["role"] == "user" and value.get("source") != "host_refresh":
                    continue
                visible = value if message["role"] == "tool" else value["observation"]
                require(visible.get("ref") in observations, "model received unknown observation")
                observation, call_id = observations[visible["ref"]]
                require(visible == {key: observation[key] for key in ("ref", "tool", "result")}
                        and (message.get("tool_call_id") == call_id
                             if message["role"] == "tool" else call_id is None),
                        "model observation differs from actual feedback")
                last_request_refs.add(visible["ref"])
            require(pending_delivery <= last_request_refs,
                    "model request omitted new feedback")
        elif kind == "controller_delivery":
            refs = data["refs"]
            require(pending_delivery is not None and set(refs) == pending_delivery
                    and len(refs) == len(set(refs)) and set(refs) <= last_request_refs
                    and not (set(refs) & delivered), "unsupported observation delivery")
            delivered.update(refs)
        elif kind in {"model_response", "model_failed"}:
            require(pending_delivery is not None, "model outcome without request")
            if kind == "model_response":
                require(pending_delivery <= delivered, "successful response omitted delivery")
            pending_delivery = None
        elif kind == "dispatch_stop":
            require(not stop, "duplicate dispatch stop")
            stop = True
        elif kind == "mcp_cleanup":
            require(not closed, "duplicate MCP cleanup")
            require(type(data.get("completed")) is bool, "MCP cleanup lacks completion flag")
            cleanup_completed = data["completed"]
            closed = True
    require(events and events[-1]["event"] == "run_end" and closed, "unsealed MCP lifecycle")
    ending = events[-1]["data"]
    require(ending.get("terminated_quiescent") is cleanup_completed
            and (ending.get("measurement_valid") is not True or cleanup_completed),
            "cleanup completion disagrees with sealed measurement")
    counts["unverified_outcomes"] += not cleanup_completed
    if current is not None and "result" not in current:
        counts["interrupted"] += 1
        counts["unverified_attempts"] += "request" not in current
        terminal = next(item["data"]["output"] for item in events if item["event"] == "terminal")
        require(terminal["reason_code"] == "cancelled", "unfinished attempt without cancellation")
    require(not counts["attempts"] or (initialized_notice and listed is not None),
            "business attempts without completed initialization/discovery")
    return counts
