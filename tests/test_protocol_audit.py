"""Protocol evidence positives use real MCP; mutations never alter original runs."""

import asyncio
import copy
import json
import runpy
from pathlib import Path

import pytest
from tests.test_lifecycle import effects, setup, wait_until
from tests.test_runtime import prepare

from harness_lab.contracts import TaskInput
from harness_lab.runtime import run

verify_protocol = runpy.run_path(str(
    Path(__file__).parents[1] / "evals/protocol_audit.py"
))["verify_protocol"]


def events(directory):
    return [json.loads(line) for line in
            (directory / "trace.jsonl").read_text(encoding="utf-8").splitlines()]


def resequence(items):
    for index, item in enumerate(items, 1):
        item["seq"] = index
    return items


@pytest.fixture(scope="module")
def real_traces(tmp_path_factory):
    root, result = tmp_path_factory.mktemp("protocol"), {}
    for name in ("normal", "read-transient", "lost-response", "malformed-read",
                 "malformed-write"):
        directory = root / name
        directory.mkdir()
        task, config, ports = prepare(directory, name)
        record = asyncio.run(run(task, config, ports))
        assert record["measurement_valid"]
        result[name] = events(config.artifact_dir)
    for name, fault in (("protocol", {"kind": "protocol_error", "stage": "write-0"}),
                        ("late", {"kind": "commit_response_delay", "attempts": [1],
                                  "delay_s": .3})):
        directory = root / name
        directory.mkdir()
        prepared, config, ports = setup(directory, fault=fault, policy="P0",
                                        await_late=name == "late", timeout=.05)
        record = asyncio.run(run(TaskInput(**prepared["task_input"]), config, ports))
        assert record["measurement_valid"]
        result[name] = events(config.artifact_dir)
    return result


@pytest.mark.parametrize("name", ["normal", "read-transient", "lost-response",
                                  "malformed-read", "malformed-write", "protocol", "late"])
def test_real_mcp_paths_have_complete_causal_evidence(real_traces, name):
    result = verify_protocol(real_traces[name])
    assert result["attempts"] == result["requests"]
    assert result["feedbacks"] >= 1
    assert result["unverified_attempts"] == result["unverified_outcomes"] == 0
    if name in {"late", "lost-response"}:
        assert result["timeouts"] == 1
    if name == "late":
        assert result["late_responses"] == 1
    if name in {"read-transient", "malformed-write", "lost-response"}:
        assert result["attempts"] == 3


@pytest.mark.parametrize("mutation", ["delete_wire", "request_id", "arguments", "duplicate",
                                      "feedback", "missing_response", "model_observation",
                                      "dispatch_after_stop", "missing_delivery", "early_timeout",
                                      "false_cleanup", "timeout_tampering"])
def test_missing_or_changed_causal_evidence_is_rejected(real_traces, mutation):
    trace = copy.deepcopy(real_traces["normal"])
    send = next(item for item in trace if item["event"] == "wire_send"
                and item["data"].get("method") == "tools/call")
    response = next(item for item in trace if item["event"] == "wire_receive"
                    and item["data"].get("id") == send["data"]["id"])
    if mutation == "delete_wire":
        trace = [item for item in trace if item["event"] not in {"wire_send", "wire_receive"}]
    elif mutation == "request_id":
        send["data"]["id"] = "other-request"
    elif mutation == "arguments":
        send["data"]["params"]["arguments"]["envelope"]["operation_id"] = "new-slot"
    elif mutation == "duplicate":
        trace.insert(trace.index(response) + 1, copy.deepcopy(response))
    elif mutation == "missing_response":
        trace.remove(response)
    elif mutation == "missing_delivery":
        trace = [item for item in trace if item["event"] != "controller_delivery"]
    elif mutation == "early_timeout":
        trace.remove(response)
        result = next(item for item in trace if item["event"] == "tool_result")
        result["data"]["result"] = {"ok": False, "error": {"code": "TIMEOUT"}}
        result["data"]["accepted_result_bytes"] = 0
    elif mutation == "false_cleanup":
        next(item for item in trace if item["event"] == "mcp_cleanup")["data"]["completed"] = False
    elif mutation == "timeout_tampering":
        next(item for item in trace if item["event"] == "tool_attempt")["data"]["timeout_s"] = 1e-9
    elif mutation == "feedback":
        feedback = next(item for item in trace if item["event"] == "feedback")
        feedback["data"]["observation"]["result"]["state"]["revision"] = 999
    elif mutation == "model_observation":
        request = next(item for item in trace if item["event"] == "model_request"
                       and any(message["role"] == "tool" for message in item["data"]["messages"]))
        message = next(message for message in request["data"]["messages"]
                       if message["role"] == "tool")
        value = json.loads(message["content"])
        value["result"]["state"]["revision"] = 999
        message["content"] = json.dumps(value)
    else:
        attempt = copy.deepcopy(next(item for item in trace if item["event"] == "tool_attempt"))
        index = next(index for index, item in enumerate(trace) if item["event"] == "dispatch_stop")
        attempt["elapsed_s"] = trace[index]["elapsed_s"]
        trace.insert(index + 1, attempt)
    with pytest.raises(ValueError):
        verify_protocol(resequence(trace))


def test_late_receipt_cannot_be_promoted_to_an_earlier_success(real_traces):
    trace = copy.deepcopy(real_traces["late"])
    late = next(item for item in trace if item["event"] == "wire_receive"
                and item["data"].get("result", {}).get("structuredContent", {}).get(
                    "kind") == "receipt")
    result = next(item for item in trace if item["event"] == "tool_result"
                  and item["data"]["tool"] == "create_ticket")
    result["data"]["result"] = late["data"]["result"]["structuredContent"]
    result["data"]["accepted_result_bytes"] = 1
    with pytest.raises(ValueError, match="lacks wire response"):
        verify_protocol(trace)


def test_timeout_nine_milliseconds_early_is_still_rejected(real_traces):
    trace = copy.deepcopy(real_traces["late"])
    attempt = next(item for item in trace if item["event"] == "tool_attempt"
                   and item["data"]["tool"] == "create_ticket")
    result = next(item for item in trace if item["event"] == "tool_result"
                  and item["data"]["tool"] == "create_ticket")
    result["elapsed_s"] = attempt["elapsed_s"] + attempt["data"]["timeout_s"] - .009
    with pytest.raises(ValueError, match="local timeout precedes its deadline"):
        verify_protocol(trace)


def test_timeout_without_send_evidence_remains_explicitly_unverified(real_traces):
    trace = copy.deepcopy(real_traces["late"])
    request_id = next(item["data"]["id"] for item in trace if item["event"] == "wire_send"
                      and item["data"].get("params", {}).get("name") == "create_ticket")
    trace = [item for item in trace if not (
        item["event"] in {"wire_send", "wire_receive"} and item["data"].get("id") == request_id
    )]
    result = verify_protocol(resequence(trace))
    assert result["attempts"] == 2 and result["requests"] == 1
    assert result["unverified_attempts"] == 1


@pytest.mark.parametrize("phase", ["startup", "post_commit"])
def test_real_cancellation_does_not_require_a_response_or_fabricate_feedback(tmp_path, phase):
    async def check():
        prepared, config, ports = setup(tmp_path, fault={
            "kind": "commit_response_delay", "attempts": [1], "delay_s": 2,
        }, timeout=3)
        running = asyncio.create_task(run(TaskInput(**prepared["task_input"]), config, ports))
        if phase == "startup":
            await asyncio.wait_for(ports.tools.initialize_sent.wait(), timeout=10)
        else:
            await wait_until(lambda: effects(prepared["database"]) == 1)
        running.cancel()
        record = await asyncio.wait_for(running, timeout=10)
        assert record["measurement_valid"] and record["output"]["reason_code"] == "cancelled"
        result = verify_protocol(events(config.artifact_dir))
        assert result["interrupted"] == int(phase == "post_commit")
        assert result["unverified_attempts"] == result["unverified_outcomes"] == 0
    asyncio.run(check())


def test_unknown_transport_outcome_is_not_invented_as_verified(real_traces):
    trace = copy.deepcopy(real_traces["late"])
    for item in trace:
        if item["event"] == "tool_result" and item["data"]["tool"] == "create_ticket":
            item["data"]["result"]["error"]["code"] = "TRANSPORT_ERROR"
        if item["event"] == "feedback" and item["data"]["observation"]["tool"] == "create_ticket":
            item["data"]["observation"]["result"]["error"]["code"] = "TRANSPORT_ERROR"
    assert verify_protocol(trace)["unverified_outcomes"] == 1
    failure = next(index for index, item in enumerate(trace) if item["event"] == "tool_result"
                   and item["data"]["tool"] == "create_ticket")
    trace.insert(failure, {"seq": 0, "elapsed_s": trace[failure]["elapsed_s"],
                          "event": "wire_receive", "data": {
                              "transport_error_type": "TotallyNotAnException"}})
    assert verify_protocol(resequence(trace))["unverified_outcomes"] == 1


def test_json_rpc_408_is_a_wire_error_without_a_local_deadline_wait(real_traces):
    trace = copy.deepcopy(real_traces["protocol"])
    for item in trace:
        if item["event"] == "wire_receive" and "error" in item["data"]:
            item["data"]["error"]["code"] = 408
        if item["event"] == "tool_result" and item["data"]["tool"] == "create_ticket":
            item["data"]["result"]["error"]["code"] = "TIMEOUT"
        if item["event"] == "feedback" and item["data"]["observation"]["tool"] == "create_ticket":
            item["data"]["observation"]["result"]["error"]["code"] = "TIMEOUT"
    assert verify_protocol(trace)["timeouts"] == 1
