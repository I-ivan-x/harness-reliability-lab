"""Offline formal-trial checks against the frozen request and private-world contract."""

import json
from pathlib import PurePosixPath, PureWindowsPath

from evals.development import read
from evals.grader import score_signature
from evals.protocol_audit import verify_protocol
from evals.run_case import regrade_case
from harness_lab.runtime import public_tools
from harness_lab.trace import replay


def _score_without_latency(score):
    return {**score, "grading_cost": {
        key: value for key, value in score["grading_cost"].items() if key != "latency_s"
    }}


def verify_row(directory, row, batch, contract):
    """Verify one preserved result; unknown usage and valid task failures remain eligible."""
    path = (directory / row["path"]).resolve()
    assert path.is_relative_to(directory.resolve())
    entry = next(item for item in read(directory / "manifest.json")["tasks"]
                 if item["id"] == row["task_id"])
    assert (row["case"], row["family"]) == (entry["file"], entry["family"])
    case_path = directory / entry["file"]
    case, saved, server = read(case_path), read(path / "manifest.json"), read(
        path / "private-server.json")
    record = replay(path)
    assert (record["run_id"], record["policy"], record["output"], record["costs"]) == (
        row["run_id"], row["policy"], row["output"], row["costs"])
    assert record["source"] == batch["source"]
    assert record["task_id"] == row["task_id"] == case["task_input"]["task_id"]
    assert record["target_ref"] == case["task_input"]["target_ref"]
    assert record["operation_id"] == record["run_id"] + ":write-0"
    assert record["limits"] == contract["budget"]
    assert record["measurement_valid"] is True and record["terminated_quiescent"] is True
    assert saved["task_input"] == case["task_input"]
    assert saved["controller"] == contract["models"][row["model"]]
    assert saved["mcp_sdk"] == contract["dependencies"]["mcp"]
    origin = batch["artifact_root"]
    path_type = PureWindowsPath if PureWindowsPath(origin).drive else PurePosixPath
    expected_server = {
        "db_path": str(path_type(origin) / row["path"] / "environment.sqlite"),
        "run_id": record["run_id"],
        "principal": "dev-user", "operation_id": record["operation_id"],
        "idempotency_key": record["operation_id"], "target_ref": record["target_ref"],
        "can_read": True, "can_write": True, "fault": case["fault_plan"] or None,
    }
    assert server == expected_server
    events = [json.loads(line) for line in
              (path / "trace.jsonl").read_text(encoding="utf-8").splitlines()]
    start = events[0]["data"]
    assert start["task_input"] == case["task_input"]
    assert start["controller"] == saved["controller"]
    assert start["config"] == {
        **contract["budget"], "seed": row["seed"], "backoff_s": contract["backoff_s"],
        "jitter_s": contract["jitter_s"], "principal": "dev-user", "can_read": True,
        "can_write": True,
    }
    tools = [event["data"]["tools"] for event in events if event["event"] == "mcp_tools"]
    assert len(tools) == 1 and public_tools(tools[0]) == contract["tools"]
    auth = {"target_ref": record["target_ref"], "can_read": True, "can_write": True}
    system = contract["system_prompt"] + "\nHost authorization: " + json.dumps(auth)
    for event in events:
        data = event["data"]
        if event["event"] == "model_request":
            assert data["messages"][0] == {"role": "system", "content": system}
            assert data["messages"][1]["role"] == "user"
            assert json.loads(data["messages"][1]["content"]) == {"task": case["task_input"]}
            assert data["tools"] == contract["tools"]
            assert data["max_output_tokens"] == contract["budget"]["output_tokens_per_call"]
        if event["event"] == "tool_attempt":
            assert data["envelope"] == {
                key: expected_server[key] for key in
                ("run_id", "principal", "operation_id", "idempotency_key")
            } | {"attempt": data["envelope"]["attempt"], "stage": data["operation"]}
            assert data["arguments"]["target_ref"] == record["target_ref"]
    protocol = verify_protocol(events)
    assert protocol["unverified_attempts"] == protocol["unverified_outcomes"] == 0, (
        "Incomplete MCP evidence", protocol)
    score = regrade_case(case_path, path)
    assert score["measurement_valid"] is True
    # The recorded score remains immutable. New diagnostics are versioned separately;
    # only the explicit decision/metric contract must match across grader versions.
    assert _score_without_latency(row["grade"]) == _score_without_latency(
        read(path / "grade.json"))
    assert score_signature(score) == score_signature(row["grade"]), (
        "Grading decision changed", row["run_id"],
        {"recorded": score_signature(row["grade"]), "verified": score_signature(score)})
    return record, score
