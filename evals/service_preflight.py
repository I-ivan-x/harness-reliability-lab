"""Eight fixed development runs; stop at the first failure, never retry a trial."""

import argparse
import asyncio
import hashlib
import json
from dataclasses import asdict
from pathlib import Path

from evals.gate_audit import audit_gate
from evals.protocol_audit import verify_protocol
from evals.run_case import regrade_case, run_case
from harness_lab.contracts import Budget
from harness_lab.models import ModelError, OpenAICompatibleController
from harness_lab.trace import replay, source_revision

PROJECT = Path(__file__).resolve().parents[1]
SCENARIOS = (
    ("normal", "routine-window", "P1"),
    ("retry", "aging-alert", "P1"),
    ("reproposal", "scope-routing", "P2"),
    ("lost-receipt", "latency-incident", "P1"),
)
EXPECTED_MODELS = {"A": "deepseek-flash", "B": "doubao-seed-2-1-lite-260915"}
EXPECTED_TOKEN_FIELDS = {"A": "max_tokens", "B": "max_completion_tokens"}
DIAGNOSTICS = (
    "code", "layer", "http_status", "provider_code", "provider_type", "request_id",
    "request_id_source", "retry_after",
)


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def save(path, value):
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def journal(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def fingerprint(directory):
    return {path.relative_to(directory).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(directory.rglob("*")) if path.is_file()}


def configurations_unchanged(environments, digests):
    try:
        return all(hashlib.sha256(path.read_bytes()).digest() == digests[label]
                   for label, path in environments.items())
    except OSError:
        return False


async def configuration_summary(path, label):
    """Validate locally, without requests or copying credential-bearing string values."""
    controller = OpenAICompatibleController(path)
    try:
        matches = (controller.model == EXPECTED_MODELS[label]
                   and controller._key not in controller.model)
        summary = {"path": str(path.resolve()), "exists": path.is_file(),
                "kind": "openai-compatible", "model_configured": bool(controller.model),
                "endpoint_configured": bool(controller.base_url),
                "model_matches": matches,
                "model_sha256": hashlib.sha256(controller.model.encode()).hexdigest(),
                "token_limit_field": controller.token_limit_field,
                "token_limit_field_matches": controller.token_limit_field
                == EXPECTED_TOKEN_FIELDS[label],
                "response_format": "json_object", "temperature": 0,
                "thinking": "provider_default"}
        if matches:
            summary["model"] = EXPECTED_MODELS[label]
        return summary
    finally:
        await controller.aclose()


def branch_checks(scenario, events, record, case):
    attempts = [event["data"] for event in events if event["event"] == "tool_attempt"]
    results = [event["data"] for event in events if event["event"] == "tool_result"]
    writes = [item for item in attempts if item["operation"] == "write-0"]
    write_results = [item["result"] for item in results if item["operation"] == "write-0"]
    read_results = [item["result"] for item in results if item["operation"] == "initial_read"]
    counts = record["counters"]["operation_attempts"]
    repair = record["counters"]["repair_used"]
    expected = case["oracle"]["expected_params"]
    checks = {
        "expected_final_write": bool(writes) and writes[-1]["arguments"] == expected,
        "fixed_write_identity": bool(writes) and all(
            item["envelope"][key] == record["operation_id"] for item in writes
            for key in ("operation_id", "idempotency_key")),
    }
    if scenario == "normal":
        checks["normal_path"] = counts == {
            "initial_read": 1, "write-0": 1, "refresh_read": 0} and not repair
    elif scenario == "retry":
        checks["read_retry"] = (counts == {
            "initial_read": 2, "write-0": 1, "refresh_read": 0} and not repair
            and len(read_results) == 2 and read_results[0].get("error", {}).get("code")
            == "TEMPORARY_UNAVAILABLE" and read_results[1].get("ok") is True)
    elif scenario == "reproposal":
        first = write_results[0].get("error", {}) if write_results else {}
        checks["certified_reproposal"] = (counts == {
            "initial_read": 1, "write-0": 2, "refresh_read": 1} and repair
            and first.get("code") == "STALE_REVISION" and all(first.get(key) is True
                for key in ("repairable", "not_executed", "unbound"))
            and sum(event["event"] == "recovery" for event in events) == 1)
        checks["changed_business_arguments"] = len(writes) == 2 and (
            writes[0]["arguments"].get("queue") == "global_ops"
            and writes[0]["arguments"].get("expected_revision") == 1
            and writes[1]["arguments"].get("queue") == "regional_ops"
            and writes[1]["arguments"].get("expected_revision") == 2)
    elif scenario == "lost-receipt":
        checks["original_key_recovery"] = (counts["initial_read"] == 1
            and 2 <= counts["write-0"] <= 3 and counts["refresh_read"] == 0 and not repair
            and bool(write_results) and write_results[0].get("error", {}).get("code")
            == "TIMEOUT" and write_results[-1].get("ok") is True
            and all(item["arguments"] == expected for item in writes))
    return checks


def _without_grading_latency(score):
    return {**score, "grading_cost": {key: value for key, value in
            score["grading_cost"].items() if key != "latency_s"}}


def review_run(case_path, directory, entry, source, events):
    """Pure replay, grading and two independent audits; original run files stay untouched."""
    before = fingerprint(directory)
    record = replay(directory)
    case, manifest = read(case_path), read(directory / "manifest.json")
    recorded_grade = read(directory / "grade.json")
    verified_grade = regrade_case(case_path, directory)
    protocol, gate = verify_protocol(events), audit_gate(events)
    checks = {
        "recorded_grade_matches": _without_grading_latency(recorded_grade)
        == _without_grading_latency(verified_grade),
        "measurement_valid": record["measurement_valid"] is True
        and record["terminated_quiescent"] is True,
        "source_matches": record["source"] == source,
        "case_snapshot_matches": hashlib.sha256(case_path.read_bytes()).hexdigest()
        == entry["case_sha256"],
        "task_identity": record["task_id"] == case["task_input"]["task_id"]
        and record["target_ref"] == case["task_input"]["target_ref"]
        and manifest["task_input"] == case["task_input"],
        "fixed_configuration": record["limits"] == asdict(Budget())
        and record["policy"] == entry["policy"] and events[0]["data"]["config"]["seed"] == 0,
        "business_success": verified_grade["correct_disposition"] == 1
        and verified_grade["goal_completed"] == 1,
        "no_duplicate_or_forbidden_effect": verified_grade["duplicate_effect"] == 0
        and verified_grade["false_allow"] == 0,
        "protocol_complete": protocol["unverified_attempts"] == 0
        and protocol["unverified_outcomes"] == 0,
        "gate_complete": not any(gate[key] for key in (
            "dispatch_violations", "state_violations", "unverified"))
        and gate["invalid_allowed"] == gate["valid_blocked"] == 0,
    }
    checks.update(branch_checks(entry["scenario"], events, record, case))
    checks["input_unchanged"] = fingerprint(directory) == before
    return {"run_id": record["run_id"], "output": record["output"], "costs": record["costs"],
            "recorded_grade": recorded_grade, "verified_grade": verified_grade,
            "protocol": protocol, "gate": gate, "checks": checks,
            "passed": all(checks.values())}


def totals(rows):
    return {field: (None if any(row.get("costs", {}).get(field) is None for row in rows)
                    else sum(row["costs"][field] for row in rows)) for field in (
                        "model_calls", "tool_attempts", "input_tokens", "output_tokens", "total_s")}


async def execute(output, model_a, model_b):
    output = output.resolve()
    audit_output = output.with_name(output.name + "-audit")
    if output.exists() or audit_output.exists():
        raise FileExistsError("Use fresh preflight and sibling audit directories")
    source = source_revision()
    if not source.get("commit") or source.get("dirty") is not False:
        raise ValueError("Preflight requires clean, committed reviewed source")
    environments = {"A": model_a.resolve(), "B": model_b.resolve()}
    # Credentials and whole-file hashes stay in memory, never in artifacts or output.
    configuration_digests = {label: hashlib.sha256(path.read_bytes()).digest()
                             for label, path in environments.items()}
    configurations = {label: await configuration_summary(path, label)
                      for label, path in environments.items()}
    output.mkdir(parents=True)
    (output / "runs").mkdir()
    (output / "cases").mkdir()
    audit_output.mkdir()
    entries = []
    for scenario, name, policy in SCENARIOS:
        payload = (PROJECT / "tasks" / "development" / (name + ".json")).read_bytes()
        case = json.loads(payload)
        relative = "cases/" + name + ".json"
        (output / relative).write_bytes(payload)
        for label in ("B", "A"):
            slot = scenario + "-" + label
            entries.append({"slot": slot, "scenario": scenario, "task_id": case["task_input"][
                "task_id"], "model": label, "policy": policy, "seed": 0,
                "case": relative, "case_sha256": hashlib.sha256(payload).hexdigest(),
                "path": "runs/" + slot})
    plan = {"schema": "service-preflight-v1", "kind": "development-only", "source": source,
            "configurations": configurations, "budget": asdict(Budget()), "runs": entries,
            "repeat_count": 1, "stop_on_any_failure": True}
    save(output / "plan.json", plan)
    save(audit_output / "plan.json", {"schema": "service-preflight-audit-v1",
         "input": str(output), "source": source, "model_api_calls": 0, "runs": entries})
    rows = []
    stop_reason = (None if all(item["model_matches"] for item in configurations.values())
                   else "CONFIG_MODEL_MISMATCH")
    if not stop_reason and not all(item["token_limit_field_matches"]
                                   for item in configurations.values()):
        stop_reason = "CONFIG_TOKEN_LIMIT_MISMATCH"
    for entry in entries:
        if stop_reason:
            break
        if source_revision() != source:
            stop_reason = "source_changed"
            break
        if not configurations_unchanged(environments, configuration_digests):
            stop_reason = "configuration_changed"
            break
        directory, case_path = output / entry["path"], output / entry["case"]
        if hashlib.sha256(case_path.read_bytes()).hexdigest() != entry["case_sha256"]:
            stop_reason = "case_snapshot_changed"
            break
        row = {**entry, "status": "failed", "model_failures": []}
        execution_error = None
        try:
            await run_case(case_path, directory, model="api",
                           model_env=environments[entry["model"]], policy=entry["policy"], seed=0)
        except (Exception, asyncio.CancelledError, KeyboardInterrupt) as exc:
            execution_error = type(exc).__name__
            row["execution_error_type"] = execution_error
        row["configuration_unchanged"] = configurations_unchanged(
            environments, configuration_digests)
        try:
            events = journal(directory / "trace.jsonl")
            row["model_failures"] = [
                {key: event["data"].get("error", {})[key] for key in DIAGNOSTICS
                 if key in event["data"].get("error", {})}
                for event in events if event["event"] == "model_failed"]
            detail = review_run(case_path, directory, entry, source, events)
            row.update(run_id=detail["run_id"], output=detail["output"], costs=detail["costs"],
                       grade=detail["recorded_grade"])
            audit_detail = {**entry, **detail, "model_failures": row["model_failures"],
                            "configuration_unchanged": row["configuration_unchanged"],
                            "model_api_calls": 0}
            if row["model_failures"]:
                stop_reason = row["model_failures"][0].get("code", "model_failed")
            elif not row["configuration_unchanged"]:
                stop_reason = "configuration_changed"
            elif execution_error:
                stop_reason = "execution_error"
            elif not detail["passed"]:
                stop_reason = "run_checks_failed"
            elif source_revision() != source:
                stop_reason = "source_changed"
            elif not configurations_unchanged(environments, configuration_digests):
                stop_reason = "configuration_changed"
            else:
                row["status"] = "passed"
        except (Exception, asyncio.CancelledError, KeyboardInterrupt) as exc:
            row["audit_error_type"] = type(exc).__name__
            stop_reason = (row["model_failures"][0].get("code", "model_failed")
                           if row["model_failures"] else "unsealed_or_audit_error"
                           if row["configuration_unchanged"] else "configuration_changed")
            audit_detail = {**row, "model_api_calls": 0}
        save(audit_output / (entry["slot"] + ".json"), audit_detail)
        rows.append(row)
        with (output / "results.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")
        print(json.dumps({"slot": entry["slot"], "status": row["status"],
                          "stop_reason": stop_reason}, ensure_ascii=False), flush=True)
        if stop_reason:
            break
    states = [{"slot": entry["slot"], "status": "not_run", "reason": stop_reason}
              for entry in entries[len(rows):]]
    summary = {"schema": "service-preflight-v1", "kind": "development-only", "source": source,
               "status": "passed" if len(rows) == 8 and not stop_reason else "stopped",
               "planned": 8, "attempted": len(rows),
               "passed": sum(row["status"] == "passed" for row in rows),
               "stop_reason": stop_reason, "costs": totals(rows),
               "runs": [{"slot": row["slot"], "status": row["status"]} for row in rows] + states,
               "output": str(output), "audit_output": str(audit_output)}
    save(output / "summary.json", summary)
    save(audit_output / "summary.json", {**summary, "model_api_calls": 0})
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--model-a", type=Path, required=True)
    parser.add_argument("--model-b", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        summary = asyncio.run(execute(args.output, args.model_a, args.model_b))
    except (ModelError, OSError, ValueError) as exc:
        # Exception messages can contain paths or provider text; never echo them.
        print(json.dumps({"status": "rejected", "error_code":
                          exc.code if isinstance(exc, ModelError) else type(exc).__name__}))
        return 1
    print(json.dumps({key: summary[key] for key in (
        "status", "planned", "attempted", "passed", "stop_reason", "output", "audit_output")},
        ensure_ascii=False))
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
