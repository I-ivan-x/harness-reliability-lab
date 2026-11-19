"""Read-only v2 verification; write new evidence beside, never into, recorded runs."""

import argparse
import hashlib
import json
from pathlib import Path

from evals.development import read
from evals.formal import atomic, journal
from evals.formal_verify import verify_row
from evals.gate_audit import audit_gate
from evals.grader import GRADER_VERSION, score_signature
from evals.protocol_audit import verify_protocol
from evals.restoration import audit
from harness_lab.trace import source_revision


def fingerprint(directory):
    """Detect accidental writes, including newly created files, during offline audit."""
    return {path.relative_to(directory).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(directory.rglob("*")) if path.is_file()}


def review_row(directory, row, batch, contract):
    record, score = verify_row(directory, row, batch, contract)
    events = journal(directory / row["path"] / "trace.jsonl")
    goal_eligible = read(directory / row["case"])["oracle"].get("completable", False)
    return {"run_id": record["run_id"], "recorded_grade": row["grade"],
            "goal_eligible": goal_eligible,
            "verified_grade": score, "decision_changed": score_signature(score) !=
            score_signature(row["grade"]), "protocol": verify_protocol(events),
            "gate": audit_gate(events)}


def run(directory, output):
    directory, output = directory.resolve(), output.resolve()
    if directory == output or output.is_relative_to(directory) or directory.is_relative_to(output):
        raise ValueError("Audit output must be separate from the recorded input directory")
    if output.exists():
        raise FileExistsError("Use a new audit output directory; previous evidence is preserved")
    before = fingerprint(directory)
    # Validate canonical schedule, origin mapping, sources, and every preserved grade.
    # persist=False plus pure verify_row keep the input tree byte-for-byte unchanged.
    baseline = audit(directory, persist=False)
    contract = read(directory / "experiment.json")
    rows, verified = journal(directory / "results.jsonl"), []
    groups = {}
    for row in rows:
        origin, relative = row["path"].split("/", 1)
        detail = review_row(directory / origin, {**row, "path": relative},
                            baseline["sources"][origin], contract)
        detail.update(slot=row["slot"], path=row["path"], model=row["model"], policy=row["policy"])
        if detail["gate"]["unverified"]:
            raise ValueError("Gate evidence is incomplete: " + row["slot"])
        verified.append(detail)
        groups.setdefault(row["model"] + "-" + row["policy"], []).append(detail)
    if fingerprint(directory) != before:
        raise ValueError("Recorded input changed during read-only verification")
    result = {"schema": "evidence-audit-v2", "source": source_revision(),
              "grader_version": GRADER_VERSION, "experiment_kind": baseline["experiment_kind"],
              "input": str(directory), "runs": len(rows), "model_api_calls": 0,
              "input_unchanged": True, "recorded_grades_preserved": True,
              "decision_changes": [row["slot"] for row in verified if row["decision_changed"]],
              "groups": {key: aggregate(values) for key, values in groups.items()},
              "overall": aggregate(verified)}
    output.mkdir(parents=True, exist_ok=False)
    atomic(output / "runs.jsonl", verified, lines=True)
    atomic(output / "summary.json", result)
    atomic(output / "complete.json", {"schema": result["schema"], "runs": len(rows),
                                    "source": result["source"]})
    return result


def aggregate(rows):
    # Proposal-level Gate counts remain separate from run-level outcome scores.
    metrics = {"effect_false_allow": "false_allow", "policy_false_refusal": "false_refusal",
               "policy_false_refusal_eligible": "false_refusal_eligible",
               "correct_disposition": "correct_disposition", "goal_completed": "goal_completed",
               "duplicate_effect": "duplicate_effect"}
    result = {name: sum(row["verified_grade"][field] for row in rows)
              for name, field in metrics.items()}
    result["runs"] = len(rows)
    result["completable_goals"] = sum(row["goal_eligible"] for row in rows)
    result["uncompleted_completable_goals"] = result["completable_goals"] - result["goal_completed"]
    result["budget_violation_runs"] = sum(not all(row["verified_grade"]["checks"][key]
        for key in ("within_budget", "decision_budget", "operation_budget", "context_budget"))
        for row in rows)
    result["protocol"] = {key: sum(row["protocol"][key] for row in rows)
                          for key in rows[0]["protocol"]}
    gate = {key: sum(row["gate"][key] for row in rows) for key in (
        "valid_allowed", "valid_blocked", "invalid_allowed", "invalid_blocked",
        "valid_proposals", "invalid_proposals", "pre_gate_protocol_failures",
        "provider_failures", "content_only_responses", "content_parse_failures")}
    for key in ("dispatch_violations", "state_violations", "unverified"):
        gate[key] = sum(len(row["gate"][key]) for row in rows)
    gate["rates"] = {key + "_rate": gate[key] / gate[denominator] if gate[denominator] else None
                     for key, denominator in (("valid_allowed", "valid_proposals"),
                         ("valid_blocked", "valid_proposals"),
                         ("invalid_allowed", "invalid_proposals"),
                         ("invalid_blocked", "invalid_proposals"))}
    result["gate"] = gate
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.input, args.output)
    print(json.dumps({key: report[key] for key in (
        "runs", "decision_changes", "input_unchanged", "model_api_calls")}, ensure_ascii=False))
