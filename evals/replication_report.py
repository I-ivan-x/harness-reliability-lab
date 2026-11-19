"""Read-only replication audit and paired statistics in a fresh sibling directory."""

import argparse
import json
from collections import Counter
from pathlib import Path
from statistics import mean

from evals.development import read
from evals.evidence_audit import aggregate, fingerprint, review_row
from evals.formal import atomic, journal
from evals.formal_report import _interval, summarize
from evals.formal_verify import _score_without_latency
from evals.grader import GRADER_VERSION
from harness_lab.trace import source_revision

DIAGNOSTICS = (
    "code", "layer", "http_status", "provider_code", "provider_type", "request_id",
    "request_id_source", "retry_after",
)


def paired_statistics(statistics, manifest, contract):
    """Use whole tasks as clusters for both frozen M and C cohort contrasts."""
    result = {}
    for model in contract["models"]:
        result[model] = {}
        for cohort in ("M", "C"):
            tasks = [entry["id"] for entry in manifest["tasks"] if entry["cohort"] == cohort]
            scores = statistics["per_task_scores"]
            differences = [mean(scores[f"{model}-P2"][task]) -
                           mean(scores[f"{model}-P1"][task]) for task in tasks]
            result[model][cohort] = {
                "tasks": len(tasks), "wins": sum(value > 0 for value in differences),
                "ties": differences.count(0), "losses": sum(value < 0 for value in differences),
                "paired_difference": mean(differences),
                "task_cluster_bootstrap_95": _interval(differences, contract["statistics"]),
            }
    return result


def review(directory, row, batch, contract):
    """Same-baseline regrading is strict; only measured grading latency may differ."""
    detail = review_row(directory, row, batch, contract)
    if (_score_without_latency(detail["verified_grade"]) !=
            _score_without_latency(detail["recorded_grade"])):
        raise ValueError("Replication grade changed: " + row["slot"])
    if detail["decision_changed"]:
        raise ValueError("Replication decision changed: " + row["slot"])
    if any(detail["protocol"][key] for key in ("unverified_attempts", "unverified_outcomes")):
        raise ValueError("Protocol evidence is incomplete: " + row["slot"])
    if any(detail["gate"][key] for key in (
            "unverified", "dispatch_violations", "state_violations",
            "invalid_allowed", "valid_blocked")):
        raise ValueError("Gate evidence is incomplete or inconsistent: " + row["slot"])
    failures = [{key: event["data"].get("error", {})[key] for key in DIAGNOSTICS
                 if key in event["data"].get("error", {})}
                for event in journal(directory / row["path"] / "trace.jsonl")
                if event["event"] == "model_failed"]
    if any(error.get("code") == "HTTP_403" for error in failures):
        raise ValueError("Complete replication violates HTTP_403 stopping rule: " + row["slot"])
    return {**detail, **{key: row[key] for key in (
        "slot", "task_id", "repeat", "path", "model", "policy", "output", "costs")},
        "model_failures": failures, "unknown_usage": any(
            row["costs"][key] is None for key in ("input_tokens", "output_tokens"))}


def run(directory, output=None):
    """Publish only a complete, independently verified 324-slot new replication."""
    from evals.replication import audit

    directory = directory.resolve()
    output = (output or directory.with_name(directory.name + "-audit")).resolve()
    if (output.parent != directory.parent or output == directory
            or not output.name.endswith("-audit")):
        raise ValueError("Audit output must be a separate sibling ending in -audit")
    if output.exists():
        raise FileExistsError("Use a fresh audit output directory; previous evidence is preserved")
    before = fingerprint(directory)
    baseline = audit(directory, persist=False)
    manifest, contract, batch = (read(directory / name) for name in (
        "manifest.json", "experiment.json", "batch.json"))
    rows = journal(directory / "results.jsonl")
    statistics = summarize(rows, manifest, contract)
    verified = [review(directory, row, batch, contract) for row in rows]
    groups = {}
    for detail in verified:
        groups.setdefault(detail["model"] + "-" + detail["policy"], []).append(detail)
    if fingerprint(directory) != before:
        raise ValueError("Recorded input changed during read-only verification")
    failed = [detail for detail in verified if not detail["verified_grade"][
        "correct_disposition"] or detail["model_failures"]]
    result = {
        **statistics, "schema": "replication-audit-v1", "source": batch["source"],
        "audit_source": source_revision(), "grader_version": GRADER_VERSION,
        "experiment_kind": baseline["experiment_kind"], "frozen_tag": batch["frozen_tag"],
        "user_override": batch["user_override"], "input": str(directory), "model_api_calls": 0,
        "input_unchanged": True, "recorded_grades_preserved": True, "decision_changes": [],
        "paired_p2_minus_p1": paired_statistics(statistics, manifest, contract),
        "audit_groups": {key: aggregate(values) for key, values in groups.items()},
        "audit_overall": aggregate(verified),
        "failures": [{key: detail[key] for key in (
            "slot", "run_id", "task_id", "model", "policy", "output", "costs",
            "model_failures", "unknown_usage")} for detail in failed],
        "model_failure_codes": dict(Counter(error.get("code", "model_failed")
            for detail in verified for error in detail["model_failures"])),
        "block_attempts": [{"path": path.relative_to(directory).as_posix(), "metadata": read(path)}
            for path in sorted((directory / "blocks").glob("*/block.json"))],
    }
    output.mkdir(parents=True, exist_ok=False)
    (output / "runs").mkdir()
    for detail in verified:
        atomic(output / "runs" / (detail["slot"] + ".json"), detail)
    atomic(output / "runs.jsonl", verified, lines=True)
    atomic(output / "summary.json", result)
    atomic(output / "complete.json", {"schema": result["schema"], "runs": len(rows),
        "source": batch["source"], "audit_source": result["audit_source"]})
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = run(args.input, args.output)
    print(json.dumps({key: report[key] for key in (
        "runs", "decision_changes", "input_unchanged", "model_api_calls")}, ensure_ascii=False))
