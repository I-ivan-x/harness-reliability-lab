"""Read-only publication of a complete replication with no model API failures."""

import argparse
import json
from pathlib import Path

from evals.development import read
from evals.evidence_audit import aggregate, fingerprint
from evals.formal import atomic, journal
from evals.formal_report import summarize
from evals.grader import GRADER_VERSION
from evals.replication_report import paired_statistics
from evals.replication_report import review as review_original
from harness_lab.trace import source_revision


def review(directory, row, batch, contract):
    """Retain all original checks and reject every recorded model_failed event."""
    detail = review_original(directory, row, batch, contract)
    if detail["model_failures"]:
        raise ValueError("Complete replication violates API stopping rule: " + row["slot"])
    return detail


def run(directory, output=None):
    """Publish only the new complete batch; historical input remains byte-for-byte intact."""
    from evals.replication_v2 import audit

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
    result = {
        **statistics, "schema": "replication-audit-v2", "source": batch["source"],
        "audit_source": source_revision(), "grader_version": GRADER_VERSION,
        "experiment_kind": baseline["experiment_kind"], "frozen_tag": batch["frozen_tag"],
        "user_override": batch["user_override"], "input": str(directory), "model_api_calls": 0,
        "input_unchanged": True, "recorded_grades_preserved": True, "decision_changes": [],
        "paired_p2_minus_p1": paired_statistics(statistics, manifest, contract),
        "audit_groups": {key: aggregate(values) for key, values in groups.items()},
        "audit_overall": aggregate(verified),
        "failures": [{key: detail[key] for key in (
            "slot", "run_id", "task_id", "model", "policy", "output", "costs",
            "model_failures", "unknown_usage")} for detail in verified
            if not detail["verified_grade"]["correct_disposition"]],
        "model_failure_codes": {},
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
