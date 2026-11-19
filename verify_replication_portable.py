"""Offline verification of the extracted ea1cddd replication delivery.

Copy this file to the archived subproject root, beside source-ref.json. Install
that project normally and run from its root, for example:
  python -m uv run --locked --no-env-file python verify_replication_portable.py \
    --input artifacts/replication-v2-2026-11-17

No Git identity is synthesized and no model or MCP process is started. The static
source reference records the delivery's tag-to-commit mapping; it is not a live
Git lookup. Output is a fresh sibling audit directory. Existing raw and audit
files remain read-only. This helper is delivery tooling, outside frozen code.
"""

import argparse
import json
import platform
import sys
from collections import Counter
from pathlib import Path

from evals.acceptance import schedule
from evals.acceptance import validate as validate_original
from evals.development import read
from evals.evidence_audit import aggregate, fingerprint
from evals.formal import active_rows, atomic, journal
from evals.formal_report import summarize
from evals.formal_verify import _score_without_latency
from evals.grader import GRADER_VERSION
from evals.replication import digest
from evals.replication_v2 import CHANGED_FIELDS, PROJECT, TAG, code_hashes
from evals.replication_v2.report import paired_statistics, review

from harness_lab.trace import source_revision

COMMIT = "ea1cddd3fe2736405b5513203161b98ef20d3797"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_static_source(reference):
    """Validate delivered bytes against a recorded reference without invoking Git."""
    require(reference["schema"] == "replication-portable-source-v2", "Source reference schema")
    require((reference["tag"], reference["commit"]) == (TAG, COMMIT), "Source reference identity")
    frozen = PROJECT / "tasks/frozen"
    manifest, original = validate_original(frozen)
    frozen_hashes = {name: digest(frozen / name) for name in (
        "manifest.json", "experiment.json", *(entry["file"] for entry in manifest["tasks"]))}
    require(reference["frozen_files_sha256"] == frozen_hashes, "Frozen task byte mismatch")
    contract_path = PROJECT / "specs/replication-v2.json"
    require(reference["replication_contract_sha256"] == digest(contract_path), "Contract bytes")
    contract = read(contract_path)
    require(set(contract) == (set(original) - {"spending"}) | {"replication"}, "Contract fields")
    require(all(contract[key] == value for key, value in original.items()
                if key not in CHANGED_FIELDS), "Scientific configuration changed")
    require(contract["freeze_tag"] == TAG, "Contract tag")
    proof = contract["replication"]
    require(proof["base_contract_sha256"] == reference["base_contract_sha256"]
            == frozen_hashes["experiment.json"], "Original contract hash")
    require(proof["code_sha256"] == reference["code_sha256"] == code_hashes(), "Code bytes")
    require(len(reference["code_sha256"]) == 31, "Expected 31 frozen code/dependency files")
    require(proof["grader_version"] == GRADER_VERSION == "judgment-v2", "Grader identity")
    require(proof["stop_on_any_model_failure"] is True and proof["no_resume"] is True,
            "Stopping contract")
    # Normal installation may use editable source or site-packages. In either
    # case, the imported Python files must have the delivered frozen bytes.
    for name, module in tuple(sys.modules.items()):
        if name in {"evals", "harness_lab"} or name.startswith(("evals.", "harness_lab.")):
            filename = getattr(module, "__file__", None)
            if not filename:
                continue
            relative = name.replace(".", "/")
            relative += "/__init__.py" if hasattr(module, "__path__") else ".py"
            if name.startswith("harness_lab"):
                relative = "src/" + relative
            require(relative in reference["code_sha256"] and digest(Path(filename))
                    == reference["code_sha256"][relative], "Imported module bytes: " + name)
    return manifest, contract


def verify_archive_audit(directory, batch, rows, verified, statistics, paired, groups, overall):
    """Compare the shipped audit with a fresh independent reconstruction."""
    summary = read(directory / "summary.json")
    require(summary["schema"] == "replication-audit-v2", "Recorded audit schema")
    require(summary["source"] == batch["source"] and summary["runs"] == 324,
            "Recorded audit source/count")
    require(summary["frozen_tag"] == TAG and summary["model_failure_codes"] == {},
            "Recorded API-clean audit contract")
    require(summary["model_api_calls"] == 0 and summary["input_unchanged"] is True
            and summary["recorded_grades_preserved"] is True
            and summary["decision_changes"] == [], "Recorded audit status")
    require(all(summary[key] == value for key, value in statistics.items()), "Recorded statistics")
    require(summary["paired_p2_minus_p1"] == paired, "Recorded paired statistics")
    require(summary["audit_groups"] == groups and summary["audit_overall"] == overall,
            "Recorded protocol/Gate aggregates")
    previous = journal(directory / "runs.jsonl")
    require(len(previous) == len(rows) == len(verified) == 324, "Recorded audit row count")
    for old, current in zip(previous, verified, strict=True):
        require(read(directory / "runs" / (old["slot"] + ".json")) == old,
                "Recorded per-run audit differs from journal")
        old_stable, current_stable = dict(old), dict(current)
        for field in ("recorded_grade", "verified_grade"):
            old_stable[field] = _score_without_latency(old[field])
            current_stable[field] = _score_without_latency(current[field])
        require(old_stable == current_stable, "Recorded independent audit changed: " + old["slot"])
    require(read(directory / "complete.json") == {
        "schema": summary["schema"], "runs": 324, "source": batch["source"],
        "audit_source": summary["audit_source"]}, "Recorded audit completion")


def run(directory, reference_path, recorded_audit=None, output=None):
    directory = directory.resolve()
    recorded_audit = (recorded_audit or directory.with_name(directory.name + "-audit")).resolve()
    output = (output or directory.with_name(directory.name + "-portable-audit")).resolve()
    require(directory.is_dir() and recorded_audit.is_dir(), "Raw and recorded audit are required")
    require(output.parent == directory.parent and output.name.endswith("-audit")
            and output not in {directory, recorded_audit}, "Use a fresh separate sibling audit")
    require(not output.exists(), "Audit output already exists")
    require(not directory.is_relative_to(recorded_audit)
            and not recorded_audit.is_relative_to(directory), "Input trees must be separate")
    before, old_audit = fingerprint(directory), fingerprint(recorded_audit)
    reference = read(reference_path)
    manifest, contract = validate_static_source(reference)
    require(read(directory / "manifest.json") == manifest, "Manifest snapshot")
    require(read(directory / "experiment.json") == contract, "Experiment snapshot")
    require(all(read(directory / entry["file"]) == read(PROJECT / "tasks/frozen" / entry["file"])
                for entry in manifest["tasks"]), "Task snapshots")
    batch = read(directory / "batch.json")
    require(batch["source"] == {"commit": COMMIT, "dirty": False}, "Recorded execution source")
    require(batch["frozen_tag"] == TAG and batch["user_override"]["monetary_checks"] is False
            and batch["experiment_kind"] == "single-batch-independent-replication",
            "Batch contract")
    require(not (directory / "stop.json").exists(), "Stopped batch has no full report")
    require(read(directory / "complete.json") == {
        "source": batch["source"], "planned_trials": 324, "executed_trials": 324}, "Completion")
    plan, rows = schedule(manifest, contract), journal(directory / "results.jsonl")
    require(read(directory / "schedule.json") == plan and len(rows) == len(plan) == 324,
            "Full canonical schedule")
    expected_blocks = {f"{number:03d}-a001" for number in range(1, 55)}
    require({path.name for path in (directory / "blocks").iterdir()} == expected_blocks,
            "Exactly 54 first-attempt blocks are required")
    require(not list(directory.glob("blocks/*/pause.json")), "Paused block in complete batch")
    require(active_rows(directory, plan, batch, contract, verify=False) == rows, "Block ledgers")
    require(len({row["run_id"] for row in rows}) == len({row["path"] for row in rows}) == 324
            and all(row["attempt"] == 1 for row in rows), "Unique first-attempt worlds")
    verified = [review(directory, row, batch, contract) for row in rows]
    statistics = summarize(rows, manifest, contract)
    paired = paired_statistics(statistics, manifest, contract)
    groups = {}
    for detail in verified:
        groups.setdefault(detail["model"] + "-" + detail["policy"], []).append(detail)
    group_counts = {key: aggregate(values) for key, values in groups.items()}
    overall = aggregate(verified)
    verify_archive_audit(recorded_audit, batch, rows, verified, statistics, paired,
                         group_counts, overall)
    require(fingerprint(directory) == before and fingerprint(recorded_audit) == old_audit,
            "Recorded inputs changed during offline verification")
    result = {**statistics, "schema": "replication-portable-audit-v2", "source": batch["source"],
              "source_ref": reference, "grader_version": GRADER_VERSION,
              "experiment_kind": batch["experiment_kind"], "frozen_tag": TAG,
              "model_api_calls": 0, "input_unchanged": True, "recorded_audit_unchanged": True,
              "recorded_grades_preserved": True, "decision_changes": [],
              "input": str(directory), "recorded_audit": str(recorded_audit),
              "verification_environment": {"python": sys.version.split()[0],
                  "platform": platform.platform(), "observed_git_source": source_revision(),
                  "identity_basis": "static source-ref.json; no Git identity synthesized"},
              "paired_p2_minus_p1": paired, "audit_groups": group_counts, "audit_overall": overall,
              "model_failure_codes": dict(Counter(error.get("code", "model_failed")
                  for detail in verified for error in detail["model_failures"]))}
    output.mkdir(exist_ok=False)
    atomic(output / "runs.jsonl", verified, lines=True)
    atomic(output / "summary.json", result)
    atomic(output / "complete.json", {"schema": result["schema"], "runs": 324,
                                     "source": batch["source"], "model_api_calls": 0})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--source-ref", type=Path, default=PROJECT / "source-ref.json")
    parser.add_argument("--recorded-audit", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    require(__debug__, "Run without -O: frozen reusable validators use assertions")
    result = run(args.input, args.source_ref, args.recorded_audit, args.output)
    fields = ("runs", "decision_changes", "model_api_calls", "input_unchanged",
              "recorded_audit_unchanged")
    print(json.dumps({key: result[key] for key in fields}, ensure_ascii=False))


if __name__ == "__main__":
    main()
