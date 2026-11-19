"""One independently frozen 324-slot replication; historical batches stay immutable."""

import argparse
import asyncio
import hashlib
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from evals.acceptance import schedule
from evals.acceptance import validate as validate_original
from evals.development import read
from evals.formal import active_rows, atomic, journal, stable
from evals.formal_verify import _score_without_latency, verify_row
from evals.gate_audit import audit_gate
from evals.grader import GRADER_VERSION
from evals.run_case import run_case
from harness_lab.models import OpenAICompatibleController
from harness_lab.trace import replay, source_revision

PROJECT = Path(__file__).resolve().parents[1]
CONTRACT = PROJECT / "specs/replication-v1.json"
TAG = "harness-replication-v1"
CHANGED_FIELDS = {"version", "freeze_tag", "spending", "invalid_trials", "execution_status"}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def utc_now():
    return datetime.now(UTC).isoformat()


def code_hashes():
    paths = [*sorted((PROJECT / "src/harness_lab").glob("*.py")),
             *sorted((PROJECT / "evals").glob("*.py")),
             PROJECT / "pyproject.toml", PROJECT / "uv.lock"]
    return {path.relative_to(PROJECT).as_posix(): digest(path) for path in paths}


def validate(root=None, contract_path=None):
    root = root or PROJECT / "tasks/frozen"
    manifest, original = validate_original(root)
    subprocess.run(["git", "diff", "--exit-code", original["freeze_tag"], "--", "tasks/frozen"],
                   cwd=PROJECT, check=True, capture_output=True)
    contract = read(contract_path or CONTRACT)
    assert set(contract) == (set(original) - {"spending"}) | {"replication"}
    assert all(contract[key] == value for key, value in original.items()
               if key not in CHANGED_FIELDS), "Scientific configuration changed"
    assert contract["freeze_tag"] == TAG
    proof = contract["replication"]
    assert proof["base_contract_sha256"] == digest(root / "experiment.json")
    assert proof["grader_version"] == GRADER_VERSION
    assert proof["stop_on_model_codes"] == ["HTTP_403"] and proof["no_resume"] is True
    assert proof["code_sha256"] == code_hashes(), "Frozen code or dependency files changed"
    return manifest, contract


def append(path, row):
    with path.open("ab") as stream:
        stream.write((json.dumps(row, ensure_ascii=False) + "\n").encode("utf-8"))
        stream.flush()
        os.fsync(stream.fileno())


def check_inputs(directory, snapshots, environments, env_hashes, source):
    stable(source)
    assert all(read(directory / name) == value for name, value in snapshots.items()), (
        "Frozen batch snapshot changed")
    assert all(digest(path) == env_hashes[label] for label, path in environments.items()), (
        "Model configuration changed")


async def execute(directory, plan, batch, contract, environments, snapshots, env_hashes):
    """One attempt per slot; a valid zero stays a result, never a retry request."""
    completed = []
    for offset in range(0, len(plan), 6):
        slots = plan[offset:offset + 6]
        block = slots[0]["block"]
        path = directory / "blocks" / f"{block:03d}-a001"
        path.mkdir()
        atomic(path / "block.json", {"block": block, "attempt": 1,
               "source": batch["source"], "slots": [s["slot"] for s in slots],
               "supersedes": [], "reason": "scheduled"})
        for slot in slots:
            try:
                check_inputs(directory, snapshots, environments, env_hashes, batch["source"])
                run_dir = path / slot["slot"]
                score = await run_case(directory / slot["case"], run_dir, model="api",
                    model_env=environments[slot["model"]], policy=slot["policy"], seed=slot["seed"])
                record = replay(run_dir)
                row = {**slot, "attempt": 1,
                       "path": run_dir.relative_to(directory).as_posix(),
                       **{key: record[key] for key in ("run_id", "output", "costs")},
                       "grade": score}
                _, verified_score = verify_row(directory, row, batch, contract)
                assert _score_without_latency(score) == _score_without_latency(verified_score)
                events = journal(run_dir / "trace.jsonl")
                gate = audit_gate(events)
                assert not any(gate[key] for key in (
                    "unverified", "dispatch_violations", "state_violations"))
                assert gate["invalid_allowed"] == gate["valid_blocked"] == 0
                check_inputs(directory, snapshots, environments, env_hashes, batch["source"])
                append(path / "results.jsonl", row)
                append(directory / "results.jsonl", row)
                completed.append(row)
                print(f"{len(completed)}/{len(plan)} {slot['slot']} "
                      f"correct={score['correct_disposition']}", flush=True)
                failures = [event["data"].get("error", {}).get("code") for event in events
                            if event["event"] == "model_failed"]
                if "HTTP_403" in failures:
                    atomic(directory / "stop.json", {"source": batch["source"],
                           "reason": "HTTP_403", "slot": slot["slot"],
                           "attempted": len(completed), "not_run": len(plan) - len(completed),
                           "ended_at_utc": utc_now(), "resume_allowed": False})
                    return False
            except BaseException as error:
                atomic(path / "pause.json", {"slot": slot, "exception": type(error).__name__,
                       "reason": "measurement_or_execution_integrity; retained; no retry"})
                atomic(directory / "stop.json", {"source": batch["source"],
                       "reason": "measurement_or_execution_integrity", "slot": slot["slot"],
                       "completed_records": len(completed), "ended_at_utc": utc_now(),
                       "resume_allowed": False})
                raise
        atomic(path / "complete.json", {"source": batch["source"],
               "slots": [s["slot"] for s in slots], "runs": 6})
    check_inputs(directory, snapshots, environments, env_hashes, batch["source"])
    assert active_rows(directory, plan, batch, contract, verify=False) == completed
    atomic(directory / "complete.json", {"source": batch["source"],
           "planned_trials": len(plan), "executed_trials": len(completed)})
    atomic(directory / "execution.json", {"ended_at_utc": utc_now(), "runs": len(completed)})
    return True


async def run(output, environments):
    manifest, contract = validate()
    source = source_revision()
    assert source["commit"] and source["dirty"] is False
    frozen_source = subprocess.check_output(["git", "rev-parse", TAG + "^{commit}"], cwd=PROJECT,
                                            text=True).strip()
    assert source["commit"] == frozen_source, "Run the exact newly frozen source"
    for label, path in environments.items():
        controller = OpenAICompatibleController(path)
        try:
            assert controller.describe() == contract["models"][label]
        finally:
            await controller.aclose()
    env_hashes = {label: digest(path) for label, path in environments.items()}
    root = PROJECT / "tasks/frozen"
    plan = schedule(manifest, contract)
    snapshots = {"manifest.json": manifest, "experiment.json": contract, "schedule.json": plan,
                 **{entry["file"]: read(root / entry["file"]) for entry in manifest["tasks"]}}
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / "blocks").mkdir()
    batch = {"source": source, "frozen_tag": TAG, "artifact_root": str(output),
             "experiment_kind": "single-batch-independent-replication",
             "python_version": sys.version.split()[0], "platform": sys.platform,
             "started_at_utc": utc_now(), "user_override": {
                 "date": "2026-11-07", "monetary_checks": False}}
    for name, value in {"batch.json": batch, **snapshots}.items():
        atomic(output / name, value)
    atomic(output / "results.jsonl", [], lines=True)
    return await execute(output, plan, batch, contract, environments, snapshots, env_hashes)


def audit(directory, persist=False):
    assert persist is False, "Audit writes belong in a fresh sibling directory"
    manifest, contract = validate()
    assert read(directory / "manifest.json") == manifest
    assert read(directory / "experiment.json") == contract
    assert all(read(directory / entry["file"]) == read(PROJECT / "tasks/frozen" / entry["file"])
               for entry in manifest["tasks"])
    batch = read(directory / "batch.json")
    assert batch["frozen_tag"] == TAG and batch["user_override"]["monetary_checks"] is False
    assert batch["source"]["dirty"] is False
    assert batch["source"]["commit"] == subprocess.check_output(
        ["git", "rev-parse", TAG + "^{commit}"], cwd=PROJECT, text=True).strip()
    plan = schedule(manifest, contract)
    assert read(directory / "schedule.json") == plan
    assert not (directory / "stop.json").exists()
    assert read(directory / "complete.json") == {
        "source": batch["source"], "planned_trials": 324, "executed_trials": 324}
    rows = journal(directory / "results.jsonl")
    assert len(rows) == len(plan) == 324
    assert active_rows(directory, plan, batch, contract, verify=False) == rows
    return batch


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--model-a", type=Path, required=True)
    parser.add_argument("--model-b", type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(0 if asyncio.run(run(args.output, {
        "A": args.model_a.resolve(), "B": args.model_b.resolve()})) else 1)
