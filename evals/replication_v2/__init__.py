"""A fresh single-attempt batch, stopped by any model API failure."""

import subprocess
import sys
from pathlib import Path

from evals.acceptance import schedule
from evals.acceptance import validate as validate_original
from evals.development import read
from evals.formal import active_rows, atomic, journal
from evals.formal_verify import _score_without_latency, verify_row
from evals.gate_audit import audit_gate
from evals.grader import GRADER_VERSION
from evals.replication import append, check_inputs, digest, utc_now
from evals.replication import code_hashes as baseline_hashes
from evals.run_case import run_case
from harness_lab.models import OpenAICompatibleController
from harness_lab.trace import replay, source_revision

PROJECT = Path(__file__).resolve().parents[2]
CONTRACT = PROJECT / "specs/replication-v2.json"
TAG = "harness-replication-v2"
CHANGED_FIELDS = {"version", "freeze_tag", "spending", "invalid_trials", "execution_status"}


def code_hashes():
    return {**baseline_hashes(), **{
        path.relative_to(PROJECT).as_posix(): digest(path)
        for path in sorted(Path(__file__).parent.glob("*.py"))}}


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
    assert proof["stop_on_any_model_failure"] is True and proof["no_resume"] is True
    previous = read(PROJECT / "specs/replication-v1.json")["replication"]
    assert baseline_hashes() == previous["code_sha256"], "Baseline runtime/evaluation changed"
    assert proof["code_sha256"] == code_hashes(), "Frozen code or dependency files changed"
    return manifest, contract


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
                if failures:
                    atomic(directory / "stop.json", {"source": batch["source"],
                           "reason": "model_api_failure", "model_failure_codes": failures,
                           "slot": slot["slot"],
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
             "started_at_utc": utc_now(), "authorization_date": "2026-11-17",
             "stopping_rule": "any model_failed event; persist then stop; no resume",
             "user_override": {
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
    assert batch["authorization_date"] == "2026-11-17"
    assert batch["stopping_rule"] == "any model_failed event; persist then stop; no resume"
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

