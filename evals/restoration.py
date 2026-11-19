"""User-authorized replacement of prior B/HTTP_429 slots after service restoration."""

import argparse
import asyncio
import shutil
import subprocess
from pathlib import Path

from evals.acceptance import schedule, validate
from evals.development import read
from evals.formal import active_rows, atomic, execute, journal
from evals.formal_report import audit as original_audit
from evals.formal_report import summarize
from evals.formal_verify import verify_row
from harness_lab.models import OpenAICompatibleController
from harness_lab.trace import source_revision


def selection(plan, rows):
    assert len(plan) == len(rows) == 324
    assert [{key: row[key] for key in slot} for row, slot in zip(rows, plan, strict=True)] == plan
    selected = [slot for slot, row in zip(plan, rows, strict=True)
                if row["model"] == "B" and row["output"]["reason_code"] == "HTTP_429"]
    validate_selection(selected)
    return selected


def validate_selection(selected):
    assert len(selected) == len({row["slot"] for row in selected}) == 108
    assert len({row["block"] for row in selected}) == 36
    for offset in range(0, len(selected), 3):
        group = selected[offset:offset + 3]
        assert {row["model"] for row in group} == {"B"}
        assert len({row["block"] for row in group}) == 1
        assert {row["policy"] for row in group} == {"P0", "P1", "P2"}


def combine(plan, retained, replacements):
    assert len(retained) == 216 and len(replacements) == 108
    rows = [{**row, "path": origin + "/" + row["path"]}
            for origin, values in (("original", retained), ("restored", replacements))
            for row in values]
    by_slot = {row["slot"]: row for row in rows}
    assert len(by_slot) == len({row["run_id"] for row in rows}) == len({
        row["path"] for row in rows}) == 324
    ordered = [by_slot[slot["slot"]] for slot in plan]
    assert [{key: row[key] for key in slot}
            for row, slot in zip(ordered, plan, strict=True)] == plan
    return ordered


def audit(directory, *, persist=True):
    frozen = Path(__file__).resolve().parents[1] / "tasks/frozen"
    manifest, contract = validate(frozen)
    plan, selected = read(directory / "schedule.json"), read(directory / "selection.json")
    assert (read(directory / "manifest.json"), read(directory / "experiment.json")) == (
        manifest, contract)
    assert plan == schedule(manifest, contract)
    validate_selection(selected)
    assert selected == [slot for slot in plan if slot["slot"] in {s["slot"] for s in selected}]
    sources = {origin: read(directory / origin / "batch.json")
               for origin in ("original", "restored")}
    assert sources["original"]["source"]["commit"] == (
        "217a4391f1ef4a94a82d1a9bff9223d636b7eb13")
    for origin, batch in sources.items():
        assert batch["source"]["dirty"] is False and batch["source"]["commit"]
        assert batch["frozen_tag"] == contract["freeze_tag"]
        assert batch["user_override"]["monetary_checks"] is False
        assert (read(directory / origin / "manifest.json"),
                read(directory / origin / "experiment.json")) == (manifest, contract)
        for entry in manifest["tasks"]:
            assert read(directory / origin / entry["file"]) == read(
                directory / entry["file"]) == read(frozen / entry["file"])
    retained = journal(directory / "original/results.jsonl")
    assert {r["slot"] for r in retained} == {r["slot"] for r in plan} - {
        r["slot"] for r in selected}
    for row in retained:
        verify_row(directory / "original", row, sources["original"], contract)
    replacement_root = directory / "restored"
    assert read(replacement_root / "complete.json") == {
        "source": sources["restored"]["source"], "planned_trials": 108, "executed_trials": 108}
    replacements = active_rows(replacement_root, selected, sources["restored"], contract,
                               block_size=3)
    assert journal(replacement_root / "results.jsonl") == replacements
    rows = combine(plan, retained, replacements)
    assert journal(directory / "results.jsonl") == rows
    assert read(directory / "complete.json") == {"included": 324, "retained": 216, "restored": 108}
    result = {**summarize(rows, manifest, contract),
              "experiment_kind": "post-restoration-composite",
              "sources": sources, "amendment": read(directory / "amendment.json"),
              "regraded_runs": 324, "audit_source": source_revision()}
    if persist:
        atomic(directory / "summary.json", result)
    return result


async def run(original, output, environment, resume=False):
    original_audit(original)
    rows, plan = journal(original / "results.jsonl"), read(original / "schedule.json")
    selected = selection(plan, rows)
    source = source_revision()
    assert source["commit"] and source["dirty"] is False
    subprocess.run(["git", "diff", "--exit-code", "217a439", "--", "src/harness_lab",
                    "evals/grader.py", "evals/run_case.py", "tasks/frozen", "pyproject.toml",
                    "uv.lock"], check=True, capture_output=True)
    manifest, contract = validate(Path("tasks/frozen"))
    controller = OpenAICompatibleController(environment)
    try:
        assert controller.describe() == contract["models"]["B"]
    finally:
        await controller.aclose()
    selected_ids = {row["slot"] for row in selected}
    retained = [row for row in rows if row["slot"] not in selected_ids]
    replacement_root = output / "restored"
    if resume:
        assert read(output / "selection.json") == selected
        assert read(replacement_root / "batch.json")["source"] == source
        assert journal(output / "original/results.jsonl") == retained
    else:
        output.mkdir(parents=True, exist_ok=False)
        for destination in (output, output / "original", replacement_root):
            destination.mkdir(exist_ok=True)
            for name in ("manifest.json", "experiment.json",
                         *[e["file"] for e in manifest["tasks"]]):
                shutil.copy2(original / name, destination / name)
        shutil.copy2(original / "batch.json", output / "original/batch.json")
        for row in retained:
            shutil.copytree(original / row["path"], output / "original" / row["path"])
        atomic(output / "original/results.jsonl", retained, lines=True)
        atomic(output / "schedule.json", plan)
        atomic(output / "selection.json", selected)
        atomic(output / "amendment.json", {"date": "2026-11-07",
               "instruction": "豆包旧HTTP 429不纳入新主结果；服务恢复后重跑这些位置。",
               "method": "216 retained + 108 fresh replacements; not an original single-pass batch",
               "scientific_base_source": "217a4391f1ef4a94a82d1a9bff9223d636b7eb13",
               "prior_records": "private archive only; excluded from this delivery"})
        atomic(replacement_root / "batch.json", {"source": source,
               "artifact_root": str(replacement_root.resolve()),
               "frozen_tag": contract["freeze_tag"],
               "user_override": {"monetary_checks": False, "post_restoration_replacement": True}})
        (replacement_root / "blocks").mkdir()
        atomic(replacement_root / "results.jsonl", [], lines=True)
    batch = read(replacement_root / "batch.json")
    await execute(replacement_root, selected, batch, contract, {"B": environment}, block_size=3)
    replacements = journal(replacement_root / "results.jsonl")
    assert not ({r["run_id"] for r in replacements} & {r["run_id"] for r in rows})
    atomic(output / "results.jsonl", combine(plan, retained, replacements), lines=True)
    atomic(output / "complete.json", {"included": 324, "retained": 216, "restored": 108})
    audit(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["run", "audit"])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--original", type=Path, default=Path("artifacts/formal-v1"))
    parser.add_argument("--model-b", type=Path)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    if args.mode == "audit":
        print(audit(args.output)["regraded_runs"])
    else:
        if args.model_b is None:
            parser.error("run requires --model-b")
        asyncio.run(run(args.original, args.output, args.model_b, args.resume))
