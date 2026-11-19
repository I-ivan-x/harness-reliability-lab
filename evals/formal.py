"""Durable, sequential execution of the frozen paired experiment; no monetary checks."""

import argparse
import asyncio
import json
import os
import subprocess
from pathlib import Path

from evals.acceptance import schedule, validate
from evals.development import read
from evals.formal_verify import verify_row
from evals.run_case import run_case
from harness_lab.models import OpenAICompatibleController
from harness_lab.trace import replay, source_revision


def atomic(path, value, *, lines=False):
    payload = ("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in value) if lines
               else json.dumps(value, indent=2, ensure_ascii=False) + "\n")
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("wb") as stream:
        stream.write(payload.encode("utf-8"))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def journal(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def active_rows(directory, plan, batch, contract, *, verify=True, block_size=6):
    """Validate attempts, returning only the immutable completed prefix of blocks."""
    rows, seen, pending = [], set(), False
    for block in dict.fromkeys(slot["block"] for slot in plan):
        slots = [slot for slot in plan if slot["block"] == block]
        assert len(slots) == block_size
        attempts = sorted((directory / "blocks").glob(f"{block:03d}-a*"))
        if not attempts:
            pending = True
            continue
        assert not pending, "Attempt exists after an unfinished block"
        for number, path in enumerate(attempts, 1):
            assert path.name == f"{block:03d}-a{number:03d}"
            seen.add(path)
            meta = read(path / "block.json")
            assert meta["source"] == batch["source"] and meta["block"] == block
            assert meta["attempt"] == number and meta["slots"] == [s["slot"] for s in slots]
            assert meta["supersedes"] == [p.relative_to(directory).as_posix()
                                          for p in attempts[:number - 1]]
            assert number == 1 or meta["reason"] == "incomplete_block_measurement"
            if number != len(attempts):
                assert not (path / "complete.json").exists(), "Completed blocks cannot be replaced"
        latest = attempts[-1]
        if not (latest / "complete.json").exists():
            pending = True
            continue
        actual = journal(latest / "results.jsonl")
        assert len(actual) == block_size
        assert read(latest / "complete.json") == {
            "source": batch["source"], "slots": [s["slot"] for s in slots], "runs": block_size}
        for row, slot in zip(actual, slots, strict=True):
            assert {key: row[key] for key in slot} == slot
            assert row["attempt"] == len(attempts)
            assert row["path"] == (latest / slot["slot"]).relative_to(directory).as_posix()
            if verify:
                verify_row(directory, row, batch, contract)
        rows.extend(actual)
    assert seen == set((directory / "blocks").iterdir()), "Unaccounted block attempt"
    assert len({row["run_id"] for row in rows}) == len(rows)
    return rows


def stable(source):
    assert source_revision() == source, "Execution source changed; preserve evidence and stop"


async def execute(directory, plan, batch, contract, environments, *, block_size=6):
    """Dispatch fresh worlds; valid zero scores and unknown usage remain scheduled trials."""
    completed = active_rows(directory, plan, batch, contract, block_size=block_size)
    previous = journal(directory / "results.jsonl")
    assert len(previous) % block_size == 0 and previous == completed[:len(previous)]
    atomic(directory / "results.jsonl", completed, lines=True)
    for offset in range(len(completed), len(plan), block_size):
        slots = plan[offset:offset + block_size]
        block = slots[0]["block"]
        old = sorted((directory / "blocks").glob(f"{block:03d}-a*"))
        path = directory / "blocks" / f"{block:03d}-a{len(old) + 1:03d}"
        path.mkdir()
        atomic(path / "block.json", {"block": block, "attempt": len(old) + 1,
               "source": batch["source"], "slots": [s["slot"] for s in slots],
               "supersedes": [p.relative_to(directory).as_posix() for p in old],
               "reason": "incomplete_block_measurement" if old else "scheduled"})
        current = []
        for slot in slots:
            try:
                stable(batch["source"])
                run_dir = path / slot["slot"]
                score = await run_case(directory / slot["case"], run_dir, model="api",
                    model_env=environments[slot["model"]], policy=slot["policy"], seed=slot["seed"])
                stable(batch["source"])
                record = replay(run_dir)
                row = {**slot, "attempt": len(old) + 1,
                       "path": run_dir.relative_to(directory).as_posix(),
                       **{key: record[key] for key in ("run_id", "output", "costs")},
                       "grade": score}
                verify_row(directory, row, batch, contract)
                with (path / "results.jsonl").open("ab") as stream:
                    stream.write((json.dumps(row, ensure_ascii=False) + "\n").encode("utf-8"))
                    stream.flush()
                    os.fsync(stream.fileno())
                current.append(row)
                print(f"{offset + len(current)}/{len(plan)} {slot['slot']} "
                      f"correct={score['correct_disposition']}", flush=True)
            except BaseException as error:
                atomic(path / "pause.json", {"slot": slot, "exception": type(error).__name__,
                       "reason": "measurement_or_execution_integrity; inspect retained evidence"})
                raise
        atomic(path / "complete.json", {"source": batch["source"],
               "slots": [s["slot"] for s in slots], "runs": block_size})
        completed.extend(current)
        atomic(directory / "results.jsonl", completed, lines=True)
    stable(batch["source"])
    assert active_rows(directory, plan, batch, contract, block_size=block_size) == completed
    assert len(completed) == len(plan)
    atomic(directory / "complete.json", {"source": batch["source"],
           "planned_trials": len(plan), "executed_trials": len(completed)})


async def run(output, environments, resume=False):
    root = Path("tasks/frozen")
    manifest, contract = validate(root)
    plan, source = schedule(manifest, contract), source_revision()
    assert source["dirty"] is False and source["commit"], "Commit reviewed source before execution"
    subprocess.run(["git", "diff", "--exit-code", contract["freeze_tag"], "--",
                    "src/harness_lab", "evals/grader.py", "evals/run_case.py", "tasks/frozen",
                    "pyproject.toml", "uv.lock"], check=True, capture_output=True)
    for label, environment in environments.items():
        controller = OpenAICompatibleController(environment)
        try:
            assert controller.describe() == contract["models"][label], "Model contract changed"
        finally:
            await controller.aclose()
    snapshots = {"manifest.json": manifest, "experiment.json": contract, "schedule.json": plan,
                 **{entry["file"]: read(root / entry["file"]) for entry in manifest["tasks"]}}
    if resume:
        batch = read(output / "batch.json")
        assert batch["source"] == source
        assert all(read(output / name) == value for name, value in snapshots.items())
    else:
        output.mkdir(parents=True, exist_ok=False)
        (output / "blocks").mkdir()
        batch = {"source": source, "frozen_tag": contract["freeze_tag"],
                 "artifact_root": str(output.resolve()), "user_override": {
            "date": "2026-11-07", "monetary_checks": False,
            "instruction": "从现在开始：全程不需要做任何费用预估等检查。"}}
        for name, value in {"batch.json": batch, **snapshots}.items():
            atomic(output / name, value)
        atomic(output / "results.jsonl", [], lines=True)
    await execute(output, plan, batch, contract, environments)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["run"])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--model-a", type=Path, required=True)
    parser.add_argument("--model-b", type=Path, required=True)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    asyncio.run(run(args.output, {"A": args.model_a, "B": args.model_b}, args.resume))
