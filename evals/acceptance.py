"""Offline acceptance preparation: references and paired schedule; never calls a model."""

import argparse
import asyncio
import itertools
import json
import random
from collections import Counter
from copy import deepcopy
from dataclasses import asdict
from importlib.metadata import version
from pathlib import Path

from evals.development import read, reference, save
from harness_lab.contracts import Budget, RunConfig, TaskInput
from harness_lab.runtime import SYSTEM_PROMPT, public_tools
from harness_lab.tool_server import ServerConfig
from harness_lab.trace import source_revision


def schedule(manifest, contract):
    """54 shuffled blocks; six policy permutations appear nine times per model."""
    rng = random.Random(contract["schedule_seed"])
    blocks = list(itertools.product(manifest["tasks"], range(1, 4)))
    rng.shuffle(blocks)
    permutations = list(itertools.permutations(("P0", "P1", "P2")))
    orders = {model: permutations * 9 for model in ("A", "B")}
    for values in orders.values():
        rng.shuffle(values)
    trials = []
    for index, (entry, repeat) in enumerate(blocks):
        seed = contract["backoff_seed_base"] + 3 * int(entry["id"].split("-")[1]) + repeat
        for model in ("A", "B")[::1 if index % 2 == 0 else -1]:
            for policy in orders[model][index]:
                trials.append({"slot": f"{entry['id']}-r{repeat}-{model}-{policy}",
                               "task_id": entry["id"], "repeat": repeat, "model": model,
                               "policy": policy, "seed": seed, "block": index + 1,
                               "case": entry["file"], "family": entry["family"]})
    return trials


def validate(root):
    manifest, contract = read(root / "manifest.json"), read(root / "experiment.json")
    entries = manifest["tasks"]
    assert len(entries) == len({entry["id"] for entry in entries}) == 18
    assert manifest["repeat_count"] == contract["repeat_count"] == 3
    assert contract["planned_trials"] == 324 and contract["concurrency"] == 1
    assert contract["policies"] == ["P0", "P1", "P2"] and set(contract["models"]) == {"A", "B"}
    assert Counter(entry["family"] for entry in entries) == {
        "F1": 2, "F2": 2, "F3": 6, "F4": 2, "F5": 3, "F6": 3,
    }
    config = RunConfig("probe", "dev-user", Path("unused"))
    assert contract["budget"] == asdict(Budget())
    assert (contract["backoff_s"], contract["jitter_s"]) == (config.backoff_s, config.jitter_s)
    assert contract["system_prompt"] == SYSTEM_PROMPT
    assert all(version(name) == value for name, value in contract["dependencies"].items())
    for entry in entries:
        case = read(root / entry["file"])
        task = TaskInput(**case["task_input"])
        assert task.task_id == entry["id"]
        assert task.target_ref == case["environment"]["target_ref"] == case["oracle"]["target_ref"]
        ServerConfig.model_validate({"db_path": "unused", "run_id": "probe", "principal": "u",
            "operation_id": "probe:write-0", "idempotency_key": "probe:write-0",
            "target_ref": task.target_ref, "can_read": True, "can_write": True,
            "fault": case["fault_plan"] or None})
        if entry["family"] == "F3":
            first = next(step["args"] for step in entry["reference"] if step["stage"] == "write-0")
            final = case["oracle"]["expected_params"]
            assert any(first[key] != final[key] for key in ("queue", "priority"))
    return manifest, contract


async def prepare(root, output, with_references):
    manifest, contract = validate(root)
    source = source_revision()
    if source["dirty"] is not False or not source["commit"]:
        raise ValueError("Commit reviewed source before recording acceptance evidence")
    output.mkdir(parents=True, exist_ok=False)
    save(output / "manifest.json", manifest)
    save(output / "experiment.json", contract)
    save(output / "schedule.json", schedule(manifest, contract))
    worlds = 0
    for entry in manifest["tasks"]:
        case = read(root / entry["file"])
        save(output / entry["file"], case)
        if not with_references:
            continue
        await reference(output / entry["file"], entry["reference"], output / entry["id"])
        for contrast in entry.get("contrasts", []):
            variant = deepcopy(case)
            variant["environment"] = deepcopy(case["oracle"]["final_state"])
            variant["environment"]["facts"].update(contrast["facts_patch"])
            variant["fault_plan"] = {}
            variant["oracle"].update(expected_params=contrast["expected_params"],
                                     final_state=variant["environment"])
            path = output / (entry["id"] + "-" + contrast["name"] + ".json")
            save(path, variant)
            steps = [{"stage": "initial_read", "attempt": 1,
                      "args": {"target_ref": case["task_input"]["target_ref"]}, "expect": "state"},
                     {"stage": "write-0", "attempt": 1,
                      "args": contrast["expected_params"], "expect": "receipt"}]
            await reference(path, steps, path.with_suffix(""))
        events = [json.loads(line) for line in (output / entry["id"] / "wire.jsonl")
                  .read_text(encoding="utf-8").splitlines()]
        tools = next(event["data"]["tools"] for event in events if event["event"] == "mcp_tools")
        assert public_tools(tools) == contract["tools"]
        worlds += 1 + len(entry.get("contrasts", []))
        print(f"verified {entry['id']}", flush=True)
    if source_revision() != source:
        raise RuntimeError("Preparation source changed; retain incomplete evidence and stop")
    save(output / "complete.json", {"source": source, "planned_trials": 324,
         "reference_worlds": worlds, "model_api_calls": 0, "formal_trials_executed": 0})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["plan", "reference"])
    parser.add_argument("--root", type=Path, default=Path("tasks/frozen"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(prepare(args.root, args.output, args.mode == "reference"))
