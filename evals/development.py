"""Bounded development calibration/pilot; never a frozen-set experiment runner."""

import argparse
import asyncio
import itertools
import json
from copy import deepcopy
from pathlib import Path

from mcp.shared.exceptions import McpError

from evals.grader import _load_state
from evals.run_case import prepare_case, regrade_case, run_case
from harness_lab.contracts import Budget
from harness_lab.mcp_port import MCPToolPort
from harness_lab.trace import TraceWriter, replay, source_revision


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def save(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")


def audit(directory):
    """Regrade every attempted pilot run and retain the original grades/costs."""
    manifest = read(directory / "manifest.json")
    entries = {entry["id"]: entry for entry in manifest["tasks"]}
    rows = [json.loads(line) for line in (directory / "results.jsonl").read_text().splitlines()]
    identities = [(row["task_id"], row["model"], row["policy"]) for row in rows]
    assert len(rows) == len(set(identities)) == 60
    assert len({row["run_id"] for row in rows}) == 60
    assert set(identities) == set(itertools.product(entries, ("A", "B"), ("P0", "P1", "P2")))
    pairing, models = {}, {}
    for row in rows:
        path = directory / row["path"]
        entry = entries[row["task_id"]]
        saved = read(path / "manifest.json")
        record = replay(path)
        score = regrade_case(directory / entry["file"], path)
        assert all(score[key] == value for key, value in row["grade"].items()
                   if key != "grading_cost")
        assert score["measurement_valid"] and record["source"] == manifest["source"]
        assert (record["run_id"], record["costs"], record["output"]) == (
            row["run_id"], row["costs"], row["output"])
        assert record["policy"] == row["policy"] and row["family"] == entry["family"]
        server = read(path / "private-server.json")
        case = read(directory / entry["file"])
        assert saved["task_input"] == case["task_input"]
        assert server["fault"] == (case["fault_plan"] or None)
        config = json.loads(
            (path / "trace.jsonl").read_text(encoding="utf-8").splitlines()[0])["data"]["config"]
        pair = (saved["task_input"], saved["controller"], record["limits"], server["fault"], config)
        key = (row["task_id"], row["model"])
        assert pairing.setdefault(key, pair) == pair
        assert models.setdefault(row["model"], saved["controller"]) == saved["controller"]
        save(path / "audit-grade.json", score)
    groups = {}
    for model, policy in itertools.product(("A", "B"), ("P0", "P1", "P2")):
        selected = [row for row in rows if (row["model"], row["policy"]) == (model, policy)]
        costs = {field: (None if any(row["costs"][field] is None for row in selected)
                        else sum(row["costs"][field] for row in selected)) for field in (
                            "model_calls", "tool_attempts", "input_tokens", "output_tokens",
                            "total_s"
                        )}
        groups[f"{model}-{policy}"] = {"n": len(selected), "costs": costs, **{
            field: sum(row["grade"][field] for row in selected) for field in (
                "correct_disposition", "goal_completed", "false_allow", "false_refusal",
                "false_refusal_eligible", "duplicate_effect"
            )}, "grading_latency_s": sum(row["grade"]["grading_cost"]["latency_s"]
                                        for row in selected)}
    save(directory / "summary.json", {"models": models, "groups": groups,
         "source": manifest["source"], "audit_source": source_revision(), "regraded_runs": 60,
         "k": 1, "grading_api_calls": sum(
             row["grade"]["grading_cost"]["api_calls"] for row in rows)})


async def reference(case_path, steps, directory):
    """Oracle-aware protocol probe: no controller, Host, synthetic usage or benchmark score."""
    prepared = prepare_case(case_path, directory)
    case = read(case_path)
    trace = TraceWriter(directory / "wire.jsonl")
    port = MCPToolPort(prepared["server_path"], directory / "mcp-stderr.log", trace)
    delivered = []
    try:
        async with port:
            for step in steps:
                envelope = {key: value for key, value in read(prepared["server_path"]).items()
                            if key in {"run_id", "principal", "operation_id", "idempotency_key"}}
                envelope.update(stage=step["stage"], attempt=step["attempt"])
                tool = "create_ticket" if step["stage"] == "write-0" else "read_state"
                try:
                    async with asyncio.timeout(Budget().tool_timeout_s):
                        reply = await port.call(tool, {**step["args"], "envelope": envelope}, 1)
                    result = reply["structuredContent"]
                    observed = (result["kind"] if result.get("ok") is True else
                                result["error"]["code"] if result.get("ok") is False else
                                "INVALID_RESULT")
                    delivered.append(result)
                    if observed == "STALE_REVISION":
                        assert all(result["error"][flag] is True for flag in (
                            "repairable", "not_executed", "unbound"
                        ))
                except (TimeoutError, McpError) as exc:
                    if isinstance(exc, McpError) and exc.error.code != 408:
                        raise
                    observed = "TIMEOUT"
                trace("reference_step", {"step": step, "observed": observed})
                assert observed == step["expect"], (case_path, step, observed)
        tickets, receipts, states = _load_state(prepared["database"])
        expected = case["oracle"].get("expected_params")
        assert port.cleanup_completed
        assert len(tickets) == len(receipts) == int(expected is not None)
        if expected:
            assert tickets[0]["params"] == expected
            receipt = next(iter(receipts.values()))
            assert receipt["params"] == expected and receipt["run_id"] == prepared["run_id"]
            assert any(item.get("receipt") == receipt for item in delivered)
        assert states[case["task_input"]["target_ref"]] == case["oracle"]["final_state"]
        save(directory / "reference.json", {"environment_verified": True,
             "source": source_revision(), "task_id": case["task_input"]["task_id"]})
    finally:
        trace.close()


async def execute(args):
    source = source_revision()
    if source["dirty"] is not False or not source["commit"]:
        raise ValueError("Commit the reviewed development source before recording evidence")
    manifest = read(args.manifest)
    entries = manifest["tasks"]
    assert len(entries) == len({entry["id"] for entry in entries}) == 10
    args.output.mkdir(parents=True, exist_ok=False)
    save(args.output / "manifest.json", {**manifest, "source": source, "mode": args.mode})
    permutations = list(itertools.permutations(("P0", "P1", "P2")))
    for index, entry in enumerate(entries):
        case = read(args.manifest.parent / entry["file"])
        assert case["task_input"]["task_id"] == entry["id"]
        case_path = args.output / entry["file"]
        save(case_path, case)
        if args.mode == "reference":
            await reference(case_path, entry["reference"], args.output / entry["id"])
            for contrast in entry.get("contrasts", []):
                variant = deepcopy(case)
                variant["environment"] = deepcopy(case["oracle"]["final_state"])
                variant["environment"]["facts"].update(contrast["facts_patch"])
                variant["fault_plan"] = {}
                variant["oracle"].update(expected_params=contrast["expected_params"],
                                         final_state=variant["environment"])
                path = args.output / (entry["id"] + "-" + contrast["name"] + ".json")
                save(path, variant)
                steps = [{"stage": "initial_read", "attempt": 1,
                          "args": {"target_ref": case["task_input"]["target_ref"]},
                          "expect": "state"}, {"stage": "write-0", "attempt": 1,
                          "args": contrast["expected_params"], "expect": "receipt"}]
                await reference(path, steps, path.with_suffix(""))
            print(f"verified {entry['id']}", flush=True)
            continue
        models = [("A", args.model_a), ("B", args.model_b)][::1 if index % 2 == 0 else -1]
        for offset, (label, env) in enumerate(models):
            for policy in permutations[(index + 3 * offset) % len(permutations)]:
                directory = args.output / f"{entry['id']}-{label}-{policy}"
                score = await run_case(case_path, directory, model="api", model_env=env,
                                       policy=policy)
                record = replay(directory)
                row = {"task_id": entry["id"], "family": entry["family"], "model": label,
                       "policy": policy, "path": directory.name, "run_id": record["run_id"],
                       "output": record["output"], "costs": record["costs"], "grade": score}
                with (args.output / "results.jsonl").open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(row) + "\n")
                print(f"{directory.name}: correct={score['correct_disposition']} "
                      f"{record['output']['disposition']}", flush=True)
                if not score["measurement_valid"] or record["source"] != source:
                    raise RuntimeError("Stop pilot: invalid measurement or source changed")
    save(args.output / "complete.json", {"mode": args.mode, "task_count": len(entries),
                                        "runs": 60 if args.mode == "pilot" else None})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["reference", "pilot", "audit"])
    parser.add_argument("--manifest", type=Path, default=Path("tasks/development/manifest.json"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--model-a", type=Path)
    parser.add_argument("--model-b", type=Path)
    arguments = parser.parse_args()
    if arguments.mode == "pilot" and not (arguments.model_a and arguments.model_b):
        parser.error("pilot requires both explicit local model configuration paths")
    if arguments.mode == "audit":
        audit(arguments.output)
    else:
        asyncio.run(execute(arguments))
