"""Offline integrity audit and task-paired statistics for the frozen experiment."""

import argparse
import itertools
import json
import random
from pathlib import Path
from statistics import mean

from evals.acceptance import schedule, validate
from evals.development import read, save
from harness_lab.trace import source_revision

FIELDS = ("model_calls", "tool_attempts", "input_tokens", "output_tokens", "total_s")
BUDGET_CHECKS = ("within_budget", "decision_budget", "operation_budget", "context_budget")


def _costs(rows):
    return {field: None if any(row["costs"][field] is None for row in rows) else
            sum(row["costs"][field] for row in rows) for field in FIELDS}


def _interval(values, statistics):
    rng = random.Random(statistics["bootstrap_seed"])
    sampled = sorted(mean(rng.choices(values, k=len(values)))
                     for _ in range(statistics["bootstrap_resamples"]))
    def percentile(p):
        index = p * (len(sampled) - 1)
        lower = int(index)
        return sampled[lower] + (sampled[min(lower + 1, len(sampled) - 1)] - sampled[lower]) * (
            index - lower)
    return [percentile(0.025), percentile(0.975)]


def summarize(rows, manifest, contract):
    """Pure statistics; synthetic callers must never label their rows as run evidence."""
    if contract["repeat_count"] != 3:
        raise ValueError("pass^3 requires exactly three scheduled repeats")
    entries = {entry["id"]: entry for entry in manifest["tasks"]}
    expected = set(itertools.product(entries, range(1, contract["repeat_count"] + 1),
                                     contract["models"], contract["policies"]))
    identities = [(row["task_id"], row["repeat"], row["model"], row["policy"]) for row in rows]
    if len(identities) != len(set(identities)) or set(identities) != expected:
        raise ValueError("Missing, duplicate or unexpected trial identities; no complete summary")
    groups, per_task, primary = {}, {}, {}
    for model, policy in itertools.product(contract["models"], contract["policies"]):
        selected = [row for row in rows if (row["model"], row["policy"]) == (model, policy)]
        key = f"{model}-{policy}"
        scores = {task: [row["grade"]["correct_disposition"] for row in sorted(
            (row for row in selected if row["task_id"] == task), key=lambda row: row["repeat"])]
            for task in entries}
        per_task[key] = scores
        cohorts = {}
        for cohort in ("M", "C"):
            values = [value for task, value in scores.items() if entries[task]["cohort"] == cohort]
            cohorts[cohort] = {"correct": sum(map(sum, values)), "n": sum(map(len, values)),
                "rate": mean(value for score in values for value in score),
                "pass_cubed": mean(all(score) for score in values), "tasks": len(values)}
        totals = {field: sum(row["grade"][field] for row in selected) for field in (
            "correct_disposition", "goal_completed", "false_allow", "false_refusal",
            "false_refusal_eligible", "duplicate_effect")}
        completable = sum(row["family"] in {"F1", "F2", "F3", "F4"} for row in selected)
        groups[key] = {"n": len(selected), **totals, "cohorts": cohorts,
            "correct_rate": totals["correct_disposition"] / len(selected),
            "goal_denominator": completable,
            "goal_completion_rate": totals["goal_completed"] / completable if completable else None,
            "false_allow_rate": totals["false_allow"] / len(selected),
            "false_refusal_rate": totals["false_refusal"] / totals["false_refusal_eligible"]
                if totals["false_refusal_eligible"] else None,
            "budget_violations": sum(not all(row["grade"]["checks"][check]
                                              for check in BUDGET_CHECKS) for row in selected),
            "costs": _costs(selected), "unknown_usage_runs": sum(any(
                row["costs"][field] is None for field in FIELDS[2:4]) for row in selected),
            "known_tokens_from_complete_runs": {
                field: sum(row["costs"][field] or 0 for row in selected) for field in FIELDS[2:4]},
            "grading_latency_s": sum(row["grade"]["grading_cost"]["latency_s"]
                                     for row in selected)}
    for model in contract["models"]:
        tasks = [task for task in entries if entries[task]["cohort"] == "M"]
        differences = [mean(per_task[f"{model}-P2"][task]) - mean(per_task[f"{model}-P1"][task])
                       for task in tasks]
        contrasts = {}
        for cohort in ("M", "C"):
            paired = [[row for row in rows if row["model"] == model and row["policy"] == policy
                       and entries[row["task_id"]]["cohort"] == cohort] for policy in ("P1", "P2")]
            before, after = map(_costs, paired)
            delta = {field: None if before[field] is None or after[field] is None else
                     after[field] - before[field] for field in FIELDS}
            net = sum(row["grade"]["goal_completed"] for row in paired[1]) - sum(
                row["grade"]["goal_completed"] for row in paired[0])
            contrasts[cohort] = {"cost_delta": delta, "net_completed_goals": net,
                "per_net_additional_goal": {field: value / net if value is not None else None
                    for field, value in delta.items()} if net > 0 else None}
        primary[model] = {"tasks": len(tasks), "wins": sum(value > 0 for value in differences),
            "ties": differences.count(0), "losses": sum(value < 0 for value in differences),
            "paired_difference": mean(differences),
            "task_cluster_bootstrap_95": _interval(differences, contract["statistics"]),
            "contrasts": contrasts}
    return {"groups": groups, "per_task_scores": per_task, "primary_f3_p2_minus_p1": primary,
            "runs": len(rows), "k": contract["repeat_count"], "grading_api_calls": sum(
                row["grade"]["grading_cost"]["api_calls"] for row in rows)}


def audit(directory):
    """Every scheduled failure remains a trial; incomplete evidence cannot become a full result."""
    from evals.formal import active_rows

    manifest, contract, batch = (read(directory / name) for name in (
        "manifest.json", "experiment.json", "batch.json"))
    root = Path(__file__).resolve().parents[1] / "tasks/frozen"
    assert validate(root) == (manifest, contract)
    assert all(read(directory / entry["file"]) == read(root / entry["file"])
               for entry in manifest["tasks"])
    assert batch["user_override"]["monetary_checks"] is False
    assert read(directory / "complete.json") == {
        "source": batch["source"], "planned_trials": 324, "executed_trials": 324}
    plan = read(directory / "schedule.json")
    rows = [json.loads(line) for line in (directory / "results.jsonl").read_text(
        encoding="utf-8").splitlines()]
    assert plan == schedule(manifest, contract) and len(plan) == 324
    assert [{key: row[key] for key in slot} for row, slot in zip(rows, plan, strict=True)] == plan
    assert len({row["run_id"] for row in rows}) == len({row["path"] for row in rows}) == 324
    assert batch["frozen_tag"] == contract["freeze_tag"] == "harness-experiment-v1"
    assert batch["source"]["dirty"] is False and batch["source"]["commit"]
    assert active_rows(directory, plan, batch, contract, verify=True) == rows
    assert len({(directory / row["path"] / "environment.sqlite").resolve() for row in rows}) == 324
    result = {**summarize(rows, manifest, contract), "source": batch["source"],
              "audit_source": source_revision(), "frozen_tag": batch["frozen_tag"],
              "user_override": batch["user_override"], "regraded_runs": len(rows),
              "block_attempts": [{"path": str(path.relative_to(directory)), "metadata": read(path)}
                  for path in sorted((directory / "blocks").glob("*/block.json"))]}
    save(directory / "summary.json", result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    print(json.dumps(audit(parser.parse_args().directory), indent=2, ensure_ascii=False))
