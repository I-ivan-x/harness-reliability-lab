"""Synthetic statistics only: these rows are never actual run evidence."""

import subprocess
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]


def test_task_paired_math_pass_cubed_and_missing_slots():
    script = '''
from evals.formal_report import summarize
manifest = {"tasks": [{"id": task, "cohort": cohort} for task, cohort in (
    ("m1", "M"), ("m2", "M"), ("c1", "C"))]}
contract = {"repeat_count": 3, "models": {"A": {}}, "policies": ["P0", "P1", "P2"],
    "statistics": {"bootstrap_seed": 20261107, "bootstrap_resamples": 2000}}
rows = []
for entry in manifest["tasks"]:
    for policy in contract["policies"]:
        for repeat in range(1, 4):
            task = entry["id"]
            correct = int((task == "m1" and policy == "P1") or
                          (task == "m2" and policy == "P2") or
                          (task == "c1" and repeat == 1))
            rows.append({"task_id": task, "repeat": repeat, "model": "A", "policy": policy,
                "family": "F3" if entry["cohort"] == "M" else "F1",
                "costs": {"model_calls": 2, "tool_attempts": 2, "input_tokens": 20,
                          "output_tokens": 5, "total_s": 1.0},
                "grade": {"correct_disposition": correct, "goal_completed": correct,
                    "false_allow": 0, "false_refusal": 0, "false_refusal_eligible": 1,
                    "duplicate_effect": 0, "checks": {key: True for key in (
                        "within_budget", "decision_budget", "operation_budget", "context_budget")},
                    "grading_cost": {"latency_s": 0.01, "api_calls": 0}}})
result = summarize(rows, manifest, contract)
primary = result["primary_f3_p2_minus_p1"]["A"]
assert (primary["wins"], primary["ties"], primary["losses"]) == (1, 0, 1)
assert primary["task_cluster_bootstrap_95"] == [-1, 1]
assert primary["paired_difference"] == 0
assert primary["contrasts"]["M"]["per_net_additional_goal"] is None
group = result["groups"]["A-P2"]
assert group["cohorts"]["M"]["pass_cubed"] == 0.5
assert group["cohorts"]["C"]["pass_cubed"] == 0
assert group["cohorts"]["C"]["rate"] == 1/3
assert group["goal_denominator"] == 9
assert result["per_task_scores"]["A-P2"]["c1"] == [1, 0, 0]
rows[0]["costs"]["input_tokens"] = None
unknown = summarize(rows, manifest, contract)["groups"]["A-P0"]
assert unknown["costs"]["input_tokens"] is None
assert unknown["unknown_usage_runs"] == 1
assert unknown["known_tokens_from_complete_runs"]["input_tokens"] == 160
for row in rows:
    if row["task_id"] == "m1" and row["policy"] == "P2":
        row["grade"]["correct_disposition"] = row["grade"]["goal_completed"] = 1
        row["costs"]["model_calls"] = 3
extra = summarize(rows, manifest, contract)["primary_f3_p2_minus_p1"]["A"]["contrasts"]["M"]
assert extra["net_completed_goals"] == 3
assert extra["per_net_additional_goal"]["model_calls"] == 1
for invalid in (rows[:-1], rows + rows[:1]):
    try:
        summarize(invalid, manifest, contract)
    except ValueError:
        pass
    else:
        raise AssertionError("Missing/duplicate trial silently accepted")
'''
    subprocess.run([sys.executable, "-c", script], cwd=PROJECT, check=True, timeout=15)
