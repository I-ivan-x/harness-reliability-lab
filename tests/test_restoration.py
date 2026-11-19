"""Synthetic selection/merge fixtures; never actual experiment evidence or API calls."""

import subprocess
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]


def test_exact_restoration_selection_and_combination():
    script = '''
from copy import deepcopy
from pathlib import Path
import pytest
from evals.acceptance import schedule, validate
from evals.restoration import combine, selection
plan = schedule(*validate(Path("tasks/frozen")))
rows = [{**slot, "run_id": f"synthetic-old-{index}",
    "path": f"blocks/{slot['block']:03d}-a001/{slot['slot']}",
    "output": {"reason_code": "HTTP_429" if slot["model"] == "B" and
               slot["block"] > 18 else "OK"}}
    for index, slot in enumerate(plan)]
next(row for row in rows if row["model"] == "A")["output"]["reason_code"] = "HTTP_429"
first_b = next(row for row in rows if row["model"] == "B")
first_b["output"]["reason_code"] = "MODEL_PARSE_ERROR"
selected = selection(plan, rows)
assert len(selected) == 108 and {row["block"] for row in selected} == set(range(19,55))
assert all(row["model"] == "B" for row in selected)
selected_slots = {row["slot"] for row in selected}
assert first_b["slot"] not in selected_slots
retained = [row for row in rows if row["slot"] not in selected_slots]
replacements = [{**slot, "run_id": f"synthetic-new-{index}",
    "path": f"blocks/{slot['block']:03d}-a001/{slot['slot']}",
    "grade": {"correct_disposition": 0}, "costs": {"input_tokens": None}}
    for index, slot in enumerate(selected)]
combined = combine(plan, retained, replacements)
assert [row["slot"] for row in combined] == [slot["slot"] for slot in plan]
assert sum(row["path"].startswith("original/") for row in combined) == 216
assert sum(row["path"].startswith("restored/") for row in combined) == 108
assert {row["run_id"] for row in combined if row["path"].startswith("original/")} == {
    row["run_id"] for row in retained}
for row in combined:
    origin = "restored" if row["slot"] in selected_slots else "original"
    source = next(item for item in replacements if item["slot"] == row["slot"]) if (
        origin == "restored") else next(item for item in retained if item["slot"] == row["slot"])
    assert row == {**source, "path": origin + "/" + source["path"]}
for field, value in (("run_id", retained[0]["run_id"]), ("policy", "unexpected"),
                     ("slot", "unexpected")):
    broken = deepcopy(replacements)
    broken[0][field] = value
    with pytest.raises((AssertionError, KeyError)):
        combine(plan, retained, broken)
bad_rows = deepcopy(rows)
next(row for row in bad_rows if row["slot"] in selected_slots)["output"]["reason_code"] = "OK"
with pytest.raises(AssertionError):
    selection(plan, bad_rows)
'''
    subprocess.run([sys.executable, "-c", script], cwd=PROJECT, check=True, timeout=20)
