"""Preparation invariants, plus one real-MCP seed propagation check; no paid API."""

import subprocess
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]


def test_complete_balanced_schedule_and_isolated_repeats():
    script = """
from collections import Counter
from pathlib import Path
from evals.acceptance import schedule, validate
m, c = validate(Path('tasks/frozen'))
rows = schedule(m,c)
assert rows == schedule(m,c)
assert len(rows) == len({r['slot'] for r in rows}) == 324
groups = {}
for r in rows: groups.setdefault(r['block'], []).append(r)
assert len(groups) == 54
for group in groups.values():
    assert len(group) == 6
    assert len({(r['task_id'],r['repeat'],r['seed']) for r in group}) == 1
    assert {(r['model'],r['policy']) for r in group} == {
        (model,policy) for model in ('A','B') for policy in ('P0','P1','P2')}
assert len({group[0]['seed'] for group in groups.values()}) == 54
for model in ('A','B'):
    counts=Counter(tuple(r['policy'] for r in group if r['model']==model)
                   for group in groups.values())
    assert len(counts)==6 and set(counts.values())=={9}
assert Counter(r['family'] for r in rows)['F3']==108
"""
    subprocess.run([sys.executable, "-c", script], cwd=PROJECT, check=True, timeout=15)


def test_explicit_backoff_seed_reaches_shared_runtime(tmp_path):
    script = """
import asyncio,json,sys
from pathlib import Path
from evals.run_case import run_case
out=Path(sys.argv[1])/'run'
asyncio.run(run_case(Path('tasks/dev/read-transient.json'),out,seed=67))
start=json.loads((out/'trace.jsonl').read_text(encoding='utf-8').splitlines()[0])
assert start['data']['config']['seed']==67
assert json.loads((out/'grade.json').read_text())['correct_disposition']==1
"""
    subprocess.run([sys.executable, "-c", script, str(tmp_path)], cwd=PROJECT,
                   check=True, timeout=30)
