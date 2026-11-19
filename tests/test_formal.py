"""Batch durability with mocked ports; temporary synthetic rows are not run evidence."""

import subprocess
import sys
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parents[1]
SCRIPT = '''
import asyncio,sys
from pathlib import Path
from unittest.mock import patch
import pytest
from evals import formal as f
root, scenario = Path(sys.argv[1]), sys.argv[2]
(root/'blocks').mkdir()
f.atomic(root/'results.jsonl', [], lines=True)
batch = {'source': {'commit': 'synthetic-test-only', 'dirty': False}}
triplet = scenario.startswith('triplet')
block_size, blocks = (3, (19,20)) if triplet else (6, (1,2))
plan = [{'slot': f't{block}-{model}-{policy}', 'task_id': f't{block}', 'repeat': 1,
    'model': model, 'policy': policy, 'seed': block, 'block': block,
    'case': f't{block}.json', 'family': 'F3'} for block in blocks
    for model in (('B',) if triplet else ('A','B')) for policy in ('P0','P1','P2')]
calls, records, fail, current_source = [], {}, [scenario.endswith('resume')], [batch['source']]
async def fake(case, directory, **kwargs):
    calls.append(directory.relative_to(root).as_posix())
    assert kwargs['model'] == 'api' and kwargs['model_env'] in ('env-A', 'env-B')
    directory.mkdir()
    (directory/'synthetic-only.txt').write_text('Mocked ports, never actual evidence')
    if fail[0] and len(calls) == block_size + 3:
        raise RuntimeError('synthetic interruption')
    records[directory.resolve()] = {'run_id': f'synthetic-{len(calls)}', 'output': {},
        'costs': {'model_calls': 1, 'tool_attempts': 0, 'input_tokens': None,
                  'output_tokens': None, 'total_s': 0.1}}
    if scenario == 'source':
        current_source[0] = {'commit': 'changed', 'dirty': True}
    return {'correct_disposition': 0, 'measurement_valid': True}
def verify(directory, row, batch, contract):
    record = records[(directory/row['path']).resolve()]
    assert row['run_id'] == record['run_id'] and row['grade']['correct_disposition'] == 0
    assert row['costs']['input_tokens'] is None
    return record, row['grade']
def execute():
    kwargs = {'block_size': block_size} if triplet else {}
    asyncio.run(f.execute(root,plan,batch,{}, {'A':'env-A','B':'env-B'}, **kwargs))
with patch.multiple(f, run_case=fake, replay=lambda path: records[path.resolve()],
                    verify_row=verify, source_revision=lambda: current_source[0]):
    if scenario == 'source':
        with pytest.raises(AssertionError, match='source changed'):
            execute()
        assert len(calls) == 1 and f.journal(root/'results.jsonl') == []
        assert (root/'blocks/001-a001/pause.json').exists()
        assert not (root/'blocks/001-a001/complete.json').exists()
    elif scenario.endswith('resume'):
        with pytest.raises(RuntimeError, match='synthetic interruption'):
            execute()
        original = f.journal(root/'results.jsonl')
        assert len(original) == block_size and not (root/'complete.json').exists()
        old = root/f'blocks/{blocks[1]:03d}-a001'
        assert len(f.journal(old/'results.jsonl')) == 2 and (old/'pause.json').exists()
        fail[0] = False
        execute()
        active = f.journal(root/'results.jsonl')
        assert len(calls) == 2*block_size+3 and active[:block_size] == original
        assert len(active) == 2*block_size
        replacement = f'blocks/{blocks[1]:03d}-a002'
        assert all(row['path'].startswith(replacement+'/') for row in active[block_size:])
        assert f.read(root/replacement/'block.json')['supersedes'] == [
            old.relative_to(root).as_posix()]
        assert len(f.journal(old/'results.jsonl')) == 2 and not (old/'complete.json').exists()
        assert f.active_rows(root,plan,batch,{},block_size=block_size) == active
        execute()
        assert len(calls) == 2*block_size+3
    else:
        execute()
        rows = f.journal(root/'results.jsonl')
        assert len(rows) == len(calls) == 2*block_size
        assert all(row['grade']['correct_disposition'] == 0 for row in rows)
        assert f.read(root/'complete.json')['executed_trials'] == 2*block_size
        assert all(f.read(root/f'blocks/{block:03d}-a001/complete.json')['runs'] == block_size
                   for block in blocks)
        execute()
        assert len(calls) == 2*block_size
        if scenario == 'malformed':
            marker = root/'blocks/001-a001/complete.json'
            good = f.read(marker)
            f.atomic(marker,{**good,'runs':5})
            with pytest.raises(AssertionError): f.active_rows(root,plan,batch,{})
            f.atomic(marker,good)
            journal = root/'blocks/001-a001/results.jsonl'
            broken = f.journal(journal)
            broken[0]['slot'] = 'unexpected'
            f.atomic(journal,broken,lines=True)
            with pytest.raises(AssertionError): f.active_rows(root,plan,batch,{})
            journal.write_text('{truncated',encoding='utf-8')
            with pytest.raises(ValueError): f.active_rows(root,plan,batch,{})
'''


@pytest.mark.parametrize("scenario", [
    "valid", "resume", "malformed", "source", "triplet", "triplet-resume"])
def test_formal_batch_durability(tmp_path, scenario):
    subprocess.run([sys.executable, "-c", SCRIPT, str(tmp_path), scenario],
                   cwd=PROJECT, check=True, timeout=20)
