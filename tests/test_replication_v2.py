"""Any-model-failure stopping; synthetic requests never call an external model."""

import subprocess
import sys
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parents[1]
SCRIPT = r'''
import asyncio,json,sys
import pytest
from pathlib import Path
from unittest.mock import patch
from evals import replication_v2 as p
from evals import replication as baseline
root,scenario=Path(sys.argv[1]),sys.argv[2]
api_failure=scenario.startswith('api:')
code=scenario.removeprefix('api:')
(root/'blocks').mkdir()
p.atomic(root/'results.jsonl',[],lines=True)
plan=[{'slot':f't{block}-{model}-{policy}','block':block,'case':'synthetic.json',
       'model':model,'policy':policy,'seed':0,'task_id':f't{block}',
       'repeat':1,'family':'F3'} for block in (1,2)
       for model in ('A','B') for policy in ('P0','P1','P2')]
source={'commit':'synthetic-test-only','dirty':False}
batch={'source':source}
envs={'A':root/'A.env','B':root/'B.env'}
for path in envs.values(): path.write_text('synthetic-noncredential')
hashes={label:p.digest(path) for label,path in envs.items()}
records,calls={},[]
async def fake(case,directory,**kwargs):
 calls.append(directory)
 directory.mkdir()
 index=len(calls)
 record={'run_id':f'synthetic-{index}','output':{'reason_code':code
          if api_failure and index==3 else 'synthetic_zero'},
          'costs':{'model_calls':1,'tool_attempts':0,'input_tokens':None,
                   'output_tokens':None,'total_s':.1}}
 records[directory]=record
 events=([{'event':'model_failed','data':{'error':({'code':code} if code!='missing_code' else {})}}]
         if api_failure and index==3 else [])
 (directory/'trace.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in events))
 if scenario=='config' and index==2: envs['B'].write_text('changed')
 return {'correct_disposition':0,'measurement_valid':True,
         'grading_cost':{'api_calls':0,'api_cost':0,'latency_s':.001}}
def verify(directory,row,*args):
 if scenario=='integrity' and len(calls)==2: raise ValueError('synthetic-only')
 assert row['costs']['input_tokens'] is None
 return records[directory/row['path']],row['grade']
gate={'unverified':[],'dispatch_violations':[],'state_violations':[],
      'invalid_allowed':0,'valid_blocked':0}
with patch.object(baseline,'stable',lambda source:None),patch.multiple(
                    p,run_case=fake,replay=lambda path:records[path],
                    verify_row=verify,audit_gate=lambda events:gate):
 if scenario in ('integrity','config'):
  with pytest.raises((ValueError,AssertionError)):
   asyncio.run(p.execute(root,plan,batch,{},envs,{},hashes))
  assert len(calls)==2 and len(p.journal(root/'results.jsonl'))==1
  assert (root/'stop.json').exists() and not (root/'complete.json').exists()
 elif api_failure:
  assert asyncio.run(p.execute(root,plan,batch,{},envs,{},hashes)) is False
  rows=p.journal(root/'results.jsonl')
  assert len(calls)==len(rows)==3
  assert rows[-1]['output']['reason_code']==code
  assert rows[-1]['grade']['correct_disposition']==0
  stop=p.read(root/'stop.json')
  assert stop['reason']=='model_api_failure'
  assert stop['not_run']==9 and stop['resume_allowed'] is False
  assert not (root/'complete.json').exists()
 else:
  assert asyncio.run(p.execute(root,plan,batch,{},envs,{},hashes)) is True
  rows=p.journal(root/'results.jsonl')
  assert len(calls)==len(rows)==12
  assert all(row['grade']['correct_disposition']==0 for row in rows)
  assert p.read(root/'complete.json')['executed_trials']==12
  assert p.active_rows(root,plan,batch,{},verify=False)==rows
'''


@pytest.mark.parametrize("scenario", ["valid-zero", "integrity", "config", *[
    "api:"+code for code in (
    "HTTP_403", "HTTP_429", "HTTP_500", "TIMEOUT", "TRANSPORT_ERROR", "INVALID_JSON",
    "INVALID_RESPONSE", "UNEXPECTED_MODEL_ERROR", "missing_code")]])
def test_independent_replication_preserves_failures_and_stops(tmp_path, scenario):
    subprocess.run([sys.executable, "-c", SCRIPT, str(tmp_path), scenario],
                   cwd=PROJECT, check=True, timeout=30)


def test_replication_contract_preserves_original_scientific_configuration(tmp_path):
    script = r'''
import copy,json,sys
from pathlib import Path
import pytest
from evals.replication_v2 import CONTRACT,validate
manifest,contract=validate()
assert len(manifest['tasks'])==18 and contract['planned_trials']==324
assert 'spending' not in contract
changed=copy.deepcopy(contract)
changed['budget']['tool_attempts']+=1
altered=Path(sys.argv[1])/'changed.json'
altered.write_text(json.dumps(changed),encoding='utf-8')
with pytest.raises(AssertionError,match='Scientific configuration changed'):
 validate(contract_path=altered)
assert CONTRACT.is_file() and contract['replication']['stop_on_any_model_failure'] is True
'''
    subprocess.run([sys.executable, "-c", script, str(tmp_path)],
                   cwd=PROJECT, check=True, timeout=30)
