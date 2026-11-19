"""Synthetic publication plus real local offline review; never invokes a model API."""

import subprocess
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]


def test_complete_synthetic_statistics_and_fresh_read_only_publication(tmp_path):
    script = r'''
import copy,json,sys
from pathlib import Path
from unittest.mock import patch
import pytest
from evals import replication as r, replication_report as a
from evals.acceptance import schedule
from evals.formal import atomic
root=Path(sys.argv[1]); source=root/'synthetic-replication'; source.mkdir()
manifest=a.read(Path('tasks/frozen/manifest.json'))
contract=a.read(Path('tasks/frozen/experiment.json'))
contract['freeze_tag']='harness-replication-v1'
origin={'commit':'synthetic-only-no-run-evidence','dirty':False}
batch={'source':origin,'frozen_tag':contract['freeze_tag'],
       'user_override':{'monetary_checks':False},'experiment_kind':'synthetic-test-only'}
for name,value in [('manifest.json',manifest),('experiment.json',contract),('batch.json',batch)]:
 atomic(source/name,value)
rows=[]
for slot in schedule(manifest,contract):
 correct=int(slot['policy']=='P2' or (slot['policy']=='P1' and slot['repeat']==1))
 grade={'grader_version':a.GRADER_VERSION,'correct_disposition':correct,'goal_completed':0,
  'false_allow':0,'false_refusal':0,'false_refusal_eligible':0,'duplicate_effect':0,
  'checks':dict.fromkeys(('within_budget','decision_budget','operation_budget','context_budget'),True),
  'grading_cost':{'latency_s':.01,'api_calls':0,'api_cost':0}}
 row={**slot,'run_id':'synthetic-'+slot['slot'],'path':'runs/'+slot['slot'],
  'grade':grade,'output':{'disposition':'COMPLETED' if correct else 'SYSTEM_FAILURE'},
  'costs':{'model_calls':2,'tool_attempts':1,'input_tokens':10,'output_tokens':2,'total_s':1}}
 run=source/row['path']; run.mkdir(parents=True)
 atomic(run/'trace.jsonl',[],lines=True)
 rows.append(row)
failed=next(row for row in rows if row['policy']=='P0')
failed['costs']['input_tokens']=failed['costs']['output_tokens']=None
atomic(source/failed['path']/'trace.jsonl',[{'event':'model_failed','data':{
 'usage':None,'error':{'code':'HTTP_429','provider_code':'RateLimit','request_id':'req-1',
 'request_id_source':'header:x-request-id','message':'PRIVATE-FREE-TEXT',
 'authorization':'PRIVATE-HEADER'}}}],lines=True)
atomic(source/'results.jsonl',rows,lines=True)
protocol={'attempts':1,'requests':1,'responses':1,'unverified_attempts':0,'unverified_outcomes':0}
gate=dict.fromkeys(('valid_allowed','valid_blocked','invalid_allowed','invalid_blocked',
 'valid_proposals','invalid_proposals','pre_gate_protocol_failures','provider_failures',
 'content_only_responses','content_parse_failures'),0)
gate.update(dispatch_violations=[],state_violations=[],unverified=[])
def fake_review(directory,row,batch,contract):
 return {'run_id':row['run_id'],'recorded_grade':row['grade'],
  'verified_grade':copy.deepcopy(row['grade']),'goal_eligible':False,
  'decision_changed':False,'protocol':protocol,'gate':gate}
def fake_audit(directory,*,persist=True):
 assert directory==source.resolve() and persist is False
 return batch
before=a.fingerprint(source)
with patch.object(r,'audit',fake_audit),patch.object(a,'review_row',fake_review):
 result=a.run(source)
 output=source.with_name(source.name+'-audit')
 assert a.fingerprint(source)==before and result['input_unchanged']
 assert result['runs']==324 and result['model_api_calls']==0 and result['decision_changes']==[]
 assert result['groups']['A-P2']['cohorts']['M']['pass_cubed']==1
 assert result['groups']['B-P1']['cohorts']['C']['pass_cubed']==0
 for model in ('A','B'):
  for cohort in ('M','C'):
   paired=result['paired_p2_minus_p1'][model][cohort]
   assert abs(paired['paired_difference']-2/3)<1e-12
   assert paired['wins']==paired['tasks'] and paired['ties']==paired['losses']==0
   assert all(abs(value-2/3)<1e-12 for value in paired['task_cluster_bootstrap_95'])
 unknown=result['groups'][failed['model']+'-P0']
 assert unknown['unknown_usage_runs']==1 and unknown['costs']['input_tokens'] is None
 assert result['model_failure_codes']=={'HTTP_429':1}
 failure=next(item for item in result['failures'] if item['slot']==failed['slot'])
 assert failure['unknown_usage'] and failure['model_failures'][0]['request_id']=='req-1'
 assert 'PRIVATE' not in json.dumps(result)
 assert result['audit_overall']['gate']['rates']['invalid_blocked_rate'] is None
 assert len(list((output/'runs').glob('*.json')))==324
 assert len(a.journal(output/'runs.jsonl'))==324 and a.read(output/'complete.json')['runs']==324
 published=a.fingerprint(output)
 with pytest.raises(FileExistsError): a.run(source)
 assert a.fingerprint(output)==published
 for unsafe in (source,source/'nested-audit',root,root/'wrong-name'):
  with pytest.raises(ValueError): a.run(source,unsafe)
 def damaging_audit(directory,*,persist=True):
  (directory/'unexpected-write').write_text('synthetic injected defect')
  return batch
 with patch.object(r,'audit',damaging_audit):
  with pytest.raises(ValueError,match='changed during'):
   a.run(source,root/'damaged-audit')
 assert not (root/'damaged-audit').exists()
 with patch.object(r,'audit',side_effect=ValueError('incomplete batch')):
  with pytest.raises(ValueError,match='incomplete batch'): a.run(source,root/'partial-audit')
 assert not (root/'partial-audit').exists()
'''
    subprocess.run([sys.executable, "-c", script, str(tmp_path)],
                   cwd=PROJECT, check=True, timeout=30)


def test_strict_same_grader_and_independent_audits_reject_changed_evidence(tmp_path):
    script = r'''
import copy,sys
from pathlib import Path
from unittest.mock import patch
import pytest
from evals import replication_report as a
from evals.formal import atomic
root=Path(sys.argv[1]); (root/'run').mkdir()
atomic(root/'run/trace.jsonl',[],lines=True)
score={'correct_disposition':0,'checks':{'final_state':False},
       'grading_cost':{'api_calls':0,'api_cost':0,'latency_s':.1}}
detail={'recorded_grade':score,'verified_grade':copy.deepcopy(score),
 'decision_changed':False,'protocol':{'unverified_attempts':0,'unverified_outcomes':0},
 'gate':{'unverified':[],'dispatch_violations':[],'state_violations':[],
         'invalid_allowed':0,'valid_blocked':0}}
row=dict(slot='synthetic-only',task_id='synthetic',repeat=1,path='run',model='B',policy='P0',
         output={},costs={'input_tokens':None,'output_tokens':None})
with patch.object(a,'review_row',return_value=detail):
 detail['verified_grade']['grading_cost']['latency_s']=999
 assert a.review(root,row,{}, {})['unknown_usage']
 detail['verified_grade']['checks']['final_state']=True
 with pytest.raises(ValueError,match='grade changed'): a.review(root,row,{}, {})
 detail['verified_grade']['checks']['final_state']=False
 detail['decision_changed']=True
 with pytest.raises(ValueError,match='decision changed'): a.review(root,row,{}, {})
 detail['decision_changed']=False
 for key in ('unverified_attempts','unverified_outcomes'):
  detail['protocol'][key]=1
  with pytest.raises(ValueError,match='Protocol'): a.review(root,row,{}, {})
  detail['protocol'][key]=0
 for key in ('unverified','dispatch_violations','state_violations'):
  detail['gate'][key]=[{'reason':'synthetic defect'}]
  with pytest.raises(ValueError,match='Gate'): a.review(root,row,{}, {})
  detail['gate'][key]=[]
 for key in ('invalid_allowed','valid_blocked'):
  detail['gate'][key]=1
  with pytest.raises(ValueError,match='Gate'): a.review(root,row,{}, {})
  detail['gate'][key]=0
 atomic(root/'run/trace.jsonl',[{'event':'model_failed',
        'data':{'error':{'code':'HTTP_403'}}}],lines=True)
 with pytest.raises(ValueError,match='HTTP_403 stopping rule'):
  a.review(root,row,{}, {})
'''
    subprocess.run([sys.executable, "-c", script, str(tmp_path)],
                   cwd=PROJECT, check=True, timeout=15)


def test_existing_preflight_evidence_review_is_strict_and_unchanged():
    script = r'''
import copy
from pathlib import Path
import pytest
from evals import replication_report as a
from harness_lab.trace import replay
original=Path('artifacts/service-preflight-2026-11-14')
if not original.is_dir():
 raise SystemExit(77)
# Use the real run bytes with only development-manifest lookup supplied synthetically.
row=copy.deepcopy(a.journal(original/'results.jsonl')[0])
run=original/row['path']; events=a.journal(run/'trace.jsonl'); record=replay(run)
manifest=a.read(run/'manifest.json')
entry={'id':row['task_id'],'file':row['case'],'family':'F1'}
contract={'models':{row['model']:manifest['controller']},'budget':record['limits'],
 'dependencies':{'mcp':manifest['mcp_sdk']},'backoff_s':events[0]['data']['config']['backoff_s'],
 'jitter_s':events[0]['data']['config']['jitter_s'],
 'system_prompt':next(event['data']['messages'][0]['content'] for event in events
   if event['event']=='model_request').split('\nHost authorization: ')[0],
 'tools':next(event['data']['tools'] for event in events if event['event']=='model_request')}
from unittest.mock import patch
from evals import formal_verify
actual_read=formal_verify.read
def manifest_read(path):
 if path==original/'manifest.json': return {'tasks':[entry]}
 return actual_read(path)
row.update(family='F1',repeat=1)
recorded_root=a.read(original/'summary.json')['output']
batch={'source':record['source'],'artifact_root':recorded_root}
before=a.fingerprint(original)
with patch.object(formal_verify,'read',manifest_read):
 verified=a.review(original,row,batch,contract)
 assert verified['verified_grade']['correct_disposition']==1
 assert not verified['decision_changed'] and not verified['model_failures']
 assert verified['protocol']['unverified_attempts']==0
 assert not verified['gate']['unverified']
 changed=copy.deepcopy(row); changed['grade']['checks']['final_state']=False
 with pytest.raises(AssertionError): a.review(original,changed,batch,contract)
assert a.fingerprint(original)==before
'''
    completed = subprocess.run([sys.executable, "-c", script],
                               cwd=PROJECT, timeout=30)
    if completed.returncode == 77:
        import pytest
        pytest.skip("Local historical preflight artifacts are absent; portable checks still apply")
    assert completed.returncode == 0
