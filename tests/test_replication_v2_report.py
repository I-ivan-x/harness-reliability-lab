"""Offline checks for API-clean publication and retained business/content failures."""

import subprocess
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]


def test_review_rejects_every_model_failure_but_keeps_proposal_invalid(tmp_path):
    script = r'''
import copy,sys
from pathlib import Path
from unittest.mock import patch
import pytest
from evals import replication_report as original
from evals.replication_v2 import report
from evals.formal import atomic
root=Path(sys.argv[1]); (root/'run').mkdir()
score={'correct_disposition':0,'checks':{'final_state':False},
       'grading_cost':{'api_calls':0,'api_cost':0,'latency_s':.1}}
detail={'recorded_grade':score,'verified_grade':copy.deepcopy(score),
 'decision_changed':False,'protocol':{'unverified_attempts':0,'unverified_outcomes':0},
 'gate':{'unverified':[],'dispatch_violations':[],'state_violations':[],
         'invalid_allowed':0,'valid_blocked':0}}
row=dict(slot='synthetic-only',task_id='synthetic',repeat=1,path='run',model='B',policy='P0',
         output={'disposition':'SYSTEM_FAILURE'},costs={'input_tokens':10,'output_tokens':2})
with patch.object(original,'review_row',return_value=detail):
 for code in ('HTTP_403','HTTP_429','HTTP_500','TIMEOUT','TRANSPORT_ERROR',
              'INVALID_JSON','INVALID_RESPONSE','UNKNOWN_FUTURE_ERROR',None):
  atomic(root/'run/trace.jsonl',[{'event':'model_failed','data':{'error':{'code':code}}}],
         lines=True)
  with pytest.raises(ValueError,match='stopping rule'):
   report.review(root,row,{}, {})
 atomic(root/'run/trace.jsonl',[{'event':'proposal_invalid',
        'data':{'reason':'invalid_json'}}],lines=True)
 result=report.review(root,row,{}, {})
 assert result['verified_grade']['correct_disposition']==0 and not result['model_failures']
 detail['verified_grade']['grading_cost']['latency_s']=99
 assert report.review(root,row,{}, {})['verified_grade']['correct_disposition']==0
 detail['verified_grade']['checks']['final_state']=True
 with pytest.raises(ValueError,match='grade changed'): report.review(root,row,{}, {})
'''
    subprocess.run([sys.executable, "-c", script, str(tmp_path)],
                   cwd=PROJECT, check=True, timeout=15)


def test_complete_publication_is_separate_strict_and_retains_zero_scores(tmp_path):
    script = r'''
import copy,sys
from pathlib import Path
from unittest.mock import patch
import pytest
from evals import replication_v2 as executor
from evals.replication_v2 import report
from evals import replication_report as original
from evals.acceptance import schedule
from evals.formal import atomic
root=Path(sys.argv[1]); source=root/'synthetic-v2'; source.mkdir()
manifest=report.read(Path('tasks/frozen/manifest.json'))
contract=report.read(Path('tasks/frozen/experiment.json'))
contract['freeze_tag']='harness-replication-v2'
batch={'source':{'commit':'synthetic-only','dirty':False},'frozen_tag':contract['freeze_tag'],
       'user_override':{'monetary_checks':False},'experiment_kind':'synthetic-test-only'}
for name,value in [('manifest.json',manifest),('experiment.json',contract),('batch.json',batch)]:
 atomic(source/name,value)
rows=[]
for slot in schedule(manifest,contract):
 correct=int(slot['policy']=='P2')
 grade={'grader_version':report.GRADER_VERSION,'correct_disposition':correct,'goal_completed':0,
  'false_allow':0,'false_refusal':0,'false_refusal_eligible':0,'duplicate_effect':0,
  'checks':dict.fromkeys(('within_budget','decision_budget','operation_budget','context_budget'),True),
  'grading_cost':{'latency_s':.01,'api_calls':0,'api_cost':0}}
 row={**slot,'run_id':'synthetic-'+slot['slot'],'path':'runs/'+slot['slot'],
  'grade':grade,'output':{'disposition':'COMPLETED' if correct else 'SYSTEM_FAILURE'},
  'costs':{'model_calls':2,'tool_attempts':1,'input_tokens':10,'output_tokens':2,'total_s':1}}
 run=source/row['path']; run.mkdir(parents=True)
 atomic(run/'trace.jsonl',[{'event':'proposal_invalid','data':{}}] if not correct else [],
        lines=True)
 rows.append(row)
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
before=report.fingerprint(source)
with patch.object(executor,'audit',fake_audit),patch.object(original,'review_row',fake_review):
 result=report.run(source)
 output=source.with_name(source.name+'-audit')
 assert report.fingerprint(source)==before and result['input_unchanged']
 assert result['schema']=='replication-audit-v2' and result['runs']==324
 assert result['model_api_calls']==0 and result['model_failure_codes']=={}
 assert result['decision_changes']==[] and len(result['failures'])==216
 assert result['groups']['A-P2']['cohorts']['M']['pass_cubed']==1
 assert result['groups']['B-P1']['cohorts']['C']['pass_cubed']==0
 for model in ('A','B'):
  for cohort in ('M','C'):
   paired=result['paired_p2_minus_p1'][model][cohort]
   assert paired['paired_difference']==1 and paired['wins']==paired['tasks']
   assert paired['task_cluster_bootstrap_95']==[1,1]
 assert len(list((output/'runs').glob('*.json')))==324
 published=report.fingerprint(output)
 with pytest.raises(FileExistsError): report.run(source)
 assert report.fingerprint(output)==published
 for unsafe in (source,source/'nested-audit',root,root/'wrong-name'):
  with pytest.raises(ValueError): report.run(source,unsafe)
 atomic(source/rows[0]['path']/'trace.jsonl',[{'event':'model_failed',
        'data':{'error':{'code':'INVALID_RESPONSE'}}}],lines=True)
 with pytest.raises(ValueError,match='API stopping rule'):
  report.run(source,root/'api-error-audit')
 assert not (root/'api-error-audit').exists()
 atomic(source/rows[0]['path']/'trace.jsonl',[],lines=True)
 def damaging_audit(directory,*,persist=True):
  (directory/'unexpected-write').write_text('synthetic injected defect')
  return batch
 with patch.object(executor,'audit',damaging_audit):
  with pytest.raises(ValueError,match='changed during'):
   report.run(source,root/'damaged-audit')
 assert not (root/'damaged-audit').exists()
'''
    subprocess.run([sys.executable, "-c", script, str(tmp_path)],
                   cwd=PROJECT, check=True, timeout=30)
