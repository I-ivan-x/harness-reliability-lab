"""Offline report publication/immutability checks; these rows are synthetic fixtures."""

import subprocess
import sys
from pathlib import Path


def test_separate_output_preserves_input_and_detects_accidental_writes(tmp_path):
    script = r'''
import copy,json,sys
from pathlib import Path
from unittest.mock import patch
import pytest
from evals import evidence_audit as a
from evals.formal import atomic
root=Path(sys.argv[1]); source=root/'input'; source.mkdir()
atomic(source/'experiment.json',{})
atomic(source/'results.jsonl',[{'path':'original/run','slot':'synthetic-only',
    'model':'A','policy':'P2'}],lines=True)
baseline={'sources':{'original':{}},'experiment_kind':'synthetic-publication-test'}
score={'false_allow':0,'false_refusal':0,'false_refusal_eligible':1,
       'correct_disposition':1,'goal_completed':1,'duplicate_effect':0,
       'checks':dict.fromkeys(('within_budget','decision_budget','operation_budget',
                               'context_budget'),True)}
gate=dict.fromkeys(('valid_allowed','valid_blocked','invalid_allowed','invalid_blocked',
    'valid_proposals','invalid_proposals','pre_gate_protocol_failures',
    'provider_failures','content_only_responses','content_parse_failures'),0)
gate.update(valid_allowed=2,valid_proposals=2,dispatch_violations=[],state_violations=[],
            unverified=[])
detail={'run_id':'synthetic-run','recorded_grade':score,'verified_grade':score,
        'decision_changed':False,'goal_eligible':True,'protocol':{'requests':2},'gate':gate}
before=a.fingerprint(source)
def fake_audit(directory,*,persist=True):
 assert directory==source.resolve() and persist is False
 return baseline
with patch.object(a,'audit',fake_audit),patch.object(a,'review_row',return_value=detail):
 output=root/'published'
 result=a.run(source,output)
 assert a.fingerprint(source)==before and result['input_unchanged']
 assert result['overall']['gate']['rates']['invalid_blocked_rate'] is None
 assert result['overall']['uncompleted_completable_goals']==0
 assert (output/'complete.json').is_file() and len(a.journal(output/'runs.jsonl'))==1
 published=a.fingerprint(output)
 with pytest.raises(FileExistsError): a.run(source,output)
 assert a.fingerprint(output)==published
 for unsafe in (source,source/'nested',root):
  with pytest.raises(ValueError): a.run(source,unsafe)
 incomplete=copy.deepcopy(detail); incomplete['gate']['unverified']=[{'reason':'missing'}]
 with patch.object(a,'review_row',return_value=incomplete):
  with pytest.raises(ValueError,match='incomplete'): a.run(source,root/'incomplete')
 assert not (root/'incomplete').exists()
def damaging_audit(directory,*,persist=True):
 assert persist is False
 (directory/'unexpected-write').write_text('synthetic injected bug')
 return baseline
with patch.object(a,'audit',damaging_audit),patch.object(a,'review_row',return_value=detail):
 with pytest.raises(ValueError,match='changed during'): a.run(source,root/'damaged')
assert not (root/'damaged').exists()
'''
    subprocess.run([sys.executable, "-c", script, str(tmp_path)],
                   cwd=Path(__file__).resolve().parents[1], check=True, timeout=20)
