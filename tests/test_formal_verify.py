"""Real-MCP evidence audit rejects changed pairing inputs without rejecting valid failures."""

import subprocess
import sys
from pathlib import Path


def test_actual_trial_audit_and_tampered_contracts(tmp_path):
    script = r'''
import asyncio,copy,json,sys
from pathlib import Path
from evals.development import read,save
from evals.formal_verify import verify_row
from evals.run_case import run_case
from harness_lab.trace import replay
root=Path(sys.argv[1]); root.mkdir()
case=read(Path('tasks/dev/normal.json')); save(root/'case.json',case)
entry={'id':case['task_input']['task_id'],'file':'case.json','family':'F1'}
save(root/'manifest.json',{'tasks':[entry]})
score=asyncio.run(run_case(root/'case.json',root/'run',seed=37))
record=replay(root/'run'); saved=read(root/'run/manifest.json')
events=[json.loads(line) for line in
        (root/'run/trace.jsonl').read_text(encoding='utf-8').splitlines()]
first=next(event['data'] for event in events if event['event']=='model_request')
contract={'models':{'A':saved['controller']},'dependencies':{'mcp':saved['mcp_sdk']},
 'budget':record['limits'],'backoff_s':.02,'jitter_s':.01,
 'system_prompt':first['messages'][0]['content'].split('\nHost authorization: ')[0],
 'tools':first['tools']}
row={'path':'run','case':'case.json','task_id':entry['id'],'family':'F1','model':'A',
 'policy':'P1','seed':37,'run_id':record['run_id'],'output':record['output'],
 'costs':record['costs'],'grade':score}
batch={'source':record['source'],'artifact_root':str(root.resolve())}
assert verify_row(root,row,batch,contract)[1]['correct_disposition']==1
assert not (root/'run/audit-grade.json').exists()
from evals.evidence_audit import fingerprint,review_row
before_review=fingerprint(root)
detail=review_row(root,row,batch,contract)
assert detail['goal_eligible'] and not detail['decision_changed']
assert detail['protocol']['requests']==detail['protocol']['attempts']==2
assert detail['gate']['valid_allowed']==2 and detail['gate']['invalid_proposals']==0
assert fingerprint(root)==before_review
def rejected(r=row,b=batch,c=contract):
 try: verify_row(root,r,b,c)
 except (AssertionError,KeyError): return
 raise AssertionError('tampered evidence accepted')
for key,value in [('seed',38),('policy','P2'),('run_id','other'),('family','F3')]:
 changed=copy.deepcopy(row); changed[key]=value; rejected(r=changed)
for key,value in [('system_prompt','changed'),('tools',[]),('backoff_s',.03)]:
 changed=copy.deepcopy(contract); changed[key]=value; rejected(c=changed)
changed=copy.deepcopy(contract); changed['models']['A']['model']='other'; rejected(c=changed)
changed=copy.deepcopy(contract); changed['budget']['tool_attempts']=9; rejected(c=changed)
rejected(b={**batch,'source':{'commit':'other','dirty':False}})
changed=copy.deepcopy(row); changed['grade']['grading_cost']['api_calls']=1; rejected(r=changed)
server=read(root/'run/private-server.json'); altered=copy.deepcopy(server)
altered['fault']={'kind':'temporary_unavailable','stage':'write-0','attempts':[1]}
save(root/'run/private-server.json',altered); rejected()
save(root/'run/private-server.json',server)
changed=copy.deepcopy(row); changed['grade']['grading_cost']['latency_s']=999
assert verify_row(root,changed,batch,contract)[1]['correct_disposition']==1
import shutil
relocated=root.with_name('relocated'); shutil.copytree(root,relocated)
assert verify_row(relocated,row,batch,contract)[1]['correct_disposition']==1
# Historical diagnostics stay untouched while a new grader can add checks/version.
legacy=copy.deepcopy(score); legacy.pop('grader_version',None)
legacy['checks'].pop('final_state',None)
save(root/'run/grade.json',legacy)
legacy_row={**row,'grade':legacy}
before=(root/'run/grade.json').read_bytes()
assert verify_row(root,legacy_row,batch,contract)[1]['correct_disposition']==1
assert (root/'run/grade.json').read_bytes()==before
bad=copy.deepcopy(legacy); bad['checks']['within_budget']=False
save(root/'run/grade.json',bad)
rejected(r={**row,'grade':bad})
save(root/'run/grade.json',score)
'''
    subprocess.run([sys.executable, "-c", script, str(tmp_path / "batch")],
                   cwd=Path(__file__).parents[1], check=True, timeout=30)


def test_valid_zero_score_and_unknown_usage_remain_auditable(tmp_path):
    script = r'''
import asyncio,dataclasses,json,sys
from pathlib import Path
from evals.development import read,save
from evals.formal_verify import verify_row
from evals.run_case import run_case
from harness_lab import models
from harness_lab.trace import replay
class UnknownUsage(models.ScriptedController):
 async def propose(self,*args,**kwargs):
  return dataclasses.replace(await super().propose(*args,**kwargs),usage=None)
models.ScriptedController=UnknownUsage
for name,expected in [('normal',1),('malformed-read',0)]:
 root=Path(sys.argv[1])/name; root.mkdir()
 case=read(Path('tasks/dev')/(name+'.json')); save(root/'case.json',case)
 entry={'id':case['task_input']['task_id'],'file':'case.json','family':'F1'}
 save(root/'manifest.json',{'tasks':[entry]})
 score=asyncio.run(run_case(root/'case.json',root/'run'))
 record=replay(root/'run'); saved=read(root/'run/manifest.json')
 events=[json.loads(line) for line in
         (root/'run/trace.jsonl').read_text(encoding='utf-8').splitlines()]
 first=next(event['data'] for event in events if event['event']=='model_request')
 contract={'models':{'A':saved['controller']},'dependencies':{'mcp':saved['mcp_sdk']},
  'budget':record['limits'],'backoff_s':.02,'jitter_s':.01,'tools':first['tools'],
  'system_prompt':first['messages'][0]['content'].split('\nHost authorization: ')[0]}
 row={'path':'run','case':'case.json','task_id':entry['id'],'family':'F1','model':'A',
  'policy':'P1','seed':0,'run_id':record['run_id'],'output':record['output'],
  'costs':record['costs'],'grade':score}
 audited=verify_row(root,row,{'source':record['source'],
                            'artifact_root':str(root.resolve())},contract)[1]
 assert audited['measurement_valid'] and audited['correct_disposition']==expected
 assert record['costs']['input_tokens'] is None
 assert record['costs']['output_tokens'] is None
'''
    subprocess.run([sys.executable, "-c", script, str(tmp_path)],
                   cwd=Path(__file__).parents[1], check=True, timeout=45)
