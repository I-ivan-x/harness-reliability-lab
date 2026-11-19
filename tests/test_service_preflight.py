"""Synthetic preflight orchestration only; no external model requests or run evidence."""

import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = r'''
import asyncio, hashlib, json, sys
from pathlib import Path
from unittest.mock import patch
from evals import service_preflight as p

root, scenario = Path(sys.argv[1]), sys.argv[2]
output = root / 'preflight'
audit = root / 'preflight-audit'
source = {'commit': 'synthetic-test-only', 'dirty': False}
current_source = [source]
calls = []
secret = 'synthetic-private-token-do-not-print'
private_url = 'https://example.invalid/v1/private-path-do-not-print'
configs = {}
for label in ('A', 'B'):
    configs[label] = root / (label + '.env')
    model = p.EXPECTED_MODELS[label]
    if scenario == 'model-mismatch' and label == 'A':
        model = 'custom-sensitive-' + secret
    configs[label].write_text('LAB_MODEL_API_KEY=' + secret + '\nLAB_MODEL_BASE_URL='
        + private_url + '\nLAB_MODEL_NAME=' + model + '\nLAB_MODEL_TOKEN_LIMIT_FIELD='
        + ('max_completion_tokens' if label == 'B' and scenario != 'token-mismatch'
           else 'max_tokens') + '\n', encoding='utf-8')

real_summary = p.configuration_summary
async def config_summary(path, label):
    summary = await real_summary(path, label)
    if scenario == 'configuration-before' and label == 'B':
        configs['A'].write_text(configs['A'].read_text() + '\n# changed before dispatch\n')
    return summary

async def fake_runner(case_path, directory, **kwargs):
    assert kwargs['model'] == 'api' and kwargs['seed'] == 0
    label = directory.name.rsplit('-', 1)[1]
    assert kwargs['model_env'] == configs[label].resolve()
    assert case_path.parent == output / 'cases'
    assert 'frozen' not in str(case_path)
    calls.append(directory.name)
    directory.mkdir()
    events = []
    code = {'403': 'HTTP_403', 'model-error': 'TIMEOUT'}.get(scenario)
    if code:
        events.append({'event': 'model_failed', 'data': {'usage': None, 'error': {
            'code': code, 'layer': 'http' if code == 'HTTP_403' else 'transport',
            'request_id': 'synthetic-request-1'}}})
    events.append({'event': 'run_end', 'data': {}})
    (directory / 'trace.jsonl').write_text(''.join(json.dumps(event) + '\n'
        for event in events), encoding='utf-8')
    (directory / 'original.txt').write_text('Synthetic original, keep unchanged')
    if scenario == 'source':
        current_source[0] = {'commit': 'changed-source', 'dirty': True}
    if scenario == 'configuration':
        configs['A'].write_text(configs['A'].read_text() + '\n# changed during run\n')
    if scenario == 'unsealed':
        raise RuntimeError(secret)
    return {'correct_disposition': 0 if scenario == 'zero' else 1}

def fake_review(case_path, directory, entry, recorded_source, events):
    assert recorded_source == source
    if scenario in ('unsealed', 'audit-error'):
        raise ValueError(secret)
    passed = scenario != 'zero'
    grade = {'correct_disposition': int(passed), 'goal_completed': int(passed)}
    return {'run_id': 'synthetic-' + entry['slot'], 'output': {'disposition': 'COMPLETED'},
        'costs': {'model_calls': 1, 'tool_attempts': 0,
            'input_tokens': None if scenario == '403' else 2, 'output_tokens': 1, 'total_s': .1},
        'recorded_grade': grade, 'verified_grade': grade, 'protocol': {}, 'gate': {},
        'checks': {'synthetic_only': passed}, 'passed': passed}

arguments = ['--output', str(output), '--model-a', str(configs['A']),
             '--model-b', str(configs['B'])]
if scenario in ('existing-output', 'existing-audit'):
    old = output if scenario == 'existing-output' else audit
    old.mkdir()
    (old / 'keep').write_bytes(b'Original preserved')
    before = p.fingerprint(old)
elif scenario == 'dirty':
    current_source[0] = {'commit': 'dirty-source', 'dirty': True}

with patch.multiple(p, run_case=fake_runner, review_run=fake_review,
                    configuration_summary=config_summary,
                    source_revision=lambda: current_source[0]):
    code = p.main(arguments)

if scenario in ('existing-output', 'existing-audit', 'dirty'):
    assert code == 1 and not calls
    if scenario != 'dirty':
        assert p.fingerprint(old) == before
        assert not (output if scenario == 'existing-audit' else audit).exists()
    else:
        assert not output.exists() and not audit.exists()
    raise SystemExit(0)

summary = p.read(output / 'summary.json')
plan = p.read(output / 'plan.json')
expected = [name + '-' + label for name in ('normal', 'retry', 'reproposal', 'lost-receipt')
            for label in ('B', 'A')]
assert len(plan['runs']) == 8
assert [entry['slot'] for entry in plan['runs']] == expected
assert [entry['policy'] for entry in plan['runs']] == ['P1'] * 4 + ['P2'] * 2 + ['P1'] * 2
assert all(entry['seed'] == 0 for entry in plan['runs'])
for entry in plan['runs']:
    payload = (output / entry['case']).read_bytes()
    assert hashlib.sha256(payload).hexdigest() == entry['case_sha256']
    assert json.loads(payload)['task_input']['task_id'] == entry['task_id']
assert audit.parent == output.parent
assert p.read(audit / 'summary.json')['model_api_calls'] == 0
serialized = '\n'.join(path.read_text(encoding='utf-8') for directory in (output, audit)
                       for path in directory.rglob('*') if path.is_file())
assert secret not in serialized and private_url not in serialized
assert 'private-path-do-not-print' not in serialized
if scenario == 'valid':
    assert code == 0 and calls == expected
    assert summary['status'] == 'passed' and summary['attempted'] == summary['passed'] == 8
    assert summary['costs']['model_calls'] == 8
else:
    assert code == 1 and summary['status'] == 'stopped'
    if scenario in ('model-mismatch', 'token-mismatch', 'configuration-before'):
        assert calls == []
        if scenario == 'model-mismatch':
            assert plan['configurations']['A']['model_sha256']
            assert 'model' not in plan['configurations']['A']
        assert summary['attempted'] == 0
    else:
        assert calls == ['normal-B'] and summary['attempted'] == 1
        assert summary['runs'][0]['status'] == 'failed'
        assert (output / 'runs/normal-B/original.txt').read_text() == (
            'Synthetic original, keep unchanged')
        assert (audit / 'normal-B.json').is_file()
    not_run = 8 - summary['attempted']
    assert sum(row['status'] == 'not_run' for row in summary['runs']) == not_run
    assert all(row['reason'] == summary['stop_reason'] for row in summary['runs']
               if row['status'] == 'not_run')
    expected_reason = {'403': 'HTTP_403', 'model-error': 'TIMEOUT',
        'zero': 'run_checks_failed', 'unsealed': 'unsealed_or_audit_error',
        'audit-error': 'unsealed_or_audit_error', 'source': 'source_changed',
        'model-mismatch': 'CONFIG_MODEL_MISMATCH', 'token-mismatch': 'CONFIG_TOKEN_LIMIT_MISMATCH',
        'configuration': 'configuration_changed',
        'configuration-before': 'configuration_changed'}[scenario]
    assert summary['stop_reason'] == expected_reason
    if scenario == '403':
        row = p.journal(output / 'results.jsonl')[0]
        assert row['model_failures'][0]['request_id'] == 'synthetic-request-1'
        assert summary['costs']['input_tokens'] is None
'''


@pytest.mark.parametrize("scenario", [
    "valid", "403", "model-error", "zero", "unsealed", "audit-error", "source",
    "existing-output", "existing-audit", "model-mismatch", "dirty",
    "configuration", "configuration-before", "token-mismatch",
])
def test_fixed_preflight_stops_and_preserves_evidence(tmp_path, scenario):
    subprocess.run([sys.executable, "-c", SCRIPT, str(tmp_path), scenario],
                   cwd=Path(__file__).resolve().parents[1], check=True, timeout=20)


def test_independent_review_rejects_changed_grade_and_wrong_branch(tmp_path):
    script = r'''
import json,sys
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch
from evals import service_preflight as p
root=Path(sys.argv[1]); run=root/'run'; run.mkdir()
source={'commit':'synthetic-test-only','dirty':False}
case={'task_input':{'task_id':'synthetic-task','target_ref':'synthetic-target'},
      'oracle':{'expected_params':{'queue':'ops','expected_revision':1,'priority':'normal'}}}
p.save(root/'case.json',case)
p.save(run/'manifest.json',{'task_input':case['task_input']})
entry={'scenario':'normal','policy':'P1','case_sha256':
       p.hashlib.sha256((root/'case.json').read_bytes()).hexdigest()}
grade={'grading_cost':{'latency_s':.1,'api_calls':0,'api_cost':0},
       'correct_disposition':1,'goal_completed':1,'duplicate_effect':0,'false_allow':0}
p.save(run/'grade.json',grade)
record={'run_id':'synthetic','operation_id':'synthetic:write-0','source':source,
        'task_id':'synthetic-task','target_ref':'synthetic-target',
        'measurement_valid':True,'terminated_quiescent':True,'limits':asdict(p.Budget()),
        'policy':'P1','output':{},'costs':{},'counters':{'repair_used':False,
        'operation_attempts':{'initial_read':1,'write-0':1,'refresh_read':0}}}
events=[{'event':'run_start','data':{'config':{'seed':0}}},
        {'event':'tool_attempt','data':{'operation':'write-0',
         'arguments':case['oracle']['expected_params'],
         'envelope':{'operation_id':'synthetic:write-0','idempotency_key':'synthetic:write-0'}}}]
protocol={'unverified_attempts':0,'unverified_outcomes':0}
gate={'dispatch_violations':[],'state_violations':[],'unverified':[],
      'invalid_allowed':0,'valid_blocked':0}
verified={**grade,'grading_cost':{**grade['grading_cost'],'latency_s':99}}
with patch.multiple(p,replay=lambda path:record,regrade_case=lambda *args:verified,
                    verify_protocol=lambda e:protocol,audit_gate=lambda e:gate):
 detail=p.review_run(root/'case.json',run,entry,source,events)
 assert detail['passed'] and detail['checks']['input_unchanged']
 verified['goal_completed']=0
 detail=p.review_run(root/'case.json',run,entry,source,events)
 assert not detail['passed'] and not detail['checks']['recorded_grade_matches']
 verified['goal_completed']=1
 record['counters']['operation_attempts']['initial_read']=2
 detail=p.review_run(root/'case.json',run,entry,source,events)
 assert not detail['passed'] and not detail['checks']['normal_path']
 gate['unverified'].append({'reason':'synthetic_missing_evidence'})
 detail=p.review_run(root/'case.json',run,entry,source,events)
 assert not detail['checks']['gate_complete']
 gate['unverified'].clear()
 gate['valid_blocked']=1
 detail=p.review_run(root/'case.json',run,entry,source,events)
 assert not detail['checks']['gate_complete']
 record['task_id']='wrong-task'
 detail=p.review_run(root/'case.json',run,entry,source,events)
 assert not detail['checks']['task_identity']
 with (root/'case.json').open('a') as stream: stream.write(' ')
 detail=p.review_run(root/'case.json',run,entry,source,events)
 assert not detail['checks']['case_snapshot_matches']
'''
    subprocess.run([sys.executable, "-c", script, str(tmp_path)],
                   cwd=Path(__file__).resolve().parents[1], check=True, timeout=20)
