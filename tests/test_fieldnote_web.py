import asyncio
import json
import subprocess
from unittest.mock import patch

from fieldnote import antigravity_diagnose as cli
from fieldnote import app as web


def test_web_analysis_uses_collected_evidence_and_model_answer(tmp_path):
    evidence = {'os': 'Linux', 'network': {'wifi_connections': [
        {'interface': 'test0', 'ssid': 'ExampleNet', 'connection': 'ExampleNet'}]}}
    seen = {}

    async def fake_ask(model, instruction, payload):
        seen['payload'] = payload
        return 'The active Wi-Fi is ExampleNet.'

    session = {'id': 'sample', 'status': 'running', 'events': [], 'analysis': None,
               'evidence': None, 'commands': [], 'error': None, 'audit_error': None}
    with patch.object(web, 'collect_system', return_value=evidence), \
         patch.object(web, 'ask', side_effect=fake_ask), \
         patch.object(web, 'AUDIT', tmp_path / 'audit.jsonl'):
        asyncio.run(web.work(session, web.DiagnosisRequest(complaint='Which Wi-Fi am I connected to?')))

    assert session['status'] == 'complete'
    assert session['analysis'] == 'The active Wi-Fi is ExampleNet.'
    assert seen['payload']['evidence']['network']['wifi_connections'][0]['ssid'] == 'ExampleNet'


def test_web_never_marks_empty_model_answer_complete(tmp_path):
    async def empty_ask(*args):
        return ''

    session = {'id': 'sample', 'status': 'running', 'events': [], 'analysis': None,
               'evidence': None, 'commands': [], 'error': None, 'audit_error': None}
    with patch.object(web, 'collect_system', return_value={'os': 'Linux', 'network': {}}), \
         patch.object(web, 'ask', side_effect=empty_ask), \
         patch.object(web, 'AUDIT', tmp_path / 'audit.jsonl'):
        asyncio.run(web.work(session, web.DiagnosisRequest(complaint='Why is Wi-Fi slow?')))

    assert session['status'] == 'error'
    assert 'empty analysis' in session['error']


def test_cli_retries_empty_success_response():
    responses = iter([
        subprocess.CompletedProcess([], 0, json.dumps({'status': 'SUCCESS', 'response': ''}), ''),
        subprocess.CompletedProcess([], 0, json.dumps({'status': 'SUCCESS', 'response': 'Found it.'}), ''),
    ])

    with patch.object(cli.shutil, 'which', return_value='/fake/agy'), \
         patch.object(cli.subprocess, 'run', side_effect=lambda *a, **kw: next(responses)) as run:
        result = asyncio.run(cli.ask('sample-model', 'Analyze evidence.', {'complaint': 'test'}))

    assert result == 'Found it.'
    assert run.call_count == 2
