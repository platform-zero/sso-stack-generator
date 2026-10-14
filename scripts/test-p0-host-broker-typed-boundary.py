#!/usr/bin/env python3
"""Fail-closed current broker/typed Worklane compatibility and secret boundary."""
import importlib.util
import json
from pathlib import Path
from unittest.mock import patch

source = Path(__file__).resolve().parents[1] / 'runtime-generator/podman-ops/p0-host-broker.py'
spec = importlib.util.spec_from_file_location('p0_typed_broker_boundary', source)
assert spec and spec.loader
broker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(broker)

for action in ('stage', 'preflight', 'snapshot', 'activate', 'restore', 'gc', 'finalize-access',
               'plan', 'apply', 'rollback', 'test'):
    response = broker.handle(json.dumps({'version': 1, 'action': action}).encode())
    assert response['ok'] is False and response['error'] == 'unsupported action: ' + action
    assert action not in broker.ACTIONS
assert broker.handle(b'{"version": 1, "action": "status", "action": "gc"}')['ok'] is False
assert broker.handle(b'{"version": true, "action": "status"}')['ok'] is False
assert broker.handle(json.dumps({'version': 1, 'action': 'operation-status', 'operation_id': 'a'*32}).encode()) == {
    'ok': False, 'error': 'no approved operation with this identifier'}
assert broker.handle(json.dumps({'version': 1, 'action': 'operation-status', 'operation_id': '../'}).encode())['ok'] is False

class Result:
    returncode = 0
    stdout = '\n'.join(json.dumps({'MESSAGE': msg, 'PRIORITY': '3'}) for msg in (
        'password=private-production-value', 'Bearer private-auth-value')) + '\n'
    stderr = 'password=also-private'

with patch.object(broker, 'run', return_value=Result()):
    response = broker.handle(json.dumps({'version': 1, 'action': 'logs',
        'unit': 'webservices-caddy.service'}).encode())
    assert response['ok'] is True and response['result']['recordCount'] == 2
    output = json.dumps(response)
    assert 'private-production-value' not in output and 'private-auth-value' not in output
    assert 'also-private' not in output and 'MESSAGE' not in output
    assert all(len(item['messageSha256']) == 64 for item in response['result']['records'])

class Failure:
    returncode = 7
    stdout = ''
    stderr = 'password=private-production-value'
with patch.object(broker.subprocess, 'run', return_value=Failure()):
    try:
        broker.run('secret-command', '--password=private-production-value')
    except broker.RequestError as error:
        assert 'private-production-value' not in str(error) and 'secret-command' not in str(error)
    else:
        raise AssertionError('native failure unexpectedly accepted')
print('typed broker socket boundary: legacy mutations closed, missing approval denied, journal secret suppressed')
