#!/usr/bin/env python3
"""Fail-closed current broker/typed Worklane compatibility and secret boundary."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from unittest.mock import patch

source = Path(__file__).resolve().parents[1] / 'runtime-generator/podman-ops/p0-host-broker.py'
spec = importlib.util.spec_from_file_location('p0_typed_broker_boundary', source)
assert spec and spec.loader
broker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(broker)

for action in ('stage', 'preflight', 'snapshot', 'activate', 'restore', 'gc', 'finalize-access',
               'apply', 'rollback', 'test'):
    response = broker.handle(json.dumps({'version': 1, 'action': action}).encode())
    assert response['ok'] is False and response['error'] == 'unsupported action: ' + action
    assert action not in broker.ACTIONS
assert broker.handle(b'{"version": 1, "action": "status", "action": "gc"}')['ok'] is False
assert broker.handle(b'{"version": true, "action": "status"}')['ok'] is False
assert broker.handle(json.dumps({'version': 1, 'action': 'operation-status', 'operation_id': 'a'*32}).encode()) == {
    'ok': False, 'error': 'no approved operation with this identifier'}
assert broker.handle(json.dumps({'version': 1, 'action': 'operation-status', 'operation_id': '../'}).encode())['ok'] is False

with tempfile.TemporaryDirectory() as d:
    root = Path(d)
    workspace = root / 'stack_lab';workspace.mkdir(mode=0o700)
    bundle = workspace / 'selected';bundle.mkdir()
    sources = {'bundle.json': {'backend':'podman'}, 'stack.ir.json': {},
               'podman-domains.json': {'domains':[{'name':'apps','user':'webservices-apps'}]},
               'podman-loopback-endpoints.json': {}}
    for name, value in sources.items(): (bundle/name).write_text(json.dumps(value))
    (bundle/'ops').mkdir()
    (bundle/'ops/platform-zero.nft').write_text('table inet platform_zero {\n policy accept\n}\n')
    (bundle/'ops/install-podman-bundle.sh').write_text('#!/bin/sh\n')
    digest = broker.tree_sha256(bundle)
    with patch.multiple(broker, STACK_ROOT=workspace, INCOMING=root/'incoming', PLANS=root/'plans'):
        response=broker.handle(json.dumps({'version':1,'action':'plan','bundle':str(bundle),'sha256':digest}).encode())
        assert response['ok'] is True and response['result']['release']==digest
        assert response['result']['state']=='awaiting-independent-root-approval'
        assert response['result']['approved'] is False and response['result']['applied'] is False
        plan_id=response['result']['plan_id'];assert len(plan_id)==32
        assert (root/'plans'/f'{plan_id}.json').stat().st_mode&0o777==0o600
        assert broker.handle(json.dumps({'version':1,'action':'apply','plan_id':plan_id}).encode())['ok'] is False
        again=broker.handle(json.dumps({'version':1,'action':'plan','bundle':str(bundle),'sha256':digest}).encode())
        assert again['ok'] is True and again['result']['plan_id']!=plan_id
        bad=bundle/'quadlet';bad.symlink_to(root)
        denied=broker.handle(json.dumps({'version':1,'action':'plan','bundle':str(bundle),'sha256':digest}).encode())
        assert denied['ok'] is False
        bad.unlink()
        staged=root/'incoming'/digest; (staged/'bundle.json').write_text('owner authored changed file')
        denied=broker.handle(json.dumps({'version':1,'action':'plan','bundle':str(bundle),'sha256':digest}).encode())
        assert denied['ok'] is False and (staged/'bundle.json').read_text()=='owner authored changed file'

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
    assert response['result']['records'] == [{'priority': '3'}, {'priority': '3'}]
    assert 'messageSha256' not in output

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
