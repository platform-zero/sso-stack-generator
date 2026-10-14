#!/usr/bin/env python3
"""Root synthetic test queue/worker fixture; never execute a real test runner."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

assert os.geteuid()==0
source=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/p0-host-operations.py'
spec=importlib.util.spec_from_file_location('p0_test_worker_fixture',source)
ops=importlib.util.module_from_spec(spec);spec.loader.exec_module(ops)
with tempfile.TemporaryDirectory(prefix='p0-test-worker-fixture-',dir='/var/lib/platform-zero')as tmp:
    base=Path(tmp);store=base/'operations';release=base/'native-release';release.mkdir()
    runner=release/'build/stack.containers/test-runner/run-tests.sh';runner.parent.mkdir(parents=True)
    runner.write_text('#!/bin/sh\nexit 0\n');runner.chmod(0o755)
    bound={'suite':'ts-unit','release':str(release),'journalSha256':'b'*64,'machineUuid':'92da4d08-6104-4054-b3e5-ef70a2a5fcb4'}
    claimed=[];commands=[]
    approver=SimpleNamespace(consume=lambda suite,opid:claimed.append((suite,opid)))
    def approved(suite,claimed_operation=None):
        assert suite=='ts-unit'
        return bound,runner,approver
    def run(command,**kwargs):
        commands.append(command)
        if command[0]=='systemd-run':return SimpleNamespace(returncode=0,stdout='',stderr='')
        assert command==[str(runner),'ts-unit']
        kwargs['stdout'].write(b'private synthetic test log marker\n')
        return SimpleNamespace(returncode=0)
    with patch.multiple(ops,OPERATIONS=store),patch.object(ops,'approved_test',side_effect=approved),\
         patch.object(ops,'guard_test_capacity',return_value=None),patch.object(ops.subprocess,'run',side_effect=run):
        queued=ops.queue_test('ts-unit');operation=queued['operation_id']
        assert queued['state']=='queued'and not queued['testPassed']and len(operation)==32
        assert not claimed and ops.status(operation)['state']=='queued'
        assert ops.status(operation)['release']=='b'*64 and str(release)not in json.dumps(ops.status(operation))
        assert ops.execute_test(operation) is True
        assert claimed==[('ts-unit',operation)]and ops.status(operation)['state']=='synthetic-test-passed'
        assert not(store/'.active.json').exists()
        assert stat.S_IMODE((store/(operation+'.log')).stat().st_mode)==0o600
        assert 'private synthetic test' not in json.dumps(ops.status(operation))
        try:ops.execute_test(operation)
        except (ValueError,FileNotFoundError):pass
        else:raise AssertionError('Synthetic test worker replayed')
        try:ops.queue_test('android-apps')
        except (ValueError,AssertionError):pass
        else:raise AssertionError('Unreviewed Android suite queued')
        with patch.object(ops,'guard_test_capacity',side_effect=ValueError('physical reserve')):
            refused=ops.queue_test('ts-unit')['operation_id']
            assert ops.execute_test(refused)is False
            assert ops.status(refused)['state']=='failed-before-approval'
            assert len(claimed)==1 and not(store/'.active.json').exists()
print('typed isolated ts-unit source: single-use synthetic worker, private status, capacity refusal')
