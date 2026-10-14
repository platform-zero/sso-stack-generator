#!/usr/bin/env python3
"""Root-only isolated queue/worker fixture; no real systemd or Podman mutation."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

assert os.geteuid()==0
source=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/p0-host-operations.py'
spec=importlib.util.spec_from_file_location('p0_typed_operations_fixture',source)
ops=importlib.util.module_from_spec(spec);spec.loader.exec_module(ops)
with tempfile.TemporaryDirectory(prefix='p0-typed-operations-test-',dir='/var/lib/platform-zero')as tmp:
    base=Path(tmp);store=base/'operations';native=base/'native';native.mkdir()
    bundle=base/'selected-bundle';bundle.mkdir()
    for name in ('bundle.json','stack.ir.json','source-provenance.json'):(bundle/name).write_text('{}')
    plan='a'*32;release='b'*64
    data={'controlCheckout':'/root/selected-control','imageInputs':'/root/reviewed-image-inputs'}
    consumed=[];commands=[]
    approver=SimpleNamespace(consume=lambda p,r:consumed.append((p,r)))
    def accepted(p):
        assert p in (plan,'c'*32,'d'*32)
        return release,bundle,data,approver
    selected=native/'releases/20261014T120000Z-eeeeeeeeeeee';selected.mkdir(parents=True)
    (native/'current').symlink_to(selected)
    pins={name:hashlib.sha256((bundle/name).read_bytes()).hexdigest() if (bundle/name).is_file() else None
          for name in ops.PIN_FILES}
    private=native/'.install-intent.json';private.write_text(json.dumps({'schemaVersion':1,'phase':'active',
        'release':str(selected),'inputs':pins}));private.chmod(0o600)
    def native_run(command,**kwargs):
        commands.append(command)
        if command[0]=='systemd-run':return SimpleNamespace(returncode=0,stdout='',stderr='')
        assert command==[str(bundle/'ops/install-podman-bundle.sh'),'--bundle',str(bundle),
                         '--control-checkout',data['controlCheckout'],'--image-inputs',data['imageInputs'],'--activate']
        assert kwargs['env']['WEBSERVICES_ACTIVATION_ROLLBACK']=='0'
        kwargs['stdout'].write(b'fixture private log marker; do not send to lane\n')
        return SimpleNamespace(returncode=0)
    with patch.multiple(ops,OPERATIONS=store,NATIVE_ROOT=native),patch.object(ops,'approved_inputs',side_effect=accepted),patch.object(ops.subprocess,'run',side_effect=native_run):
        queued=ops.queue_apply(plan)
        assert queued=={'operation_id':plan,'release':release,'state':'queued','applied':False}
        assert not consumed and len(commands)==1 and commands[0][0]=='systemd-run'
        assert ops.status(plan)['state']=='queued'
        assert stat.S_IMODE((store/(plan+'.json')).stat().st_mode)==0o600
        try:ops.queue_apply('c'*32)
        except ValueError:pass
        else:raise AssertionError('Parallel isolated apply accepted')
        assert len(commands)==1
        assert ops.execute_apply(plan) is True
        assert consumed==[(plan,release)] and ops.status(plan)['state']=='native-installed'
        bound=ops.read_private(store/(plan+'.json'))
        assert bound['selectedRelease']==str(selected)
        assert bound['selectedJournalSha256']==hashlib.sha256(private.read_bytes()).hexdigest()
        assert 'selectedRelease' not in ops.status(plan)
        assert not (store/'.active.json').exists()
        assert stat.S_IMODE((store/(plan+'.log')).stat().st_mode)==0o600
        assert 'private log' not in json.dumps(ops.status(plan))
        assert all(not any('rollback' in token or 'restore' in token for token in command)for command in commands)
        try:ops.execute_apply(plan)
        except (ValueError,FileNotFoundError):pass
        else:raise AssertionError('Executed operation replayed')
        with patch.object(ops,'approved_inputs',side_effect=ValueError('Missing root approval')):
            fail='c'*32
            # Queueing itself must refuse without approval and leave no receipt.
            try:ops.queue_apply(fail)
            except ValueError:pass
            else:raise AssertionError('Unapproved operation was queued')
            assert not (store/(fail+'.json')).exists()
        # A native installer exit-zero is not proof of the approved final pins.
        wrong='c'*32
        old=private.read_bytes();changed=json.loads(old)
        changed['inputs']['site/agent-vm.json']='f'*64
        private.write_text(json.dumps(changed))
        ops.queue_apply(wrong)
        assert ops.execute_apply(wrong) is False
        assert ops.status(wrong)['state']=='failed-after-approval'
        assert consumed[-1]==(wrong,release) and not(store/'.active.json').exists()
        private.write_bytes(old)
        blocked='d'*32
        ops.atomic_private(store/'.active.json',{'schemaVersion':1,'operationId':plan})
        try:ops.queue_apply(blocked)
        except ValueError:pass
        else:raise AssertionError('Interrupted worker lease bypassed')
        assert not(store/(blocked+'.json')).exists()
        (store/'.active.json').unlink()
print('typed apply source: isolated queue, one-use worker, private status, no unapproved/replayed/parallel mutation')
