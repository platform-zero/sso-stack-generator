#!/usr/bin/env python3
"""Root source worker fixture; mock native installer, never stop a real unit."""
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
spec=importlib.util.spec_from_file_location('p0_rollback_worker_fixture',source)
ops=importlib.util.module_from_spec(spec);spec.loader.exec_module(ops)
with tempfile.TemporaryDirectory(prefix='p0-rollback-worker-',dir='/var/lib/platform-zero')as tmp:
 base=Path(tmp);store=base/'operations';native=base/'native';native.mkdir(mode=0o700)
 prior=native/'releases/first';selected=native/'releases/second';restored=native/'releases/reinstalled'
 for p in (prior,selected,restored):p.mkdir(parents=True)
 installer=selected/'ops/install-podman-bundle.sh';installer.parent.mkdir();installer.write_text('#!/bin/sh\nexit 0\n');installer.chmod(0o755)
 previous_inputs={'bundle.json':'e'*64,'stack.ir.json':'f'*64}
 (prior/'installation-receipt.json').write_text(json.dumps({'inputs':previous_inputs}))
 (prior/'installation-receipt.json').chmod(0o600)
 current=native/'.install-intent.json';current.write_text(json.dumps({'phase':'active','release':str(selected),'previousRelease':str(prior)}));current.chmod(0o600)
 (native/'current').symlink_to(selected)
 bound={'currentJournalSha256':'a'*64,'machineUuid':'92da4d08-6104-4054-b3e5-ef70a2a5fcb4',
        'applyRelease':'b'*64,'previousRelease':str(prior),'selectedRelease':str(selected)}
 data={'controlCheckout':'/root/p0-control','imageInputs':'/root/images.json'}
 apply_id='d'*32;claimed=[];commands=[]
 approver=SimpleNamespace(consume=lambda apply,op:claimed.append((apply,op)))
 def approved(apply,claimed_operation=None):
  assert apply==apply_id
  return bound,data,approver
 def run(argv,**kwargs):
  commands.append(argv)
  if argv[0]=='systemd-run':return SimpleNamespace(returncode=0,stdout='',stderr='')
  assert argv==[str(installer),'--bundle',str(prior),'--control-checkout',data['controlCheckout'],
                '--image-inputs',data['imageInputs'],'--activate']
  assert kwargs['env']['WEBSERVICES_ACTIVATION_ROLLBACK']=='0'
  kwargs['stdout'].write(b'private predecessor installer log marker\n')
  current.write_text(json.dumps({'schemaVersion':1,'phase':'active','release':str(restored),
            'previousRelease':str(selected),'inputs':previous_inputs}));current.chmod(0o600)
  (native/'current').unlink();(native/'current').symlink_to(restored)
  return SimpleNamespace(returncode=0)
 with patch.multiple(ops,OPERATIONS=store,NATIVE_ROOT=native),\
      patch.object(ops,'approved_rollback',side_effect=approved),\
      patch.object(ops,'guard_test_capacity',return_value=None),patch.object(ops.subprocess,'run',side_effect=run):
  queued=ops.queue_rollback(apply_id);opid=queued['operation_id']
  assert queued['state']=='queued'and queued['rolledBack']is False and not claimed
  assert ops.status(opid)['state']=='queued'and str(prior)not in json.dumps(ops.status(opid))
  succeeded=ops.execute_rollback(opid)
  assert succeeded,{'state':ops.status(opid)['state'],'nativeCalls':len(commands),'approvalClaimed':bool(claimed)}
  assert claimed==[(apply_id,opid)]and ops.status(opid)['state']=='native-predecessor-reinstalled'
  assert not (store/'.active.json').exists()and stat.S_IMODE((store/(opid+'.log')).stat().st_mode)==0o600
  try:ops.execute_rollback(opid)
  except (ValueError,FileNotFoundError):pass
  else:raise AssertionError('Synthetic rollback worker replayed')
  with patch.object(ops,'guard_test_capacity',side_effect=ValueError('physical reserve')):
   denied=ops.queue_rollback(apply_id)['operation_id'];assert ops.execute_rollback(denied)is False
   assert ops.status(denied)['state']=='failed-before-approval'and len(claimed)==1
print('typed rollback source worker: single-flight, exact former composition, private status, physical refusal')
