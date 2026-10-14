#!/usr/bin/env python3
"""Root synthetic 60/95 same-composition rollback authority fixture; no services."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from unittest.mock import patch

assert os.geteuid()==0
base_source=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops'
def loaded(name):
 p=base_source/name;s=importlib.util.spec_from_file_location(name.replace('-','_'),p)
 module=importlib.util.module_from_spec(s);s.loader.exec_module(module);return module
rollback=loaded('p0-host-rollback-approve.py');identity=loaded('p0-host-test-approve.py')
with tempfile.TemporaryDirectory(prefix='p0-rollback-authority-',dir='/var/lib/platform-zero')as tmp:
 base=Path(tmp);native=base/'native';native.mkdir(mode=0o700)
 operations=base/'operations';operations.mkdir(mode=0o700)
 old=native/'releases/old-pinned';current=native/'releases/new-pinned'
 for p in (old,current):p.mkdir(parents=True)
 shared={'bundle.json':'{}','stack.ir.json':json.dumps({'services':{'service'+str(i):{}for i in range(95)}}),
   'podman-domains.json':'{"domains":[]}',
   'site/agent-vm.json':'{}','site/agent-vm.provenance.json':'{}',
   'site/manifest.json':json.dumps({'modules':['module'+str(i)for i in range(60)]}),
   'site/components.lock.json':'{}','site/global.settings/registry-image-ids.json':'{}',
   'site/global.settings/webservices.sops.json':'encrypted-fixture-input'}
 for root in (old,current):
  contents=dict(shared,**{'source-provenance.json':json.dumps({'siteCommit':'1'*40,
                     'generatorCommit':('2'if root==old else '3')*40,
                     'generatorDirty':False,'siteDirty':False})})
  for name,value in contents.items():
   file=root/name;file.parent.mkdir(parents=True,exist_ok=True);file.write_text(value)
  test=root/'build/stack.containers/test-runner/run-tests.sh';test.parent.mkdir(parents=True)
  test.write_text('#!/bin/sh\nexit 0\n');test.chmod(0o755)
 installer=current/'ops/install-podman-bundle.sh';installer.parent.mkdir()
 installer.write_text('#!/bin/sh\nexit 0\n');installer.chmod(0o755)
 def pins(root):return {name:hashlib.sha256((root/name).read_bytes()).hexdigest()for name in rollback.PINNED}
 old_receipt={'schemaVersion':1,'phase':'active','release':str(old),'inputs':pins(old)}
 current_receipt={'schemaVersion':1,'phase':'active','release':str(current),
                  'previousRelease':str(old),'inputs':pins(current)}
 def private(path,value):
  path.write_text(json.dumps(value,sort_keys=True)+'\n');path.chmod(0o600)
 private(old/'installation-receipt.json',old_receipt)
 private(current/'installation-receipt.json',current_receipt)
 private(native/'.install-intent.json',current_receipt)
 (native/'current').symlink_to(current)
 apply_id='a'*32;private(operations/(apply_id+'.json'),{'schemaVersion':1,'operationId':apply_id,
                   'kind':'apply','state':'native-installed','release':'b'*64,
                   'selectedRelease':str(current),
                   'selectedJournalSha256':hashlib.sha256((native/'.install-intent.json').read_bytes()).hexdigest()})
 machine='92da4d08-6104-4054-b3e5-ef70a2a5fcb4';dmi=base/'dmi';dmi.write_text(machine+'\n')
 marker=base/'marker';private(marker,{'schemaVersion':1,'scope':'isolated-synthetic','machineUuid':machine})
 approvals=base/'approvals'
 with patch.multiple(identity,NATIVE=native,MARKER=marker,DMI=dmi),\
      patch.multiple(rollback,ROOT=native,OPERATIONS=operations,APPROVALS=approvals),\
      patch.object(rollback,'trust',return_value=identity):
  try:rollback.approve(apply_id,False,now=100)
  except ValueError:pass
  else:raise AssertionError('Unreviewed rollback accepted')
  bound=rollback.review_selection(apply_id)
  assert bound['previousRelease']==str(old)and bound['selectedRelease']==str(current)
  ticket=rollback.approve(apply_id,True,now=100)
  assert ticket['expiresAt']==700 and rollback.review(apply_id,now=101)==bound
  changed=old/'stack.ir.json';prior=changed.read_bytes();changed.write_bytes(b'{}')
  try:rollback.review(apply_id,now=101)
  except ValueError:pass
  else:raise AssertionError('Mutated predecessor pin passed rollback')
  changed.write_bytes(prior)
  assert rollback.consume(apply_id,'c'*32,now=101)==bound
  assert rollback.review(apply_id,now=101,claimed_operation='c'*32)==bound
  try:rollback.consume(apply_id,'d'*32,now=102)
  except FileNotFoundError:pass
  else:raise AssertionError('Rollback receipt replayed')
  try:rollback.review(apply_id,now=701,claimed_operation='c'*32)
  except ValueError:pass
  else:raise AssertionError('Expired rollback claim accepted')
  marker.write_text(json.dumps({'schemaVersion':1,'scope':'production','machineUuid':machine}))
  try:rollback.review(apply_id,now=101,claimed_operation='c'*32)
  except ValueError:pass
  else:raise AssertionError('Production marker accepted for synthetic rollback')
print('typed rollback source authority: same 60/95 pins, predecessor receipt, one-use synthetic claim')
