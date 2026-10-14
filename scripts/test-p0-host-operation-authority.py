#!/usr/bin/env python3
"""Root fixture: real approval and binder converge before an apply may queue."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from unittest.mock import patch

assert os.geteuid()==0
ops_dir=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops'
def source(name):
    spec=importlib.util.spec_from_file_location('p0_fixture_'+name,ops_dir/name)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module
broker=source('p0-host-broker.py');binder=source('p0-host-install-inputs.py')
approver=source('p0-host-approve.py');operations=source('p0-host-operations.py')
with tempfile.TemporaryDirectory(prefix='p0-authorized-apply-test-',dir='/var/lib/platform-zero')as tmp:
    root=Path(tmp);incoming=root/'incoming';incoming.mkdir(mode=0o700)
    control=root/'control';control.mkdir(mode=0o700)
    subprocess.run(['git','-C',str(control),'init','-q'],check=True,capture_output=True)
    (control/'ops').mkdir();(control/'ops/agent_vm_spec.py').write_text('# reviewed fixture\n')
    subprocess.run(['git','-C',str(control),'add','ops/agent_vm_spec.py'],check=True,capture_output=True)
    subprocess.run(['git','-C',str(control),'-c','user.name=Fixture','-c','user.email=fixture@example.invalid',
                    'commit','-qm','Fixture'],check=True,capture_output=True)
    commit=subprocess.check_output(['git','-C',str(control),'rev-parse','HEAD'],text=True).strip()
    candidate=root/'candidate';(candidate/'ops').mkdir(parents=True);(candidate/'site').mkdir()
    fields={'bundle.json':{'backend':'podman'},'stack.ir.json':{},
            'podman-domains.json':{'domains':[{'name':'apps','user':'webservices-apps'}]},
            'podman-loopback-endpoints.json':{},
            'source-provenance.json':{'generatorCommit':'a'*40,'siteCommit':'b'*40,
                                      'generatorDirty':False,'siteDirty':False}}
    for name,value in fields.items():(candidate/name).write_text(json.dumps(value))
    (candidate/'ops/platform-zero.nft').write_text('table inet platform_zero {\n policy accept\n}\n')
    (candidate/'ops/install-podman-bundle.sh').write_text('#!/bin/sh\nexit 0\n')
    (candidate/'site/manifest.json').write_text(json.dumps({'site':'latium','agentVmSpec':'agent-vm.json'}))
    vm=json.dumps({'runtime':{'controlCommit':commit}}).encode()
    (candidate/'site/agent-vm.json').write_bytes(vm)
    (candidate/'site/agent-vm.provenance.json').write_text(json.dumps({'schemaVersion':1,
        'path':'agent-vm.json','sha256':hashlib.sha256(vm).hexdigest(),'controlCommit':commit}))
    release=broker.tree_sha256(candidate);bundle=incoming/release;shutil.copytree(candidate,bundle)
    plans=root/'plans';plans.mkdir(mode=0o700);approvals=root/'approvals';operations_dir=root/'operations'
    identifier='e'*32
    proposal=plans/(identifier+'.json');proposal.write_text(json.dumps({'schemaVersion':1,
        'planId':identifier,'release':release,'createdAt':int(time.time()),
        'state':'awaiting-independent-root-approval'}));proposal.chmod(0o600)
    image=root/'images.json';image.write_text('{}\n')
    marker=root/'marker.json';uuid='92da4d08-6104-4054-b3e5-ef70a2a5fcb4'
    marker.write_text(json.dumps({'schemaVersion':1,'scope':'isolated-synthetic','machineUuid':uuid}));marker.chmod(0o600)
    dmi=root/'dmi';dmi.write_text(uuid+'\n')
    config=root/'maintenance-install.json'
    trusted_broker=root/'trusted-broker';shutil.copyfile(ops_dir/'p0-host-broker.py',trusted_broker)
    trusted_validator=root/'trusted-validator';trusted_validator.write_text('print("reviewed fixture")\n')
    with patch.multiple(binder,OUTPUT=config,TRUSTED_BROKER=trusted_broker,
                        TRUSTED_VALIDATOR=trusted_validator,MARKER=marker,DMI=dmi),\
         patch.multiple(approver,PLANS=plans,APPROVALS=approvals,ISOLATED_MARKER=marker,DMI=dmi),\
         patch.multiple(operations,PLANS=plans,APPROVALS=approvals,INCOMING=incoming,
                        INPUTS=config,OPERATIONS=operations_dir,APPROVER=ops_dir/'p0-host-approve.py',
                        BINDER=ops_dir/'p0-host-install-inputs.py',BROKER=ops_dir/'p0-host-broker.py'):
        bound=binder.prepare(bundle,control,image,release);assert bound['ready']
        approver.approve(identifier,release,'isolated',uuid)
        def loaded(path,name):
            if 'approver' in name:return approver
            if 'binder' in name:return binder
            if 'broker' in name:return broker
            raise ValueError('unexpected trusted module')
        with patch.object(operations,'load',side_effect=loaded):
            selected,actual,options,approved=operations.approved_inputs(identifier)
            assert selected==release and actual==bundle and options['controlCommit']==commit
            assert approved is approver
            assert not operations_dir.exists()
            image.write_text('{"tampered":true}\n')
            try:operations.approved_inputs(identifier)
            except ValueError:pass
            else:raise AssertionError('Changed offline image authority accepted')
            assert not operations_dir.exists()
            image.write_text('{}\n')
            marker.write_text(json.dumps({'schemaVersion':1,'scope':'production','machineUuid':uuid}))
            try:operations.approved_inputs(identifier)
            except ValueError:pass
            else:raise AssertionError('Production marker reused for isolated approval')
            assert not operations_dir.exists()
print('typed apply authority: real root plan/approval/input convergence; tamper and scope refuse before queue')
