#!/usr/bin/env python3
"""Root fixture: immutable synthetic input binding without executing lane bundle code."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
from unittest.mock import patch

assert os.geteuid()==0
root=Path(__file__).resolve().parents[1]
source=root/'runtime-generator/podman-ops/p0-host-install-inputs.py'
spec=importlib.util.spec_from_file_location('p0_host_install_inputs',source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
broker_spec=importlib.util.spec_from_file_location('p0_host_broker_source',source.with_name('p0-host-broker.py'))
broker=importlib.util.module_from_spec(broker_spec);broker_spec.loader.exec_module(broker)
with tempfile.TemporaryDirectory(prefix='p0-maintenance-input-test-',dir='/var/lib/platform-zero') as tmp:
    base=Path(tmp);bundle=base/'bundle';bundle.mkdir(mode=0o700);(bundle/'ops').mkdir();(bundle/'site').mkdir()
    control=base/'control';control.mkdir(mode=0o700)
    subprocess.run(['git','-C',str(control),'init','-q'],check=True,capture_output=True)
    (control/'README').write_text('reviewed synthetic control\n')
    (control/'ops').mkdir();(control/'ops/agent_vm_spec.py').write_text('# reviewed synthetic validator\n')
    subprocess.run(['git','-C',str(control),'add','README','ops/agent_vm_spec.py'],check=True,capture_output=True)
    subprocess.run(['git','-C',str(control),'-c','user.name=Fixture','-c','user.email=fixture@example.invalid',
                    'commit','-qm','Fixture'],check=True,capture_output=True)
    commit=subprocess.check_output(['git','-C',str(control),'rev-parse','HEAD'],text=True).strip()
    sources={'bundle.json':{'backend':'podman'},'stack.ir.json':{},
             'podman-domains.json':{'domains':[{'name':'apps','user':'webservices-apps'}]},
             'podman-loopback-endpoints.json':{},
             'source-provenance.json':{'generatorDirty':False,'siteDirty':False,
                                       'generatorCommit':'a'*40,'siteCommit':'b'*40}}
    for name,body in sources.items():(bundle/name).write_text(json.dumps(body))
    (bundle/'ops/platform-zero.nft').write_text('table inet platform_zero {\n policy accept\n}\n')
    (bundle/'ops/install-podman-bundle.sh').write_text('#!/bin/sh\nexit 0\n')
    # Intentionally untrusted candidate code must NEVER run while binding inputs.
    (bundle/'ops/p0-host-broker.py').write_text('raise RuntimeError("untrusted bundle code executed")\n')
    (bundle/'ops/verify-agent-vm-bundle.py').write_text('raise RuntimeError("untrusted verifier executed")\n')
    (bundle/'site/manifest.json').write_text(json.dumps({'site':'latium','agentVmSpec':'agent-vm.json'}))
    vm=b'{"runtime":{"controlCommit":"'+commit.encode()+b'"}}'
    (bundle/'site/agent-vm.json').write_bytes(vm)
    (bundle/'site/agent-vm.provenance.json').write_text(json.dumps({'schemaVersion':1,'path':'agent-vm.json',
        'sha256':hashlib.sha256(vm).hexdigest(),'controlCommit':commit}))
    images=base/'images.json';images.write_text('{}\n')
    trusted=base/'trusted-broker';shutil.copyfile(source.with_name('p0-host-broker.py'),trusted)
    validator=base/'trusted-validator';validator.write_text('print("validated by trusted fixture")\n')
    marker=base/'marker.json';dmi=base/'dmi';machine='92da4d08-6104-4054-b3e5-ef70a2a5fcb4'
    marker.write_text(json.dumps({'schemaVersion':1,'scope':'isolated-synthetic','machineUuid':machine}));marker.chmod(0o600)
    dmi.write_text(machine+'\n')
    output=base/'maintenance-install.json';digest=broker.tree_sha256(bundle)
    with patch.multiple(module,OUTPUT=output,TRUSTED_BROKER=trusted,TRUSTED_VALIDATOR=validator,
                        MARKER=marker,DMI=dmi):
        first=module.prepare(bundle,control,images,digest)
        assert first['ready']and not first['unchanged']
        assert stat.S_IMODE(output.stat().st_mode)==0o600
        assert module.prepare(bundle,control,images,digest)['unchanged']
        bound=output.read_bytes()
        images.write_text('{"changed":true}\n')
        try:module.prepare(bundle,control,images,digest)
        except ValueError:pass
        else:raise AssertionError('Changed image inputs silently adopted')
        assert output.read_bytes()==bound
        marker.write_text(json.dumps({'schemaVersion':1,'scope':'production','machineUuid':machine}))
        try:module.prepare(bundle,control,images,digest)
        except ValueError:pass
        else:raise AssertionError('Production context accepted for synthetic apply')
        assert output.read_bytes()==bound
print('protected maintenance input preparation: exact pins, source trust and CAS')
