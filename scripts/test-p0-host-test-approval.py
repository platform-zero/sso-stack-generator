#!/usr/bin/env python3
"""Root-only real synthetic selected-test approval fixture; no test execution."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
from unittest.mock import patch

assert os.geteuid()==0
source=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/p0-host-test-approve.py'
spec=importlib.util.spec_from_file_location('p0_synthetic_test_approver',source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
with tempfile.TemporaryDirectory(prefix='p0-synthetic-test-approval-',dir='/var/lib/platform-zero')as tmp:
    base=Path(tmp);native=base/'native';native.mkdir(mode=0o700)
    selected=native/'releases/20261014T140000Z-aaaaaaaaaaaa';selected.mkdir(parents=True)
    runner=selected/'build/stack.containers/test-runner/run-tests.sh';runner.parent.mkdir(parents=True)
    runner.write_text('#!/bin/sh\nexit 0\n');runner.chmod(0o755)
    (native/'current').symlink_to(selected)
    journal=native/'.install-intent.json';journal.write_text(json.dumps({'schemaVersion':1,'phase':'active',
        'release':str(selected),'inputs':{'bundle.json':'a'*64}}));journal.chmod(0o600)
    dmi=base/'dmi';machine='92da4d08-6104-4054-b3e5-ef70a2a5fcb4';dmi.write_text(machine+'\n')
    marker=base/'marker';marker.write_text(json.dumps({'schemaVersion':1,
        'scope':'isolated-synthetic','machineUuid':machine}));marker.chmod(0o600)
    approvals=base/'test-approvals'
    with patch.multiple(module,APPROVALS=approvals,MARKER=marker,DMI=dmi,NATIVE=native):
        try:module.approve('android-apps',now=100)
        except ValueError:pass
        else:raise AssertionError('Unreviewed Android emulator suite permitted')
        first=module.approve('ts-unit',now=100)
        assert first['suite']=='ts-unit'and not first['applied']
        saved=approvals/'ts-unit.json';assert stat.S_IMODE(saved.stat().st_mode)==0o600
        assert module.review('ts-unit',now=101)['release']==str(selected)
        assert module.consume('ts-unit','a'*32,now=101)['suite']=='ts-unit'
        claimed=approvals/'consumed'/('a'*32+'.json')
        assert claimed.is_file()and not saved.exists()
        assert module.review('ts-unit',now=101,claimed_operation='a'*32)['journalSha256']
        try:module.consume('ts-unit','a'*32,now=101)
        except FileNotFoundError:pass
        else:raise AssertionError('Synthetic test approval replayed')
        try:module.review('ts-unit',now=701,claimed_operation='a'*32)
        except ValueError:pass
        else:raise AssertionError('Expired synthetic test approval accepted')
        original=runner.read_bytes();runner.write_text('# changed selected test runner\n')
        try:module.review('ts-unit',now=101,claimed_operation='a'*32)
        except ValueError:pass
        else:raise AssertionError('Modified selected test source accepted')
        runner.write_bytes(original)
        marker.write_text(json.dumps({'schemaVersion':1,'scope':'production','machineUuid':machine}))
        try:module.review('ts-unit',now=101,claimed_operation='a'*32)
        except ValueError:pass
        else:raise AssertionError('Synthetic test approval reused on production')
        assert claimed.is_file()
print('typed test approval source: selected root runner, machine/marker, expiry, suite and hash-bound refusal')
