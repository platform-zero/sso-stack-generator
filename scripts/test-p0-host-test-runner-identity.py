#!/usr/bin/env python3
"""Root fixture: typed unit runner cannot choose an unpinned rootless identity."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

assert os.geteuid()==0
source=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/p0-host-operations.py'
spec=importlib.util.spec_from_file_location('p0_runner_identity_fixture',source)
ops=importlib.util.module_from_spec(spec);spec.loader.exec_module(ops)
with tempfile.TemporaryDirectory(prefix='p0-runner-identity-',dir='/var/lib/platform-zero') as tmp:
    base=Path(tmp)
    native=base/'native';native.mkdir()
    release=native/'releases'/'current';release.mkdir(parents=True)
    manifest=release/'podman-domains.json'
    state=base/'test-runners'/'state';state.mkdir(parents=True)
    os.chown(state,1997,1997)
    def domains(user='webservices-test-runners',uid=1997):
        return {'domains':[{'name':'test-runners','user':user,'uid':uid,
                'stateRoot':str(state),'graphRoot':str(state.parent/'storage')}]}
    manifest.write_text(json.dumps(domains())+'\n')
    journal=native/'.install-intent.json'
    def write_journal(digest):
        journal.write_text(json.dumps({'phase':'active','release':str(release),
            'inputs':{'podman-domains.json':digest}})+'\n')
        journal.chmod(0o600)
    write_journal(hashlib.sha256(manifest.read_bytes()).hexdigest())
    account=SimpleNamespace(pw_name='webservices-test-runners',pw_uid=1997,
                            pw_dir='/home/webservices-test-runners')
    original=Path.is_socket
    def socket(path):
        return str(path)=='/run/user/1997/bus'
    with patch.object(ops,'NATIVE_ROOT',native),patch.object(ops.pwd,'getpwnam',return_value=account),\
         patch.object(Path,'is_socket',socket):
        assert ops.selected_test_runner_account(release)==(account,state)
        manifest.write_text(json.dumps(domains(user='root',uid=0))+'\n')
        try:ops.selected_test_runner_account(release)
        except ValueError:pass
        else:raise AssertionError('Changed manifest selected an unauthorized root runner')
        write_journal(hashlib.sha256(manifest.read_bytes()).hexdigest())
        try:ops.selected_test_runner_account(release)
        except ValueError:pass
        else:raise AssertionError('Native-journal-bound root runner was authorized')
        manifest.write_text(json.dumps(domains(uid=1998))+'\n')
        write_journal(hashlib.sha256(manifest.read_bytes()).hexdigest())
        try:ops.selected_test_runner_account(release)
        except ValueError:pass
        else:raise AssertionError('Wrong pinned UID was authorized')
        manifest.write_text(json.dumps(domains())+'\n')
        write_journal(hashlib.sha256(manifest.read_bytes()).hexdigest())
        with patch.object(Path,'is_socket',return_value=False):
            try:ops.selected_test_runner_account(release)
            except ValueError:pass
            else:raise AssertionError('Unready rootless user bus was authorized')
print('typed synthetic test runner: pinned installed UID, digest, and user bus required')
