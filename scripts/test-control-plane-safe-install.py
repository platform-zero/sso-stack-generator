#!/usr/bin/env python3
"""Root fixture: preserve authored SSH/KVM while provisioning typed host transport."""
import importlib.util,os,pwd,stat,tempfile
from pathlib import Path
from unittest.mock import patch

root=Path(__file__).resolve().parents[1]
source=root/'runtime-generator/podman-ops/install-platform-zero-control-plane.sh'
body=source.read_text()
assert 'useradd --user-group --create-home' in body
assert 'one valid subordinate range' in body
assert 'install-domain-dispatch-key.py' in body
assert 'usermod -aG kvm' in body
assert 'existing KVM ownership rule requires separate review' in body
assert 'chown "$kvm_user:kvm" /dev/kvm' not in body
assert 'udevadm control' not in body
assert 'sed -i "/ p0-${domain}$/d"' not in body

spec=importlib.util.spec_from_file_location('domain_key_install',root/'runtime-generator/podman-ops/install-domain-dispatch-key.py')
assert spec and spec.loader
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
assert os.geteuid()==0
with tempfile.TemporaryDirectory()as d:
    home=Path(d)/'home';home.mkdir(mode=0o700)
    account=type('Account',(),{'pw_uid':os.getuid()+1001,'pw_gid':os.getgid()+1001,'pw_dir':str(home)})()
    auth=home/'.ssh/authorized_keys';key='ssh-ed25519 AAAAB3NzaC1lZDI1NTE5AAAAIC12345= p0-apps'
    with patch.object(module.pwd,'getpwnam',return_value=account):
        assert module.install_key(auth,'webservices-apps','apps',key) is True
        assert module.install_key(auth,'webservices-apps','apps',key) is False
        assert auth.stat().st_uid==account.pw_uid and stat.S_IMODE(auth.stat().st_mode)==0o600
        first=auth.read_bytes();assert first.endswith(b' p0-apps\n')
        authored=b'ssh-ed25519 AAAA-real-author-key owner-authored\n'
        auth.write_bytes(authored+first);os.chown(auth,account.pw_uid,account.pw_gid)
        assert module.install_key(auth,'webservices-apps','apps',key) is False
        assert auth.read_bytes()==authored+first
        auth.write_bytes(authored+b'ssh-ed25519 different p0-apps\n');os.chown(auth,account.pw_uid,account.pw_gid)
        try:module.install_key(auth,'webservices-apps','apps',key)
        except ValueError:pass
        else:raise AssertionError('Unrelated domain authority was overwritten')
        assert auth.read_bytes()==authored+b'ssh-ed25519 different p0-apps\n'
        auth.unlink();auth.symlink_to(home/'outside')
        try:module.install_key(auth,'webservices-apps','apps',key)
        except ValueError:pass
        else:raise AssertionError('Linked authorized key was accepted')
print('typed control-plane install source: account/kvm preflight and exact SSH key CAS')
