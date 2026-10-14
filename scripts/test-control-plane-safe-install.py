#!/usr/bin/env python3
"""Root fixture: preserve authored SSH/KVM while provisioning typed host transport."""
import importlib.util,os,pwd,stat,subprocess,tempfile
from pathlib import Path
from unittest.mock import patch

root=Path(__file__).resolve().parents[1]
source=root/'runtime-generator/podman-ops/install-platform-zero-control-plane.sh'
body=source.read_text()
assert 'useradd --user-group --create-home' in body
assert 'one valid subordinate range' in body
assert 'install-domain-dispatch-key.py' in body
assert 'usermod -aG kvm' in body
assert body.index('kvm_user="$(jq') < body.index('  useradd --user-group --create-home')
assert 'existing KVM ownership rule requires separate review' in body
assert 'chown "$kvm_user:kvm" /dev/kvm' not in body
assert 'udevadm control' not in body
assert 'sed -i "/ p0-${domain}$/d"' not in body
# systemd-run observed root:kvm 0660 yet a shell-test decimal `-eq 060`
# rejected octal bitmask value 48. Exercise the actual source expression.
mask=next(line.strip().split(' || {',1)[0]for line in body.splitlines()if '8#$kvm_mode & 060' in line)
for mode,allowed in (('660',True),('600',False),('620',False),('666',False)):
    tested=subprocess.run(['bash','-c','kvm_mode="$1"; '+mask,'--',mode],capture_output=True)
    assert (tested.returncode==0)is allowed,(mode,mask)
preflight=body[body.index('refuse_unmanaged_target() {'):body.index('while read -r member target; do')]
with tempfile.TemporaryDirectory() as d:
    a=Path(d)/'reviewed';b=Path(d)/'installed'
    a.write_bytes(b'reviewed control');b.write_bytes(a.read_bytes());b.chmod(0o644)
    script='set -euo pipefail\n'+preflight+'\nrefuse_unmanaged_target "$1" "$2"\n'
    assert subprocess.run(['bash','-c',script,'--',str(a),str(b)],capture_output=True).returncode==0
    b.write_bytes(b'owner-authored control')
    assert subprocess.run(['bash','-c',script,'--',str(a),str(b)],capture_output=True).returncode!=0
    assert b.read_bytes()==b'owner-authored control'
    b.unlink();b.symlink_to(a)
    assert subprocess.run(['bash','-c',script,'--',str(a),str(b)],capture_output=True).returncode!=0

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
