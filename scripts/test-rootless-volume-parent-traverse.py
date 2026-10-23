#!/usr/bin/env python3
"""Root fixture: exact domain traversal, no broad parent chmod or ACL replacement."""
import importlib.util,os,stat,subprocess,tempfile
from pathlib import Path
from unittest.mock import patch

assert os.geteuid()==0
root=Path(__file__).resolve().parents[1]
p=root/'runtime-generator/podman-ops/grant-rootless-volume-parent-traverse.py'
spec=importlib.util.spec_from_file_location('p0_volume_parent',p);assert spec and spec.loader
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
install=(root/'runtime-generator/podman-ops/install-podman-bundle.sh').read_text()
assert install.index('grant-rootless-volume-parent-traverse.py')<install.index('journal starting\n')
assert 'chmod 0711 /mnt/stack/rootless' not in install
with tempfile.TemporaryDirectory()as d:
    parent=Path(d)/'stack';parent.mkdir(mode=0o755)
    shared=parent/'rootless';shared.mkdir(mode=0o700)
    for n in ('platform','apps'):(shared/n).mkdir(mode=0o700)
    with patch.object(mod,'ROOTLESS_PARENT',shared):
        # Authored group read exists but is masked off; a new UID must not unmask it.
        subprocess.run(['setfacl','-m','g::r-x,m::--x',str(shared)],check=True)
        before=mod.entries(shared)
        assert mod.grant('platform','webservices-platform',shared/'platform') is True
        assert mod.grant('platform','webservices-platform',shared/'platform') is False
        after=mod.entries(shared)
        assert after.get(('user','webservices-platform'))=='--x'
        assert after.get(('mask',''))=='--x'
        assert all(after.get(k)==v for k,v in before.items()if k!=('mask',''))
        assert shared.stat().st_mode&0o007==0
        subprocess.run(['setfacl','-m','u:webservices-apps:r--',str(shared)],check=True)
        conflicts=mod.entries(shared)
        try:mod.grant('apps','webservices-apps',shared/'apps')
        except ValueError:pass
        else:raise AssertionError('Authored domain ACL was replaced')
        assert mod.entries(shared)==conflicts
    link=parent/'alias';link.symlink_to(shared)
    with patch.object(mod,'ROOTLESS_PARENT',link):
        try:mod.grant('platform','webservices-platform',link/'platform')
        except ValueError:pass
        else:raise AssertionError('Linked shared root was trusted')
print('selected rootless ACL: only domain execute, no shared chmod, conflicting ACL preserved')
