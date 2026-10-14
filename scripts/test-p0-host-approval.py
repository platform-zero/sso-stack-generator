#!/usr/bin/env python3
"""Root fixture: plan identity is not approval, and production proof is distinct."""
import importlib.util,json,os,stat,tempfile
from pathlib import Path
from unittest.mock import patch

assert os.geteuid()==0
root=Path(__file__).resolve().parents[1]
p=root/'runtime-generator/podman-ops/p0-host-approve.py'
spec=importlib.util.spec_from_file_location('p0_host_approve',p);assert spec and spec.loader
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
uuid='92da4d08-6104-4054-b3e5-ef70a2a5fcb4';release='b'*64
with tempfile.TemporaryDirectory()as d:
    path=Path(d);plans=path/'plans';plans.mkdir(mode=0o700);marker=path/'marker.json';dmi=path/'dmi';dmi.write_text(uuid+'\n')
    marker.write_text(json.dumps({'schemaVersion':1,'scope':'isolated-synthetic','machineUuid':uuid}));marker.chmod(0o600)
    def plan(ident):
        q=plans/(ident+'.json');q.write_text(json.dumps({'schemaVersion':1,'planId':ident,'release':release,'createdAt':100,'state':'awaiting-independent-root-approval'}));q.chmod(0o600)
    first='a'*32;plan(first)
    with patch.multiple(module,PLANS=plans,APPROVALS=path/'approvals',DMI=dmi,ISOLATED_MARKER=marker):
        x=module.approve(first,release,'isolated',uuid,now=101)
        assert x['context']=='isolated' and x['applied']is False
        saved=path/'approvals'/(first+'.json')
        assert saved.is_file()and stat.S_IMODE(saved.stat().st_mode)==0o600
        assert module.review(first,release,now=102)['context']=='isolated'
        dmi.write_text('8cc1f504-90ca-499b-b500-4e55955638e0\n')
        try:module.review(first,release,now=102)
        except ValueError:pass
        else:raise AssertionError('Cross-machine approval accepted')
        dmi.write_text(uuid+'\n')
        try:module.review(first,release,now=1000)
        except ValueError:pass
        else:raise AssertionError('Expired signed approval accepted')
        marker.write_text(json.dumps({'schemaVersion':1,'scope':'production','machineUuid':uuid}))
        try:module.review(first,release,now=102)
        except ValueError:pass
        else:raise AssertionError('Synthetic scope changed after approval')
        marker.write_text(json.dumps({'schemaVersion':1,'scope':'isolated-synthetic','machineUuid':uuid}))
        assert module.consume(first,release,now=102)['context']=='isolated'
        assert not saved.exists() and (path/'approvals/consumed'/saved.name).is_file()
        try:module.consume(first,release,now=102)
        except FileNotFoundError:pass
        else:raise AssertionError('Approval claim replay accepted')
        try:module.approve(first,release,'isolated',uuid,now=102)
        except (FileExistsError,ValueError):pass
        else:raise AssertionError('Approval replay replaced root authority')
        second='c'*32;plan(second)
        try:module.approve(second,release,'production',uuid,now=101)
        except ValueError:pass
        else:raise AssertionError('Production without recovery receipts approved')
        evidence={}
        for purpose in ('recovery','announcement','rollback'):
            f=path/(purpose+'.json');f.write_text(json.dumps({'schemaVersion':1,'planId':second,
                'release':release,'scope':'production','purpose':purpose,'verified':True}));f.chmod(0o600);evidence[purpose]=f
        third='d'*32;plan(third)
        try:module.approve(second,release,'production',uuid,{p:evidence['recovery']for p in evidence},now=101)
        except ValueError:pass
        else:raise AssertionError('Reused proof accepted for three gates')
        x=module.approve(second,release,'production',uuid,evidence,now=101)
        assert x['applied']is False and x['context']=='production'
        assert module.review(second,release,now=102)['context']=='production'
        original=evidence['recovery'].read_bytes()
        evidence['recovery'].unlink();evidence['recovery'].symlink_to(evidence['announcement'])
        try:module.review(second,release,now=102)
        except (ValueError,OSError):pass
        else:raise AssertionError('Linked production receipt accepted')
        evidence['recovery'].unlink();evidence['recovery'].write_bytes(original);evidence['recovery'].chmod(0o600)
        evidence['recovery'].write_text(json.dumps({'schemaVersion':1,'planId':second,
            'release':release,'scope':'production','purpose':'recovery','verified':True,'changed':True}))
        try:module.review(second,release,now=102)
        except ValueError:pass
        else:raise AssertionError('Edited production proof accepted after root approval')
        evidence['recovery'].write_bytes(original)
        assert module.consume(second,release,now=102)['context']=='production'
        assert not(path/'approvals'/(second+'.json')).exists()
        assert (path/'approvals/consumed'/(second+'.json')).is_file()
        duplicate=path/'duplicate.json';duplicate.write_text('{"schemaVersion":1,"schemaVersion":1}');duplicate.chmod(0o600)
        try:module.strict(duplicate)
        except ValueError:pass
        else:raise AssertionError('Duplicate approval JSON accepted')
        hardlink=path/'hardlink.json';os.link(duplicate,hardlink)
        try:module.strict(duplicate)
        except ValueError:pass
        else:raise AssertionError('Hardlinked approval authority accepted')
        try:module.approve(third,release,'isolated',uuid,now=1001)
        except ValueError:pass
        else:raise AssertionError('Expired plan accepted')
        marker.write_text(json.dumps({'schemaVersion':1,'scope':'production','machineUuid':uuid}))
        try:module.approve(third,release,'isolated',uuid,now=101)
        except ValueError:pass
        else:raise AssertionError('Production machine was mislabelled isolated')
print('independent root approval: exact machine, separate proof purposes, replay/expiry denied')
