#!/usr/bin/env python3
"""Bounded preparation of 14 immutable/per-store build bases, NOT a build.

Six mutable FROM tag/store pairs have site-committed linux/amd64 config and
manifest IDs. Fetch by pinned manifest, then locally tag only in an exclusive
test graph. Eight digest FROM pairs are already content-addressed. Stop on
base/tag drift, foreign graph state or physical reserve loss; never start a
container, build unit, service or readiness marker here.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re

HERE=Path(__file__).resolve().parent
def load(name,file):
    s=importlib.util.spec_from_file_location(name,HERE/file)
    m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
registry=load('venue_registry_images','venue-registry-images.py')
authority=registry.authority
stage=registry.stage;graph=registry.graph;Refusal=stage.Refusal

def identity(command,ref):
    value=registry.pulled(command,ref)
    if value is not None:
        res=graph.run(command+['image','inspect','--format','{{.Architecture}}/{{.Os}}',ref],timeout=30)
        if res.returncode or res.stdout.strip()!='amd64/linux':
            raise Refusal('selected build base is not linux/amd64')
    return value

def inventory(bundle,plan,data,recorded):
    expected=data['venueRegistryVerified'].copy();expected.update(recorded)
    roots,found=registry.probe(bundle,plan,data,expected)
    for key,value in recorded.items():
        user,sep,ref=key.partition('|')
        if not sep or user not in roots or identity(roots[user][1],ref)!=value:
            raise Refusal('selected local build FROM alias/config ID drift')
    return roots,found

def fetch_selected(command,ref,source):
    pinned=source['buildBaseImages'].get(ref)
    user,_,base=ref.partition('|')
    existing=identity(command,base)
    if pinned:
        expected=pinned['configId']
        if existing is not None and existing!=expected:raise Refusal('frozen FROM tag points to another config ID')
        if existing is None:
            digest_ref=pinned['registryReference']+'@'+pinned['linuxAmd64ManifestDigest']
            registry.fetch(command,digest_ref)
            if identity(command,digest_ref)!=expected:
                raise Refusal('immutable build-base manifest config ID differs from clean site pin')
            tagged=graph.run(command+['image','tag',digest_ref,pinned['registryReference']],timeout=35)
            if tagged.returncode:raise Refusal('selected build-base local tag could not be installed')
            existing=identity(command,base)
        if existing!=expected:raise Refusal('selected build-base FROM alias unavailable after pinned tag')
    elif re.search(r'@sha256:[0-9a-f]{64}\Z',base):
        if existing is None:
            registry.fetch(command,base)
            existing=identity(command,base)
        if not existing:raise Refusal('digest-based build base could not be inspected')
    else:raise Refusal('mutable build base lacks clean site identity')
    return existing

def prepare(bundle,selector,site_source,ledger,max_new):
    p,data,plan,_=registry.journal(bundle,selector,site_source,ledger)
    source=authority.authority(bundle,selector,site_source,require_pinned_bases=True)
    if (data.get('venueRegistryPhase')!='inert-ready' or
            data.get('venueRegistryVerified')!=source['imageIds'] or
            len(source['buildBaseStores'])!=14 or source['frozenBuildBasePairs']!=6 or
            source['unfrozenBuildBaseReferences']):
        raise Refusal('all 60 direct images and 14 frozen build-base inputs required')
    if type(max_new) is not int or not 1<=max_new<=14:raise Refusal('one to fourteen bounded new bases per invocation')
    if data.get('venueBuildBasePhase') is None:
        data['venueBuildBasePhase']='preparing'
        data['venueBuildBasePlan']=source['buildBaseStores']
        data['venueBuildBaseFrozenSha256']=source['frozenBuildBaseSha256']
        data['venueBuildBaseVerified']={}
        stage.write_ledger(p,data)
    if (data.get('venueBuildBasePhase') not in ('preparing','inert-ready') or
            data.get('venueBuildBasePlan')!=source['buildBaseStores'] or
            data.get('venueBuildBaseFrozenSha256')!=source['frozenBuildBaseSha256'] or
            not isinstance(data.get('venueBuildBaseVerified'),dict) or
            any(k not in source['buildBaseStores'] or not re.fullmatch(r'sha256:[0-9a-f]{64}',v)
                for k,v in data['venueBuildBaseVerified'].items())):
        raise Refusal('build-base image journal differs from frozen 14-pair authority')
    verified=data['venueBuildBaseVerified']
    for key,value in verified.items():
        pinned=source['buildBaseImages'].get(key)
        if pinned and value!=pinned['configId']:
            raise Refusal('journaled mutable base ID differs from clean site')
    pending=data.get('venueBuildBasePending')
    if pending is not None:
        if pending not in source['buildBaseStores'] or pending in verified:
            raise Refusal('interrupted build-base pull does not match selected input')
        roots=registry.command_graphs(bundle,plan)
        user,_,base=pending.partition('|');observed=identity(roots[user][1],base)
        pinned=source['buildBaseImages'].get(pending)
        if not observed or (pinned and observed!=pinned['configId']):
            raise Refusal('interrupted build-base pull needs exact selected-image review')
        verified[pending]=observed;data.pop('venueBuildBasePending');stage.write_ledger(p,data)
    roots,_=inventory(bundle,plan,data,verified)
    if data['venueBuildBasePhase']=='inert-ready':
        if set(verified)!=set(source['buildBaseStores']):raise Refusal('claimed full build bases incomplete')
        return {'status':'inert-ready','verifiedBasePairs':len(verified),'remaining':0,
                'activationAuthorized':False,'acceptedIntegratedInstalls':0}
    for candidate in sorted(set(source['buildBaseStores'])-set(verified))[:max_new]:
        user,_,base=candidate.partition('|');command=roots[user][1]
        registry.reserve()
        data['venueBuildBasePending']=candidate;stage.write_ledger(p,data)
        value=fetch_selected(command,candidate,source)
        verified[candidate]=value;data.pop('venueBuildBasePending');stage.write_ledger(p,data)
        roots,_=inventory(bundle,plan,data,verified)
    if set(verified)==set(source['buildBaseStores']):
        data['venueBuildBasePhase']='inert-ready';stage.write_ledger(p,data)
    return {'status':data['venueBuildBasePhase'],'verifiedBasePairs':len(verified),
            'remaining':len(source['buildBaseStores'])-len(verified),
            'activationAuthorized':False,'acceptedIntegratedInstalls':0}

def main():
    a=argparse.ArgumentParser(description=__doc__)
    for key in ('bundle','selector','site-source','ledger'):a.add_argument('--'+key,required=True)
    a.add_argument('--max-new',type=int,default=1)
    args=a.parse_args()
    try:print(json.dumps(prepare(args.bundle,args.selector,args.site_source,args.ledger,args.max_new),sort_keys=True))
    except (Refusal,OSError,KeyError,ValueError,TypeError) as exc:
        raise SystemExit('venue build-base preparation refused: '+str(exc)) from exc
if __name__=='__main__':main()
