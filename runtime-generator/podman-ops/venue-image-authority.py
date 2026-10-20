#!/usr/bin/env python3
"""Read-only complete selected image/build authority for the cuts/finance venue.

Do not infer image authority from 1 offline archive or a successful source
suite. Every selected direct container reference must have a frozen per-store
config ID; every local .build consumer must have a generated build unit.
No pull, build, container start, image archive or registry request here.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('venue_stage',HERE/'venue-owned-stage.py')
stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage)
Refusal=stage.Refusal
spec=importlib.util.spec_from_file_location('venue_pinned_images',HERE/'install-pinned-images.py')
pinned_images=importlib.util.module_from_spec(spec);spec.loader.exec_module(pinned_images)
HEX=re.compile(r'sha256:[0-9a-f]{64}\Z')
REF=re.compile(r'(?:[a-z0-9][a-z0-9.:-]*/[a-z0-9][a-z0-9._/-]*:(?!latest\Z)[A-Za-z0-9._-]+(?:@sha256:[0-9a-f]{64})?|[a-z0-9][a-z0-9.:-]*/[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64})\Z')

def build_bases(bundle,unit):
    """Read generated build inputs without executing a Containerfile."""
    options={}
    for line in unit.read_text().splitlines():
        if line.startswith(('SetWorkingDirectory=','File=')):
            key,value=line.split('=',1)
            if key in options:raise Refusal('duplicate generated build path')
            options[key]=value.strip('"')
    if set(options)!={'SetWorkingDirectory','File'}:raise Refusal('build unit lacks exact context and Containerfile')
    work=Path(options['SetWorkingDirectory']);parts=work.parts
    if parts.count('current')!=1 or parts[-1]!='build' and 'build' not in parts:
        raise Refusal('build working directory outside selected current/build')
    offset=parts.index('current')+1
    if parts[offset:offset+1]!=('build',):raise Refusal('build working directory outside selected current/build')
    relative=Path(*parts[offset+1:])/options['File']
    if relative.is_absolute() or any(part=='..' for part in relative.parts):
        raise Refusal('build Containerfile escapes selected build context')
    source=Path(bundle)/'build'/relative
    if source.is_symlink() or not source.is_file() or not source.resolve().is_relative_to((Path(bundle)/'build').resolve()):
        raise Refusal('generated build Containerfile source absent or linked')
    refs=[];stages=set()
    for line in source.read_text().splitlines():
        fields=line.strip().split()
        if not fields or fields[0].upper()!='FROM':continue
        if len(fields)<2 or fields[1].startswith(('--','$')):raise Refusal('dynamic build FROM lacks immutable authority')
        base=fields[1]
        if base!='scratch' and base not in stages:refs.append(base)
        if len(fields)>2:
            if len(fields)!=4 or fields[2].upper()!='AS' or not re.fullmatch(r'[A-Za-z0-9_-]+',fields[3]):
                raise Refusal('ambiguous multi-stage build FROM')
            stages.add(fields[3])
    if not refs:raise Refusal('build lacks external base identity')
    return refs

def authority(bundle,selector,site_source=None,require_pinned_bases=False):
    b=Path(bundle);plan=stage.owned_plan(b,selector)
    names={a['name'].removeprefix(plan['prefix']+'-'):a['name'] for a in plan['accounts']}
    identities=b/'site/global.settings/registry-image-ids.json'
    if identities.is_symlink() or not identities.is_file():raise Refusal('frozen per-store identity authority missing')
    registry_ids=json.loads(identities.read_text())
    if (not isinstance(registry_ids,dict) or len(registry_ids)!=57 or
            any(not isinstance(k,str) or not isinstance(v,str) or not HEX.fullmatch(v) for k,v in registry_ids.items())):
        raise Refusal('malformed 57 frozen site image config identities')
    local_ids=pinned_images.frozen_image_ids(b)
    data=pinned_images.selected_image_ids(b)
    local_pins=b/'site/global.settings/local-build-image-ids.json'
    local_sha=None;producer_pins={}
    if local_ids:
        manifest=json.loads((b/'site/manifest.json').read_text())
        if (manifest.get('localBuildImagePinsPath')!='global.settings/local-build-image-ids.json' or
                local_pins.is_symlink() or not local_pins.is_file()):
            raise Refusal('frozen managed build identity source missing')
        document=json.loads(local_pins.read_text());ir=json.loads((b/'stack.ir.json').read_text())
        producer_pins={name:s['frozenBuildImage'] for name,s in ir['services'].items()
                       if 'build' in s and (s.get('lifecycle')!='on-demand' or s.get('quadletManaged') is True)}
        if (type(document.get('schemaVersion')) is not int or document['schemaVersion']!=1 or
                len(producer_pins)!=13 or document.get('images')!=producer_pins):
            raise Refusal('all thirteen frozen recipe identities must match the selected site')
        local_sha=hashlib.sha256(local_pins.read_bytes()).hexdigest()
    rows={};builds={};unit_count=0;base_refs={};store_bases={};mutable_store_bases=set()
    for directory in sorted((b/'quadlet').iterdir()):
        if not directory.is_dir() or directory.is_symlink():raise Refusal('unknown Quadlet image authority')
        user='root' if directory.name=='rootful' else names.get(directory.name.removeprefix('rootless-'))
        if not user:raise Refusal('unknown rootless image store')
        for unit in directory.glob('*.container'):
            images=[x[6:] for x in unit.read_text().splitlines() if x.startswith('Image=')]
            if len(images)!=1 or unit.is_symlink():raise Refusal('selected unit image is ambiguous')
            unit_count+=1;ref=images[0]
            file=directory/(unit.stem+'.build')
            if ref.endswith('.build') or (local_ids and file.exists()):
                if file.is_symlink() or not file.is_file():
                    raise Refusal('selected local build consumer lacks exact generated build unit')
                if local_ids:
                    name=unit.stem.removeprefix(plan['prefix']+'-')
                    if (producer_pins.get(name)!=ref or local_ids.get(user+'|'+ref)!=ref or
                            file.read_text().splitlines().count('RefuseManualStart=yes')!=1 or
                            unit.read_text().splitlines().count('Pull=never')!=1):
                        raise Refusal('frozen recipe/consumer may build, pull or substitute an image')
                    rows.setdefault(user+'|'+ref,[]).append(unit.name)
                elif ref!=unit.stem+'.build':
                    raise Refusal('selected build consumer differs from exact recipe')
                if require_pinned_bases and file.read_text().splitlines().count('Pull=never')!=1:
                    raise Refusal('selected build unit may pull an unreviewed base')
                if (require_pinned_bases and unit.stem.removeprefix(plan['prefix']+'-') in
                        ('keycloak','onboarding','mastodon-rss-publisher','firefly-native-api') and
                        file.read_text().splitlines().count('Network=none')!=1):
                    raise Refusal('selected local-only build permits unreviewed network egress')
                digest=hashlib.sha256(file.read_bytes()).hexdigest()
                bases=build_bases(b,file)
                builds[str(file.relative_to(b))]={'user':user,'sha256':digest}
                for base in bases:
                    base_refs.setdefault(base,[]).append(str(file.relative_to(b)))
                    store_bases.setdefault(user+'|'+base,[]).append(str(file.relative_to(b)))
                    if not re.search(r'@sha256:[0-9a-f]{64}\Z',base):mutable_store_bases.add(user+'|'+base)
            else:
                if not (HEX.fullmatch(ref) or REF.fullmatch(ref)) or ref.endswith(':latest'):
                    raise Refusal('unreviewed implicit image or mutable latest')
                key=user+'|'+ref
                rows.setdefault(key,[]).append(unit.name)
    if unit_count!=92 or len(builds)!=13 or len(rows)!=len(data) or set(rows)!=set(data):
        raise Refusal('92 containers, 13 recipes and exact registry plus imported image authority required')
    for key,image_id in data.items():
        ref=key.split('|',1)[1]
        if ref.startswith('sha256:') and ref!=image_id:
            raise Refusal('offline direct image/config identity differs')
    unpinned=sorted(base for base in base_refs if not re.search(r'@sha256:[0-9a-f]{64}\Z',base))
    pins=b/'site/global.settings/build-base-image-ids.json'
    base_map={};base_sha=None
    if pins.exists():
        if pins.is_symlink() or not pins.is_file():raise Refusal('build-base frozen source unsafe')
        base_sha=hashlib.sha256(pins.read_bytes()).hexdigest()
        base_document=json.loads(pins.read_text())
        if (base_document.get('schemaVersion')!=1 or base_document.get('platform')!='linux/amd64' or
                not isinstance(base_document.get('baseImages'),dict) or
                set(base_document['baseImages'])!=mutable_store_bases):
            raise Refusal('frozen build-base per-store identities differ from selected FROM inputs')
        for key,row in base_document['baseImages'].items():
            ref=key.split('|',1)[1];expanded=ref if '/' in ref else 'docker.io/library/'+ref
            if (not isinstance(row,dict) or set(row)!=set(('registryReference','linuxAmd64ManifestDigest','configId')) or
                    row['registryReference']!=expanded or
                    not HEX.fullmatch(row['linuxAmd64ManifestDigest']) or not HEX.fullmatch(row['configId'])):
                raise Refusal('frozen build-base tag/image identity malformed')
            base_map[key]=row
    if require_pinned_bases and mutable_store_bases and (not site_source or set(base_map)!=mutable_store_bases):
        raise Refusal('local build base tags lack clean frozen per-store config authority')
    source=hashlib.sha256(identities.read_bytes()).hexdigest()
    if site_source is not None:
        checkout=Path(site_source)
        commit=json.loads((b/'source-provenance.json').read_text())['siteCommit']
        if not re.fullmatch(r'[0-9a-f]{40}',commit) or checkout.is_symlink() or not checkout.is_dir():
            raise Refusal('reviewed clean site source missing')
        git=['git','-c','safe.directory='+str(checkout),'-C',str(checkout)]
        actual=subprocess.run(git+['rev-parse','HEAD'],capture_output=True,text=True,timeout=20)
        dirty=subprocess.run(git+['status','--porcelain'],capture_output=True,text=True,timeout=20)
        frozen=subprocess.run(git+['show',commit+':sites/latium/global.settings/registry-image-ids.json'],
                              capture_output=True,text=True,timeout=20)
        if (actual.returncode or actual.stdout.strip()!=commit or dirty.returncode or dirty.stdout.strip() or
                frozen.returncode or frozen.stdout.encode()!=identities.read_bytes()):
            raise Refusal('bundle image identity bytes differ from clean pinned site source')
        if local_sha is not None:
            local_source=subprocess.run(git+['show',commit+':sites/latium/global.settings/local-build-image-ids.json'],
                                        capture_output=True,text=True,timeout=20)
            if local_source.returncode or local_source.stdout.encode()!=local_pins.read_bytes():
                raise Refusal('bundle local image IDs differ from clean pinned site source')
        if base_sha is not None:
            build_pins=subprocess.run(git+['show',commit+':sites/latium/global.settings/build-base-image-ids.json'],
                                      capture_output=True,text=True,timeout=20)
            if build_pins.returncode or build_pins.stdout.encode()!=pins.read_bytes():
                raise Refusal('bundle build-base IDs differ from clean pinned site source')
    return {'schemaVersion':1,'generatorCommit':plan['sourceCommit'],
            'bundleIrSha256':plan['bundleIrSha256'],'quadletTreeSha256':plan['quadletTreeSha256'],
            'selectorSha256':plan['selectorSha256'],'frozenRegistrySha256':source,
            'containerUnits':unit_count,'directImageReferences':len(registry_ids),'localBuildUnits':len(builds),
            'selectedImagePairs':len(data),'frozenLocalImagePairs':len(local_ids),'frozenLocalPinsSha256':local_sha,
            'buildBaseReferences':len(base_refs),'buildBaseStorePairs':len(store_bases),
            'mutableBuildBaseReferences':unpinned,
            'unfrozenBuildBaseReferences':sorted(set(mutable_store_bases)-set(base_map)),
            'frozenBuildBasePairs':len(base_map),'frozenBuildBaseSha256':base_sha,
            'imageIds':data,'buildUnits':builds,'buildBaseImages':base_map,
            'buildBaseStores':sorted(store_bases),'activationAuthorized':False,
            'acceptedIntegratedInstalls':0}

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--bundle',required=True);ap.add_argument('--selector',required=True)
    ap.add_argument('--site-source')
    ap.add_argument('--require-pinned-bases',action='store_true')
    a=ap.parse_args()
    try:
        result=authority(a.bundle,a.selector,a.site_source,a.require_pinned_bases)
        print(json.dumps({k:v for k,v in result.items() if k not in ('imageIds','buildUnits','buildBaseImages','buildBaseStores')},sort_keys=True))
    except (Refusal,KeyError,OSError,ValueError,TypeError,subprocess.SubprocessError) as exc:
        raise SystemExit('venue complete image/build authority refused: '+str(exc)) from exc
if __name__=='__main__':main()
