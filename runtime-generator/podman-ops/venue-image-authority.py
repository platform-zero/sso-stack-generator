#!/usr/bin/env python3
"""Read-only complete selected image/build authority for a 60/95 venue.

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
    data=json.loads(identities.read_text())
    if not isinstance(data,dict) or not data or any(not isinstance(k,str) or not isinstance(v,str) or not HEX.fullmatch(v) for k,v in data.items()):
        raise Refusal('malformed frozen site image config identities')
    rows={};builds={};unit_count=0;base_refs={};mutable_store_bases=set()
    for directory in sorted((b/'quadlet').iterdir()):
        if not directory.is_dir() or directory.is_symlink():raise Refusal('unknown Quadlet image authority')
        user='root' if directory.name=='rootful' else names.get(directory.name.removeprefix('rootless-'))
        if not user:raise Refusal('unknown rootless image store')
        for unit in directory.glob('*.container'):
            images=[x[6:] for x in unit.read_text().splitlines() if x.startswith('Image=')]
            if len(images)!=1 or unit.is_symlink():raise Refusal('selected unit image is ambiguous')
            unit_count+=1;ref=images[0]
            if ref.endswith('.build'):
                file=directory/(unit.stem+'.build')
                if ref!=unit.stem+'.build' or file.is_symlink() or not file.is_file():
                    raise Refusal('selected local build consumer lacks exact generated build unit')
                if require_pinned_bases and file.read_text().splitlines().count('Pull=never')!=1:
                    raise Refusal('selected build unit may pull an unreviewed base')
                digest=hashlib.sha256(file.read_bytes()).hexdigest()
                bases=build_bases(b,file)
                builds[str(file.relative_to(b))]={'user':user,'sha256':digest}
                for base in bases:
                    base_refs.setdefault(base,[]).append(str(file.relative_to(b)))
                    if not re.search(r'@sha256:[0-9a-f]{64}\Z',base):mutable_store_bases.add(user+'|'+base)
            else:
                if not (HEX.fullmatch(ref) or REF.fullmatch(ref)) or ref.endswith(':latest'):
                    raise Refusal('unreviewed implicit image or mutable latest')
                key=user+'|'+ref
                rows.setdefault(key,[]).append(unit.name)
    if unit_count!=93 or len(builds)!=14 or len(rows)!=60 or set(rows)!=set(data):
        raise Refusal('93 selected containers, 14 local build units and 60 frozen authority/image pairs required')
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
        if base_sha is not None:
            build_pins=subprocess.run(git+['show',commit+':sites/latium/global.settings/build-base-image-ids.json'],
                                      capture_output=True,text=True,timeout=20)
            if build_pins.returncode or build_pins.stdout.encode()!=pins.read_bytes():
                raise Refusal('bundle build-base IDs differ from clean pinned site source')
    return {'schemaVersion':1,'generatorCommit':plan['sourceCommit'],
            'bundleIrSha256':plan['bundleIrSha256'],'quadletTreeSha256':plan['quadletTreeSha256'],
            'selectorSha256':plan['selectorSha256'],'frozenRegistrySha256':source,
            'containerUnits':unit_count,'directImageReferences':len(rows),'localBuildUnits':len(builds),
            'buildBaseReferences':len(base_refs),'mutableBuildBaseReferences':unpinned,
            'unfrozenBuildBaseReferences':sorted(set(mutable_store_bases)-set(base_map)),
            'frozenBuildBasePairs':len(base_map),'frozenBuildBaseSha256':base_sha,
            'imageIds':data,'buildUnits':builds,'buildBaseImages':base_map,'activationAuthorized':False,
            'acceptedIntegratedInstalls':0}

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--bundle',required=True);ap.add_argument('--selector',required=True)
    ap.add_argument('--site-source')
    ap.add_argument('--require-pinned-bases',action='store_true')
    a=ap.parse_args()
    try:
        result=authority(a.bundle,a.selector,a.site_source,a.require_pinned_bases)
        print(json.dumps({k:v for k,v in result.items() if k not in ('imageIds','buildUnits','buildBaseImages')},sort_keys=True))
    except (Refusal,KeyError,OSError,ValueError,TypeError,subprocess.SubprocessError) as exc:
        raise SystemExit('venue complete image/build authority refused: '+str(exc)) from exc
if __name__=='__main__':main()
