#!/usr/bin/env python3
"""Resolve one immutable site lock into an isolated module workspace."""
import argparse, hashlib, json, shutil, subprocess, sys
from pathlib import Path

def fail(msg): raise SystemExit(f"site lock error: {msg}")
def load(path, label):
    try: value=json.loads(Path(path).read_text())
    except Exception as exc: fail(f"cannot read {label}: {exc}")
    if not isinstance(value, dict): fail(f"{label} must be an object")
    return value
def run(args, cwd=None):
    result=subprocess.run(args,cwd=cwd,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    if result.returncode: fail(f"{' '.join(args)} failed: {(result.stderr or result.stdout).strip()}")
    return result.stdout.strip()
def safe_path(value, label):
    p=Path(value or '.')
    if p.is_absolute() or '..' in p.parts: fail(f"unsafe {label}: {value}")
    return p
def clone(lock, root):
    # A checkout is always newly created.  The optional cache is deliberately
    # absent here: it must never be adjacent to outputs or test fixtures.
    dst=root / lock['id']
    run(['git','clone','--no-checkout',lock['git'],str(dst)])
    run(['git','-C',str(dst),'fetch','--no-tags','origin',lock['commit']])
    run(['git','-C',str(dst),'cat-file','-e',lock['commit']+'^{commit}'])
    run(['git','-C',str(dst),'checkout','--detach','--force',lock['commit']])
    actual=run(['git','-C',str(dst),'rev-parse','HEAD'])
    if actual != lock['commit']: fail(f"module '{lock['id']}' did not resolve pinned commit")
    return dst
def caps(value, module, field):
    if value is None: return []
    if not isinstance(value,list): fail(f"module '{module}' {field} must be an array")
    result=[]
    for item in value:
      if not isinstance(item,dict) or not isinstance(item.get('capability'),str) or not isinstance(item.get('version'),str):
        fail(f"module '{module}' has invalid {field} capability")
      result.append((item['capability'],item['version']))
    return result
def validate_config(schema, value, where='config'):
    if not schema: return
    typ=schema.get('type')
    expected={'object':dict,'array':list,'string':str,'boolean':bool,'number':(int,float),'integer':int}
    if typ and (not isinstance(value,expected.get(typ,object)) or (typ in ('number','integer') and isinstance(value,bool))): fail(f"invalid {where}: expected {typ}")
    if 'enum' in schema and value not in schema['enum']: fail(f"invalid {where}: value is not allowed")
    if typ=='object':
      props=schema.get('properties',{})
      for key in schema.get('required',[]):
        if key not in value: fail(f"invalid {where}: missing '{key}'")
      if schema.get('additionalProperties') is False:
        unknown=set(value)-set(props)
        if unknown: fail(f"invalid {where}: unknown keys {', '.join(sorted(unknown))}")
      for key, child in props.items():
        if key in value: validate_config(child,value[key],f'{where}.{key}')
def main():
 p=argparse.ArgumentParser(); p.add_argument('--site-lock',required=True); p.add_argument('--workspace',required=True); p.add_argument('--resolved',required=True); args=p.parse_args()
 lock_path=Path(args.site_lock).resolve(); lock=load(lock_path,'site lock')
 if lock.get('schemaVersion') != 1 or not isinstance(lock.get('modules'),list): fail('expected schemaVersion: 1 and modules array')
 encoded=lock_path.read_bytes(); lock_hash=hashlib.sha256(encoded).hexdigest(); ids=set(); modules=[]; workspace=Path(args.workspace)
 if workspace.exists(): shutil.rmtree(workspace)
 workspace.mkdir(parents=True)
 for entry in lock['modules']:
  if not isinstance(entry,dict): fail('module entries must be objects')
  ident=entry.get('id'); commit=entry.get('commit'); git=entry.get('git')
  if not isinstance(ident,str) or not ident or ident in ids: fail(f"duplicate or invalid module id: {ident}")
  if not isinstance(git,str) or not git or not isinstance(commit,str) or len(commit) < 40: fail(f"module '{ident}' requires git and immutable commit")
  ids.add(ident); repo=clone(entry,workspace); rel=safe_path(entry.get('path','.'),f"module '{ident}' path"); source=(repo/rel).resolve()
  if not source.is_dir() or repo.resolve() not in (source,*source.parents): fail(f"module '{ident}' path is outside checkout")
  descriptor=load(source/'module.json',f"module '{ident}' descriptor")
  if descriptor.get('schemaVersion') != 1 or descriptor.get('id') != ident: fail(f"module '{ident}' descriptor id/schemaVersion mismatch")
  validate_config(descriptor.get('configuration',{}).get('schema',{}),entry.get('config',{}),f"module '{ident}' config")
  modules.append({'lock':entry,'repo':repo,'source':source,'descriptor':descriptor})
 providers={}; routes={}; volumes={}
 for m in modules:
  ident=m['lock']['id']
  for cap,ver in caps(m['descriptor'].get('provides'),ident,'provides'):
   if cap in providers: fail(f"capability '{cap}' is provided by both {providers[cap][0]} and {ident}")
   providers[cap]=(ident,ver)
  for service in m['descriptor'].get('services',[]) or []:
   if not isinstance(service,dict) or not isinstance(service.get('name'),str): fail(f"module '{ident}' has invalid service")
   for route in service.get('routes',[]) or []:
    if not isinstance(route, str) or not route: fail(f"module '{ident}' has invalid route")
    if route in routes: fail(f"route conflict '{route}' ({routes[route]}, {ident})")
    routes[route]=ident
   for volume in service.get('volumes',[]) or []:
    if not isinstance(volume, str) or not volume: fail(f"module '{ident}' has invalid volume")
    if volume in volumes: fail(f"volume conflict '{volume}' ({volumes[volume]}, {ident})")
    volumes[volume]=ident
 for m in modules:
  ident=m['lock']['id']
  for cap,ver in caps(m['descriptor'].get('requires'),ident,'requires'):
   if cap not in providers: fail(f"module '{ident}' requires missing capability '{cap}@{ver}'")
   if providers[cap][1] != ver: fail(f"module '{ident}' requires '{cap}@{ver}', provider is @{providers[cap][1]}")
 result={'schemaVersion':1,'siteLockSha256':lock_hash,'modules':[{'id':m['lock']['id'],'git':m['lock']['git'],'commit':m['lock']['commit'],'path':m['lock'].get('path','.'),'descriptorSha256':hashlib.sha256((m['source']/'module.json').read_bytes()).hexdigest(),'verificationCommands':m['descriptor'].get('verification',{}).get('commands',[])} for m in modules]}
 Path(args.resolved).parent.mkdir(parents=True,exist_ok=True); Path(args.resolved).write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
if __name__=='__main__': main()
