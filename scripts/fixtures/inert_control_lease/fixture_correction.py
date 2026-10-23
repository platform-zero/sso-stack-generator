import types
"""Explicit INTERNAL observations only. Real controller2e0 current() and real
committed g768 lifecycle.host_context() execute against own p0testslotlayout.
No real root/proc/target operation; the six-argument API has no fake seam.
"""
import ast,copy,importlib.util,json,stat,types
from pathlib import Path,PurePosixPath as P
from unittest.mock import patch
import inert_control_lease_native as m
import test_native_lease as original
R=Path(__file__).resolve().parent
PROFILE=json.loads((R/'SOURCE-LOCK.json').read_text())
OLD_SETUP=original.NativeTests.setUp
OLD_MUTATE=original.NativeTests.mutate
OLD_COMMAND=original.NativeTests.command
class MetadataFS(original.FS):
 def walk(self,root,followlinks=False,onerror=None):return super().walk(root,followlinks=followlinks)
 def open(self,*args,**kwargs):
  fd=super().open(*args,**kwargs);self.peakfds=max(getattr(self,'peakfds',0),len(self.fds));return fd
 def getegid(self):return getattr(self,'egid',0)
 def stat(self,p,dir_fd=None,follow_symlinks=True):
  if str(p).startswith(('/proc/self/ns/','/proc/1/ns/')):return types.SimpleNamespace(st_dev=9,st_ino=99)
  return super().stat(p,dir_fd=dir_fd,follow_symlinks=follow_symlinks)
class SlotPath(P):
 fs=None
 def lstat(self):return self.fs.lstat(str(self))
 def is_symlink(self):
  n=self.fs.nodes.get(str(self));return n is not None and stat.S_ISLNK(n.mode)
 def exists(self):return str(self) in self.fs.nodes
 def read_bytes(self):return self.fs.nodes[str(self)].data
 def resolve(self,strict=False):
  current=SlotPath(self)
  for count in range(16):
   found=False
   for prefix in tuple(reversed(current.parents))+(current,):
    if prefix.is_symlink():
     target=self.fs.readlink(str(prefix));base=SlotPath(target) if target.startswith('/') else prefix.parent/target
     current=base/current.relative_to(prefix);found=True;break
   if not found:
    if strict and str(current) not in self.fs.nodes:raise FileNotFoundError()
    return current
  raise ValueError('PUBLIC fake link loop')
class SeedPath(type(Path())):
 def read_text(self,*args,**kwargs):
  if self.name=='SOURCE-LOCK.json':return json.dumps({'ops':PROFILE['codeAuthority']['ops']})
  return super().read_text(*args,**kwargs)
def tree(test,root):
 return {n[len(root)+1:]:m.digest(v.data) for n,v in test.fs.nodes.items() if n.startswith(root+'/') and not stat.S_ISDIR(v.mode)}
def rechain(state):
 f=state[m.FENCE];base={k:copy.deepcopy(v) for k,v in state.items() if k not in (m.FENCE,m.KEY)}
 first=m.digest(m.encoded(base));f['ledgerSha256Before']=first;epochs=[]
 for phase in ('intended','sudo-issued','sudo-done','tmpfiles-issued','tmpfiles-done','fenced'):
  epochs.append(m.digest(m.encoded(base)));f['phase']=phase;f['intendedEpochs']=list(epochs);base[m.FENCE]=copy.deepcopy(f)
 return state

def install(test):
 with patch.object(original,'FS',MetadataFS),patch.object(original,'Path',SeedPath):OLD_SETUP(test)
 f=test.fs;SlotPath.fs=f
 controller_path=R/'public-controller/ops/p0_host_context.py'
 controller_ast=ast.parse(controller_path.read_bytes())
 public=types.ModuleType('public_2e0_context');public.__file__=str(controller_path)
 exec(compile(controller_ast,'<external-exact-public-controller2e0>','exec'),public.__dict__);public.Path=SlotPath
 test.public_context=public;test.current_calls=[];real_current=public.current
 def current(**kwargs):
  test.current_calls.append({'runtimePresent':test.runtime in f.nodes,'phase':test.data().get(m.KEY,{}).get('phase')})
  return real_current(**kwargs)
 public.current=current
 profile=copy.deepcopy(PROFILE);profile['codeRoot']='.';profile['targetAuthority']['namespace']=test.ns
 code_map=tree(test,test.flat);code_map={n:code_map[n] for n in profile['codeAuthority']['ops']}
 profile['codeAuthority']['ops']=code_map;profile['ops']=code_map
 for name in profile['targetAuthority']['ops']:f.nodes[test.bundle+'/ops/'+name].data=('PUBLIC ORIGINAL gb7 TARGET '+name).encode()
 profile['targetAuthority']['ops']=tree(test,test.bundle+'/ops')
 profile['ec4']=test.ec4
 for name in m.GENERATED_OPS:f.put(test.bundle+'/ops/'+name,data=(R/'generator/generated10'/name).read_bytes())
 policy_body=(R/'policy_fence.py').read_bytes();test.policy=m.digest(policy_body)
 f.nodes[test.flat+'/policy_fence.py'].data=policy_body
 profile['policyFenceSha256']=test.policy
 native_body=(R/'inert_control_lease_native.py').read_bytes()
 f.nodes[test.flat+'/inert_control_lease_native.py'].data=native_body
 profile['nativeLeaseSha256']=m.digest(native_body)
 f.nodes[test.flat+'/SOURCE-LOCK.json'].data=m.encoded(profile)
 oldnames=[a['name'] for a in test.plan['accounts']]
 accounts=[{'name':test.ns+'-'+domain,'uid':4000+i} for i,domain in enumerate(public.DOMAINS)]
 mapping=dict(zip(oldnames,[a['name'] for a in accounts]))
 def translate(v):
  if type(v) is str:
   for old,new in mapping.items():v=v.replace(old,new)
   return v
  if type(v) is list:return [translate(x) for x in v]
  if type(v) is dict:return {translate(k):translate(x) for k,x in v.items()}
  return v
 test.state=translate(test.state);test.images=translate(test.images)
 test.plan['accounts']=accounts;test.plan['sourceCommit']=profile['targetAuthority']['generatorCommit']
 f.nodes['/selector.json'].data=m.encoded({'schemaVersion':1,'namespace':test.ns})
 test.plan['selectorSha256']=m.digest(f.nodes['/selector.json'].data)
 test.plan['quadletTreeSha256']=m.digest(m.encoded(tree(test,test.bundle+'/quadlet')))
 test.plan_sha=m.digest(m.canonical(test.plan));test.state['plan']=copy.deepcopy(test.plan)
 provenance={'schemaVersion':1,'generatorCommit':test.plan['sourceCommit'],'siteCommit':'c'*40,'generatorDirty':False,'siteDirty':False}
 f.nodes[test.bundle+'/source-provenance.json'].data=m.encoded(provenance);test.provenance=m.digest(m.encoded(provenance))
 f.nodes[test.bundle+'/site/global.settings/registry-image-ids.json'].data=m.encoded(test.images)
 f.put(test.bundle+'/build/public-build-input',data=b'PUBLIC held build closure')
 doc={'schemaVersion':1,'namespace':test.ns,'controlCommit':profile['controller']['commit'],
  'siteVmSpecSha256':m.digest(f.nodes[test.bundle+'/site/agent-vm.json'].data),'sourceProvenanceSha256':test.provenance,
  'guestName':'p0-venue-'+test.ns.removeprefix('p0test-')+'-agents','guestAddress':'10.77.0.2',
  'servicePorts':{'https':18443,'smtp':1025,'imap':1143},'domains':{d:4000+i for i,d in enumerate(public.DOMAINS)},
  'services':{d:[] for d in tuple(public.DOMAINS)+('rootful',)}}
 body=m.canonical(doc)+b'\n';context_digest=m.digest(body)
 oldslot=test.slot;test.slot=str(P(oldslot).parent/('host-'+doc['controlCommit']+'-'+context_digest))
 units={n:f.nodes[oldslot+'/units/'+n].data for n in m.HOST_NAMES}
 for name in tuple(f.nodes):
  if name==oldslot or name.startswith(oldslot+'/'):f.nodes.pop(name);f.generation+=1
 manifest_files={}
 for name,contents in [('host-role.json',body),('p0_host_context.py',(R/'public-controller/ops/p0_host_context.py').read_bytes())]+[('units/'+n,b) for n,b in units.items()]:
  f.put(test.slot+'/'+name,data=contents);manifest_files[name]=m.digest(contents)
 manifest={'role':'host','controlCommit':doc['controlCommit'],'hostContextSha256':context_digest,'files':manifest_files}
 f.put(test.slot+'/manifest.json',data=m.encoded(manifest))
 base='/usr/local/libexec/'+test.ns+'-control';f.nodes[base+'/agent-services-current-host'].data=test.slot.encode()
 test.context=public.Context(doc,digest=context_digest)
 test.context._lease_slot_manifest=manifest
 # Execute UNMODIFIED actual public function AST, not a constant context return.
 source=ast.parse((R/'public-code/venue-start-quarantine.py').read_bytes())
 fn=next(n for n in source.body if isinstance(n,ast.FunctionDef) and n.name=='host_context')
 lifecycle=types.SimpleNamespace();env={'Path':SlotPath,'stat':stat,'Refusal':m.Refused,
  'stage':types.SimpleNamespace(sha=lambda p:m.digest(f.nodes[str(p)].data)),
  'load':lambda *args:public}
 exec(compile(ast.Module(body=[fn],type_ignores=[]),'<frozen-g768-host_context>','exec'),env)
 lifecycle.host_context=env['host_context'];test.lifecycle=lifecycle
 hostpaths=[str(P('/etc/systemd/system')/test.context.unit(n)) for n in m.HOST_NAMES]
 test.state['venueHostUnitsRetirement']={'phase':'retired','contextSha256':context_digest,'neverStartedInstallerVersion':1,
  'units':[{'path':p,'sha256':manifest_files['units/'+name]} for p,name in zip(hostpaths,m.HOST_NAMES)],
  'identities':{p:{'dev':1,'ino':800+i} for i,p in enumerate(hostpaths)},'removed':hostpaths}
 frozen=m.digest(f.nodes[test.bundle+'/site/global.settings/registry-image-ids.json'].data)
 authority={'imageIds':test.images,'frozenRegistrySha256':frozen,'generatorCommit':test.plan['sourceCommit'],
  'selectorSha256':test.plan['selectorSha256'],'quadletTreeSha256':test.plan['quadletTreeSha256']}
 test.registry.authority.authority=lambda *args:copy.deepcopy(authority)
 closure={'ops':m.digest(m.encoded(tree(test,test.bundle+'/ops'))),'slot':m.digest(m.encoded(tree(test,test.slot))),
  'quadlet':m.digest(m.encoded(tree(test,test.bundle+'/quadlet'))),'site':m.digest(m.encoded(tree(test,test.bundle+'/site'))),
  'build':m.digest(m.encoded(tree(test,test.bundle+'/build'))),'imageIds':test.images,
  'frozenRegistrySha256':frozen,'provenanceSha256':test.provenance,'slotPath':test.slot,'manifest':manifest}
 test.closure=closure
 directory=m.ident(f.lstat(test.runtime));lease=m._Native.full_stat(f.lstat(test.runtime+'/lifecycle.lock'))
 policies=[]
 specs=(('/etc/sudoers.d/'+test.ns+'-agent-identity',0o440,(test.ns+'-provisioner ALL=(root) NOPASSWD: '+str(test.context.source/'agent-identity-host.py')+' *\n').encode()),
  ('/etc/tmpfiles.d/'+test.ns+'-control.conf',0o644,('d '+test.runtime+' 0700 root root -\n').encode()))
 for name,mode,contents in specs:
  f.put(name,stat.S_IFREG|mode,contents);saved=m._Native.full_stat(f.lstat(name));f.nodes.pop(name).linked=False;f.generation+=1
  policies.append({'path':name,'mode':mode,'bodySha256':m.digest(contents),'parent':m.ident(f.lstat(str(P(name).parent))),'file':saved})
 test.state[m.FENCE]={'schemaVersion':1,'phase':'fenced','namespace':test.ns,'hostContextSha256':context_digest,
  'provenanceSha256':test.provenance,'planSha256':test.plan_sha,'operationSha256':test.policy,
  'sourceClosureSha256':m.digest(m.canonical(closure)),'ledgerPath':test.ledger,'ledgerParent':m.ident(f.lstat('/audit')),
  'leaseIdentity':{'directory':directory,'file':lease},'policies':policies}
 f.nodes[test.ledger].data=m.encoded(rechain(test.state))
 receipt='/audit/original-artifact-receipt.json';f.put(receipt,stat.S_IFREG|0o600,b'SYNTHETIC receipt; NOT historical proof')
 profile['targetAuthority']['inputConfiguration']={'schemaVersion':1,'bundlePath':test.bundle,'selectorPath':'/selector.json',
  'ledgerPath':test.ledger,'provenanceSha256':test.provenance,'planSha256':test.plan_sha,
  'initialReviewedLedgerSha256':m.digest(f.nodes[test.ledger].data),'historicalArtifactReceiptPath':receipt,
  'historicalArtifactReceiptSha256':m.digest(f.nodes[receipt].data),
  'ops':{n:{'sha256':h,'mode':stat.S_IMODE(f.nodes[test.bundle+'/ops/'+n].mode)} for n,h in tree(test,test.bundle+'/ops').items()}}
 f.nodes[test.flat+'/SOURCE-LOCK.json'].data=m.encoded(profile)
 f.directory('/sys/fs/cgroup');test.tmp_overrides={}
 test.p0testslotlayout={'root':base,'slot':test.slot,'controllerCommit':profile['controller']['commit'],'controllerSha256':profile['controller']['sha256']}

def mutate(test,fn):
 before=test.data();state=copy.deepcopy(before);fn(state)
 # Valid-facts override ONLY: changing pre-fence normal history means the
 # fixture fence was produced after that history. NEVER repair a changed fence.
 if m.KEY not in state and state.get(m.FENCE)==before.get(m.FENCE) and m.FENCE in state:rechain(state)
 test.fs.nodes[test.ledger].data=m.encoded(state)
 if m.KEY not in state:
  node=test.fs.nodes[test.flat+'/SOURCE-LOCK.json'];profile=json.loads(node.data)
  profile['targetAuthority']['inputConfiguration']['initialReviewedLedgerSha256']=m.digest(m.encoded(state));node.data=m.encoded(profile)

def command(test,argv):
 if '--property=UnitPath' in argv:return '/usr/lib/systemd/system\n'
 if len(argv)>2 and argv[1]=='show' and argv[2] in m.TMPFILES:
  values={'LoadState':'loaded','ActiveState':'active','SubState':'exited','Type':'oneshot','RemainAfterExit':'yes',
   'MainPID':'0','ControlPID':'0','Result':'success','ExecMainStatus':'0','ControlGroup':'/system.slice/'+argv[2],
   'FragmentPath':'/usr/lib/systemd/system/'+argv[2],'DropInPaths':''}
  values.update(getattr(test,'tmp_overrides',{}));props=argv[-1].split('=',1)[1].split(',')
  return '\n'.join(k+'='+values[k] for k in props)+'\n'
 return OLD_COMMAND(test,argv)

def apply():
 original.NativeTests.setUp=install;original.NativeTests.mutate=mutate;original.NativeTests.command=command
