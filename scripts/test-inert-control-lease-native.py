#!/usr/bin/env python3
"""Portable ordinary-user native220/policy134 SOURCE regressions, not approval.
All path overrides select TEST dependencies only; production APIs are unchanged.
"""
import argparse,copy,hashlib,json,os,pathlib,resource,shutil,subprocess,sys,tempfile
SHA_CONTROLLER='36323e5b1afd6106da677b028aa47d4c4b4f0552437b8f8e91d8b2f92eb9927d'
def bounded(path,maximum):
 path=pathlib.Path(path)
 if path.is_symlink() or not path.is_file() or path.stat().st_size>maximum:raise ValueError('invalid bounded test input')
 return path.read_bytes()
def main():
 if os.geteuid()==0:raise SystemExit('ordinary-user SOURCE runner only; Root forbidden')
 if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode):raise SystemExit('requires -I -S -B')
 resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 repo=pathlib.Path(__file__).resolve().parents[1];fixtures=repo/'scripts/fixtures/inert_control_lease'
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--native-source',type=pathlib.Path,default=repo/'ops/host-admin/inert_control_lease_native.py')
 parser.add_argument('--policy-source',type=pathlib.Path,default=repo/'ops/host-admin/policy_fence.py')
 parser.add_argument('--fixture-config',type=pathlib.Path,default=fixtures/'fixture-config.json')
 parser.add_argument('--controller-source-root',type=pathlib.Path,required=True,help='TEST-only explicit owner checkout/fixture root containing ops/p0_host_context.py; exact public2e0 bytes required')
 parser.add_argument('--generator-source-root',type=pathlib.Path,required=True,help='TEST-only explicit public dataset root containing code57/ and target57/; all public committed pins are checked, no Git/network fetch')
 parser.add_argument('--group',choices=('all','native','policy'),default='all')
 parser.add_argument('--output',type=pathlib.Path)
 args=parser.parse_args();native=bounded(args.native_source,2097152);policy=bounded(args.policy_source,1048576)
 config=json.loads(bounded(args.fixture_config,262144));profile=copy.deepcopy(config['profile'])
 if config.get('actualTarget') is not None or profile['targetAuthority']['inputConfiguration'] is not None:raise SystemExit('actual private configuration forbidden')
 if profile['targetAuthority']['namespace']!='p0test-example':raise SystemExit('synthetic example namespace required')
 if len(profile['codeAuthority']['ops'])!=57 or len(profile['targetAuthority']['ops'])!=57:raise SystemExit('complete public57 maps required')
 if config['controller']['sha256']!=SHA_CONTROLLER or profile['controller']['commit']!='2e0f9c8a73ecfafb1bcbc2fdea4718d25cf14e29':raise SystemExit('exact public controller2e0 required')
 controller=bounded(args.controller_source_root/'ops/p0_host_context.py',262144)
 if hashlib.sha256(controller).hexdigest()!=SHA_CONTROLLER:raise SystemExit('external public controller source mismatch')
 public_members=[]
 for folder,authority in (('code57',profile['codeAuthority']),('target57',profile['targetAuthority'])):
  for name,sha in authority['ops'].items():
   if pathlib.PurePosixPath(name).name!=name:raise SystemExit('invalid public fixture member')
   body=bounded(args.generator_source_root/folder/name,1048576)
   if hashlib.sha256(body).hexdigest()!=sha:raise SystemExit('public generator source mismatch')
   public_members.append((folder,name,body))
 groups=['native'] if args.group=='native' else ['policy-104','policy-code9','policy-budget9','policy-fresh12']
 if args.group=='all':groups=['native']+groups
 summaries=[];failed=False
 with tempfile.TemporaryDirectory(prefix='portable-source-tests-') as temporary:
  root=pathlib.Path(temporary);root.chmod(0o700)
  for file in fixtures.rglob('*'):
   if file.is_symlink():raise SystemExit('fixture symlink forbidden')
   if file.is_file():
    dest=root/file.relative_to(fixtures);dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(bounded(file,2097152))
  for folder,name,body in public_members:
   dest=root/'generator'/folder/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(body)
  dest=root/'public-controller/ops/p0_host_context.py';dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(controller)
  for folder in ('USER_TMP','evidence'):(root/folder).mkdir(mode=0o700)
  (root/'inert_control_lease_native.py').write_bytes(native);(root/'policy_fence.py').write_bytes(policy)
  profile['nativeLeaseSha256']=hashlib.sha256(native).hexdigest();profile['policyFenceSha256']=hashlib.sha256(policy).hexdigest()
  for name in ('SOURCE-LOCK.json','SOURCE-LOCK.template.json'):(root/name).write_text(json.dumps(profile,sort_keys=True,indent=2)+'\n')
  env={'PATH':'/usr/bin:/bin','HOME':os.environ.get('HOME',str(root)),'TMPDIR':str(root/'USER_TMP'),'PYTHONDONTWRITEBYTECODE':'1','PYTHONNOUSERSITE':'1','LC_ALL':'C'}
  for group in groups:
   run=subprocess.run([sys.executable,'-I','-S','-B',str(root/'portable_worker.py'),group],cwd=root,env=env,check=False)
   file=root/(group+'-RESULTS.json')
   if file.is_file():summaries.append(json.loads(file.read_text()))
   else:summaries.append({'group':group,'testsRun':0,'failures':[],'errors':[['worker-startup','no complete result; see raw stderr']]})
   failed=failed or run.returncode!=0
  result={'scope':'portable SOURCE/fakes preparation only','groups':summaries,'testsRun':sum(row['testsRun'] for row in summaries),'nativeSourceSha256':hashlib.sha256(native).hexdigest(),'policySourceSha256':hashlib.sha256(policy).hexdigest(),'actualTarget':None,'nativeApproval':False,'publicationApproved':False}
  if args.output:
   args.output.mkdir(parents=True,exist_ok=True);(args.output/'RESULTS.json').write_text(json.dumps(result,indent=2)+'\n')
   for name in ('NEW-POLICY-FULL-SCALE.json','DATA-SCALE-PROOF.json','ACTUAL-S2-CONTEXT-SCALE-PROOF.json'):
    if (root/name).is_file():shutil.copyfile(root/name,args.output/name)
  print(json.dumps({k:v for k,v in result.items() if k!='groups'},indent=2));return failed
if __name__=='__main__':sys.exit(main())
