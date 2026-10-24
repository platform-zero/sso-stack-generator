#!/usr/bin/env python3
"""Rootless finance source/model/temp-FD tests, NEVER native/installed proof.

All accounts, namespaces, managers, engines, DB rows and Root ownership are
explicit model projections. Only disposable files/FDs and owning parsers run.
"""
import argparse
import contextlib
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]
OPS = BASE / 'runtime-generator/podman-ops'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


m = load('rootless_finance_owner', OPS / 'native-finance-ownership.py')
n = m.n
v = load('rootless_finance_descriptor', OPS / 'verify-agent-vm-bundle.py')
legacy = load('rootless_finance_legacy_fixture', BASE / 'scripts/test-native-finance-ownership.py')
hook = load('rootless_finance_shell_fixture', BASE / 'scripts/test-native-finance-installer-hook.py')
recovery = load('rootless_finance_recovery', OPS / 'native-recovery-owner.py')
ACTUAL_PUBLIC_ROLE = None
ACTOR = dict(uid=780, gid=780, user='webservices-lab-platform', home='/home/webservices-lab-platform',
             subuidStart=200000, overflowUid=65534)
ACCOUNT = NS(pw_uid=780, pw_gid=780, pw_name=ACTOR['user'], pw_dir=ACTOR['home'])
CGROUP = '/user.slice/user-780.slice/user@780.service/app.slice/webservices-keycloak-configure.service'
CID = 'a' * 64
FINANCE = hook.FINANCE
RUNTIME = FINANCE.with_name('configure-runtime.sh')


def roles():
    domains = {'domains': []}; ir = {'services': {}, 'volumes': {}}
    for domain, uid, names in [('platform', 780, ('keycloak-configure', 'keycloak', 'postgres')),
                                ('finance', 783, ('firefly-identity-check',))]:
        root = '/mnt/stack/source-role/' + domain
        user = 'webservices-lab-' + domain
        domains['domains'].append(dict(name=domain, uid=uid, user=user, volumeRoot=root + '/volumes',
                                       stateRoot=root + '/state', graphRoot=root + '/graph'))
        for name in names:
            ir['services'][name] = dict(placement='rootless', rootlessDomain=domain, rootlessUser=user,
                rootlessVolumeRoot=root + '/volumes', lifecycle='oneshot' if name in ('keycloak-configure', 'firefly-identity-check') else 'daemon',
                module={'keycloak-configure':'keycloak-auth-gateway','keycloak':'keycloak','postgres':'postgres','firefly-identity-check':'firefly-iii'}[name])
    ir['services']['keycloak-configure'].update(user='1000:0',
        environment=dict(FIREFLY_NATIVE_OWNERSHIP_FILE=m.INPUT, DOMAIN='example.invalid', KEYCLOAK_REALM='webservices'), volumes=[m.MOUNT])
    ir['services']['firefly-identity-check'].update(user='33:33', userns='keep-id:uid=33,gid=33')
    return ir, domains


def descriptor():
    return v.native_finance_reference(*roles())


def execution():
    return dict(pid=31, process=dict(uid=200999, gid=780, cgroup=CGROUP, startTicks=100),
                uidMap=[[0,780,1],[1,200000,65536]], gidMap=[[0,780,1],[1,200000,65536]],
                user='1000:0', userns='', mount=dict(source=str(m.SLOT), target='/run/p0-finance', rw=False, type='bind'))


def source_frame():
    source = dict(authority=copy.deepcopy(ACTOR), imageUser='1000',
                  financeScriptSha256=m.sha(FINANCE.read_bytes()), runtimeScriptSha256=m.sha(RUNTIME.read_bytes()))
    for name, key in [('keycloak-configure','configure'),('keycloak','keycloak'),('postgres','postgres')]:
        source[key] = dict(source=ACTOR['home']+'/.config/containers/systemd/webservices-'+name+'.container', sourceSha256='b'*64,
                           fragment='/run/user/780/systemd/generator/webservices-'+name+'.service', fragmentSha256='c'*64, image='sha256:'+'d'*64)
    return source


def native_receipt():
    value = legacy.receipt(); value['source'] = source_frame()
    value['original']['container'] = dict(id=CID, image=value['source']['configure']['image'], source=value['source']['configure'],
        conmon=dict(uid=780, cgroup=CGROUP, startTicks=90), execution=execution())
    value['original']['database']['source'] = value['source']['postgres']
    return value


class SourceRole(unittest.TestCase):
    def test_complete_canonical_rootless_cohort(self):
        ir, domains = roles(); d = v.native_finance_reference(ir, domains)
        self.assertEqual(d['actor'], dict(domain='platform',uid=780,user=ACTOR['user']))
        self.assertEqual(d['consumer']['user'], '1000:0')
        self.assertTrue(d['readOnly'])
        self.assertEqual(v.standalone_boundaries(ir, domains, v.canonical_path('/mnt/stack/source-role'))['keycloak-configure'][0][0], v.canonical_path(str(m.SLOT)))

    def test_actual_sanitized_public_role_with_owning_configure_stanza(self):
        if ACTUAL_PUBLIC_ROLE is None:
            self.skipTest('explicit sanitized public role fixture not supplied')
        actual = json.loads(ACTUAL_PUBLIC_ROLE.read_bytes())
        ir = {'services': copy.deepcopy(actual['services']), 'volumes': {}}
        configure = ir['services']['keycloak-configure']
        configure['volumes'] = configure.pop('nativeFinanceVolumes')
        configure['environment'] = {'FIREFLY_NATIVE_OWNERSHIP_FILE': configure.pop('nativeFinanceInput')}
        stanza = hook.GATEWAY.read_text().split('  keycloak-auth-gateway:',1)[0]
        self.assertIn('    user: "1000:0"', stanza)
        configure['user'] = '1000:0'  # literal from the new owning configure-only stanza
        finance = ir['services']['firefly-identity-check']
        domains = {'domains': copy.deepcopy(actual['platform']) + [dict(name='finance',uid=783,user=finance['rootlessUser'],volumeRoot=finance['rootlessVolumeRoot'])]}
        self.assertEqual(v.native_finance_reference(ir,domains)['actor']['uid'],780)
        self.assertEqual(v.standalone_boundaries(ir,domains,v.canonical_path('/mnt/stack/host-stack-lab'))['keycloak-configure'][0][1],'/run/p0-finance')

    def test_not_a_rootless_enum_or_arbitrary_identity_waiver(self):
        for name in ('keycloak-configure','keycloak','postgres','firefly-identity-check'):
            for key, value in [('placement','rootful'),('rootlessDomain','apps'),('rootlessUser','foreign'),
                               ('rootlessVolumeRoot','/mnt/stack/other'),('module','foreign'),('lifecycle','on-demand')]:
                ir, domains = roles(); ir['services'][name][key] = value
                with self.subTest(name=name,key=key), self.assertRaises(ValueError): v.native_finance_reference(ir,domains)
        for key,value in [('user','0:0'),('userns','host'),('userns','keep-id'),('userns','private')]:
            ir,domains=roles();ir['services']['keycloak-configure'][key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):v.native_finance_reference(ir,domains)

    def test_wrong_or_missing_domain_metadata_refuses(self):
        for domain in ('platform','finance'):
            for key,value in [('uid',1000),('uid',True),('user','webservices-platform')]:
                ir,domains=roles();next(row for row in domains['domains'] if row['name']==domain)[key]=value
                with self.subTest(domain=domain,key=key),self.assertRaises(ValueError):v.native_finance_reference(ir,domains)
        for key,value in [('user','0:0'),('userns','host'),('userns','keep-id:uid=1000,gid=1000')]:
            ir,domains=roles();ir['services']['firefly-identity-check'][key]=value
            with self.subTest(checker=key,value=value),self.assertRaises(ValueError):v.native_finance_reference(ir,domains)
        ir,domains=roles();domains['domains'].append(copy.deepcopy(domains['domains'][0]))
        with self.assertRaises(ValueError):v.native_finance_reference(ir,domains)
        with self.assertRaises(ValueError):v.native_finance_reference(ir)

    def test_historical_descriptor_is_not_reclassified(self):
        old=load('rootless_legacy_reference_fixture',BASE/'scripts/test-native-finance-reference.py')
        d=v.native_finance_reference(old.fixture_ir())
        self.assertEqual(d['placement'],'rootful');self.assertNotIn('actor',d);self.assertNotIn('transport',d)


class CanonicalAccount(unittest.TestCase):
    def account(self, *, members=(), extra=False, uid=780):
        account=NS(pw_uid=uid,pw_gid=780,pw_name=ACTOR['user'],pw_dir=ACTOR['home'])
        group=NS(gr_gid=780,gr_name=ACTOR['user'],gr_mem=list(members))
        stack=contextlib.ExitStack()
        stack.enter_context(patch.object(n.pwd,'getpwnam',return_value=account))
        stack.enter_context(patch.object(n.pwd,'getpwuid',return_value=account))
        stack.enter_context(patch.object(n.pwd,'getpwall',return_value=[account]+([NS(pw_name='foreign',pw_gid=780)] if extra else [])))
        stack.enter_context(patch.object(n.grp,'getgrnam',return_value=group))
        stack.enter_context(patch.object(n.grp,'getgrgid',return_value=group))
        stack.enter_context(patch.object(n.storage,'namespace_root_id',return_value=200000))
        stack.enter_context(patch.object(Path,'read_text',return_value='65534\n'))
        return stack

    def test_exact_nss_and_kernel_source_projection(self):
        with self.account():
            self.assertEqual(n.finance_actor(descriptor()),ACTOR)
            self.assertEqual(n.finance_file_profile(descriptor()),dict(gid=780,directoryMode=0o750,fileMode=0o440))

    def test_foreign_account_primary_or_supplemental_member_refuses(self):
        for options in ({'members':['foreign']},{'extra':True},{'uid':1000}):
            with self.subTest(options=options),self.account(**options),self.assertRaises(ValueError):n.finance_actor(descriptor())

    def test_identity_flags_are_not_permissions(self):
        for key,value in [('actor',{'domain':'platform','uid':1000,'user':'operator'}),('consumer',{'user':'0:0'}),('transport','world-readable')]:
            d=descriptor();d[key]=value
            with self.subTest(key=key),self.account(),self.assertRaises(ValueError):n.finance_actor(d)

    def test_rootful_profile_does_not_query_actor_nss(self):
        with patch.object(n.pwd,'getpwnam',side_effect=AssertionError('unrelated account read')):
            self.assertEqual(n.finance_file_profile(),dict(gid=0,directoryMode=0o755,fileMode=0o444))


class NamespaceOrigin(unittest.TestCase):
    def test_pure_original_frame_and_retained_receipt(self):
        value=native_receipt()
        self.assertEqual(m.original_receipt(value,source_frame(),legacy.ISSUER),legacy.EDGE)
        for field in ('execution','conmon'):
            bad=copy.deepcopy(value);bad['original']['container'][field]={}
            with self.subTest(field=field),self.assertRaises((ValueError,KeyError)):m.original_receipt(bad,source_frame(),legacy.ISSUER)

    def test_wrong_uid_gid_namespace_mapping_mount_and_scope_refuse(self):
        changes=[('user','0:0'),('userns','host'),('uidMap',[[0,0,65537]]),('gidMap',[[0,0,65537]]),
                 ('mount',dict(source='/var/lib',target='/run/p0-finance',rw=False,type='bind')),
                 ('mount',dict(source=str(m.SLOT),target='/run/p0-finance',rw=True,type='bind'))]
        for key,value in changes:
            frame=execution();frame[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):m.rootless_execution(frame,ACTOR,CID,CGROUP)
        for key,value in [('uid',780),('gid',0),('cgroup','/system.slice/foreign.service')]:
            frame=execution();frame['process'][key]=value
            with self.subTest(process=key),self.assertRaises(ValueError):m.rootless_execution(frame,ACTOR,CID,CGROUP)

    def test_exact_actor_cid_libpod_scope_not_other_scope(self):
        frame=execution();frame['process']['cgroup']='/user.slice/user-780.slice/user@780.service/user.slice/libpod-'+CID+'.scope'
        self.assertEqual(m.rootless_execution(frame,ACTOR,CID,CGROUP),frame)
        frame['process']['cgroup']=frame['process']['cgroup'].replace(CID,'b'*64)
        with self.assertRaises(ValueError):m.rootless_execution(frame,ACTOR,CID,CGROUP)
        foreign=CGROUP.replace('webservices-keycloak-configure.service','other.service')
        frame=execution();frame['process']['cgroup']=foreign
        with self.assertRaises(ValueError):m.rootless_execution(frame,ACTOR,CID,foreign)

    def backend(self):
        backend=object.__new__(m.Native);backend.actor=copy.deepcopy(ACTOR)
        backend.units={'keycloak-configure':NS(scope='rootless-platform')}
        backend.commands={'rootless-platform':(['actor-manager'],['actor-podman']), 'rootful':(['FORBIDDEN'],['FORBIDDEN'])}
        frame=execution()
        value=dict(id=CID,pid=frame['pid'],user=frame['user'],userns=frame['userns'],mounts=[frame['mount']])
        calls=[]
        def run(args,timeout):
            self.assertEqual(args[0],'actor-podman');calls.append(args)
            return NS(stdout=json.dumps(value))
        backend.selection=NS(run=run,left=lambda:100)
        proc=dict(frame['process']);proc.pop('gid')
        scalars={'uid_map':'0 780 1\n1 200000 65536\n','gid_map':'0 780 1\n1 200000 65536\n','status':'Gid:\t780\t780\t780\t780\n'}
        return backend,value,proc,scalars,calls

    def test_actual_namespace_observer_uses_actor_engine_and_kernel_scalars(self):
        backend,value,proc,scalars,calls=self.backend()
        with patch.object(n,'process_fields',return_value=proc) as process,patch.object(m,'finance_proc',side_effect=lambda pid,name:scalars[name]):
            result=backend.execution(CID,{'ControlGroup':CGROUP})
        self.assertEqual(result,execution());self.assertEqual(len(calls),2)
        self.assertEqual(process.call_args.args,(31,200999))

    def test_namespace_or_pid_race_refuses(self):
        backend,value,proc,scalars,calls=self.backend()
        count=0
        def scalar(pid,name):
            nonlocal count
            if name=='uid_map':
                count+=1
                if count>1:return '0 780 1\n1 300000 65536\n'
            return scalars[name]
        with patch.object(n,'process_fields',return_value=proc),patch.object(m,'finance_proc',side_effect=scalar),self.assertRaises(ValueError):
            backend.execution(CID,{'ControlGroup':CGROUP})


class ActualBackendContext(unittest.TestCase):
    def create(self, *, symbolic=False, wrong_scope=None, image_user='1000', bad_handoff=False):
        ir,domains=roles();source=source_frame();calls=[];reads=[]
        if symbolic:ir['services']['keycloak-configure']['environment']['DOMAIN']='${DOMAIN}'
        units=[NS(container=name,name='webservices-'+name+'.service',scope=wrong_scope if name=='postgres' and wrong_scope else 'rootless-platform',role='oneshot' if name=='keycloak-configure' else 'daemon') for name in ('keycloak-configure','keycloak','postgres')]
        loaded={};images={}
        for unit in units:
            key='configure' if unit.container=='keycloak-configure' else unit.container
            loaded[unit.name]={k:value for k,value in source[key].items() if k!='image'}
            images[unit.name]={'configId':source[key]['image']}
        old=dict(phase='starting',readiness=dict(loadedInputs={'rootless-platform':loaded},images={'rootless-platform':images}))
        env=b'DOMAIN=example.invalid\n'
        old['domainRuntimeProjections']={'platform':{'environmentStoreHandoff':dict(kind='domain-persistent-environment',domain='platform',uid=780,gid=780,
            stateStore=domains['domains'][0]['stateRoot']+'/runtime-env',files={'keycloak-configure.env':{'sha256':m.sha(env)}})}}
        if bad_handoff:old['domainRuntimeProjections']['platform']['environmentStoreHandoff']['files']['keycloak-configure.env']['sha256']='e'*64
        release=Path('/source-fixture/root/releases/one');root=release.parent.parent
        def run(args,timeout):
            calls.append(args);self.assertEqual(args[0],'actor-podman' if 'image' in args else 'actor-manager')
            if 'image' in args:return NS(stdout=json.dumps(image_user))
            unit=next(unit for unit in units if unit.name==args[-1]);key='configure' if unit.container=='keycloak-configure' else unit.container
            props={name:'' for name in m.r.PROPERTIES}
            props.update(Id=unit.name,LoadState='loaded',DropInPaths='',ConditionResult='yes',AssertResult='yes',Type='oneshot' if unit.role=='oneshot' else 'notify',SourcePath=source[key]['source'],FragmentPath=source[key]['fragment'])
            return NS(stdout='\n'.join(k+'='+v for k,v in props.items()))
        selection=NS(ir=ir,domains=domains,plan=units,deadline=0,snapshot=lambda:{'intentSha256':'f'*64},installed_sources=lambda:True,
            commands=lambda:{'rootless-platform':(['actor-manager'],['actor-podman']), 'rootful':(['FORBIDDEN'],['FORBIDDEN'])},
            source_identity=lambda unit,sp,fp:loaded[unit.name],run=run,left=lambda:100,
            account=lambda scope:ACCOUNT,actor_custody=lambda account,path:{path.parent:(780,780,0o700)})
        publisher=(OPS/'native-finance-ownership.py').read_bytes()
        def read(path,**kwargs):
            reads.append((path,kwargs))
            if path==release/'bundle.json':return json.dumps({'liveOps':{'ops/native-finance-ownership.py':m.sha(publisher)}}).encode()
            if path==release/'ops/native-finance-ownership.py':return publisher
            if path==release/'runtime/configs/keycloak/configure-finance.sh':return FINANCE.read_bytes()
            if path==release/'runtime/configs/keycloak/configure-runtime.sh':return RUNTIME.read_bytes()
            if path==Path(domains['domains'][0]['stateRoot'])/'runtime-env/keycloak-configure.env':
                self.assertEqual(kwargs['owner'],780);self.assertTrue(kwargs['private']);return env
            raise AssertionError('unclaimed fixture read '+str(path))
        with patch.object(n,'Selection',return_value=selection),patch.object(n,'finance_actor',return_value=copy.deepcopy(ACTOR)),\
             patch.object(n,'read_file',side_effect=read),patch.object(m.os,'geteuid',return_value=0),patch.object(n,'boot_id',return_value=legacy.uid(3)):
            backend=m.Native(root,release,old)
        return backend,calls,reads

    def test_actual_constructor_selects_own_manager_engine_and_image_user(self):
        backend,calls,reads=self.create()
        self.assertEqual(backend.actor,ACTOR);self.assertEqual(backend.source,source_frame())
        self.assertTrue(all('FORBIDDEN' not in command for command in calls))

    def test_domain_resolves_from_actor_persistent_store_not_operator_root(self):
        backend,calls,reads=self.create(symbolic=True)
        self.assertEqual(backend.issuer,legacy.ISSUER)
        self.assertTrue(any(str(path).endswith('/platform/state/runtime-env/keycloak-configure.env') for path,kw in reads))
        self.assertFalse(any(path==backend.root/'runtime-env/keycloak-configure.env' for path,kw in reads))

    def test_foreign_or_rootful_database_scope_refuses_before_native_query(self):
        with self.assertRaises(ValueError):self.create(wrong_scope='rootful')

    def test_actual_image_user_and_actor_environment_store_handoff_refuse_drift(self):
        with self.assertRaises(ValueError):self.create(image_user='0:0')
        with self.assertRaises(ValueError):self.create(symbolic=True,bad_handoff=True)

    def test_actual_live_cid_conmon_belong_to_actor_runtime(self):
        backend,calls,reads=self.create();unit=backend.units['keycloak-configure']
        value=dict(name='keycloak-configure',id=CID,unit=unit.name,running=True,dead=False,restarting=False,status='running',image=backend.source['configure']['image'],conmonPid=41,
                   pid=31,healthConfigured=False,health='',restartCount=0,startedAt='source-fixture-time')
        self.assertEqual(set(value),m.r.CONTAINER_FIELDS)
        observed=[]
        commands=[]
        def inspect(args,timeout):commands.append(args);self.assertEqual(args[0],'actor-podman');return NS(stdout=json.dumps(value))
        backend.selection.run=inspect
        def read(path,**kwargs):
            observed.append((path,kwargs));self.assertEqual(path,Path('/run/user/780/webservices-keycloak-configure.cid'))
            self.assertEqual(kwargs['owner'],780);return (CID+'\n').encode()
        with patch.object(n,'read_file',side_effect=read),patch.object(n,'process_fields',return_value=dict(uid=780,cgroup=CGROUP,startTicks=90)) as process,\
             patch.object(backend,'execution',return_value=execution()):
            result=backend.live('keycloak-configure',{'ControlGroup':CGROUP,'SourcePath':backend.source['configure']['source'],'FragmentPath':backend.source['configure']['fragment']})
            self.assertEqual(result['conmon']['uid'],780);self.assertEqual(result['execution'],execution())
            for key,bad in [('restartCount',1),('pid',100)]:
                saved=value[key];value[key]=bad
                with self.subTest(change=key),self.assertRaises(ValueError):
                    backend.live('keycloak-configure',{'ControlGroup':CGROUP,'SourcePath':backend.source['configure']['source'],'FragmentPath':backend.source['configure']['fragment']})
                value[key]=saved
        self.assertEqual(process.call_args.args,(41,780));self.assertEqual(len(observed),6)
        self.assertEqual(len(commands),3)

    def test_native_db_export_uses_postgres_own_store_only(self):
        backend,calls,reads=self.create();observed=[]
        def run(args,timeout):observed.append(args);return NS(stdout=json.dumps([legacy.EDGE]))
        backend.selection.run=run
        with patch.object(backend,'props',return_value=dict(ActiveState='active',Result='success')),\
             patch.object(backend,'live',return_value=dict(id=CID,image='sha256:'+'d'*64)):
            edge,origin=backend.export_edge()
        self.assertEqual(edge,legacy.EDGE);self.assertEqual(observed[0][0],'actor-podman')
        self.assertEqual(observed[0][-1],m.SQL);self.assertNotIn('FORBIDDEN',observed[0])


class RootlessReference(unittest.TestCase):
    def setUp(self):
        self.root=Path('/source-fixture/root');self.release=self.root/'releases/one'
        self.ir,self.domains=roles();self.d=v.native_finance_reference(self.ir,self.domains)
        self.source=source_frame();self.native=native_receipt()
        self.publisher=(OPS/'native-finance-ownership.py').read_bytes()
        self.content=dict(schemaVersion=1,kind='root-native-finance-input',root=str(self.root),release=str(self.release),intentSha256='e'*64,
            sourceSha256=m.FINANCE_SOURCE_SHA256,issuer=legacy.ISSUER,status='retained',nativeFinanceOwnership=legacy.EDGE,
            transport=dict(kind='root-owned-platform-group-readonly-v1',actorUid=780,actorGid=780,actorUser=ACTOR['user'],consumerUid=1000,consumerGid=0,overflowUid=65534))
        self.physical=dict(directory=dict(path=str(m.SLOT),identity=[1,2,0,780,stat.S_IFDIR|0o750,2,4096,1,2],mountId=17),
            input=dict(path=str(m.SLOT/'input.json'),identity=[1,3,0,780,stat.S_IFREG|0o440,1,1024,1,2],mountId=17,sha256='b'*64,content=self.content))
        pins={'stack.ir.json':m.sha(m.encoded(self.ir)),'podman-domains.json':m.sha(m.encoded(self.domains))}
        self.ref=dict(schemaVersion=1,kind='root-native-finance-reference',status='completed',root=str(self.root),release=str(self.release),inputs=pins,
            intentSha256='e'*64,descriptor=self.d,publisher=dict(path='ops/native-finance-ownership.py',sha256=m.sha(self.publisher),origin='root-native-finance-ownership'),**self.physical)
        loaded={};images={}
        for name,key in [('keycloak-configure','configure'),('keycloak','keycloak'),('postgres','postgres')]:
            loaded['webservices-'+name+'.service']={k:v for k,v in self.source[key].items() if k!='image'}
            images['webservices-'+name+'.service']={'configId':self.source[key]['image']}
        self.intent=dict(release=str(self.release),inputs=pins,nativeFinanceReference=self.ref,nativeFinanceOwnershipReceipt=self.native,
                         readiness=dict(loadedInputs={'rootless-platform':loaded},images={'rootless-platform':images}))

    def observe(self, *, bad_cas=False, physical=None):
        def read(path,**kw):
            values={self.release/'stack.ir.json':m.encoded(self.ir),self.release/'podman-domains.json':m.encoded(self.domains),
                self.root/'.install-intent.json':m.encoded(self.intent),self.release/'installation-receipt.json':b'{}' if bad_cas else m.encoded(self.intent),
                self.release/'bundle.json':m.encoded({'liveOps':{'ops/native-finance-ownership.py':m.sha(self.publisher)}}),
                self.release/'ops/native-finance-ownership.py':self.publisher,
                self.release/'runtime/configs/keycloak/configure-finance.sh':FINANCE.read_bytes(),
                self.release/'runtime/configs/keycloak/configure-runtime.sh':RUNTIME.read_bytes()}
            self.assertIn(path,values);return values[path]
        with patch.object(n,'read_file',side_effect=read),patch.object(n,'finance_actor',return_value=copy.deepcopy(ACTOR)),\
             patch.object(n,'lock_held'),patch.object(n,'pointer'),patch.object(n,'directory_pin',return_value=(0,1000,0o700)),\
             patch.object(n,'finance_reference_files',return_value=physical or self.physical):
            return n.verify_native_finance_reference(self.root,self.release,self.intent)

    def test_exact_current_root_reference_with_original_namespace_frame(self):
        result=self.observe();self.assertEqual(result['status'],'completed')
        self.assertFalse(result['activationAuthorized']);self.assertFalse(result['readinessAuthorized'])

    def test_root_reference_dual_cas_namespace_source_and_actor_drift_refuse(self):
        with self.assertRaises(ValueError):self.observe(bad_cas=True)
        saved=copy.deepcopy(self.native)
        for change in ('namespace','source','conmon','missing-origin'):
            self.intent['nativeFinanceOwnershipReceipt']=copy.deepcopy(saved)
            item=self.intent['nativeFinanceOwnershipReceipt']
            if change=='namespace':item['original']['container']['execution']['uidMap'][0][1]=0
            if change=='source':item['source']['configure']['sourceSha256']='f'*64
            if change=='conmon':item['original']['container']['conmon']['uid']=0
            if change=='missing-origin':item.pop('original')
            with self.subTest(change=change),self.assertRaises((ValueError,KeyError)):self.observe()

    def test_transport_flags_and_physical_reference_drift_refuse(self):
        for key,value in [('actorUid',1000),('actorGid',0),('consumerUid',0),('overflowUid',0),('kind','site-approved')]:
            saved=copy.deepcopy(self.content['transport']);self.content['transport'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.observe()
            self.content['transport']=saved
        physical=copy.deepcopy(self.physical);physical['input']['identity'][1]=99
        with self.assertRaises(ValueError):self.observe(physical=physical)

    def test_recovery_finance_adapter_preserves_exact_validated_gid(self):
        classes=[cls for cls in vars(recovery).values() if isinstance(cls,type) and hasattr(cls,'finance_reference_owners')]
        self.assertEqual(len(classes),1)
        obj=object.__new__(classes[0]);obj.finance_reference=self.observe()
        self.assertEqual(obj.finance_reference_owners(),dict(uids=[0],gids=[780],ranges=[]))
        obj.finance_reference['reference']['input']['identity'][3]=0
        with self.assertRaises(ValueError):obj.finance_reference_owners()


class TemporaryFinanceFD(unittest.TestCase):
    """Real no-follow/FD/inode/mode/xattr operations; Root UID/GID projected."""
    def setUp(self):
        previous=os.umask(0o077);self.addCleanup(os.umask,previous)
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.parent=Path(self.temp.name);self.slot=self.parent/'namespace'
        self.slot.mkdir(mode=0o750);self.slot.chmod(0o750)
        self.leaf=self.slot/'input.json';self.leaf.write_text('{"fixtureOnly":true}\n');self.leaf.chmod(0o440)
        self.real_stat=os.stat;self.real_fstat=os.fstat;self.real_pread=os.pread
        self.bad_uid=None;self.bad_gid=None
        def project(info):
            fields=('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
            values={key:getattr(info,key) for key in fields};values.update(st_uid=0 if self.bad_uid is None else self.bad_uid,st_gid=780 if self.bad_gid is None else self.bad_gid)
            return NS(**values)
        self.project=project
        self.addCleanup(patch.stopall)
        patch.object(n.os,'stat',side_effect=lambda *args,**kw:project(self.real_stat(*args,**kw))).start()
        patch.object(n.os,'fstat',side_effect=lambda *args:project(self.real_fstat(*args))).start()
        patch.object(n,'finance_actor',return_value=copy.deepcopy(ACTOR)).start()

    def observe(self):
        real_path=Path
        with patch.object(n,'Path',side_effect=lambda value: self.slot if str(value)=='/var/lib/webservices-native-finance' else real_path(value)),\
             patch.object(n,'root_directory'):
            # Only fixture ancestor UID/permissions are assumed; selected leaf
            # profile, exact names, links, ACL/xattr, mounts and races are real.
            return n.finance_reference_files(descriptor())

    def test_selected_0750_0440_profile_and_real_fd_hash(self):
        result=self.observe();self.assertEqual(result['input']['content'],{'fixtureOnly':True})
        self.assertEqual(result['directory']['identity'][2:4],[0,780])
        self.assertEqual(result['input']['identity'][2:4],[0,780])
        self.assertEqual(result['input']['sha256'],m.sha(self.leaf.read_bytes()))

    def test_world_read_write_or_foreign_owner_profiles_refuse(self):
        for mode in (0o444,0o640,0o400,0o660):
            self.leaf.chmod(mode)
            with self.subTest(file=oct(mode)),self.assertRaises(ValueError):self.observe()
        self.leaf.chmod(0o440)
        for mode in (0o755,0o700,0o770):
            self.slot.chmod(mode)
            with self.subTest(directory=oct(mode)),self.assertRaises(ValueError):self.observe()
        self.slot.chmod(0o750)
        for key,value in [('bad_uid',780),('bad_gid',0)]:
            setattr(self,key,value)
            with self.subTest(key=key),self.assertRaises(ValueError):self.observe()
            setattr(self,key,None)

    def test_symlink_hardlink_additional_file_and_oversize_refuse(self):
        self.leaf.unlink();self.leaf.symlink_to(self.parent/'missing')
        with self.assertRaises((OSError,ValueError)):self.observe()
        self.leaf.unlink();self.leaf.write_text('{}');self.leaf.chmod(0o440)
        linked=self.parent/'second-link';os.link(self.leaf,linked)
        with self.assertRaises(ValueError):self.observe()
        linked.unlink();extra=self.slot/'foreign';extra.write_text('{}')
        with self.assertRaises(ValueError):self.observe()
        extra.unlink();self.leaf.chmod(0o600);self.leaf.write_bytes(b' '*65537);self.leaf.chmod(0o440)
        with self.assertRaises(ValueError):self.observe()

    def test_extended_attribute_refuses(self):
        self.leaf.chmod(0o600)
        os.setxattr(self.leaf,'user.finance-fixture',b'not-approved');self.leaf.chmod(0o440)
        with self.assertRaises(ValueError):self.observe()

    def test_real_fd_path_replacement_race_refuses(self):
        def changed(fd,size,offset):
            body=self.real_pread(fd,size,offset);self.leaf.rename(self.parent/'old-input')
            self.leaf.write_bytes(body);self.leaf.chmod(0o440);return body
        with patch.object(n.os,'pread',side_effect=changed),self.assertRaises(ValueError):self.observe()

    def test_new_namespace_only_gets_finite_permissions_never_existing_repair(self):
        self.leaf.unlink();self.slot.rmdir()
        selected=NS(walk_directory=lambda path:(os.open(self.parent,os.O_RDONLY|os.O_DIRECTORY),[]),unchanged=lambda pins:None)
        with patch.object(m,'SLOT',self.slot),patch.object(n,'load',return_value=selected),patch.object(m.os,'fchown') as chown:
            fd=m.slot_directory(descriptor());os.close(fd)
            self.assertEqual(stat.S_IMODE(self.real_stat(self.slot).st_mode),0o750)
            self.assertEqual(chown.call_args.args[1:],(0,780))
            chown.reset_mock();self.slot.chmod(0o755)
            with self.assertRaises(ValueError):m.slot_directory(descriptor())
            chown.assert_not_called();self.assertEqual(stat.S_IMODE(self.real_stat(self.slot).st_mode),0o755)

    def test_actual_publisher_assigns_root_group_0440_without_broader_writes(self):
        self.leaf.unlink();value=dict(kind='root-native-finance-input',root='/fixture/root')
        with patch.object(m,'SLOT',self.slot),patch.object(m,'slot_directory',side_effect=lambda desc:os.open(self.slot,os.O_RDONLY|os.O_DIRECTORY)),\
             patch.object(m.os,'fchown') as chown,patch.object(n,'read_file',side_effect=lambda path,**kw:path.read_bytes()):
            m.publish_input(value,descriptor())
        self.assertEqual(chown.call_args.args[1:],(0,780));self.assertEqual(stat.S_IMODE(self.real_stat(self.leaf).st_mode),0o440)
        self.assertEqual(set(os.listdir(self.slot)),{'input.json'});self.assertEqual(json.loads(self.leaf.read_bytes()),value)


class RootlessPublication(unittest.TestCase):
    """Actual typed producer/publication flow with projected backend/Root CAS."""
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.slot=Path(self.temp.name)/'namespace';self.events=[];self.physical=None
        self.root=Path('/fixture/root');self.release=self.root/'releases/one'
        test=self
        class Backend(legacy.FakeNative):
            def __init__(self,root,release,old):
                super().__init__(root,release,old);self.descriptor=descriptor();self.source=source_frame()
            def observe_original(self,custody):
                if self.mode=='missed':raise ValueError('synthetic backend missed original live invocation')
                origin=super().observe_original(custody)
                origin['container']=dict(id=CID,image=self.source['configure']['image'],source=self.source['configure'],
                    conmon=dict(uid=780,cgroup=CGROUP,startTicks=90),execution=execution())
                return origin
            def export_edge(self):
                edge,db=super().export_edge();db['source']=self.source['postgres'];return edge,db
        self.Backend=Backend;self.Backend.instances=[];self.Backend.mode='ok'
        self.old=dict(phase='starting',inputs={'stack.ir.json':'b'*64,'podman-domains.json':'c'*64})
        self.value=None
        self.addCleanup(patch.stopall)
        patch.object(m,'Native',Backend).start();patch.object(m,'SLOT',self.slot).start()
        patch.object(n,'finance_actor',return_value=copy.deepcopy(ACTOR)).start();patch.object(n,'lock_held').start()
        patch.object(n,'read_file',side_effect=lambda *args,**kw:m.encoded(self.value)).start()
        patch.object(n,'finance_reference_files',side_effect=lambda *args:self.physical).start()
        def publish(content,d):
            self.events.append(copy.deepcopy(content));self.assertEqual(d,descriptor())
            self.physical=dict(directory=dict(path=str(self.slot),identity=[1,2,0,780,stat.S_IFDIR|0o750,2,1,1,1],mountId=10),
                input=dict(path=str(self.slot/'input.json'),identity=[1,3,0,780,stat.S_IFREG|0o440,1,1,1,1],mountId=10,sha256=m.sha(m.encoded(content)),content=content))
        patch.object(m,'publish_input',side_effect=publish).start()

    def arm(self):
        return m.transact(self.root,self.release,self.old,'arm')

    def test_fresh_arm_then_original_success_capture_then_retained_publication(self):
        arm=self.arm();self.value=dict(self.old,financeOwnershipCustody=arm.record)
        reference=arm.publish(self.value);reference.recheck(self.value)
        self.assertEqual(self.events[0]['status'],'fresh');self.assertIsNone(self.events[0]['nativeFinanceOwnership'])
        self.assertEqual(self.events[0]['transport']['actorGid'],780)
        with self.assertRaises(ValueError):arm.publish(self.value)
        self.old=dict(self.value,nativeFinanceReference=reference.record)
        captured=m.transact(self.root,self.release,self.old,'capture')
        self.value=dict(self.old,nativeFinanceOwnershipReceipt=captured.record)
        result=captured.publish(self.value);result.recheck(self.value)
        self.assertEqual(self.events[-1]['status'],'retained');self.assertEqual(self.events[-1]['nativeFinanceOwnership'],legacy.EDGE)
        self.assertFalse(captured.record['readinessAuthorized']);self.assertEqual(captured.record['original']['container']['conmon']['uid'],780)

    def test_missing_original_arm_or_invocation_refuses_before_publication(self):
        with self.assertRaises(ValueError):m.transact(self.root,self.release,self.old,'capture')
        arm=self.arm();self.old['financeOwnershipCustody']=arm.record
        self.Backend.mode='missed'
        with self.assertRaises(ValueError):m.transact(self.root,self.release,self.old,'capture')
        self.assertEqual(self.events,[])

    def test_foreign_unclaimed_input_is_not_adopted(self):
        arm=self.arm();self.value=dict(self.old,financeOwnershipCustody=arm.record)
        self.slot.mkdir();(self.slot/'input.json').write_text('{}')
        with self.assertRaisesRegex(ValueError,'no adoption'):arm.publish(self.value)
        self.assertEqual(self.events,[])

    def test_existing_reference_inode_cas_changed_refuses_no_repair(self):
        self.old['nativeFinanceReference']=dict(directory={'foreign':True},input={'foreign':True})
        arm=self.arm();self.value=dict(self.old,financeOwnershipCustody=arm.record)
        self.physical=dict(directory={},input={})
        with self.assertRaisesRegex(ValueError,'changed before publication'):arm.publish(self.value)
        self.assertEqual(self.events,[])

    def test_caller_json_and_missing_current_dual_cas_cannot_publish(self):
        arm=self.arm();self.value={}
        prepared=dict(self.old,financeOwnershipCustody=arm.record)
        with self.assertRaises(ValueError):arm.publish(prepared)
        with self.assertRaises(ValueError):m.RootFinanceResult(object(),arm.backend,'arm',arm.record)
        self.assertEqual(self.events,[])


class RootlessReadinessClause(unittest.TestCase):
    def gate(self,prior,binding=None):
        source=(OPS/'native-readiness-owner.py').read_text()
        start=source.index("    if 'nativeFinanceReferenceBindingSha256' in binding:")
        end=source.index('    require(isinstance(proof, dict)',start)
        namespace={'require':n.require,'r':n.r}
        exec(compile('def gate(prior_intent,binding):\n'+source[start:end],'<actual finance active clause>','exec'),namespace)
        namespace['gate'](prior,binding if binding is not None else {'nativeFinanceReferenceBindingSha256':'a'*64})

    def test_fresh_reference_and_bare_marker_never_confer_readiness(self):
        for prior in ({},{'nativeFinanceOwnershipReceipt':{'kind':'root-native-finance-ownership','status':'completed'}},
                      {'nativeFinanceOwnershipReceipt':{'kind':'root-native-finance-ownership','status':'completed'},'nativeFinanceReference':{'input':{'content':{'status':'fresh'}}}}):
            with self.subTest(prior=prior),self.assertRaises(ValueError):self.gate(prior)

    def test_retained_completed_clause_and_unchanged_legacy_noop(self):
        prior={'nativeFinanceOwnershipReceipt':{'kind':'root-native-finance-ownership','status':'completed'},'nativeFinanceReference':{'input':{'content':{'status':'retained'}}}}
        self.gate(prior);self.gate({},binding={})
        for value in (None,True,'not-a-source-binding'):
            with self.subTest(value=value),self.assertRaises(ValueError):self.gate(prior,{'nativeFinanceReferenceBindingSha256':value})


class RootlessConsumer(hook.ConsumerTransport):
    # Inherit the original seven legacy cases as explicit compatibility checks.
    def rootless_file(self, *, native=None, file_stat='65534:0:440:1', directory_stat='65534:0:750', read_only=True, changes=None):
        c=self.fixture.c;script=c.path/'rootless-finance.sh';path=c.path/'rootless-input.json'
        overflow=c.path/'overflowuid';overflow.write_text('65534\n')
        uid_map=c.path/'uid_map';uid_map.write_text('0 780 1\n1 200000 65536\n')
        gid_map=c.path/'gid_map';gid_map.write_text('0 780 1\n1 200000 65536\n')
        mountinfo=c.path/'mountinfo';mountinfo.write_text('1 1 0:1 / /run/p0-finance '+('ro' if read_only else 'rw')+' - tmpfs tmpfs rw\n')
        source=FINANCE.read_text().replace('/run/p0-finance/input.json',str(path))
        source=source.replace('/proc/sys/kernel/overflowuid',str(overflow)).replace('/proc/self/mountinfo',str(mountinfo))
        source=source.replace('/proc/self/uid_map',str(uid_map)).replace('/proc/self/gid_map',str(gid_map))
        source=source.replace("$(stat -c '%u:%g:%a:%h' -- \"$finance_input\")",file_stat)
        source=source.replace("$(stat -c '%u:%g:%a' -- /run/p0-finance)",directory_stat)
        source=source.replace('$(id -u)','1000').replace('$(id -g)','0')
        source=source.replace('! -L /run/p0-finance','true')  # TEMP projection only; production no-link check remains
        script.write_text(source)
        value=dict(schemaVersion=1,kind='root-native-finance-input',root='/fixture/root',release='/fixture/root/releases/one',intentSha256='a'*64,
            sourceSha256=m.sha(script.read_bytes()),issuer='https://keycloak.'+c.env['DOMAIN']+'/realms/'+c.env['REALM'],status='retained' if native else 'fresh',nativeFinanceOwnership=native,
            transport=dict(kind='root-owned-platform-group-readonly-v1',actorUid=780,actorGid=780,actorUser=ACTOR['user'],consumerUid=1000,consumerGid=0,overflowUid=65534))
        if changes:value.update(changes)
        path.write_text(json.dumps(value));c.env['FIREFLY_NATIVE_OWNERSHIP_FILE']=str(path)
        return script

    def test_rootless_group_read_fresh_then_native_retained_no_repairs(self):
        script=self.rootless_file();result=self.run_transport(script)
        self.assertEqual(result.returncode,0,result.stderr)
        native=self.native_model_edge();self.fixture.c.state['argv']=[]
        script=self.rootless_file(native=native);result=self.run_transport(script)
        self.assertEqual(result.returncode,0,result.stderr);self.fixture.c.assert_no_mutations()
        self.assertFalse(any(a[1].endswith('/service-account-user') for a in self.fixture.c.state['argv']))

    def test_mapped_owner_world_read_or_write_transport_refuses_before_api(self):
        for options in ({'file_stat':'0:0:440:1'},{'file_stat':'65534:0:444:1'},
                        {'directory_stat':'65534:0:755'},{'read_only':False}):
            with self.subTest(options=options):
                script=self.rootless_file(**options);self.assertNotEqual(self.run_transport(script).returncode,0)
                self.assertEqual(self.fixture.c.state['argv'],[])

    def test_rootless_namespace_cannot_fall_back_to_legacy_world_readable_file(self):
        for namespace in ('0 780 1\n1 200000 65536\n','0 0 65537\n'):
            with self.subTest(namespace=namespace):
                script=self.rootless_file(file_stat='0:0:444:1')
                (self.fixture.c.path/'uid_map').write_text(namespace)
                path=self.fixture.c.path/'rootless-input.json';value=json.loads(path.read_text());value.pop('transport');path.write_text(json.dumps(value))
                self.assertNotEqual(self.run_transport(script).returncode,0);self.assertEqual(self.fixture.c.state['argv'],[])

    def test_private_child_parent_relative_maps_preserve_group_read_transport(self):
        native=None
        for namespace in ('0 0 65537\n','0 0 1\n1 1 65536\n'):
            with self.subTest(namespace=namespace):
                script=self.rootless_file(native=native)
                for name in ('uid_map','gid_map'):(self.fixture.c.path/name).write_text(namespace)
                result=self.run_transport(script);self.assertEqual(result.returncode,0,result.stderr)
                if native is not None:self.fixture.c.assert_no_mutations()
                native=self.native_model_edge();self.fixture.c.state['argv']=[]

    def test_foreign_namespace_actor_and_group_refuse_before_api(self):
        for name,body in [('uid_map','0 1000 1\n1 200000 65536\n'),('gid_map','0 0 1\n1 200000 65536\n')]:
            with self.subTest(name=name):
                script=self.rootless_file();(self.fixture.c.path/name).write_text(body)
                self.assertNotEqual(self.run_transport(script).returncode,0);self.assertEqual(self.fixture.c.state['argv'],[])

    def test_arbitrary_transport_identity_fields_refuse_before_api(self):
        script=self.rootless_file();value=json.loads((self.fixture.c.path/'rootless-input.json').read_text())
        value['transport']['actorUser']='foreign'
        (self.fixture.c.path/'rootless-input.json').write_text(json.dumps(value))
        self.assertNotEqual(self.run_transport(script).returncode,0);self.assertEqual(self.fixture.c.state['argv'],[])


if __name__=='__main__':
    parser=argparse.ArgumentParser(add_help=False)
    parser.add_argument('--public-role-fixture',type=Path)
    args,rest=parser.parse_known_args()
    ACTUAL_PUBLIC_ROLE=args.public_role_fixture
    unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
