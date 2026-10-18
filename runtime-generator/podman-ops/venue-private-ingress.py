#!/usr/bin/env python3
"""Receipted private bridge relays inside the existing inert/start lifecycle.

No enablement, global resolver change, public bind, URI rewriting or guest power.
Only the dispatcher may start these exact units after native fence/TLS checks.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import stat
import struct
import sys
import time
import types

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
UNIT_DIRECTORY=Path('/etc/systemd/system')
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
stage=load('ingress_stage','venue-owned-stage.py')
graph=load('ingress_graph','venue-graph-clear.py')
https=load('ingress_https','render-existing-host-ingress.py')
mail=load('ingress_mail','render-existing-host-mail-ingress.py')
Refusal=stage.Refusal

def context(bundle,selector,ledger):
    b=Path(bundle);p=Path(ledger);s=p.lstat()
    if (os.geteuid()!=0 or p.is_symlink() or not stat.S_ISREG(s.st_mode) or s.st_uid or
            s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o600):raise Refusal('private ingress requires root0600 journal')
    data=json.loads(p.read_text());plan=stage.owned_plan(b,selector)
    if data.get('plan')!=plan:raise Refusal('private ingress source/plan differs')
    return b,p,data,plan

def manifest(bundle,selector,plan):
    selected=https.network.strict_json(Path(selector));proposal=https.render(bundle,selected)
    mail_proposal=mail.render(bundle,selected)
    if proposal['guestGateway']!='192.168.140.1' or proposal['bridge']!='virbr140':
        raise Refusal('private resolver/ingress authority differs')
    for file in (Path(bundle)/'quadlet').glob('*/*.container'):
        if [line for line in file.read_text().splitlines() if line.startswith('DNS=')]!=['DNS=192.168.140.1']:
            raise Refusal('native service lacks exclusive isolated DNS')
    rows={}
    for name,sock,service in [(proposal['unit'],proposal['socket'],proposal['service']),
                              (proposal['httpUnit'],proposal['httpSocket'],proposal['httpService'])]+[
            (row['unit'],row['socket'],row['service']) for row in mail_proposal['units']]:
        if not re.fullmatch(re.escape(plan['prefix'])+r'-ingress-[a-z]+',name):raise Refusal('unbound private relay name')
        for suffix,text in [('socket',sock),('service',service)]:
            path=UNIT_DIRECTORY/(name+'.'+suffix)
            rows[str(path)]={'text':text,'sha256':hashlib.sha256(text.encode()).hexdigest()}
    if len(rows)!=8:raise Refusal('exact four private relay pairs required')
    return rows,proposal,mail_proposal

def checked(bundle,selector,ledger,*,required=True):
    b,p,data,plan=context(bundle,selector,ledger)
    if not required and 'venueIngressPhase' not in data:return {}
    rows,_,_=manifest(b,selector,plan)
    records=data.get('venueIngressUnits',{})
    if (data.get('venueIngressPhase')!='inert-ready' or data.get('venueIngressPlan')!={k:v['sha256'] for k,v in rows.items()} or
            set(records)!=set(rows)):raise Refusal('complete exact inert private ingress receipt required')
    for file,row in rows.items():
        path=Path(file);s=path.lstat();record=records[file]
        if (path.is_symlink() or any(q.is_symlink() for q in path.parents) or not stat.S_ISREG(s.st_mode) or
                s.st_nlink!=1 or (s.st_dev,s.st_ino,s.st_uid,stat.S_IMODE(s.st_mode))!=
                (record['dev'],record['ino'],0,0o644) or stage.sha(path)!=row['sha256'] or record['sha256']!=row['sha256']):
            raise Refusal('private ingress installed file identity/content changed')
    return rows

def prepare(bundle,selector,ledger):
    b,p,data,plan=context(bundle,selector,ledger);rows,_,_=manifest(b,selector,plan)
    if (data.get('venueInstallerVersion')!=1 or data.get('venueInstallerPhase')!='preparing' or
            data.get('status')!='units-staged' or data.get('activationAuthorized') is not False or
            'venueIngressPhase' in data):raise Refusal('fresh inactive ingress preparation required')
    if (UNIT_DIRECTORY.is_symlink() or any(p.is_symlink() for p in UNIT_DIRECTORY.parents) or
            not UNIT_DIRECTORY.is_dir() or UNIT_DIRECTORY.stat().st_uid or UNIT_DIRECTORY.stat().st_mode&0o022 or
            any(os.path.lexists(file) for file in rows)):raise Refusal('private ingress destination occupied or unsafe')
    data.update(venueIngressPhase='preparing',venueIngressPlan={k:v['sha256'] for k,v in rows.items()},venueIngressUnits={})
    stage.write_ledger(p,data)
    for file,row in rows.items():
        data['venueIngressPending']=file;stage.write_ledger(p,data)
        fd=os.open(file,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
        with os.fdopen(fd,'w') as out:out.write(row['text']);out.flush();os.fsync(out.fileno())
        Path(file).chmod(0o644);s=Path(file).lstat()
        data['venueIngressUnits'][file]={'dev':s.st_dev,'ino':s.st_ino,'sha256':row['sha256']}
        data.pop('venueIngressPending');stage.write_ledger(p,data)
    if graph.run(['systemctl','daemon-reload'],timeout=30).returncode:raise Refusal('private ingress daemon reload failed')
    data['venueIngressPhase']='inert-ready';stage.write_ledger(p,data)
    checked(b,selector,p)
    return {'privateInactiveRelayUnits':8,'activationAuthorized':False}

def retire(bundle,selector,ledger):
    rows=checked(bundle,selector,ledger);b,p,data,plan=context(bundle,selector,ledger)
    if data.get('activationAuthorized') is not False or data.get('venueInstallerPhase')!='retiring':
        raise Refusal('fenced exact inactive private ingress retirement required')
    names=[Path(file).name for file in rows]
    result=graph.run(['systemctl','show',*names,'-p','ActiveState','-p','UnitFileState'],timeout=30)
    if result.returncode:raise Refusal('cannot inspect private relay retirement state')
    states=[line.partition('=')[2] for line in result.stdout.splitlines() if line.startswith('ActiveState=')]
    if len(states)!=8 or any(value not in ('inactive','failed') for value in states):raise Refusal('private relay remains active')
    enabled=[line.partition('=')[2] for line in result.stdout.splitlines() if line.startswith('UnitFileState=')]
    if len(enabled)!=8 or any(value not in ('disabled','static') for value in enabled):
        raise Refusal('private relay has unreviewed enablement or unreadable install state')
    jobs=graph.run(['systemctl','list-jobs','--no-legend','--no-pager'],timeout=30)
    if jobs.returncode or any(len(row)<4 or row[1] in names for row in [line.split() for line in jobs.stdout.splitlines()]):
        raise Refusal('private relay has pending or unreadable jobs')
    checked(b,selector,p)  # Full-set CAS before the first unlink; never glob-delete.
    for file in rows:
        path=Path(file);record=data['venueIngressUnits'][file];s=path.lstat()
        if path.is_symlink() or (s.st_dev,s.st_ino,s.st_uid)!=(record['dev'],record['ino'],0) or stage.sha(path)!=record['sha256']:
            raise Refusal('private relay retirement CAS changed')
        data['venueIngressRetirePending']=file;stage.write_ledger(p,data)
        path.unlink();data.setdefault('venueIngressRetired',[]).append(file);data.pop('venueIngressRetirePending');stage.write_ledger(p,data)
    if graph.run(['systemctl','daemon-reload'],timeout=30).returncode:raise Refusal('private relay retirement reload failed')
    data['venueIngressPhase']='retired-inert';stage.write_ledger(p,data)

def native_network(context,bundle):
    authority=context.require_runtime()
    if authority['phase'] not in ('starting','running'):raise Refusal('current lifecycle authority required for relay proof')
    pointer=context.source/'agent-services-current-host';slot=pointer.resolve(strict=True)
    if not pointer.is_symlink() or pointer.lstat().st_uid or slot.parent!=context.source/'agent-service-releases':raise Refusal('relay host role selection differs')
    manifest_file=slot/'manifest.json';ms=manifest_file.lstat()
    if manifest_file.is_symlink() or not stat.S_ISREG(ms.st_mode) or ms.st_uid or ms.st_nlink!=1 or ms.st_mode&0o022:
        raise Refusal('relay host role manifest is not protected')
    manifest=json.loads(manifest_file.read_text());file=slot/'agent_vm_spec.py';s=file.lstat()
    if (file.is_symlink() or not stat.S_ISREG(s.st_mode) or any(p.is_symlink() for p in file.parents) or s.st_uid or s.st_nlink!=1 or s.st_mode&0o022 or
            stage.sha(file)!=manifest['files'].get('agent_vm_spec.py')):raise Refusal('relay native network helper hash differs')
    body=file.read_bytes();module=types.ModuleType('verified_relay_network');module.__file__=str(file)
    exec(compile(body,str(file),'exec'),module.__dict__)
    if not callable(getattr(module,'network_preflight',None)):
        raise Refusal('selected controller lacks the read-only native network proof API')
    spec=module.load(Path(bundle)/'site/agent-vm.json')
    if stage.sha(Path(bundle)/'site/agent-vm.json')!=context.data['siteVmSpecSha256']:
        raise Refusal('relay public VM spec differs from selected context')
    return module.network_preflight(context,spec,authority['bootId'])

def dns_addresses(host,gateway,*,ipv6=False):
    """Bounded explicit A/AAAA query; no host fallback or public IPv6 escape."""
    kind=28 if ipv6 else 1
    nonce=secrets.randbelow(65536);question=b''.join(bytes([len(part)])+part.encode('ascii') for part in host.split('.'))+b'\0'+struct.pack('!HH',kind,1)
    packet=struct.pack('!6H',nonce,0x100,1,0,0,0)+question
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as stream:
        stream.settimeout(2);stream.sendto(packet,(gateway,53));body,peer=stream.recvfrom(4096)
    if peer!=(gateway,53) or len(body)<12:raise Refusal('private DNS peer/header differs')
    ident,flags,questions,answers,_,_=struct.unpack('!6H',body[:12])
    if (ident!=nonce or not flags&0x8000 or flags&0x20f or questions!=1 or
            body[12:12+len(question)]!=question):raise Refusal('private DNS response differs')
    if ipv6:
        if answers:raise Refusal('canonical hostname has unapproved IPv6/CNAME answer')
        return []  # Explicit successful NODATA, never inferred from an error.
    if answers<1:raise Refusal('private IPv4 DNS authority is absent')
    def skip(pos):
        for _ in range(128):
            if pos>=len(body):raise Refusal('truncated private DNS name')
            size=body[pos];pos+=1
            if size==0:return pos
            if size&0xc0==0xc0:
                if pos>=len(body):raise Refusal('truncated private DNS pointer')
                return pos+1
            if size>63 or pos+size>len(body):raise Refusal('invalid private DNS label')
            pos+=size
        raise Refusal('unbounded private DNS name')
    pos=skip(12)+4;found=[]
    for _ in range(answers):
        pos=skip(pos)
        if pos+10>len(body):raise Refusal('truncated private DNS answer')
        kind,cls,_,size=struct.unpack('!HHIH',body[pos:pos+10]);pos+=10
        if pos+size>len(body):raise Refusal('truncated private DNS data')
        if kind!=1 or cls!=1 or size!=4:raise Refusal('private DNS answer is not exact IPv4 host authority')
        found.append(socket.inet_ntoa(body[pos:pos+size]));pos+=size
    if not found or set(found)!={gateway}:raise Refusal('canonical hostname escaped private ingress DNS')
    return found

def ca_context(bundle,data,plan):
    ir=json.loads((Path(bundle)/'stack.ir.json').read_text())
    ca=Path(ir['volumes']['caddy_ca']['hostPath']);certs=Path(ir['volumes']['caddy_certs']['hostPath'])
    for path in (ca,certs):
        record=next((row for row in data['venueDataBindDirs'] if row['path']==str(path)),None);s=path.lstat()
        if (record is None or path.is_symlink() or any(p.is_symlink() for p in path.parents) or
                not stat.S_ISDIR(s.st_mode) or s.st_uid or s.st_mode&0o022 or (s.st_dev,s.st_ino)!=(record['dev'],record['ino'])):
            raise Refusal('private CA source root changed')
    root=certs/'pki/authorities/local/root.crt';bundle_file=ca/'caddy-ca.crt'
    for path in (root,bundle_file):
        s=path.lstat()
        if path.is_symlink() or any(p.is_symlink() for p in path.parents) or not stat.S_ISREG(s.st_mode) or s.st_uid or s.st_nlink!=1 or s.st_mode&0o022:
            raise Refusal('private public-CA source is not an exact protected file')
    public=root.read_bytes().strip();body=bundle_file.read_bytes()
    if not public or public not in body:raise FileNotFoundError('Caddy public root not yet published into shared CA bundle')
    trust=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    trust.load_verify_locations(cadata=public.decode('ascii'))  # Only this fresh scoped root, not public/original CAs.
    return trust,hashlib.sha256(body).hexdigest()

def tls_probe(trust,address,port,hostname):
    with socket.create_connection((address,port),timeout=3) as raw:
        with trust.wrap_socket(raw,server_hostname=hostname) as secure:
            return hashlib.sha256(secure.getpeercert(binary_form=True)).hexdigest()

def smtp_probe(trust,address,port,hostname):
    import smtplib
    client=smtplib.SMTP(timeout=3,local_hostname='p0-private-probe.invalid')
    try:
        client.connect(address,port);client.ehlo();code,_=client.docmd('STARTTLS')
        if code!=220:raise ConnectionError('selected SMTP STARTTLS not yet ready')
        with trust.wrap_socket(client.sock,server_hostname=hostname) as secure:
            return hashlib.sha256(secure.getpeercert(binary_form=True)).hexdigest()
    except smtplib.SMTPException:raise ConnectionError('selected SMTP handshake not yet ready') from None
    finally:client.close()

def starting(bundle,selector,ledger,controller,deadline):
    b,p,data,plan=context(bundle,selector,ledger)
    if (time.monotonic()>=deadline or data.get('venueInstallerVersion')!=2 or
            data.get('venueInstallerPhase')!='starting' or data.get('status')!='installed-starting' or
            data.get('venueStartPhase')!='starting' or data.get('activationAuthorized') is not True or
            data.get('venueStartHostContextSha256')!=controller.digest):
        raise Refusal('private ingress startup fenced or expired')
    authority=controller.require_runtime()
    if authority['phase']!='starting':raise Refusal('private ingress requires matching STARTING authority')
    checked(b,selector,p);controller.physical_reserves()
    return b,p,data,plan

def queue(bundle,selector,ledger,controller,deadline,names):
    lifecycle=load('relay_start_lifecycle','venue-start-quarantine.py');registry=load('relay_start_registry','venue-registry-images.py')
    with lifecycle.lifecycle(controller):
        b,p,data,plan=starting(bundle,selector,ledger,controller,deadline)
        if 'venueIngressStartPending' in data:raise Refusal('indeterminate private ingress intent; no replay')
        allowed={Path(file).name for file in checked(b,selector,p) if file.endswith('.socket')}|{plan['prefix']+'-caddy.service'}
        health=load('relay_root_health','venue-root-health.py')
        allowed.update(Path(file).name for file in health.checked(b,selector,p) if file.endswith('.timer'))
        if not names or len(names)!=len(set(names)) or not set(names)<=allowed:
            raise Refusal('private ingress start escaped exact socket/Caddy unit set')
        native_network(controller,b);registry.reserve()
        if time.monotonic()>=deadline:raise Refusal('private ingress queue deadline')
        data['venueIngressStartPending']=names;stage.write_ledger(p,data)
        if graph.run(['systemctl','start','--job-mode=fail','--no-block',*names],timeout=30).returncode:
            raise Refusal('selected private ingress start request failed; intent retained')
        data.setdefault('venueIngressQueued',[]).extend(names);data.pop('venueIngressStartPending');stage.write_ledger(p,data)

def wait(bundle,selector,ledger,controller,deadline,probe):
    lifecycle=load('relay_observe_lifecycle','venue-start-quarantine.py')
    while True:
        with lifecycle.lifecycle(controller):
            b,p,data,plan=starting(bundle,selector,ledger,controller,deadline)
            epoch=data['venueStartMonotonicUsec']
        # Read-only native/TLS probes must not exclude an operator cancellation.
        try:proof=probe(b,data,plan)
        except PermissionError:raise Refusal('cannot establish private ingress readiness') from None
        except ssl.SSLCertVerificationError:raise Refusal('private TLS peer does not match this scoped CA/hostname') from None
        except (FileNotFoundError,ConnectionError,TimeoutError,ssl.SSLError):proof=None
        if proof is not None:
            with lifecycle.lifecycle(controller):
                _,_,current,_=starting(bundle,selector,ledger,controller,deadline)
                if current['venueStartMonotonicUsec']!=epoch:raise Refusal('private ingress readiness epoch changed')
                return proof
        time.sleep(1)

def sockets_ready(data,names):
    lifecycle=load('relay_socket_observer','venue-start-quarantine.py')
    ready=True
    for name in names:
        result=graph.run(['systemctl','show',name,'-p','ActiveState','-p','Result','-p','ExecMainStatus',
            '-p','ExecMainStartTimestampMonotonic','-p','InactiveExitTimestampMonotonic','-p','FragmentPath','-p','DropInPaths'],timeout=30)
        if result.returncode:raise Refusal('cannot observe exact private socket startup')
        row=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
        if row.get('FragmentPath')!=str(UNIT_DIRECTORY/name) or row.get('DropInPaths')!='':
            raise Refusal('private socket has foreign fragment/overrides')
        ready=lifecycle.observed_ready(row,data['venueStartMonotonicUsec'],name) and ready
    return ready

def bootstrap_tls(bundle,selector,ledger,controller,deadline):
    b,p,data,plan=context(bundle,selector,ledger);_,proposal,_=manifest(b,selector,plan)
    selected=https.network.strict_json(Path(selector));_,_,gateway,hosts=https.network.network_authority(b,selected)
    hostname=next((host for host in hosts if host.startswith('keycloak.')),None)
    if hostname is None:raise Refusal('canonical Keycloak TLS name missing')
    native_network(controller,b)
    for host in hosts:
        dns_addresses(host,str(gateway));dns_addresses(host,str(gateway),ipv6=True)
    queue(b,selector,p,controller,deadline,[plan['prefix']+'-root-health.timer',plan['prefix']+'-caddy.service'])
    def upstream(b,data,plan):
        lifecycle=load('relay_caddy_observer','venue-start-quarantine.py')
        name=plan['prefix']+'-caddy.service'
        observed=graph.run(['systemctl','show',name,'-p','ActiveState','-p','Result','-p','ExecMainStatus','-p','ExecMainStartTimestampMonotonic','-p','InactiveExitTimestampMonotonic'],timeout=30)
        if observed.returncode:raise Refusal('cannot observe scoped Caddy startup')
        row=dict(line.split('=',1) for line in observed.stdout.splitlines() if '=' in line)
        if not lifecycle.observed_ready(row,data['venueStartMonotonicUsec'],name):return None
        trust,ca=ca_context(b,data,plan);leaf=tls_probe(trust,'127.0.0.1',selected['ports']['443'],hostname)
        return {'caBundleSha256':ca,'leafSha256':leaf,'hostnamesVerified':len(hosts)}
    proof=wait(b,selector,p,controller,deadline,upstream)
    queue(b,selector,p,controller,deadline,[proposal['unit']+'.socket',proposal['httpUnit']+'.socket'])
    def relay(b,data,plan):
        if not sockets_ready(data,[proposal['unit']+'.socket',proposal['httpUnit']+'.socket']):return None
        trust,_=ca_context(b,data,plan)
        for port in proposal['guestPorts']:tls_probe(trust,str(gateway),port,hostname)
        import http.client
        for port in proposal['guestHttpPorts']:
            client=http.client.HTTPConnection(str(gateway),port,timeout=3)
            try:
                client.request('GET','/',headers={'Host':hostname});response=client.getresponse()
                if response.status!=308 or response.getheader('Location')!='https://'+hostname+'/':raise Refusal('private canonical HTTP redirect differs')
            finally:client.close()
        return True
    wait(b,selector,p,controller,deadline,relay)
    lifecycle=load('relay_tls_receipt','venue-start-quarantine.py')
    with lifecycle.lifecycle(controller):
        b,p,data,plan=starting(b,selector,p,controller,deadline)
        data['venueIngressTlsProof']={**proof,'startMonotonicUsec':data['venueStartMonotonicUsec'],'canonicalPort':443}
        stage.write_ledger(p,data)

def finish_mail(bundle,selector,ledger,controller,deadline):
    b,p,data,plan=context(bundle,selector,ledger);_,_,proposal=manifest(b,selector,plan)
    selected=https.network.strict_json(Path(selector));_,_,gateway,hosts=https.network.network_authority(b,selected)
    hostname=next((host for host in hosts if host.startswith('mail.')),None)
    if hostname is None:raise Refusal('canonical mail TLS name missing')
    def probe_at(address,bridge):
        def probe(b,data,plan):
            if bridge and not sockets_ready(data,[row['unit']+'.socket' for row in proposal['units']]):return None
            trust,ca=ca_context(b,data,plan)
            for row in proposal['units']:
                ports=row['guestPorts'] if bridge else [row['guestPorts'][1]]
                for port in ports:
                    if row['unit'].endswith('-smtp'):smtp_probe(trust,address,port,hostname)
                    else:tls_probe(trust,address,port,hostname)
            return {'caBundleSha256':ca,'canonicalMailTlsVerified':True}
        return probe
    wait(b,selector,p,controller,deadline,probe_at('127.0.0.1',False))
    queue(b,selector,p,controller,deadline,[row['unit']+'.socket' for row in proposal['units']])
    proof=wait(b,selector,p,controller,deadline,probe_at(str(gateway),True))
    lifecycle=load('relay_mail_receipt','venue-start-quarantine.py')
    with lifecycle.lifecycle(controller):
        b,p,data,plan=starting(b,selector,p,controller,deadline)
        data['venueIngressMailProof']={**proof,'startMonotonicUsec':data['venueStartMonotonicUsec']};stage.write_ledger(p,data)
