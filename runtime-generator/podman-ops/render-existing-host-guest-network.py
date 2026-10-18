#!/usr/bin/env python3
"""Render/read-only screen of a proposed private libvirt guest bridge.

Default rendering never mutates the host. Explicit --prepare-owned creates
only a new source-bound bridge after its narrow fence, with a private intent
journal and no adoption/retry. It creates no VM or stack activation authority;
network boot readiness is not integrated ingress/delivery proof.
"""
import argparse
import ipaddress
import hashlib
import importlib.util
import os
import stat
import json
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET


class Refusal(ValueError):
    pass


def strict_json(path):
    path = Path(path)
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 2_000_000:
        raise Refusal('Missing or unsafe network input')
    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise Refusal('Duplicate network authority key')
            result[key] = value
        return result
    return json.loads(path.read_text(), object_pairs_hook=pairs)


def network_authority(bundle, selector):
    bundle = Path(bundle)
    vm = strict_json(bundle / 'site/agent-vm.json')
    venue = strict_json(bundle / 'podman-domains.json').get('venue')
    guest = selector.get('guest')
    if (not isinstance(venue, dict) or not isinstance(guest, dict)
            or set(guest) != {'name','network','networkConfig','servicePorts','diskRoot','controlCommit'}):
        raise Refusal('Missing site/selector venue authority')
    expected = {key: vm.get(key) for key in ('name','network','networkConfig','servicePorts','diskRoot')}
    expected['controlCommit'] = vm.get('runtime', {}).get('controlCommit')
    if guest != expected or guest.get('name') != guest.get('network','') + '-agents':
        raise Refusal('Guest authority differs from generated site')
    ports = guest['servicePorts']
    if (not isinstance(ports, dict) or set(ports) != {'https','imap','smtp'}
            or any(type(ports[k]) is not int or ports[k] != venue.get('portMap',{}).get(source)
                   for k,source in (('https','443'),('imap','993'),('smtp','587')))):
        raise Refusal('Guest ports differ from rendered host venue')
    if guest['diskRoot'] != '/mnt/lab_debian/agent_vm/' + guest['name']:
        raise Refusal('Guest disk root overlaps unknown ownership')
    try:
        interface = ipaddress.IPv4Interface(guest['networkConfig']['address'])
        gateway = ipaddress.IPv4Address(guest['networkConfig']['gateway'])
    except (ValueError, KeyError, TypeError) as exc:
        raise Refusal('Invalid private bridge address') from exc
    subnet = interface.network
    if (subnet.prefixlen != 24 or not subnet.is_private or not 140 <= subnet.network_address.packed[2] <= 199
            or gateway != subnet.network_address + 1 or interface.ip == gateway
            or guest['networkConfig'].get('nameservers') != [str(gateway)]
            or not re.fullmatch(r'p0-venue-[a-z0-9-]{1,24}', guest['network'])):
        raise Refusal('Guest network is not a distinct reviewed private /24')
    settings = bundle / 'site/global.settings/stack.config.yaml'
    caddy = bundle / 'runtime/configs/caddy/Caddyfile'
    if any(not p.is_file() or p.is_symlink() or p.stat().st_size > 1_000_000 for p in (settings,caddy)):
        raise Refusal('Missing bounded site domain/Caddy routing authority')
    domains = re.findall(r'(?m)^  domain: "([a-z][a-z0-9.-]{2,100})"$', settings.read_text())
    if len(domains) != 1 or domains[0] != 'datamancy.net':
        raise Refusal('Unreviewed guest DNS domain')
    labels = set(re.findall(r'([a-z][a-z0-9-]*)\.\{\$DOMAIN\}', caddy.read_text()))
    if (not {'keycloak','matrix','mail','control','ntfy','portal','search'}.issubset(labels)
            or not 40 <= len(labels) <= 100):
        raise Refusal('Incomplete generated private Caddy route DNS catalog')
    return guest, subnet, gateway, sorted({domains[0],*(name+'.'+domains[0] for name in labels)})


def screen_host(subnet, network_name, bridge_name, *, routes=None, network_names=None, links=None):
    """Read-only host collision screen; an absent name is not install authority."""
    if routes is None:
        routes = json.loads(subprocess.check_output(['ip','-j','-4','route','show'], text=True, timeout=10))
    if links is None:
        links = json.loads(subprocess.check_output(['ip','-j','link','show'], text=True, timeout=10))
    if network_names is None:
        network_names = subprocess.check_output(['virsh','-c','qemu:///system','net-list','--all','--name'], text=True, timeout=10).splitlines()
    if not isinstance(routes,list) or not isinstance(links,list) or not isinstance(network_names,list):
        raise Refusal('Unparseable host route/network authority')
    if network_name in network_names or bridge_name in {item.get('ifname') for item in links}:
        raise Refusal('Proposed private bridge/network already exists')
    for row in routes:
        destination=row.get('dst')
        if destination == 'default':
            continue
        try: occupied=ipaddress.ip_network(destination, strict=False)
        except (ValueError, TypeError) as exc: raise Refusal('Unparseable host route') from exc
        if subnet.overlaps(occupied):
            raise Refusal('Proposed guest subnet overlaps host route')
    return {'routeCollision':False,'existingNetworkCollision':False,'bridgeCollision':False}


def render(bundle, selector):
    guest, subnet, gateway, hostnames = network_authority(bundle, selector)
    bridge_name='virbr'+str(subnet.network_address.packed[2])
    root=ET.Element('network')
    ET.SubElement(root,'name').text=guest['network']
    ET.SubElement(root,'forward',{'mode':'nat'})
    ET.SubElement(root,'bridge',{'name':bridge_name,'stp':'on','delay':'0'})
    ET.SubElement(root,'domain',{'name':'datamancy.net','localOnly':'yes'})
    dns=ET.SubElement(root,'dns')
    host=ET.SubElement(dns,'host',{'ip':str(gateway)})
    for hostname in hostnames:
        ET.SubElement(host,'hostname').text=hostname
    ET.SubElement(root,'ip',{'address':str(gateway),'netmask':'255.255.255.0'})
    ET.indent(root)
    return ET.tostring(root,encoding='unicode')+'\n', {'network':guest['network'],'bridge':bridge_name,
        'subnet':str(subnet),'gateway':str(gateway),'dnsNameCount':len(hostnames),
        'guest':guest['name'],'diskRoot':guest['diskRoot'],'controlCommit':guest['controlCommit'],
        'defined':False,'activated':False,'ingressProven':False}


def owned_helpers():
    here=Path(__file__).resolve().parent
    def load(name,file):
        spec=importlib.util.spec_from_file_location(name,here/file)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
    lifecycle=load('network_lifecycle','venue-start-quarantine.py')
    fence=load('network_fence','render-existing-host-guest-fence.py')
    return lifecycle,fence


def prepare_owned(bundle,selector,journal):
    """Create only a new fenced bridge; no VM, old-network adoption or retry."""
    lifecycle,fence=owned_helpers();stage=lifecycle.stage
    journal=Path(journal);parent=journal.parent;info=parent.lstat()
    if (os.geteuid()!=0 or parent.is_symlink() or not stat.S_ISDIR(info.st_mode) or
            info.st_uid or stat.S_IMODE(info.st_mode)!=0o700 or os.path.lexists(journal)):
        raise Refusal('new root-private network journal required; inspect before retry')
    plan=stage.owned_plan(bundle,selector);context=lifecycle.host_context(bundle,plan)
    selection=strict_json(selector)
    with lifecycle.lifecycle(context):
        if os.path.lexists(context.runtime/'runtime-authority.json'):
            raise Refusal('network provisioning requires preactivation scope')
        lifecycle.units.units_idle(plan);context.physical_reserves()
        xml,network=render(bundle,selection)
        screen_host(ipaddress.ip_network(network['subnet']),network['network'],network['bridge'])
        names=subprocess.check_output(['virsh','-c','qemu:///system','list','--all','--name'],text=True,timeout=20).splitlines()
        if network['guest'] in names:raise Refusal('unreceipted selected guest already exists')
        policy=fence.render(bundle,selection)
        tables=json.loads(subprocess.check_output(['nft','-j','list','tables'],text=True,timeout=20))
        if any(row.get('table',{}).get('name')==policy['table'] for row in tables.get('nftables',[])):
            raise Refusal('guest fence table already exists; never adopt')
        xml_path=journal.with_suffix('.xml');nft_path=journal.with_suffix('.nft')
        if any(os.path.lexists(p) for p in (xml_path,nft_path)):raise Refusal('network artifacts already exist')
        data={'schemaVersion':1,'namespace':plan['prefix'],'phase':'artifact-intended',
              'selectorSha256':plan['selectorSha256'],'bundleIrSha256':plan['bundleIrSha256'],
              'hostContextSha256':context.digest,'installerSha256':stage.sha(__file__),
              'network':network,'xmlSha256':hashlib.sha256(xml.encode()).hexdigest(),
              'fenceTable':policy['table'],'fenceSha256':hashlib.sha256(policy['nftables'].encode()).hexdigest(),
              'activationAuthorized':False,'acceptedIntegratedInstalls':0}
        stage.write_ledger(journal,data,create=True)
        for path,body in ((xml_path,xml),(nft_path,policy['nftables'])):
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'w') as out:out.write(body);out.flush();os.fsync(out.fileno())
        subprocess.run(['nft','-c','-f',str(nft_path)],check=True,timeout=30,capture_output=True)
        data['phase']='fence-installing';stage.write_ledger(journal,data)
        subprocess.run(['nft','-f',str(nft_path)],check=True,timeout=30,capture_output=True)
        data['phase']='network-create-intended';stage.write_ledger(journal,data)
        # net-create refuses an existing name atomically. Never net-define an
        # unowned pre-existing network. Persist only the UUID just created here.
        subprocess.run(['virsh','-c','qemu:///system','net-create',str(xml_path)],check=True,timeout=30,capture_output=True)
        uuid=subprocess.check_output(['virsh','-c','qemu:///system','net-uuid',network['network']],text=True,timeout=20).strip()
        if not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',uuid):raise Refusal('new network UUID invalid')
        data.update(phase='network-created',networkUuid=uuid);stage.write_ledger(journal,data)
        live=subprocess.check_output(['virsh','-c','qemu:///system','net-dumpxml',uuid],text=True,timeout=20)
        element=ET.fromstring(live)
        if element.findtext('name')!=network['network'] or element.find('bridge').get('name')!=network['bridge']:
            raise Refusal('new network native identity differs')
        # Persist the exact just-created native definition, not a name-based
        # replacement. Artifacts and partial intent remain on any failure.
        persistent=journal.with_suffix('.native.xml')
        fd=os.open(persistent,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as out:out.write(live);out.flush();os.fsync(out.fileno())
        subprocess.run(['virsh','-c','qemu:///system','net-define',str(persistent)],check=True,timeout=30,capture_output=True)
        # Do not enable network autostart without its durable boot fence. This
        # first runtime bridge exists for selected host publishers only; guest
        # creation remains gated by the separately installed boot policy.
        status=subprocess.check_output(['virsh','-c','qemu:///system','net-info',uuid],text=True,timeout=20)
        if any(not re.search(r'(?m)^'+field+r':\s+yes\s*$',status) for field in ('Active','Persistent')) or not re.search(r'(?m)^Autostart:\s+no\s*$',status):
            raise Refusal('new runtime network identity/policy differs')
        native_fence=subprocess.check_output(['nft','-j','list','table','inet',policy['table']],timeout=20)
        data.update(phase='network-runtime-ready',networkAutostart=False,nativeXmlSha256=hashlib.sha256(live.encode()).hexdigest(),
                    nativeFenceSha256=hashlib.sha256(native_fence).hexdigest(),guestCreated=False)
        stage.write_ledger(journal,data)
        return {'status':data['phase'],'network':network['network'],'uuid':uuid,
                'bridge':network['bridge'],'guestCreated':False,'activationAuthorized':False}


def retire_owned(bundle,selector,journal,expected_sha):
    lifecycle,_=owned_helpers();stage=lifecycle.stage;journal=Path(journal);info=journal.lstat()
    if (os.geteuid()!=0 or journal.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid or
            info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600 or stage.sha(journal)!=expected_sha):
        raise Refusal('exact protected owned-network journal SHA review required')
    plan=stage.owned_plan(bundle,selector);context=lifecycle.host_context(bundle,plan)
    with lifecycle.lifecycle(context):
        data=strict_json(journal)
        if (data.get('phase')!='network-runtime-ready' or data.get('namespace')!=plan['prefix'] or
                data.get('selectorSha256')!=plan['selectorSha256'] or data.get('bundleIrSha256')!=plan['bundleIrSha256'] or
                data.get('hostContextSha256')!=context.digest or data.get('guestCreated') is not False):
            raise Refusal('only exact never-guest owned runtime network may be retired here')
        runtime=context.runtime/'runtime-authority.json'
        if os.path.lexists(runtime):
            st=runtime.lstat();receipt=strict_json(runtime)
            if (runtime.is_symlink() or not stat.S_ISREG(st.st_mode) or st.st_uid or st.st_nlink!=1 or
                    stat.S_IMODE(st.st_mode)!=0o600 or receipt.get('schemaVersion')!=2 or
                    receipt.get('hostContextSha256')!=context.digest or receipt.get('activationAuthorized') is not False or
                    receipt.get('phase')!='failed-quarantined'):
                raise Refusal('runtime authority not exactly fenced before network retirement')
        lifecycle.units.units_idle(plan)
        _,network=render(bundle,strict_json(selector));uuid=data['networkUuid'];table=data['fenceTable']
        actual=subprocess.check_output(['virsh','-c','qemu:///system','net-uuid',network['network']],text=True,timeout=20).strip()
        live=subprocess.check_output(['virsh','-c','qemu:///system','net-dumpxml',uuid],text=True,timeout=20)
        native=subprocess.check_output(['nft','-j','list','table','inet',table],timeout=20)
        if (actual!=uuid or hashlib.sha256(live.encode()).hexdigest()!=data['nativeXmlSha256'] or
                hashlib.sha256(native).hexdigest()!=data['nativeFenceSha256']):
            raise Refusal('owned native network/fence ID or bytes changed')
        links=json.loads(subprocess.check_output(['ip','-j','link','show','master',network['bridge']],text=True,timeout=20))
        if links:raise Refusal('selected bridge has attached interfaces; no unreviewed peer teardown')
        guests=subprocess.check_output(['virsh','-c','qemu:///system','list','--all','--uuid'],text=True,timeout=20).splitlines()
        for guest in guests:
            if not guest.strip():continue  # virsh appends a blank separator line
            root=ET.fromstring(subprocess.check_output(['virsh','-c','qemu:///system','dumpxml',guest],text=True,timeout=20))
            if any(source.get('network')==network['network'] or source.get('bridge')==network['bridge']
                   for source in root.findall('./devices/interface/source')):
                raise Refusal('a domain references the selected network/bridge; no guest adoption or teardown')
        data['phase']='network-retire-intended';data['retirerSha256']=stage.sha(__file__);stage.write_ledger(journal,data)
        subprocess.run(['virsh','-c','qemu:///system','net-destroy',uuid],check=True,timeout=30,capture_output=True)
        data['phase']='network-destroyed';stage.write_ledger(journal,data)
        subprocess.run(['virsh','-c','qemu:///system','net-undefine',uuid],check=True,timeout=30,capture_output=True)
        remaining=subprocess.check_output(['virsh','-c','qemu:///system','net-list','--all','--uuid'],text=True,timeout=20).splitlines()
        if uuid in remaining:raise Refusal('owned network still defined; fence retained')
        data['phase']='network-undefined-fence-held';stage.write_ledger(journal,data)
        current=subprocess.check_output(['nft','-j','list','table','inet',table],timeout=20)
        if hashlib.sha256(current).hexdigest()!=data['nativeFenceSha256']:raise Refusal('fence changed during native network retirement')
        boot=data.get('bootFence')
        if boot:
            hook=hook_helpers();hook_path=Path(boot['path']);info=hook_path.lstat();hook.protected_file(hook_path,0o755)
            if (info.st_dev,info.st_ino)!=(boot['dev'],boot['ino']) or stage.sha(hook_path)!=boot['sha256']:raise Refusal('installed boot hook changed; fence retained')
            proof=Path(boot['policy']['proofPath'])
            if os.path.lexists(proof):
                hook.protected_file(proof,0o600);document=strict_json(proof)
                if document.get('networkUuid')!=uuid or document.get('hookSha256')!=boot['sha256']:raise Refusal('foreign boot proof; no deletion')
            boot['phase']='hook-retirement-intended';stage.write_ledger(journal,data);hook_path.unlink()
            if os.path.lexists(proof):proof.unlink()
            fd=os.open(hook_path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(fd)
            finally:os.close(fd)
            boot['phase']='retired';stage.write_ledger(journal,data)
        subprocess.run(['nft','delete','table','inet',table],check=True,timeout=30,capture_output=True)
        data['phase']='network-retired';stage.write_ledger(journal,data)
        return {'status':'network-retired','retiredNetworkUuid':uuid,'guestDataTouched':False,'activationAuthorized':False}


HOOK_DIRECTORY=Path('/etc/libvirt/hooks/network.d')


def hook_helpers():
    spec=importlib.util.spec_from_file_location('owned_guest_fence_hook',Path(__file__).with_name('venue-guest-fence-hook.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def boot_context(bundle,selector,journal,expected_sha):
    lifecycle,fence=owned_helpers();stage=lifecycle.stage;journal=Path(journal);info=journal.lstat()
    if (os.geteuid()!=0 or journal.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid or info.st_nlink!=1 or
            stat.S_IMODE(info.st_mode)!=0o600 or stage.sha(journal)!=expected_sha):raise Refusal('exact protected network journal SHA required')
    plan=stage.owned_plan(bundle,selector);context=lifecycle.host_context(bundle,plan);data=strict_json(journal)
    if (data.get('phase')!='network-runtime-ready' or data.get('hostContextSha256')!=context.digest or
            data.get('selectorSha256')!=plan['selectorSha256'] or data.get('bundleIrSha256')!=plan['bundleIrSha256'] or
            data.get('guestCreated') is not False):raise Refusal('exact never-guest runtime network required for boot policy')
    return lifecycle,fence,plan,context,data


def stage_boot_fence(bundle,selector,journal,expected_sha):
    lifecycle,fence,plan,context,data=boot_context(bundle,selector,journal,expected_sha);stage=lifecycle.stage;hook=hook_helpers()
    with lifecycle.lifecycle(context):
        if stage.sha(journal)!=expected_sha or data.get('bootFence'):raise Refusal('boot-fence intent already exists or CAS changed; inspect before retry')
        lifecycle.units.units_idle(plan);context.physical_reserves()
        if os.path.lexists(context.runtime/'runtime-authority.json'):raise Refusal('boot policy staging requires preactivation context')
        _,network=render(bundle,strict_json(selector));uuid=data['networkUuid']
        actual=subprocess.check_output(['virsh','-c','qemu:///system','net-uuid',network['network']],text=True,timeout=20).strip()
        xml=subprocess.check_output(['virsh','-c','qemu:///system','net-dumpxml',uuid],text=True,timeout=20)
        native=subprocess.check_output(['nft','-j','list','table','inet',data['fenceTable']],timeout=20)
        status=subprocess.check_output(['virsh','-c','qemu:///system','net-info',uuid],text=True,timeout=20)
        if (actual!=uuid or hashlib.sha256(xml.encode()).hexdigest()!=data['nativeXmlSha256'] or hashlib.sha256(native).hexdigest()!=data['nativeFenceSha256'] or
                not re.search(r'(?m)^Autostart:\s+no\s*$',status)):raise Refusal('runtime network/fence/policy differs; no boot hook adoption')
        policy=fence.render(bundle,strict_json(selector))
        if policy['table']!=data['fenceTable'] or hashlib.sha256(policy['nftables'].encode()).hexdigest()!=data['fenceSha256']:
            raise Refusal('boot fence source differs from exact runtime fence')
        embedded={'namespace':plan['prefix'],'network':network['network'],'uuid':uuid,'table':policy['table'],
                  'nftables':policy['nftables'],'nftablesSha256':data['fenceSha256'],
                  'networkXmlFingerprint':hook.xml_fingerprint(ET.fromstring(xml)),
                  'nativeFenceFingerprint':hook.json_fingerprint(json.loads(native)),
                  'proofPath':str(context.runtime/'network-fence-boot-proof.json')}
        destination=HOOK_DIRECTORY/(plan['prefix']+'-fence');source=Path(hook.__file__).read_text()
        if source.count('POLICY = None')!=1 or os.path.lexists(destination):raise Refusal('boot hook source/destination not fresh')
        body=source.replace('POLICY = None','POLICY = '+repr(embedded),1).encode()
        data['bootFence']={'phase':'install-intended','path':str(destination),'sha256':hashlib.sha256(body).hexdigest(),
                          'policy':embedded,'sourceSha256':stage.sha(__file__),'networkAutostartEnabled':False}
        stage.write_ledger(journal,data)
        for directory in reversed([HOOK_DIRECTORY,*HOOK_DIRECTORY.parents]):
            if not directory.exists():directory.mkdir(mode=0o755)
            st=directory.lstat()
            if directory.is_symlink() or not stat.S_ISDIR(st.st_mode) or st.st_uid or st.st_mode&0o022:raise Refusal('unprotected libvirt hook directory')
        fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o755);os.fchmod(fd,0o755)
        with os.fdopen(fd,'wb') as out:out.write(body);out.flush();os.fsync(out.fileno())
        fd=os.open(HOOK_DIRECTORY,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
        info=destination.lstat();data['bootFence'].update(phase='hook-staged',dev=info.st_dev,ino=info.st_ino)
        stage.write_ledger(journal,data)
        return {'status':'owned-boot-hook-staged','daemonRefreshAndNativeProofRequired':True,'networkAutostartEnabled':False,'guestCreated':False}


def prove_boot_fence(bundle,selector,journal,expected_sha):
    lifecycle,_,plan,context,data=boot_context(bundle,selector,journal,expected_sha);stage=lifecycle.stage;hook=hook_helpers()
    with lifecycle.lifecycle(context):
        boot=data.get('bootFence',{});path=Path(boot.get('path',''));info=path.lstat();hook.protected_file(path,0o755)
        if (stage.sha(journal)!=expected_sha or boot.get('phase')!='hook-staged' or
                (info.st_dev,info.st_ino)!=(boot['dev'],boot['ino']) or stage.sha(path)!=boot['sha256']):raise Refusal('exact staged boot hook CAS required')
        lifecycle.units.units_idle(plan);context.physical_reserves()
        if os.path.lexists(context.runtime/'runtime-authority.json'):raise Refusal('native boot policy proof requires preactivation context')
        # A libvirt restart is permitted only with ALL domains stopped and no
        # domain autostart that could restart old production or authored work.
        guests=subprocess.check_output(['virsh','-c','qemu:///system','list','--all','--uuid'],text=True,timeout=20).splitlines()
        for guest in filter(str.strip,guests):
            state=subprocess.check_output(['virsh','-c','qemu:///system','domstate',guest],text=True,timeout=20).strip()
            detail=subprocess.check_output(['virsh','-c','qemu:///system','dominfo',guest],text=True,timeout=20)
            if state!='shut off' or not re.search(r'(?m)^Autostart:\s+(?:disable|no)\s*$',detail):raise Refusal('domain live/autostart; no libvirt restart')
        networks=subprocess.check_output(['virsh','-c','qemu:///system','net-list','--all','--uuid'],text=True,timeout=20).splitlines()
        for existing in filter(str.strip,networks):
            detail=subprocess.check_output(['virsh','-c','qemu:///system','net-info',existing],text=True,timeout=20)
            if re.search(r'(?m)^Autostart:\s+yes\s*$',detail) and not re.search(r'(?m)^Active:\s+yes\s*$',detail):
                raise Refusal('stopped autostart network; no libvirt restart')
        uuid=data['networkUuid'];network=data['network'];actual=subprocess.check_output(['virsh','-c','qemu:///system','net-uuid',network['network']],text=True,timeout=20).strip()
        xml=subprocess.check_output(['virsh','-c','qemu:///system','net-dumpxml',uuid],text=True,timeout=20)
        native=subprocess.check_output(['nft','-j','list','table','inet',data['fenceTable']],timeout=20)
        links=json.loads(subprocess.check_output(['ip','-j','link','show','master',network['bridge']],text=True,timeout=20))
        if actual!=uuid or links or hashlib.sha256(xml.encode()).hexdigest()!=data['nativeXmlSha256'] or hashlib.sha256(native).hexdigest()!=data['nativeFenceSha256']:
            raise Refusal('network/fence/attached interface changed before native hook proof')
        if subprocess.check_output(['systemctl','is-active','libvirtd.service'],text=True,timeout=20).strip()!='active':
            raise Refusal('libvirt daemon is not active; no stopped/failed production restart')
        proof_path=Path(boot['policy']['proofPath'])
        if os.path.lexists(proof_path):raise Refusal('native boot proof path already exists; no stale proof reuse')
        boot['phase']='native-proof-intended';stage.write_ledger(journal,data)
        subprocess.run(['systemctl','restart','libvirtd.service'],check=True,timeout=60,capture_output=True)
        subprocess.run(['virsh','-c','qemu:///system','net-destroy',uuid],check=True,timeout=30,capture_output=True)
        subprocess.run(['virsh','-c','qemu:///system','net-start',uuid],check=True,timeout=30,capture_output=True)
        hook.protected_file(proof_path,0o600);proof=strict_json(proof_path)
        if (proof.get('schemaVersion')!=1 or proof.get('activationAuthorized') is not False or proof.get('network')!=network['network'] or
                proof.get('networkUuid')!=uuid or proof.get('namespace')!=plan['prefix'] or proof.get('hookSha256')!=boot['sha256'] or
                proof.get('bootId')!=Path('/proc/sys/kernel/random/boot_id').read_text().strip() or proof.get('event')!='start/begin' or
                proof.get('networkXmlFingerprint')!=boot['policy']['networkXmlFingerprint'] or
                proof.get('nativeFenceFingerprint')!=boot['policy']['nativeFenceFingerprint']):raise Refusal('native libvirt invocation proof missing or changed; autostart remains off')
        subprocess.run(['virsh','-c','qemu:///system','net-autostart',uuid],check=True,timeout=30,capture_output=True)
        status=subprocess.check_output(['virsh','-c','qemu:///system','net-info',uuid],text=True,timeout=20)
        if any(not re.search(r'(?m)^'+key+r':\s+yes\s*$',status) for key in ('Active','Persistent','Autostart')):raise Refusal('native network boot policy not ready')
        boot.update(phase='native-hook-proven',networkAutostartEnabled=True,proofSha256=stage.sha(proof_path));data['networkAutostart']=True
        stage.write_ledger(journal,data)
        return {'status':'owned-network-native-boot-fence-proven','networkAutostartEnabled':True,'hostRebootPerformed':False,'guestCreated':False,'activationAuthorized':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle',type=Path,required=True)
    parser.add_argument('--selector',type=Path,required=True)
    parser.add_argument('--inspect-host',action='store_true',help='Read-only route/name/link collision check')
    mode=parser.add_mutually_exclusive_group()
    mode.add_argument('--prepare-owned',action='store_true',help='Explicit new fenced bridge creation, no guest or stack activation')
    mode.add_argument('--retire-owned',action='store_true',help='Explicit exact never-guest network/fence retirement')
    mode.add_argument('--stage-owned-boot-fence',action='store_true')
    mode.add_argument('--prove-owned-boot-fence',action='store_true')
    parser.add_argument('--journal',type=Path)
    parser.add_argument('--expected-journal-sha',help='Reviewed protected journal SHA for owned boot policy or exact never-guest retirement')
    args=parser.parse_args()
    try:
        if args.stage_owned_boot_fence or args.prove_owned_boot_fence:
            if args.journal is None or not args.expected_journal_sha or args.inspect_host:raise Refusal('exact network journal SHA and one boot operation required')
            operation=stage_boot_fence if args.stage_owned_boot_fence else prove_boot_fence
            print(json.dumps(operation(args.bundle,args.selector,args.journal,args.expected_journal_sha),sort_keys=True));return
        if args.retire_owned:
            if args.journal is None or not args.expected_journal_sha or args.inspect_host:raise Refusal('exact owned journal SHA and one retirement operation required')
            print(json.dumps(retire_owned(args.bundle,args.selector,args.journal,args.expected_journal_sha),sort_keys=True));return
        if args.expected_journal_sha is not None:raise Refusal('journal SHA requires an explicit owned boot/retirement operation')
        if args.prepare_owned:
            if args.journal is None or args.inspect_host:raise Refusal('exact new journal and one operation required')
            print(json.dumps(prepare_owned(args.bundle,args.selector,args.journal),sort_keys=True));return
        if args.journal is not None:raise Refusal('journal only belongs to explicit owned network operations')
        xml,info=render(args.bundle,strict_json(args.selector))
        if args.inspect_host:
            info.update(screen_host(ipaddress.ip_network(info['subnet']),info['network'],info['bridge']))
        print(json.dumps(info,sort_keys=True),file=sys.stderr)
        print(xml,end='')
    except (Refusal,ValueError,KeyError,TypeError,OSError,subprocess.SubprocessError,json.JSONDecodeError) as exc:
        raise SystemExit('private guest network refused: '+str(exc)) from exc


if __name__=='__main__':main()
