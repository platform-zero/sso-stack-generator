#!/usr/bin/env python3
"""Scoped, strict-TLS live readiness for an INSTALLED isolated Caddy.

No localhost admin API, --insecure, CA substitution or service activation.
Success proves only the Caddy transport/config, NOT upstreams, guest reachability,
or integrated acceptance. Requires a future installed-stack journal; inert stages
and adapter-only checks deliberately cannot satisfy this probe.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import subprocess

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('venue_owned_stage',HERE/'venue-owned-stage.py')
stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage)
Refusal=stage.Refusal

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def authority(bundle,selector,ledger):
    if os.geteuid()!=0:raise Refusal('root required for installed Caddy identity')
    bundle=Path(bundle);selector=Path(selector);ledger=Path(ledger)
    if ledger.is_symlink() or not ledger.is_file() or ledger.stat().st_uid!=0 or stat.S_IMODE(ledger.stat().st_mode)!=0o600:
        raise Refusal('protected installed venue journal required')
    data=json.loads(ledger.read_text());plan=stage.owned_plan(bundle,selector)
    if data.get('status')!='installed-running' or data.get('plan')!=plan or data.get('activationAuthorized') is not True:
        raise Refusal('only a separately reviewed installed venue can be probed')
    selected=json.loads(selector.read_text());prefix=plan['prefix'];state=selected['rootful']['stateRoot']
    quadlet=Path('/etc/containers/systemd')/(prefix+'-caddy.container')
    recorded=data.get('unitFiles',{}).get(str(quadlet))
    if not recorded or quadlet.is_symlink() or not quadlet.is_file() or sha(quadlet)!=recorded['sha256']:
        raise Refusal('selected installed Caddy unit source drift')
    lines=quadlet.read_text().splitlines()
    if (lines.count('Network=host')!=1 or
            'Environment=CONTAINERS_STORAGE_CONF='+state+'/containers-storage.conf' not in lines or
            'Environment=CONTAINERS_CONF='+state+'/containers.conf' not in lines):
        raise Refusal('Caddy lost isolated rootful transport authority')
    settings=(bundle/'site/global.settings/stack.config.yaml').read_text()
    if settings.count('\nruntime:\n')!=1:raise Refusal('site runtime domain block ambiguous')
    match=re.search(r'(?m)^  domain: "([a-z0-9.-]+)"$',settings.split('\nruntime:\n',1)[1])
    if not match:raise Refusal('site domain authority missing')
    hostname='portal.'+match.group(1)
    config=Path(data.get('renderedCaddyPath') or '')
    release=Path(data.get('releaseRoot') or '')
    state_root=Path(state);state_record=data.get('pathIdentities',{}).get(state)
    if not state_record or state_root.is_symlink() or not state_root.is_dir():
        raise Refusal('installed rootful state owner missing')
    st=state_root.lstat()
    if (st.st_dev,st.st_ino,st.st_uid)!=(state_record['dev'],state_record['ino'],0):
        raise Refusal('rootful state identity changed')
    if (not config.is_absolute() or not release.is_absolute() or release.is_symlink() or
            release.parent!=state_root/'releases' or release.parent.is_symlink() or
            any(p.is_symlink() for p in config.parents if str(p).startswith(state+'/')) or
            not str(config).startswith(str(release)+'/') or
            config!=release/'runtime/configs/caddy/Caddyfile' or config.is_symlink() or not config.is_file() or
            sha(config)!=data.get('renderedCaddySha256')):
        raise Refusal('rendered installed Caddyfile bytes/venue release differ')
    runtime=config.read_text()
    ports=selected['ports'];http=ports['80'];https=ports['443']
    if not all(runtime.count(token)==1 for token in ('admin off','default_bind 127.0.0.1',
             'http_port '+str(http),'https_port '+str(https))):
        raise Refusal('full rendered Caddy transport/admin configuration differs')
    volume=Path(selected['rootful']['volumeRoot']);volume_record=data.get('pathIdentities',{}).get(str(volume))
    if not volume_record or not volume.is_dir() or volume.is_symlink():
        raise Refusal('installed rootful volume authority missing')
    vst=volume.lstat()
    if (vst.st_dev,vst.st_ino,vst.st_uid)!=(volume_record['dev'],volume_record['ino'],0):
        raise Refusal('rootful volume identity changed')
    cert=volume/'caddy_certs/pki/authorities/local/root.crt'
    if (not cert.is_file() or cert.lstat().st_uid!=0 or cert.lstat().st_nlink!=1 or cert.stat().st_size<300 or
            any(p.is_symlink() for p in (cert,*cert.parents) if str(p).startswith(selected['rootful']['volumeRoot'])) or
            not str(cert).startswith(selected['rootful']['volumeRoot']+'/')):
        raise Refusal('selected Caddy local CA is not available in isolated volume')
    service=prefix+'-caddy.service'
    checked=subprocess.run(['systemctl','show','-p','ActiveState','--value',service],
                           capture_output=True,text=True,timeout=15,cwd='/')
    if checked.returncode or checked.stdout.strip()!='active':
        raise Refusal('installed Caddy service is not active')
    return hostname,http,https,cert,config

def request(port,hostname,path='/',*,tls_context=None):
    with socket.create_connection(('127.0.0.1',port),timeout=4) as plain:
        plain.settimeout(4)
        if tls_context is None:connection=plain
        else:connection=tls_context.wrap_socket(plain,server_hostname=hostname)
        with connection:
            connection.sendall(('GET '+path+' HTTP/1.1\r\nHost: '+hostname+'\r\nConnection: close\r\n\r\n').encode('ascii'))
            response=b''
            while b'\r\n\r\n' not in response and len(response)<16384:
                data=connection.recv(4096)
                if not data:break
                response+=data
    if b'\r\n\r\n' not in response:raise Refusal('Caddy HTTP headers missing or oversized')
    lines=response.split(b'\r\n\r\n',1)[0].decode('iso-8859-1').split('\r\n')
    if not re.fullmatch(r'HTTP/1\.[01] [1-5][0-9]{2}( .*)?',lines[0]):
        raise Refusal('Caddy HTTP status invalid')
    headers={}
    for line in lines[1:]:
        key,sep,value=line.partition(':')
        if not sep:raise Refusal('invalid HTTP response header')
        headers.setdefault(key.lower(),[]).append(value.strip())
    return int(lines[0].split()[1]),headers

def probe(bundle,selector,ledger):
    hostname,http,https,ca,config=authority(bundle,selector,ledger)
    uri='/__p0_venue_transport_probe?scope=caddy'
    status,headers=request(int(http),hostname,uri)
    if status!=308 or headers.get('location')!=['https://'+hostname+uri]:
        raise Refusal('actual private HTTP transport lacks exact standard HTTPS redirect')
    context=ssl.create_default_context(cafile=str(ca))
    if not context.check_hostname or context.verify_mode!=ssl.CERT_REQUIRED:
        raise Refusal('verified Caddy TLS mode unexpectedly disabled')
    secure_status,_=request(int(https),hostname,uri,tls_context=context)
    # A 502 can mean upstreams are not yet started. Never credit it as app
    # readiness; TLS verification and Caddy's loaded HTTP redirect are scoped.
    return {'transportReady':True,'tlsHostnameAndCaVerified':True,'httpStatus':status,
            'httpsStatus':secure_status,'configSha256':sha(config),
            'upstreamReady':False,'guestReachabilityProven':False,
            'activationAuthorized':False,'acceptedIntegratedInstalls':0}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('bundle','selector','ledger'):p.add_argument('--'+key,required=True)
    a=p.parse_args()
    try:print(json.dumps(probe(a.bundle,a.selector,a.ledger),sort_keys=True))
    except (Refusal,KeyError,ValueError,OSError,ssl.SSLError,subprocess.SubprocessError,json.JSONDecodeError) as exc:
        raise SystemExit('venue Caddy live readiness refused: '+str(exc)) from exc
if __name__=='__main__':main()
