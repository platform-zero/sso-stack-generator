#!/usr/bin/env python3
"""Root-only disposable netns packet probe for a PROPOSED nft guest fence.

No host nftables, host links, real guest or installation are changed. Caller
must supply reviewed private proposal. A pass is not physical bridge proof.
"""
import argparse
import hashlib
import json
import os
import subprocess
import time


def run(*argv, input=None):
    return subprocess.run(argv,input=input,text=True,check=True,capture_output=True,timeout=15)


def cmd(pid,*args,input=None):
    return run('nsenter','-t',str(pid),'-n',*args,input=input)


def try_connect(pid,ip,port):
    return int(cmd(pid,'python3','-c',
        'import socket,sys; s=socket.socket(); s.settimeout(.9); '
        'print(s.connect_ex((sys.argv[1],int(sys.argv[2]))))',ip,str(port)).stdout.strip())


def host_digest():
    return hashlib.sha256(run('nft','list','ruleset').stdout.encode()).hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--proposal',required=True)
    args=p.parse_args();assert os.geteuid()==0
    proposal=json.load(open(args.proposal))
    assert proposal['schemaVersion']==1 and proposal['bridge']=='virbr140' and proposal['gateway']=='192.168.140.1'
    assert proposal['caddyPorts']==[80,56045,443,56042]
    prior=host_digest()
    def absent(*argv):
        return subprocess.run(argv,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=8).returncode!=0
    namespaces=[];server=None;forward_server=None
    result={'scope':'nft packet behavior in disposable network namespaces only; no actual bridge, host install or guest',
            'activationAuthorized':False,'acceptedIntegratedInstalls':0,
            'hostFenceAbsentBefore':absent('nft','list','table','inet','p0test_r1_guest_fence'),
            'hostBridgeAbsentBefore':absent('ip','link','show','dev','virbr140')}
    assert result['hostFenceAbsentBefore'] and result['hostBridgeAbsentBefore']
    try:
        for _ in range(3):
            proc=subprocess.Popen(['unshare','-n','sleep','90'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            namespaces.append(proc)
        host,guest,other=[n.pid for n in namespaces]
        for pid in (host,guest,other):cmd(pid,'ip','link','set','lo','up')
        cmd(host,'ip','link','add','virbr140','type','bridge')
        cmd(host,'ip','addr','add','192.168.140.1/24','dev','virbr140')
        cmd(host,'ip','link','set','virbr140','up')
        cmd(host,'ip','link','add','gb-host','type','veth','peer','name','gb-guest')
        cmd(host,'ip','link','set','gb-guest','netns',str(guest))
        cmd(host,'ip','link','set','gb-host','master','virbr140')
        cmd(host,'ip','link','set','gb-host','up')
        cmd(guest,'ip','addr','add','192.168.140.115/24','dev','gb-guest')
        cmd(guest,'ip','link','set','gb-guest','up')
        cmd(guest,'ip','route','add','default','via','192.168.140.1')
        cmd(host,'ip','link','add','wan-host','type','veth','peer','name','wan-guest')
        cmd(host,'ip','link','set','wan-guest','netns',str(other))
        cmd(host,'ip','addr','add','192.168.141.1/24','dev','wan-host')
        cmd(host,'ip','link','set','wan-host','up')
        cmd(other,'ip','addr','add','192.168.141.2/24','dev','wan-guest')
        cmd(other,'ip','link','set','wan-guest','up')
        cmd(other,'ip','route','add','192.168.140.0/24','via','192.168.141.1')
        cmd(host,'sysctl','-qw','net.ipv4.ip_forward=1')
        cmd(host,'nft','-f','-',input=proposal['nftables'])
        # These intentionally include synthetic sensitive-looking host ports;
        # neither a socket nor the fence is installed in the real namespace.
        server=subprocess.Popen(['nsenter','-t',str(host),'-n','python3','-u','-c',
            'import socket,time; ports=(22,53,80,443,2019,56000,56042,56045); '
            'sockets=[socket.socket() for _ in ports]; '
            '[(s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1),'
            's.bind(("192.168.140.1",p)),s.listen()) for s,p in zip(sockets,ports)]; '
            'print("READY",flush=True); time.sleep(40)'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
        if server.stdout.readline().strip()!='READY':raise RuntimeError('isolated synthetic listeners failed')
        forward_server=subprocess.Popen(['nsenter','-t',str(other),'-n','python3','-u','-c',
            'import socket,time; s=socket.socket(); '
            's.bind(("192.168.141.2",8443));s.listen();'
            'print("READY",flush=True);time.sleep(40)'],
            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
        if forward_server.stdout.readline().strip()!='READY':raise RuntimeError('isolated RFC1918 target failed')
        result['hostForwardTargetAlive']=try_connect(host,'192.168.141.2',8443)==0
        result['guestForwardInternalDenied']=try_connect(guest,'192.168.141.2',8443)!=0
        result['guestHttpsAllowed']=try_connect(guest,'192.168.140.1',443)==0
        result['guestRedirectAllowed']=try_connect(guest,'192.168.140.1',80)==0
        result['guestMappedHttpAllowed']=try_connect(guest,'192.168.140.1',56045)==0
        result['guestMappedHttpsAllowed']=try_connect(guest,'192.168.140.1',56042)==0
        result['guestBrokerSshAllowed']=try_connect(guest,'192.168.140.1',22)==0
        result['guestDnsAllowed']=try_connect(guest,'192.168.140.1',53)==0
        result['internalPublisherDenied']=try_connect(guest,'192.168.140.1',56000)!=0
        result['mistakenAdminListenerDenied']=try_connect(guest,'192.168.140.1',2019)!=0
        result['nonBridgeHttpsDenied']=try_connect(other,'192.168.140.1',443)!=0
        result['nonBridgeDnsDenied']=try_connect(other,'192.168.140.1',53)!=0
        result['hostInternalPublisherStillAlive']=try_connect(host,'192.168.140.1',56000)==0
    finally:
        if forward_server is not None:
            forward_server.terminate()
            try:forward_server.wait(timeout=4)
            except subprocess.TimeoutExpired:forward_server.kill();forward_server.wait(timeout=3)
        if server is not None:
            server.terminate()
            try:server.wait(timeout=4)
            except subprocess.TimeoutExpired:server.kill();server.wait(timeout=3)
        for proc in namespaces:
            proc.terminate()
            try:proc.wait(timeout=4)
            except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=3)
    # Host nft counters legitimately move while real production traffic runs.
    # Compare the scoped table/link absence, not the entire live ruleset hash.
    result['hostRulesChecksumSame']=prior==host_digest()
    result['hostFenceAbsentAfter']=absent('nft','list','table','inet','p0test_r1_guest_fence')
    result['hostBridgeAbsentAfter']=absent('ip','link','show','dev','virbr140')
    assert all(value is True for key,value in result.items() if key.endswith(('Allowed','Denied','Alive','AbsentBefore','AbsentAfter'))),result
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':main()
