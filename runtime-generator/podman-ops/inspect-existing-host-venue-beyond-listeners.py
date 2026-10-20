#!/usr/bin/env python3
"""Read-only diagnostic beyond the four known host-network consumers.

Does NOT change normal physical venue refusal or authorize installation.
Never use this diagnostic as a replacement for the full installer gates.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

HERE=Path(__file__).resolve().parent

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,HERE/path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inspect(bundle,selector,inventory):
    venue=load('physical_venue','verify-existing-host-venue.py')
    intent=load('host_listener_intent','verify-existing-host-listener-intent.py')
    bundle=Path(bundle);selector=Path(selector)
    checked=subprocess.run([sys.executable,'-B',str(HERE/'verify-existing-host-venue.py'),
        '--bundle',str(bundle),'--selector',str(selector),'--protected-inventory',str(inventory)],
        capture_output=True,text=True,timeout=75)
    expected='venue preflight refused: host-network container lacks isolated listener proof: '
    authority=json.loads(selector.read_text())
    if checked.returncode==0 or checked.stderr.strip()!=expected+authority['unitPrefix']+'-alloy.container':
        raise venue.Refusal('physical venue does not stop at the expected listener gate; preflight exit='+str(checked.returncode)+'; '+checked.stderr.strip())
    classified=intent.verify(bundle)
    if classified['activationAuthorized'] or classified['hostNetworkCount']!=4:
        raise venue.Refusal('host-network static diagnostic lost scoped authority')
    venue.screen_venue_volume_init(bundle,authority)
    mounts=venue.screen_quadlet_mounts(bundle,authority,diagnostic_host_network=True)
    rootful=venue.screen_rootful_store_quadlets(bundle,authority)
    ports=venue.screen_rendered_ports(bundle,authority)
    return {'schemaVersion':1,'scope':'read-only after expected physical Alloy refusal; STATIC diagnostic, no host-network runtime proof',
            'checkedMounts':mounts,'checkedRootfulStoreUnits':rootful,'checkedPublishedPorts':ports,
            'hostNetworkUnits':classified['hostNetworkUnits'],
            'activationAuthorized':False,'acceptedIntegratedInstalls':0}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for arg in ('bundle','selector','protected-inventory'):p.add_argument('--'+arg,required=True)
    a=p.parse_args()
    try:print(json.dumps(inspect(a.bundle,a.selector,a.protected_inventory),sort_keys=True))
    except (ValueError,KeyError,TypeError,OSError,json.JSONDecodeError,subprocess.TimeoutExpired) as exc:
        raise SystemExit('venue post-listener diagnostic refused: '+str(exc)) from exc

if __name__=='__main__':main()
