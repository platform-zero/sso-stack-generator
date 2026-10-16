#!/usr/bin/env python3
"""Read-only check of actual rendered namespaced native DNS identities."""
import argparse,json
from pathlib import Path

def check(bundle):
    metadata=json.loads((bundle/'podman-domains.json').read_text())
    prefix=metadata.get('venue',{}).get('unitPrefix')
    if not prefix or prefix=='webservices':raise ValueError('explicit namespaced venue bundle required')
    checked=0
    for file in (bundle/'quadlet').glob('*/*.container'):
        lines=file.read_text().splitlines()
        if 'Network=host' in lines:continue
        if not file.stem.startswith(prefix+'-'):raise ValueError('selected native prefix differs')
        name=file.stem.removeprefix(prefix+'-')
        if 'ContainerName='+prefix+'-'+name not in lines or 'NetworkAlias='+name not in lines:
            raise ValueError('namespaced service lost its original network DNS identity: '+name)
        checked+=1
    if not checked:raise ValueError('no selected native peer identities checked')
    return checked

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--bundle',type=Path,required=True)
    args=parser.parse_args();print('Actual rendered native peer aliases checked:',check(args.bundle))
if __name__=='__main__':main()
