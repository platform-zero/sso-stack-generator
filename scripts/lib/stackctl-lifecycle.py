#!/usr/bin/env python3
"""Native selected-installation status. Unit state is not application readiness."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]


def journal_module():
    path=ROOT/'runtime-generator/podman-ops/install-journal.py'
    spec=importlib.util.spec_from_file_location('stackctl_native_journal',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def unit_states(command, units):
    result=subprocess.run(command+['show',*units,'-p','Id','-p','LoadState','-p','ActiveState',
        '-p','SubState','-p','Result'],capture_output=True,text=True,timeout=30,cwd='/')
    if result.returncode or len(result.stdout)>1024*1024:raise ValueError('Selected unit status unavailable')
    rows=[]
    for block in result.stdout.strip().split('\n\n'):
        row=dict(line.split('=',1) for line in block.splitlines() if '=' in line)
        if row.get('Id') not in units or not row.get('ActiveState') or not row.get('LoadState'):
            raise ValueError('Incomplete selected unit status')
        rows.append(row)
    if len(rows)!=len(units) or len({r['Id'] for r in rows})!=len(units):
        raise ValueError('Selected unit status count/identity mismatch')
    return rows


def status(root, journal=None):
    if not root.is_absolute() or os.geteuid()!=0:raise ValueError('Root and an absolute metadata root required')
    journal=journal or journal_module();journal.directory(root)
    intent=journal.read(root/'.install-intent.json')
    base={'schemaVersion':1,'scope':'selected native metadata and systemd state only',
          'applicationReadiness':'unproven','mutationsPerformed':False,'containerRuntimeInvoked':False,
          'stateRoot':str(root),'selectedRelease':None,'nativePhase':intent.get('phase') if intent else None}
    current=root/'current'
    if not current.exists() and not current.is_symlink():return base
    if not current.is_symlink():raise ValueError('Native current selection is not a pointer')
    release=current.resolve(strict=True)
    if release.parent!=root/'releases':raise ValueError('Selected release escaped metadata root')
    journal.directory(release)
    receipt=journal.read(release/'installation-receipt.json')
    if not receipt or receipt.get('release')!=str(release):raise ValueError('Selected receipt mismatch')
    if journal.fingerprint(release,receipt['inputs'].keys())!=receipt['inputs']:
        raise ValueError('Selected immutable input binding changed')
    base['selectedRelease']=release.name
    base['receiptPhase']=receipt['phase']
    base['domains']=[{'name':label,'units':unit_states(command,units)}
                    for label,command,units in journal.selected_quarantine_plans(release)]
    base['unitCounts']={state:sum(r['ActiveState']==state for d in base['domains'] for r in d['units'])
                        for state in ('active','activating','deactivating','inactive','failed')}
    return base


def main():
    parser=argparse.ArgumentParser(description=__doc__);commands=parser.add_subparsers(dest='command',required=True)
    p=commands.add_parser('status');p.add_argument('--state-root',required=True,type=Path);p.add_argument('--json',action='store_true')
    args=parser.parse_args()
    try:result=status(args.state_root)
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
        print('stackctl: selected installation inspection refused; verify root access, receipt and unit authority',file=sys.stderr);return 1
    print(json.dumps(result,indent=2,sort_keys=True));return 0


if __name__=='__main__':raise SystemExit(main())
