#!/usr/bin/env python3
"""Native installation entry point and selected status; unit state is not readiness."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]


def ops_directory():
    # A generated distribution owns ops/; never fall back to a development
    # checkout nested inside a bundle whose native payload is missing.
    return ROOT/'ops' if (ROOT/'bundle.json').exists() else ROOT/'runtime-generator/podman-ops'


def journal_module():
    path=ops_directory()/'install-journal.py'
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


def install_command(bundle, activate=False, image_inputs=None, resume=None):
    bundle=bundle.absolute()
    if bundle.is_symlink() or not bundle.is_dir():raise ValueError('Plain generated bundle required')
    # The canonical installer owns all crypto, immutable supply, resource,
    # ownership, journal and activation gates. Do not duplicate or skip them.
    args=['bash',str(ops_directory()/'install-podman-bundle.sh'),'--bundle',str(bundle)]
    if activate:
        if os.geteuid()!=0:raise ValueError('Activation requires root')
        args.append('--activate')
    if image_inputs is not None:args.extend(['--image-inputs',str(image_inputs.absolute())])
    if resume is not None:
        if not isinstance(resume,str) or not re.fullmatch(r'[a-f0-9]{64}',resume):
            raise ValueError('Exact resume intent SHA-256 required')
        args.extend(['--resume-intent',resume])
    return args


def main():
    parser=argparse.ArgumentParser(description=__doc__);commands=parser.add_subparsers(dest='command',required=True)
    p=commands.add_parser('status');p.add_argument('--state-root',required=True,type=Path);p.add_argument('--json',action='store_true')
    p=commands.add_parser('install');p.add_argument('--bundle',required=True,type=Path)
    p.add_argument('--activate',action='store_true');p.add_argument('--image-inputs',type=Path)
    p.add_argument('--resume-intent',metavar='EXACT_SHA256');p.add_argument('--age-key-file',type=Path)
    args=parser.parse_args()
    try:
        if args.command=='install':
            command=install_command(args.bundle,args.activate,args.image_inputs,args.resume_intent)
            env=dict(os.environ)
            if args.age_key_file:
                key=args.age_key_file.absolute()
                if key.is_symlink() or not key.is_file() or key.stat().st_mode&0o077:
                    raise ValueError('Private regular age identity file required')
                env['SOPS_AGE_KEY_FILE']=str(key)
            os.execvpe(command[0],command,env)
        result=status(args.state_root)
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
        print('stackctl: native operation refused; verify root access, private identity, receipt and unit authority',file=sys.stderr);return 1
    print(json.dumps(result,indent=2,sort_keys=True));return 0


if __name__=='__main__':raise SystemExit(main())
