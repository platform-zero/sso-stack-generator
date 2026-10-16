#!/usr/bin/env python3
"""Quarantine ONLY an exact version-2 failed start; never reset populated data.

A crash during activation can leave a target partly active. The selected
version-2 installer must journal the intent BEFORE queuing any unit. This
worker stops only the selected 194-unit namespace in reverse declared order,
retains all data/graphs/inputs, and will not issue an automatic retry.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat
import time

HERE=Path(__file__).resolve().parent
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
stage=load('venue_stage','venue-owned-stage.py')
units=load('venue_units','venue-unit-stage.py')
graph=load('venue_graph','venue-graph-clear.py')
Refusal=stage.Refusal

def selected_commands(plan):
    root=['systemctl']
    return [(None,root)]+[(a, ['runuser','-u',a['name'],'--','env',
                'HOME='+a['home'],'XDG_RUNTIME_DIR=/run/user/'+str(a['uid']),
                'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/'+str(a['uid'])+'/bus',
                'systemctl','--user']) for a in plan['accounts']]

def targets(bundle,plan,state):
    selected=units.manifest(bundle,plan)
    if (selected!=state.get('unitFiles') or len(selected)!=194 or
            len(state.get('installedUnits',[]))!=194):
        raise Refusal('installed unit names/source SHA not selected')
    paths={row['path']:row for row in state['installedUnits']}
    if set(paths)!=set(selected):raise Refusal('installed unit inode set changed')
    commands={None:[],**{a['name']:[] for a in plan['accounts']}}
    for dest,entry in selected.items():
        p=Path(dest);s=p.lstat();row=paths[dest]
        if (p.is_symlink() or not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or
                (s.st_dev,s.st_ino,s.st_uid)!=(row['dev'],row['ino'],entry['uid']) or
                units.hashlib.sha256(p.read_bytes()).hexdigest()!=entry['sha256']):
            raise Refusal('selected installed unit inode/content changed before quarantine')
        account=next((a for a in plan['accounts'] if a['uid']==entry['uid']),None) if entry['uid'] else None
        owner=account['name'] if account else None
        if entry['uid'] and account is None:raise Refusal('unit UID not selected account')
        if p.suffix in ('.container','.build','.network','.target'):
            commands[owner].append(p.stem+('' if p.suffix=='.target' else
                              '-build.service' if p.suffix=='.build' else
                              '-network.service' if p.suffix=='.network' else '.service'))
    return commands

def quarantine(bundle,selector,ledger):
    p=Path(ledger)
    if os.geteuid()!=0 or p.is_symlink() or not p.is_file() or p.stat().st_uid!=0 or stat.S_IMODE(p.stat().st_mode)!=0o600:
        raise Refusal('exact root0600 failed-start journal required')
    state=json.loads(p.read_text());plan=stage.owned_plan(bundle,selector)
    if (state.get('plan')!=plan or state.get('venueInstallerVersion')!=2 or
            state.get('venueStartPhase') not in ('starting','failed-quarantining') or
            state.get('status') not in ('units-staged','installed-starting') or
            state.get('managerStarted')!=[a['name'] for a in plan['accounts']] or
            state.get('managerStopped') or state.get('activationAuthorized') is not True or
            state.get('venueStartIntent')!=plan['quadletTreeSha256']):
        raise Refusal('no exact version-2 failed activation intent; never stop an inert or other venue')
    selected=targets(bundle,plan,state)
    marker=Path(plan['roots']['rootful-state'])/'volume-ready-r1.txt'
    if marker.is_symlink() or (marker.exists() and
            (not marker.is_file() or marker.stat().st_uid!=0 or stat.S_IMODE(marker.stat().st_mode)!=0o600)):
        raise Refusal('readiness marker changed before failed-start stop')
    if state['venueStartPhase']=='starting':
        state['venueStartPhase']='failed-quarantining';stage.write_ledger(p,state)
    # Stop exact namespace units, never restart previously stopped production.
    # Targets first, then containers/builds/networks; the latter cannot be
    # inferred stopped merely because a target has entered inactive state.
    for account,command in reversed(selected_commands(plan)):
        owner=account['name'] if account else None
        names=selected[owner]
        ordered=sorted(names,key=lambda x:(not x.endswith('.target'),x),reverse=False)
        for name in ordered:
            result=graph.run(command+['stop','--no-block',name],timeout=30)
            if result.returncode:raise Refusal('selected start quarantine stop request failed; receipt retained')
    # units_idle checks every selected namespace on every manager AND jobs.
    # No graph/data retirement occurs here. Failed or partly stopped intent
    # remains quarantining and requires explicit review/resume.
    deadline=time.monotonic()+180
    while True:
        try:units.units_idle(plan);break
        except Refusal as exc:
            if ('became active' not in str(exc) and 'unexpected systemd job' not in str(exc)) or time.monotonic()>=deadline:
                raise
            time.sleep(2)
    state['venueStartPhase']='failed-quarantined'
    state['activationAuthorized']=False  # no restart after failure without a fresh exact intent
    state['venueStartQuarantineUnits']=sum(map(len,selected.values()))
    stage.write_ledger(p,state)
    return {'status':'failed-quarantined','selectedUnitNames':state['venueStartQuarantineUnits'],
            'populatedDataRetained':True,'activationAuthorized':False,'acceptedIntegratedInstalls':0}

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('bundle','selector','ledger'):ap.add_argument('--'+name,required=True)
    a=ap.parse_args()
    try:print(json.dumps(quarantine(a.bundle,a.selector,a.ledger),sort_keys=True))
    except (Refusal,OSError,KeyError,ValueError,TypeError) as exc:
        raise SystemExit('venue exact failed-start quarantine refused: '+str(exc)) from exc
if __name__=='__main__':main()
