import json,re
class Refused(Exception):
    """Only fixed reason tokens, never private paths/bodies/argv/errors."""

def require(value):
    if not value:raise Refused('protected-boundary-refused')

def retirement_shape(state,plan,context):
    """Necessary strict schema; native_observations additionally proves host facts."""
    require(type(state.get('venueInstallerVersion')) is int and state['venueInstallerVersion']==1)
    require(state.get('status')=='retired-empty' and state.get('venueInstallerPhase')=='retired-inert'
            and state.get('activationAuthorized') is False and canonical(state.get('plan'))==canonical(plan))
    require(not any(k.startswith(('venueStart','venueRuntimeAuthority')) for k in state))
    for key in state:
        if 'pending' not in key.lower():continue
        require(key=='venueRegistryFailedPendingRetirement')
        history=state[key]
        require(type(history) is dict and set(history)=={'schemaVersion','pending','selectedImageId','retiredImageId',
            'verifiedSha256','sourceProvenanceSha256','operationSourceSha256','phase','ledgerSha256Before'})
        require(type(history['schemaVersion']) is int and history['schemaVersion']==1
                and history['phase']=='retired-drifted-pending' and type(history['pending']) is str
                and 0<len(history['pending'])<=2048 and history['pending'].count('|')==1)
        for field in ('selectedImageId','retiredImageId'):
            require(type(history[field]) is str and re.fullmatch('sha256:[0-9a-f]{64}',history[field]))
        require(history['selectedImageId']!=history['retiredImageId'])
        for field in ('verifiedSha256','sourceProvenanceSha256','operationSourceSha256','ledgerSha256Before'):
            require(type(history[field]) is str and re.fullmatch('[0-9a-f]{64}',history[field]))
    accounts=plan.get('accounts');require(type(accounts) is list and len(accounts)==7)
    names=[a['name'] for a in accounts];require(len(set(names))==7)
    require(state.get('graphCleared')==['root']+names and type(state.get('managerStopped')) is list
            and len(state['managerStopped'])==7 and set(state['managerStopped'])==set(names))
    for field in ('venueCompositeMode','venueRuntimeEnvPhase','venueDomainRuntimePhase','venueReleasePhase','venueRegistryPhase','venueBuildBasePhase'):
        require(state.get(field)=='retired-inert')
    installed=state.get('installedUnits');retired=state.get('retiredUnits')
    require(type(installed) is list and len(installed)==190 and type(retired) is list and len(retired)==190)
    require(all(type(r) is dict and set(r)=={'dev','ino','path'} and type(r['dev']) is int and r['dev']>=0
                and type(r['ino']) is int and r['ino']>0 and type(r['path']) is str for r in installed))
    require(len({r['path'] for r in installed})==190 and all(type(p) is str for p in retired)
            and len(set(retired))==190 and {r['path'] for r in installed}==set(retired))
    host=state.get('venueHostUnitsRetirement')
    require(type(host) is dict and host.get('phase')=='retired' and host.get('contextSha256')==context.digest
            and type(host.get('neverStartedInstallerVersion')) is int and host['neverStartedInstallerVersion']==1)
    expected={str(Path('/etc/systemd/system')/context.unit(n)) for n in
              ('p0-identity-reconcile.service','p0-identity-reconcile.timer','p0-web.service')}
    require(type(host.get('units')) is list and {r['path'] for r in host['units']}==expected
            and len(host['units'])==3 and type(host.get('removed')) is list and len(host['removed'])==3
            and set(host['removed'])==expected)

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
