#!/usr/bin/env python3
"""Private metadata journal for the existing, serialized Podman installer.

No implicit mutation/replay. Explicit native preparation is delegated only to
source-bound owners under the canonical lock. A pending attempt requires exact
journal CAS plus an unchanged input fingerprint.
"""
import argparse
import hashlib
import importlib.util
import fcntl
import pwd
import subprocess
import json
import os
from pathlib import Path
import stat
import tempfile
import time
import re
import sys

PHASES = ('preparing', 'units-selected', 'building', 'starting', 'active', 'failed', 'retired-failed', 'retired-clean')
CORE_INPUTS = ('bundle.json', 'stack.ir.json', 'source-provenance.json')
PINNED_INPUTS = ('podman-domains.json', 'site/agent-vm.json',
                 'site/agent-vm.provenance.json', 'site/manifest.json',
                 'site/components.lock.json', 'site/global.settings/registry-image-ids.json',
                 'site/global.settings/webservices.sops.json',
                 'site/global.settings/build-base-image-ids.json')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('Unsafe installation journal directory')


def read(path):
    if not path.exists() and not path.is_symlink():
        return None
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
        raise ValueError('Unsafe installation journal')
    value = json.loads(path.read_text())
    if not isinstance(value, dict) or value.get('schemaVersion') != 1 or value.get('phase') not in PHASES:
        raise ValueError('Unknown installation journal')
    return value


def write(path, value, raw=None):
    directory(path.parent)
    read(path)
    if raw is not None and json.loads(raw) != value:
        raise ValueError('Raw canonical record does not match validated value')
    body = raw if raw is not None else (json.dumps(value, sort_keys=True) + '\n').encode()
    fd, name = tempfile.mkstemp(prefix='.install-journal-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(body)
            output.flush(); os.fsync(output.fileno())
        os.chmod(name, 0o600); os.replace(name, path)
        fd = os.open(path.parent, os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        Path(name).unlink(missing_ok=True)


def fingerprint(bundle, names=None):
    # Missing optional site inputs are pinned as absent, not silently skipped.
    # Historical three-key receipts remain verifiable for narrowly guarded
    # retirement; only NEW installations may record the expanded pin set.
    names = tuple(names) if names is not None else CORE_INPUTS + PINNED_INPUTS
    if (len(set(names)) != len(names) or not set(CORE_INPUTS).issubset(names)
            or not set(names).issubset(CORE_INPUTS + PINNED_INPUTS)):
        raise ValueError('Unknown installation pin authority')
    result = {}
    for name in names:
        path = bundle / name
        if name in CORE_INPUTS or path.exists() or path.is_symlink():
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise ValueError('Installation pin must be a regular file')
            result[name] = digest(path)
        else:
            result[name] = None
    return result


def standalone_profile(bundle):
    # Either canonical declaration selects the stronger host admission path;
    # removing one declaration must not silently select legacy admission.
    selected = False
    for name in ('site/manifest.json', 'podman-domains.json'):
        path = bundle / name
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('Unsafe installation profile input')
            value = json.loads(path.read_text())
            if not isinstance(value, dict):
                raise ValueError('Invalid installation profile input')
            selected = selected or value.get('deploymentMode') == 'standalone'
    return selected


def readiness_owner():
    source = Path(__file__).with_name('native-readiness-owner.py')
    spec = importlib.util.spec_from_file_location('native_journal_readiness_owner', source)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def update(root, bundle, release, phase, expected=''):
    directory(root)
    if not root.is_absolute() or release.parent != root / 'releases':
        raise ValueError('Installation receipt escaped selected release root')
    release.parent.mkdir(mode=0o755, exist_ok=True)
    directory(release.parent)
    path = root / '.install-intent.json'
    old = read(path)
    inputs = fingerprint(bundle)
    if phase == 'preparing':
        previous = None
        if old and old['phase'] not in ('active', 'retired-failed', 'retired-clean'):
            if expected != digest(path) or old.get('inputs') != inputs:
                raise ValueError('Pending installation needs exact CAS and unchanged inputs')
            # Retain only a previous-release claim made at the original,
            # active-to-preparing transition; do not infer it from a failure.
            previous = old.get('previousRelease')
            if previous is not None and (not isinstance(previous, str)
                    or Path(previous).parent != root / 'releases'):
                raise ValueError('Untrusted previous native release claim')
        elif expected:
            raise ValueError('Stale installation recovery CAS')
        elif old and old['phase'] == 'active':
            old_release = Path(old['release'])
            if (old_release.parent != root / 'releases' or not old_release.is_dir()
                    or (root / 'current').resolve() != old_release):
                raise ValueError('Current active release does not match prior journal')
            directory(old_release)
            prior_receipt = read(old_release / 'installation-receipt.json')
            if (not prior_receipt or prior_receipt['phase'] != 'active'
                    or prior_receipt['release'] != str(old_release)
                    or prior_receipt['inputs'] != old['inputs']
                    or fingerprint(old_release, old['inputs'].keys()) != old['inputs']):
                raise ValueError('Prior selected release input pins changed')
            previous = str(old_release)
        value = {'schemaVersion': 1, 'release': str(release), 'inputs': inputs, 'phase': phase,
                 'previousRelease': previous,'steps': [phase],
                 'resumedFrom': old.get('release') if old and old['phase'] not in ('active', 'retired-failed', 'retired-clean') else None}
        # Original finance provenance ONLY, never an activation/readiness permit.
        # Required for retained Run2: the owning arm validates it anew. Retired
        # (data-disposed) attempts do not carry an original identity forward.
        if old and old['phase'] not in ('retired-failed', 'retired-clean'):
            fields = {'nativeFinanceOwnershipReceipt': 'root-native-finance-ownership',
                      'nativeFinanceReference': 'root-native-finance-reference'}
            for field, kind in fields.items():
                if field not in old: continue
                original = old[field]; prior = Path(old['release']) / 'installation-receipt.json'
                if (read(prior) != old or prior.read_bytes() != path.read_bytes()
                        or not isinstance(original, dict) or type(original.get('schemaVersion')) is not int
                        or original['schemaVersion'] != 1 or original.get('kind') != kind
                        or original.get('status') != 'completed'
                        or (field == 'nativeFinanceOwnershipReceipt' and any(original.get(flag) is not False
                            for flag in ('activationAuthorized', 'readinessAuthorized', 'journalWritten')))):
                    raise ValueError('Original native finance provenance/dual records differ')
                value[field] = original
    else:
        if not old or old.get('release') != str(release) or old.get('inputs') != inputs:
            raise ValueError('Installation journal binding mismatch')
        if old['phase'] in ('active', 'failed', 'retired-failed', 'retired-clean'):
            raise ValueError('Terminal installation journal cannot advance')
        if phase != 'failed' and PHASES.index(phase) != PHASES.index(old['phase']) + 1:
            raise ValueError('Installation phase ordering mismatch')
        value = dict(old, phase=phase, steps=old['steps'] + [phase])
        if standalone_profile(bundle) and phase in ('units-selected', 'starting', 'active'):
            owner = readiness_owner()
            if phase == 'units-selected':
                # Caddy bootstrap can execute required volume-init before the
                # final target transaction. Its attempt timestamp starts here.
                value['readiness'] = owner.seal_selection(root, release, old)
            elif phase == 'starting':
                value['readiness'] = owner.capture_images(root, release, old)
            else:
                # This is synchronous canonical admission, not an externally
                # supplied token or a target-active assertion. Refusal writes
                # no active receipt/intent and leaves failed/pending evidence.
                value['nativeReadiness'] = owner.verify_active_transition(root, release, old)
    # Native private-directory preparation consumes this new receipt leaf
    # BEFORE source copying. Its root-only custody must not depend on umask.
    # Never normalize an existing release's permissions here.
    release.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory(release)
    # Preserve each immutable release's own compact receipt, not an experiment backup.
    write(release / 'installation-receipt.json', value)
    write(path, value)
    return value


def seafile_preparation_owner():
    source = Path(__file__).with_name('native-seafile-bootstrap.py')
    spec = importlib.util.spec_from_file_location('canonical_native_seafile_bootstrap', source)
    owner = importlib.util.module_from_spec(spec); sys.modules[spec.name] = owner
    spec.loader.exec_module(owner)
    return owner


def prepare_seafile(root, release):
    """Canonical Main producer, before any runtime projection or service start."""
    directory(root); directory(release)
    old = read(root / '.install-intent.json')
    if (release.parent != root / 'releases' or not standalone_profile(release)
            or not old or old.get('phase') != 'preparing' or old.get('release') != str(release)
            or read(release / 'installation-receipt.json') != old or fingerprint(release) != old['inputs']
            or old.get('domainRuntimeProjections') or old.get('nativeSeafilePreparation')
            or old.get('nativeSeafileOwnership')):
        raise ValueError('Exact unpublished standalone preparing Seafile source required')
    owner = seafile_preparation_owner()
    owner.load_protocol().projection_owner().lock_held(root)
    if 'seafile' not in json.loads((release / 'stack.ir.json').read_bytes())['services']:
        return dict(module='seafile', status='not-selected')
    try:
        preparation = owner.Fresh(root, release, old)
        native = release / 'native-seafile'
        native.mkdir(mode=0o700)
        directory(native)
        original = (root / '.install-intent.json').read_bytes()
        if hashlib.sha256(original).hexdigest() != preparation.binding.receipt_sha:
            raise ValueError('Original Seafile preparation receipt changed')
        # Immutable canonical origin snapshot, NOT a caller-minted permit.
        write(native / 'preparation-receipt.json', old, raw=original)
        value = dict(old, nativeSeafilePreparation=preparation.plan)
        write(release / 'installation-receipt.json', value)
        write(root / '.install-intent.json', value)
        result = preparation.run(value)
        proof = preparation.publish(value, result)
        value = dict(value, nativeSeafileOwnership=proof)
        write(release / 'installation-receipt.json', value)
        write(root / '.install-intent.json', value)
        return proof
    except Exception as error:
        # Preserve trusted guard locations, never selected module exception text.
        raise ValueError('Canonical native Seafile preparation refused').with_traceback(error.__traceback__) from None


def project_domain(root, release, domain):
    """Canonical preparing-record owner; projector never mints its own lease."""
    directory(root)
    if release.parent != root / 'releases' or not standalone_profile(release):
        raise ValueError('Projection requires the selected standalone release')
    old = read(root / '.install-intent.json')
    if (not old or old['phase'] != 'preparing' or old['release'] != str(release)
            or read(release / 'installation-receipt.json') != old
            or fingerprint(release) != old['inputs']):
        raise ValueError('Projection requires identical preparing input authority')
    if domain in old.get('domainRuntimeProjections', {}):
        raise ValueError('Projection replay requires canonical failed-intent disposition')
    source = Path(__file__).with_name('native-runtime-projection-owner.py')
    spec = importlib.util.spec_from_file_location('native_journal_projection_owner', source)
    owner = importlib.util.module_from_spec(spec); sys.modules[spec.name] = owner
    spec.loader.exec_module(owner)
    custody = owner.prepare_custody(root, release, old, domain)
    value = dict(old, projectionCustody=custody)
    write(release / 'installation-receipt.json', value)
    write(root / '.install-intent.json', value)
    proof = owner.project_and_handoff(root, release, value, domain)
    projections = dict(value.get('domainRuntimeProjections', {}))
    projections[domain] = proof
    value = dict(value, domainRuntimeProjections=projections)
    write(release / 'installation-receipt.json', value)
    write(root / '.install-intent.json', value)
    env_spec = importlib.util.spec_from_file_location('native_journal_projected_env_owner',
               Path(__file__).with_name('native-projected-env-owner.py'))
    env_owner = importlib.util.module_from_spec(env_spec); sys.modules[env_spec.name] = env_owner
    env_spec.loader.exec_module(env_owner)
    handoff = env_owner.copy_environment(root, release, value, domain)
    if not isinstance(handoff, dict) or handoff.get('status') != 'completed':
        raise ValueError('Canonical projected environment handoff incomplete')
    projections[domain] = dict(proof, environmentStoreHandoff=handoff)
    value = dict(value, domainRuntimeProjections=projections)
    write(release / 'installation-receipt.json', value)
    write(root / '.install-intent.json', value)
    return projections[domain]


def native_file_owner():
    source = Path(__file__).with_name('native-install-files.py')
    spec = importlib.util.spec_from_file_location('stack_native_file_owner', source)
    owner = importlib.util.module_from_spec(spec)
    exec(compile(source.read_bytes(), str(source), 'exec'), owner.__dict__)
    return owner


def runtime_environment_unit_owner():
    source = Path(__file__).with_name('native-runtime-env-units.py')
    spec = importlib.util.spec_from_file_location('stack_runtime_environment_unit_owner', source)
    owner = importlib.util.module_from_spec(spec)
    exec(compile(source.read_bytes(), str(source), 'exec'), owner.__dict__)
    return owner


def publish_runtime_environment_units(root, release):
    """Seal exact adjunct custody before one-process file publication."""
    owner = runtime_environment_unit_owner(); owner.o.lock_held(root)
    directory(root); directory(release)
    path, receipt = root / '.install-intent.json', release / 'installation-receipt.json'
    old = read(path)
    if (not old or old.get('phase') != 'preparing' or old.get('release') != str(release)
            or release.parent != root / 'releases' or read(receipt) != old or digest(path) != digest(receipt)
            or any(key in old for key in ('nativeRuntimeEnvUnitCustody', 'nativeRuntimeEnvUnits'))):
        raise ValueError('Exact unpublished runtime environment unit transaction required')
    key = (str(root), str(release))
    try:
        custody = owner.prepare_custody(root, release, old)
        if read(path) != old or read(receipt) != old:
            raise ValueError('Runtime environment unit preparation CAS changed')
        prepared = dict(old, nativeRuntimeEnvUnitCustody=custody)
        write(receipt, prepared); write(path, prepared)
        proof = owner.publish(root, release, prepared)
        if (read(path) != prepared or read(receipt) != prepared or digest(path) != digest(receipt)
                or proof.get('kind') != 'native-runtime-env-units' or proof.get('status') != 'completed'
                or proof.get('release') != str(release) or proof.get('inputs') != prepared.get('inputs')
                or proof.get('custodySha256') != owner.p.sha(owner.p.encoded(custody))
                or proof.get('intentSha256') != digest(path) or proof.get('receiptSha256') != digest(path)
                or proof.get('runtimeDeferred') is not True or proof.get('updaterOwned') is not False
                or proof.get('activationAuthorized') is not False or proof.get('readinessAuthorized') is not False):
            raise ValueError('Runtime environment unit proof or record CAS differs')
        final = dict(prepared, nativeRuntimeEnvUnits=proof)
        write(receipt, final); write(path, final)
        return proof
    finally:
        pending = getattr(owner, '_sessions', {}).pop(key, None)
        if pending is not None: pending.close()


def seal_runtime_environment_copies(root, release):
    """Record actual Root-issued copies, never authorize a runtime restore."""
    owner = runtime_environment_unit_owner(); owner.o.lock_held(root)
    directory(root); directory(release)
    path, receipt = root / '.install-intent.json', release / 'installation-receipt.json'
    old = read(path)
    if (not old or old.get('release') != str(release) or release.parent != root / 'releases'
            or old.get('phase') not in {'preparing', 'units-selected', 'building', 'starting', 'active'}
            or read(receipt) != old or digest(path) != digest(receipt)):
        raise ValueError('Exact runtime copy observation transaction required')
    proof = owner.seal_running_copies(root, release, old)
    if (read(path) != old or read(receipt) != old or digest(path) != digest(receipt)
            or proof.get('kind') != 'root-runtime-copy-observation' or proof.get('status') != 'completed'
            or proof.get('release') != str(release) or proof.get('inputs') != old.get('inputs')
            or proof.get('intentSha256') != digest(path) or proof.get('receiptSha256') != digest(path)
            or proof.get('activationAuthorized') is not False or proof.get('readinessAuthorized') is not False
            or proof.get('resetAuthorized') is not False or proof.get('journalWritten') is not False):
        raise ValueError('Actual Root runtime copy proof or source CAS differs')
    final = dict(old, nativeRuntimeEnvironmentCopies=proof)
    write(receipt, final); write(path, final)
    return proof


def rootful_environment_owner():
    source = Path(__file__).with_name('native-rootful-env-owner.py')
    spec = importlib.util.spec_from_file_location('stack_rootful_environment_owner', source)
    owner = importlib.util.module_from_spec(spec)
    exec(compile(source.read_bytes(), str(source), 'exec'), owner.__dict__)
    return owner


def project_rootful_environment(root, release):
    """Retain source FDs through custody sealing and exact persistent copy."""
    owner = rootful_environment_owner(); owner.o.lock_held(root)
    directory(root); directory(release)
    path, receipt = root / '.install-intent.json', release / 'installation-receipt.json'
    old = read(path)
    if (not old or old.get('phase') != 'preparing' or old.get('release') != str(release)
            or release.parent != root / 'releases' or read(receipt) != old or digest(path) != digest(receipt)
            or any(key in old for key in ('rootfulEnvCustody', 'rootfulEnvironmentStoreHandoff'))):
        raise ValueError('Exact unpublished rootful environment transaction required')
    key = (str(root), str(release))
    try:
        custody = owner.prepare_custody(root, release, old)
        if read(path) != old or read(receipt) != old:
            raise ValueError('Rootful environment preparation record CAS changed')
        prepared = dict(old, rootfulEnvCustody=custody)
        write(receipt, prepared); write(path, prepared)
        proof = owner.copy_environment(root, release, prepared)
        if (read(path) != prepared or read(receipt) != prepared or digest(path) != digest(receipt)
                or proof.get('kind') != 'rootful-persistent-environment' or proof.get('status') != 'completed'
                or proof.get('release') != str(release) or proof.get('inputs') != prepared.get('inputs')
                or proof.get('sourceCustodySha256') != owner.p.sha(owner.p.encoded(custody))
                or proof.get('stateStore') != str(root / 'runtime-env') or proof.get('runtimeDeferred') is not True
                or proof.get('activationAuthorized') is not False or proof.get('readinessAuthorized') is not False
                or proof.get('removeUnselected') is not False):
            raise ValueError('Rootful environment proof or journal CAS differs')
        final = dict(prepared, rootfulEnvironmentStoreHandoff=proof)
        write(receipt, final); write(path, final)
        return proof
    finally:
        pending = getattr(owner, '_sessions', {}).pop(key, None)
        if pending is not None: pending.close()


def native_stop_selection(root, release):
    """Read the exact sealed source union; never discover a live prefix."""
    owner = native_file_owner(); o, p, native = owner.o, owner.p, owner.native
    o.lock_held(root); directory(root); directory(release)
    if release.parent != root / 'releases': raise ValueError('Selected stop source escapes metadata')
    with p.directory(root) as fd:
        o.root_directory(os.fstat(fd), private=True)
        pin = p.custody_record(fd)
        if pin['acl'] or pin['defaultAcl']: raise ValueError('Stop metadata root ACL differs')
        raw, _ = p.read_at(fd, '.install-intent.json', private=True)
        current = p.current_record(fd)
    with p.directory(release) as fd:
        o.root_directory(os.fstat(fd), private=True)
        pin = p.custody_record(fd)
        if pin['acl'] or pin['defaultAcl']: raise ValueError('Stop source root ACL differs')
        receipt, _ = p.read_at(fd, 'installation-receipt.json', private=True)
    value = p.strict(raw)
    if (receipt != raw or value.get('release') != str(release)
            or value.get('phase') not in {'preparing', 'units-selected', 'building', 'starting', 'active', 'failed'}
            or set(value.get('inputs', {})) != p.INPUTS
            or fingerprint(release, value['inputs'].keys()) != value['inputs']):
        raise ValueError('Stop source private records/full inputs differ')
    custody, proof = value.get('nativeUnitFileCustody'), value.get('nativeUnitFiles')
    if (not isinstance(custody, dict) or not isinstance(proof, dict)
            or proof.get('status') != 'completed' or proof.get('release') != str(release)
            or custody.get('inputs') != value['inputs'] or proof.get('inputs') != value['inputs']):
        raise ValueError('Exact selected-file ownership has not completed')
    expected = standalone_binding(release)
    scope, operator, authority = owner.storage.authority(release)
    if expected != authority: raise ValueError('Stop storage source changed')
    marker_fd, _ = o.open_absolute(scope, operator)
    try: marker_body, _ = p.read_at(marker_fd, owner.storage.MARKER, private=True)
    finally: os.close(marker_fd)
    if p.strict(marker_body) != expected or p.sha(marker_body) != custody.get('scopeMarkerSha256'):
        raise ValueError('Stop selection marker changed')
    accounts = custody.get('accounts', {})
    if set(accounts) != set(native.IDENTITIES): raise ValueError('Seven sealed stop actors required')
    for name, account in accounts.items():
        uid, user = native.IDENTITIES[name]
        actual, group = o.pwd.getpwnam(user), o.grp.getgrnam(user)
        if (account != dict(uid=uid, user=user, gid=actual.pw_gid, home=actual.pw_dir,
                            subuidStart=owner.storage.namespace_root_id(user))
                or (actual.pw_uid, actual.pw_name, actual.pw_dir) != (uid, user, '/home/' + user)
                or group.gr_gid != actual.pw_gid or o.pwd.getpwuid(uid).pw_name != user
                or o.grp.getgrgid(group.gr_gid).gr_name != user):
            raise ValueError('Stop actor NSS/subrange changed')
    old = custody.get('stopOnlyPrevious'); previous = None
    if old is not None:
        previous = p.canonical(old['release'])
        if (previous.parent != root / 'releases' or previous == release
                or native.source_plan(previous, previous=True) != old.get('source')):
            raise ValueError('Stop-only previous source changed')
    if current is not None:
        target = current['target']
        selected = p.canonical(target) if target.startswith('/') else root / p.relative(target)
        if current['identity'][2:4] != [0, 0] or selected not in {release, previous}:
            raise ValueError('Stop current is not selected by exact source custody')
    selected = native.validate_installed(release, previous)['plan']
    with p.directory(root) as fd:
        final, _ = p.read_at(fd, '.install-intent.json', private=True)
        final_current = p.current_record(fd)
    with p.directory(release) as fd:
        final_receipt, _ = p.read_at(fd, 'installation-receipt.json', private=True)
    if final != raw or final_receipt != raw or final_current != current:
        raise ValueError('Stop selection record/current CAS changed')
    return selected


def install_selected_files(root, release):
    """Publish exact selected files in one retained-FD preparing transaction."""
    owner = native_file_owner()
    owner.o.lock_held(root)
    directory(root); directory(release)
    path, receipt = root / '.install-intent.json', release / 'installation-receipt.json'
    old = read(path)
    if (not old or old.get('phase') != 'preparing' or old.get('release') != str(release)
            or release.parent != root / 'releases' or read(receipt) != old
            or digest(path) != digest(receipt)
            or any(key in old for key in ('nativeUnitFileCustody', 'nativeUnitFiles'))):
        raise ValueError('Exact unpublished selected-file transaction required')
    key = (str(root), str(release))
    try:
        custody = owner.prepare_custody(root, release, old)
        if read(path) != old or read(receipt) != old:
            raise ValueError('Selected-file preparation record CAS changed')
        prepared = dict(old, nativeUnitFileCustody=custody)
        write(receipt, prepared); write(path, prepared)
        proof = owner.project_and_handoff(root, release, prepared)
        if (read(path) != prepared or read(receipt) != prepared
                or digest(path) != digest(receipt)
                or proof.get('kind') != 'native-selected-unit-files' or proof.get('status') != 'completed'
                or proof.get('release') != str(release) or proof.get('inputs') != prepared.get('inputs')
                or proof.get('intentSha256') != digest(path) or proof.get('receiptSha256') != digest(path)
                or proof.get('activationAuthorized') is not False or proof.get('readinessAuthorized') is not False):
            raise ValueError('Selected-file publication proof or record CAS differs')
        final = dict(prepared, nativeUnitFiles=proof)
        write(receipt, final); write(path, final)
        return proof
    finally:
        pending = getattr(owner, '_sessions', {}).pop(key, None)
        if pending is not None: pending.close()


def complete_clean_reset(root, expected):
    """Consume a same-process stopped lease; only this owner retires records.

    No caller-supplied report or boolean is accepted. The explicit synthetic
    reset authority and exact scope/stop/source/CAS checks remain in the backend.
    Caller must retain canonical inherited FD9 across ALL root record writes.
    """
    directory(root)
    if not isinstance(expected, str) or re.fullmatch('[a-f0-9]{64}', expected) is None:
        raise ValueError('Exact complete-clean intent CAS required')
    owner_spec = importlib.util.spec_from_file_location('native_clean_lock_owner',
                 Path(__file__).with_name('native-runtime-projection-owner.py'))
    lock_owner = importlib.util.module_from_spec(owner_spec); sys.modules[owner_spec.name] = lock_owner
    owner_spec.loader.exec_module(lock_owner)
    lock_owner.lock_held(root)
    path = root / '.install-intent.json'
    old = read(path)
    if not old or old['phase'] not in ('active', 'failed', 'retired-failed', 'retired-clean') or digest(path) != expected:
        raise ValueError('Complete-clean requires exact eligible terminal intent')
    release = Path(old['release'])
    receipt_path = release / 'installation-receipt.json'
    if release.parent != root / 'releases' or read(receipt_path) != old:
        raise ValueError('Complete-clean source receipt differs')
    reset_spec = importlib.util.spec_from_file_location('native_journal_clean_reset',
                 Path(__file__).with_name('host-clean-reset.py'))
    backend = importlib.util.module_from_spec(reset_spec); sys.modules[reset_spec.name] = backend
    reset_spec.loader.exec_module(backend)
    if old['phase'] == 'retired-clean':
        # This is historical eligibility only. The normal fresh custody review,
        # complete inventory/CAS and same-process stopped lease remain mandatory.
        backend.prior_completed_reset(root, old)
    reviewed = backend.review_runtime_custody(root, expected)
    custody = reviewed['cleanResetCustody']
    if old.get('cleanResetCustody') != custody:
        if digest(path) != expected or read(receipt_path) != old:
            raise ValueError('Complete-clean custody publication CAS changed')
        old = dict(old, cleanResetCustody=custody)
        write(receipt_path, old)
        write(path, old)
        expected = digest(path)
    reviewed = backend.review(root, expected)
    plan_sha = reviewed['planSha256']
    lease = backend.issue_stopped_lease(root, expected, plan_sha)
    result = backend.execute(root, expected, plan_sha, lease)
    if (digest(path) != expected or read(receipt_path) != old
            or read(path) != old or result.get('completeCleanReset') is not True
            or result.get('intentSha256') != expected or result.get('planSha256') != plan_sha
            or result.get('phase') != 'complete-owned-synthetic-clean'
            or result.get('requiredJournalTransition') != 'journal-owner-exact-CAS-retired-clean-no-restart'):
        raise ValueError('Complete-clean result or unchanged root authority differs; inspect durable evidence')
    prefix = result.get('claimPrefix', '')
    match = re.fullmatch(r'\.clean-reset-(' + re.escape(plan_sha) + r'-[a-f0-9]{32})-', prefix)
    if not match:
        raise ValueError('Complete-clean operation identity differs')
    attempt = match.group(1)
    result_path = root / '.host-clean-reset' / (attempt + '-result.json')
    intent_path = root / '.host-clean-reset' / (attempt + '-intent.json')
    result_body, _ = backend.read_file(result_path, private=True, gid=0)
    intent_body, _ = backend.read_file(intent_path, private=True, gid=0)
    operation = backend.strict(intent_body)
    if (backend.canonical(backend.strict(result_body)) != backend.canonical(result)
            or operation.get('claimPrefix') != prefix or operation.get('intentSha256') != expected
            or operation.get('planSha256') != plan_sha
            or backend.sha(backend.canonical(operation.get('plan'))) != plan_sha):
        raise ValueError('Complete-clean durable evidence differs')
    lock_owner.lock_held(root)
    if digest(path) != expected or read(receipt_path) != old:
        raise ValueError('Complete-clean final journal CAS changed')
    value = dict(old, phase='retired-clean', previousRelease=None,
        steps=old['steps'] + ['retired-clean'],
        completeCleanReset=dict(intentSha256=expected, planSha256=plan_sha,
            resultPath=str(result_path), resultSha256=backend.sha(result_body),
            applicationAcceptance=False, rootfulStoreColdAcceptance=False,
            automaticRestart=False, dataCompatibilityProven=False))
    write(receipt_path, value)
    write(path, value)
    return value['completeCleanReset']


def standalone_binding(release):
    source = Path(__file__).with_name('grant-rootless-volume-parent-traverse.py')
    spec = importlib.util.spec_from_file_location('journal_storage_binding', source)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    scope, operator, expected = module.authority(release)
    module.marker(scope, expected)
    module.safe_parent(scope, operator)
    return expected


def native_stop_inventory(release):
    """Current trusted selector, historical source policy, stop/read use ONLY."""
    source = Path(__file__).with_name('native-selection.py')
    spec = importlib.util.spec_from_file_location('stack_native_stop_selection', source)
    module = importlib.util.module_from_spec(spec)
    exec(compile(source.read_bytes(), str(source), 'exec'), module.__dict__)
    return module.inventory(release, previous=True)


def selected_quarantine_plans(release):
    """Bind stop/read plans to root-owned files in only the failed release."""
    directory(release)
    manifest = release / 'podman-domains.json'
    info = manifest.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('Unmanaged failed release domain authority')
    metadata = json.loads(manifest.read_text())
    standalone = metadata.get('deploymentMode') == 'standalone'
    if standalone: standalone_binding(release)  # No relaxed free-form user authority.
    domains = metadata['domains']
    if not isinstance(domains, list) or not domains:
        raise ValueError('Missing failed release domains')
    commands = [('rootful', ['systemctl'])]
    seen = set()
    for domain in domains:
        name, user, uid = domain['name'], domain['user'], domain['uid']
        if (not isinstance(name, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', name)
                or (not standalone and user != 'webservices-' + name)
                or not isinstance(user, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,31}', user)
                or type(uid) is not int or name in seen):
            raise ValueError('Invalid failed release domain authority')
        seen.add(name)
        account = pwd.getpwnam(user)
        if account.pw_uid != uid:
            raise ValueError('Failed release authority identity drift')
        commands.append(('rootless-' + name, ['runuser', '-u', user, '--', 'env',
                         'HOME=' + account.pw_dir, 'XDG_RUNTIME_DIR=/run/user/' + str(uid),
                         'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/' + str(uid) + '/bus', 'systemctl', '--user']))
    if standalone:
        inventory = native_stop_inventory(release)
        if set(inventory) != {label for label, _ in commands}:
            raise ValueError('Historical stopped inventory scope mismatch')
        # Include networks, all emitted targets and on-demand producers. A
        # container-only scan falsely declared their selected managers stopped.
        return [(label, command, sorted(inventory[label]['units'])) for label, command in commands]
    plans = []
    for label, command in commands:
        quadlet = release / 'quadlet' / label
        directory(quadlet)
        units = ['webservices.target']
        for path in quadlet.iterdir():
            if path.suffix not in ('.container', '.build'):
                continue
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                    or not re.fullmatch(r'webservices-[a-zA-Z0-9_.@-]+', path.stem)):
                raise ValueError('Unmanaged failed release service authority')
            units.append(path.stem + ('-build.service' if path.suffix == '.build' else '.service'))
        plans.append((label, command, sorted(set(units))))
    return plans


def unconfigured_unit(command, unit):
    result = subprocess.run(command + ['show', unit, '-p', 'LoadState', '-p', 'ActiveState',
                            '-p', 'FragmentPath', '-p', 'UnitFileState'],
                            capture_output=True, text=True, timeout=30)
    props = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    return (result.returncode == 0 and props.get('LoadState') == 'not-found'
            and props.get('ActiveState') == 'inactive' and props.get('FragmentPath') == ''
            and props.get('UnitFileState') in ('', 'not-found'))


def offline_actor(release, label):
    """Never revive a stopped standalone manager merely to inspect its units."""
    if not label.startswith('rootless-'): return None
    metadata = json.loads((release / 'podman-domains.json').read_text())
    if metadata.get('deploymentMode') != 'standalone': return None
    name = label.removeprefix('rootless-')
    row = next(r for r in metadata['domains'] if r['name'] == name)
    manager = 'user@' + str(row['uid']) + '.service'
    result = subprocess.run(['systemctl', 'show', manager, '-p', 'Id', '-p', 'LoadState',
                             '-p', 'ActiveState', '-p', 'SubState', '-p', 'MainPID', '-p', 'Job'],
                            capture_output=True, text=True, timeout=15)
    props = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    if (result.returncode or props.get('Id') != manager or props.get('LoadState') != 'loaded'):
        raise ValueError('Unknown selected manager state')
    if props.get('ActiveState') == 'active' and props.get('SubState') == 'running': return None
    if (props.get('ActiveState') not in ('inactive', 'failed') or
            props.get('SubState') not in ('dead', 'failed') or props.get('MainPID') != '0' or props.get('Job') != ''):
        raise ValueError('Selected manager has pending activity')
    return row


def assert_domain_offline(bundle, domain):
    directory(bundle)
    if not standalone_profile(bundle):
        raise ValueError('Offline preparation requires standalone source authority')
    label = 'rootless-' + domain
    plans = [row for row in selected_quarantine_plans(bundle) if row[0] == label]
    if len(plans) != 1:
        raise ValueError('Unknown selected offline actor')
    actor = offline_actor(bundle, label)
    if actor is None:
        raise ValueError('Stop the selected actor through its canonical lifecycle before preparing')
    verify_offline_actor(actor, plans[0][1])
    return {'domain': domain, 'uid': actor['uid'], 'status': 'offline-preparation-only'}


def offline_control(command):
    # Unit-file operations only: never start a manager, socket or application.
    return command[:-2] + ['SYSTEMD_OFFLINE=1', *command[-2:], '--no-reload']


def offline_subordinate_start(user):
    spec = importlib.util.spec_from_file_location('stack_offline_subids',
             Path(__file__).with_name('grant-rootless-volume-parent-traverse.py'))
    storage = importlib.util.module_from_spec(spec); spec.loader.exec_module(storage)
    return storage.namespace_root_id(user)


def verify_offline_actor(row, command):
    linger = Path('/var/lib/systemd/linger') / row['user']
    if linger.exists() or linger.is_symlink(): raise ValueError('Stopped actor still has a linger trigger')
    result = subprocess.run(offline_control(command) + ['is-enabled', 'webservices.target', 'podman.socket'],
                            capture_output=True, text=True, timeout=15)
    states = result.stdout.splitlines()
    if result.returncode not in (0, 1, 4) or len(states) != 2 or any(
            state not in ('disabled', 'masked', 'not-found') for state in states):
        raise ValueError('Stopped actor still has boot/API activation')
    start = offline_subordinate_start(row['user'])
    for proc in Path('/proc').glob('[0-9]*'):
        try:
            status = (proc / 'status').read_text()
        except (FileNotFoundError, ProcessLookupError): continue
        uid_lines = [line for line in status.splitlines() if line.startswith('Uid:')]
        if len(uid_lines) != 1: raise ValueError('Unknown process identity during stopped proof')
        ids = list(map(int, uid_lines[0].split()[1:]))
        if any(uid == row['uid'] or start <= uid < start + 65536 for uid in ids):
            raise ValueError('Stopped actor still owns a live namespace/process')
    jobs = subprocess.run(['systemctl', 'list-jobs', '--no-legend', '--no-pager'],
                          capture_output=True, text=True, timeout=15)
    manager = 'user@' + str(row['uid']) + '.service'
    if jobs.returncode or any(manager in line.split() for line in jobs.stdout.splitlines()):
        raise ValueError('Stopped actor manager job remains')


def verify_quarantined(release, allow_unconfigured=False):
    """Read actual selected managers; no service/volume mutation or trigger replay."""
    plans = selected_quarantine_plans(release)
    os.chdir('/')
    for label, command, units in plans:
        actor = offline_actor(release, label)
        if actor is not None:
            verify_offline_actor(actor, command)
            continue
        result = subprocess.run(command + ['show', *units, '-p', 'ActiveState', '--value'],
                                capture_output=True, text=True, timeout=30)
        states = [s for s in result.stdout.splitlines() if s]
        if result.returncode or len(states) != len(units) or any(s not in ('inactive', 'failed') for s in states):
            raise ValueError('Failed selection not stopped; retirement refused')
        result = subprocess.run(command + ['is-enabled', 'webservices.target'],
                                capture_output=True, text=True, timeout=10)
        if (result.stdout.strip() not in ('disabled', 'masked')
                and not (allow_unconfigured and unconfigured_unit(command, 'webservices.target'))):
            raise ValueError('Failed selection boot trigger not quarantined')
        result = subprocess.run(command + ['list-jobs', '--no-legend', '--no-pager'],
                                capture_output=True, text=True, timeout=15)
        if result.returncode or any('webservices' in line for line in result.stdout.splitlines()):
            raise ValueError('Failed selection jobs remain; retirement refused')
    timer = subprocess.run(['systemctl', 'is-enabled', 'webservices-auto-update.timer'],
                           capture_output=True, text=True, timeout=10)
    if (timer.stdout.strip() not in ('disabled', 'masked')
            and not unconfigured_unit(['systemctl'], 'webservices-auto-update.timer')):
        raise ValueError('Failed selection timer not quarantined')


def unselected_configuration_roots(domains):
    roots = [Path('/etc/containers/systemd'), Path('/etc/systemd/system')]
    for row in domains:
        home = Path(pwd.getpwnam(row['user']).pw_dir)
        roots.extend((home / '.config/containers/systemd', home / '.config/systemd/user'))
    return roots


def unselected_preparation_binding(root, release):
    """No selected pointers or installed configuration; never adopt a live stage."""
    binding = standalone_binding(release)
    if binding['scope']['dataClass'] != 'synthetic':
        raise ValueError('Unselected retirement requires an explicitly synthetic scope')
    # A different already-clean retained current is metadata, not an active
    # predecessor or this preparation's selection. Pin it independently; never
    # infer compatibility or adopt its stores.
    unselected_clean_current_pin(root, release)
    pointers = [root / 'previous']
    config_roots = unselected_configuration_roots(binding['domains'])
    for row in binding['domains']:
        pointers.extend(Path(row['stateRoot']) / name for name in ('current', 'previous'))
    if any(p.exists() or p.is_symlink() for p in pointers):
        raise ValueError('A selected/current or previous release exists')
    for base in config_roots:
        for parent in (*reversed(base.parents), base):
            if parent.is_symlink(): raise ValueError('Linked unit configuration authority')
        if base.exists() and any(base.rglob('webservices*')):
            raise ValueError('Installed stack unit configuration exists')
    return binding


def verify_unselected_preparation(root, release, value):
    """Never-selected synthetic preparation only; read-only native evidence."""
    unselected_preparation_binding(root, release)
    os.chdir('/')
    for label, command, units in selected_quarantine_plans(release):
        actor = offline_actor(release, label)
        if actor is not None:
            verify_offline_actor(actor, command)
            continue
        result = subprocess.run(command + ['show', *units, '-p', 'ActiveState', '--value'],
                                capture_output=True, text=True, timeout=30)
        states = [s for s in result.stdout.splitlines() if s]
        if result.returncode or len(states) != len(units) or any(s != 'inactive' for s in states):
            raise ValueError('Never-selected service absence not proved')
        for unit in (['webservices.target', 'webservices-auto-update.timer'] if label == 'rootful' else ['webservices.target']):
            result = subprocess.run(command + ['is-enabled', unit], capture_output=True, text=True, timeout=10)
            if result.stdout.strip() not in ('not-found', 'disabled', 'masked'):
                raise ValueError('Unexpected boot trigger in unselected preparation')
        result = subprocess.run(command + ['list-jobs', '--no-legend', '--no-pager'],
                                capture_output=True, text=True, timeout=15)
        if result.returncode or any('webservices' in line for line in result.stdout.splitlines()):
            raise ValueError('Stack jobs remain in unselected preparation')


def seal_unselected(root, expected, reviewed):
    """Repair cp -a's owner reset on an exact never-selected synthetic stage."""
    directory(root)
    path = root / '.install-intent.json'; value = read(path)
    if (not reviewed or not re.fullmatch(r'[a-f0-9]{64}', expected) or not value
            or digest(path) != expected or value['phase'] not in ('preparing', 'failed')
            or value.get('steps') not in (['preparing'], ['preparing', 'failed'])
            or value.get('previousRelease') is not None):
        raise ValueError('Exact reviewed initial preparation required for staging seal')
    release = Path(value['release'])
    if release.parent != root / 'releases' or release.is_symlink():
        raise ValueError('Unselected stage escaped metadata root')
    if (read(release / 'installation-receipt.json') != value
            or fingerprint(release, value['inputs'].keys()) != value['inputs']):
        raise ValueError('Unselected staging input/receipt binding changed')
    binding = unselected_preparation_binding(root, release)
    operator = Path(binding['scope']['root']).stat().st_uid
    paths = [release]
    for base, dirs, files in os.walk(release, followlinks=False):
        paths.extend(Path(base) / name for name in dirs + files)
        if len(paths) > 100000: raise ValueError('Oversized staging tree')
    # Validate the entire derived artifact before changing ANY owner. No links,
    # devices, foreign owners, application store or original-cache adoption.
    for item in paths:
        info = item.lstat()
        if (not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
                or info.st_uid not in (0, operator)
                or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1)):
            raise ValueError('Unrecognized staging ownership or linked/special artifact')
    if digest(path) != expected: raise ValueError('Staging seal CAS changed')
    for item in paths:
        info = item.lstat(); os.chown(item, 0, 0, follow_symlinks=False)
        os.chmod(item, stat.S_IMODE(info.st_mode) & ~0o022)
    release.chmod(0o700)
    directory(release)
    if fingerprint(release, value['inputs'].keys()) != value['inputs']:
        raise ValueError('Staging bytes changed while sealing')
    return {'sealed': True, 'entries': len(paths), 'intentSha256': expected,
            'dataPreserved': True, 'applicationAcceptance': False}


def retire_empty_preparation(root, bundle, expected, reviewed, verifier=None):
    """Retire only a failed synthetic receipt leaf, before any source copy.

    The original separate source is mandatory: an empty release cannot prove
    its own input binding. No permissions, pointers, actors or data are changed.
    Clear the abandoned allocator lease, restoring only exact existing clean-
    current metadata when present. Never adopt data or grant rollback/readiness.
    """
    directory(root)
    path = root / '.install-intent.json'; value = read(path)
    failed = value and value['phase'] == 'failed' and value.get('steps') == ['preparing', 'failed']
    retired_empty = (value and value['phase'] == 'retired-failed'
                     and value.get('steps') == ['preparing', 'failed', 'retired-failed']
                     and value.get('emptyPreparationOnly') is True and value.get('neverSelectedProved') is True
                     and value.get('activationAuthorized') is False and value.get('dataCompatibilityProved') is False
                     and value.get('dataPreserved') is True
                     and isinstance(value.get('retiredIntentSha256'), str)
                     and re.fullmatch(r'[a-f0-9]{64}', value['retiredIntentSha256']))
    if (not reviewed or bundle is None or not re.fullmatch(r'[a-f0-9]{64}', expected)
            or not value or digest(path) != expected or not (failed or retired_empty)
            or value.get('previousRelease') is not None):
        raise ValueError('Exact reviewed failed initial preparation required')
    retired = (dict(value, phase='retired-failed', steps=value['steps'] + ['retired-failed'],
                    retiredIntentSha256=expected, neverSelectedProved=True, emptyPreparationOnly=True,
                    dataPreserved=True, dataCompatibilityProved=False, activationAuthorized=False)
               if failed else value)
    release = Path(value['release'])
    if release.parent != root / 'releases' or bundle == release or bundle.is_relative_to(release):
        raise ValueError('Separate source and exact empty release required')
    directory(release); directory(bundle)
    def empty_leaf():
        receipt = read(release / 'installation-receipt.json')
        # The second alternative recovers interruption after publishing only
        # this operation's exactly derived terminal receipt, never other drift.
        return (sorted(item.name for item in release.iterdir()) == ['installation-receipt.json']
                and (receipt == retired or receipt == value
                     and (release / 'installation-receipt.json').read_bytes() == path.read_bytes()))
    if not empty_leaf() or fingerprint(bundle) != value['inputs']:
        raise ValueError('Empty preparation/source/dual-record binding changed')
    manifest = json.loads((bundle / 'site/manifest.json').read_text())
    metadata = json.loads((bundle / 'podman-domains.json').read_text())
    if (manifest.get('deploymentMode') != 'standalone' or metadata.get('deploymentMode') != 'standalone'
            or manifest.get('installerStateRoot') != str(root) or metadata.get('installerStateRoot') != str(root)
            or not isinstance(manifest.get('storageScope'), dict)
            or manifest['storageScope'].get('dataClass') != 'synthetic'
            or metadata.get('storageScope') != manifest['storageScope']):
        raise ValueError('Only the exact standalone synthetic preparation may retire')
    def current_pin():
        current = root / 'current'
        if not current.exists() and not current.is_symlink(): return None
        info = current.lstat()
        if not stat.S_ISLNK(info.st_mode) or info.st_uid != 0:
            raise ValueError('Untrusted retained current pointer')
        target = current.resolve(strict=True)
        if target == release or target.parent != root / 'releases':
            raise ValueError('Empty preparation is selected or current escaped root')
        directory(target)
        receipt = target / 'installation-receipt.json'; prior = read(receipt)
        if not prior or prior['phase'] != 'retired-clean' or prior.get('release') != str(target):
            raise ValueError('Retained current must already be clean-retired')
        return (info.st_dev, info.st_ino, info.st_ctime_ns, os.readlink(current), digest(receipt))
    current = current_pin()
    # Query only this source's selected services, boot/API triggers and jobs.
    # Existing canonical offline-actor/NSS/process checks remain authoritative.
    if verifier is None:
        # No units have been installed from this receipt-only leaf. Absence is
        # accepted only with native not-found/inactive/no-fragment evidence.
        verify_quarantined(bundle, allow_unconfigured=True)
    else:
        verifier(bundle)
    if (digest(path) != expected or not empty_leaf() or fingerprint(bundle) != value['inputs']
            or current_pin() != current):
        raise ValueError('Empty preparation CAS changed during offline review')
    write(release / 'installation-receipt.json', retired)
    if current is not None:
        # The abandoned empty leaf is NOT selected source. Restore only the
        # exact existing clean-current metadata authority, never data/actors or
        # an active predecessor. Keep its original canonical bytes unchanged.
        prior_path = (root / 'current').resolve() / 'installation-receipt.json'
        prior = read(prior_path); body = prior_path.read_bytes()
        if current_pin() != current or hashlib.sha256(body).hexdigest() != current[-1]:
            raise ValueError('Clean-current authority changed before publication')
        write(path, prior, raw=body)
    else:
        # No selected source existed. Drop only the terminal allocator lease;
        # retain the abandoned leaf's immutable failed evidence, not a fake
        # selected source that could pass future metadata admission.
        path.unlink()
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)
    return dict(retired, rootAuthorityRelease=prior['release'] if current is not None else None,
                globalIntentCleared=current is None)


def unselected_clean_current_pin(root, release):
    current = root / 'current'
    if not current.exists() and not current.is_symlink(): return None
    info = current.lstat()
    if not stat.S_ISLNK(info.st_mode) or (info.st_uid, info.st_gid) != (0, 0):
        raise ValueError('Untrusted retained unselected-current pointer')
    target = current.resolve(strict=True)
    if target == release or target.parent != root / 'releases':
        raise ValueError('Unselected preparation is current or escaped root')
    directory(target)
    receipt = target / 'installation-receipt.json'; prior = read(receipt)
    if not prior or prior['phase'] != 'retired-clean' or prior.get('release') != str(target):
        raise ValueError('Retained current must already be clean-retired')
    return (info.st_dev, info.st_ino, info.st_ctime_ns, os.readlink(current), digest(receipt))


def unselected_disposition_owner():
    source = Path(__file__).with_name('native-unselected-disposition.py')
    spec = importlib.util.spec_from_file_location('stack_unselected_disposition', source)
    owner = importlib.util.module_from_spec(spec); sys.modules[spec.name] = owner
    exec(compile(source.read_bytes(), str(source), 'exec'), owner.__dict__)
    return owner


def retire_unselected(root, expected, reviewed, verifier=verify_unselected_preparation):
    """Exact-CAS terminal disposition; no stop/restart/data/account mutation."""
    directory(root)
    path = root / '.install-intent.json'
    value = read(path)
    if (not reviewed or not re.fullmatch(r'[a-f0-9]{64}', expected) or not value
            or digest(path) != expected or value['phase'] not in ('preparing', 'failed')
            or value.get('steps') not in (['preparing'], ['preparing', 'failed'])
            or value.get('previousRelease') is not None):
        raise ValueError('Only exact reviewed initial preparation can be retired as unselected')
    release = Path(value['release'])
    if release.parent != root / 'releases': raise ValueError('Unselected release escaped receipt root')
    directory(release)
    if fingerprint(release, value['inputs'].keys()) != value['inputs']:
        raise ValueError('Unselected release input binding changed')
    current = unselected_clean_current_pin(root, release)
    pointer = None
    try:
        if current is not None:
            # Holding the original symlink inode defeats same-target ABA even
            # when ext4 reuses an inode and its cached nanosecond timestamp.
            pointer = os.open(root / 'current', os.O_PATH | os.O_NOFOLLOW)
            info = os.fstat(pointer)
            if ((info.st_dev, info.st_ino, info.st_ctime_ns) != current[:3]
                    or not stat.S_ISLNK(info.st_mode) or info.st_nlink != 1
                    or unselected_clean_current_pin(root, release) != current):
                raise ValueError('Retained clean-current pointer changed before review')
        disposition = {}
        if any(key in value for key in ('nativeUnitFileCustody', 'nativeUnitFiles', 'rootfulEnvCustody', 'rootfulEnvironmentStoreHandoff')):
            # Never erase custody or pretend a published preparation was empty.
            # Hold the original current pointer across BOTH disposition and
            # terminal publication; no gap permits same-target symlink ABA.
            owner = unselected_disposition_owner()
            leaf = read(release / 'installation-receipt.json')
            if leaf == value:
                proof = owner.dispose(root, release, value, expected)
            else:
                proof = owner.completed_report(root, release, value, expected)
            disposition = {'publicationDisposition': proof}
        retired = dict(value, phase='retired-failed', steps=['preparing', 'failed', 'retired-failed'],
                       retiredIntentSha256=expected, neverSelectedProved=True, dataPreserved=True,
                       dataCompatibilityProved=False, **disposition)
        # Recover ONLY this exact operation's interrupted leaf-before-root write.
        if read(release / 'installation-receipt.json') not in (value, retired):
            raise ValueError('Unselected release receipt binding changed')
        verifier(root, release, value)
        if (digest(path) != expected or read(release / 'installation-receipt.json') not in (value, retired)
                or fingerprint(release, value['inputs'].keys()) != value['inputs']
                or unselected_clean_current_pin(root, release) != current
                or (pointer is not None and os.fstat(pointer).st_nlink != 1)):
            raise ValueError('Unselected preparation CAS changed during review')
        write(release / 'installation-receipt.json', retired)
        if current is not None:
            prior_path = (root / 'current').resolve() / 'installation-receipt.json'
            prior = read(prior_path); body = prior_path.read_bytes()
            if (unselected_clean_current_pin(root, release) != current
                    or os.fstat(pointer).st_nlink != 1
                    or hashlib.sha256(body).hexdigest() != current[-1]):
                raise ValueError('Clean-current authority changed before publication')
            write(path, prior, raw=body)
        else:
            path.unlink()
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try: os.fsync(fd)
            finally: os.close(fd)
        return dict(retired, rootAuthorityRelease=prior['release'] if current is not None else None,
                    globalIntentCleared=current is None)
    finally:
        if pointer is not None: os.close(pointer)


def quarantine_failed(root, expected, reviewed, verifier=verify_quarantined, wait_seconds=120):
    """Exact-CAS, selected-unit-only graceful stop after an interrupted failure.

    This does not retire an intent, touch data, restart a previous release, or
    force-kill a unit. A failed check leaves the intent failed for root review.
    """
    directory(root)
    if not reviewed or not re.fullmatch(r'[a-f0-9]{64}', expected):
        raise ValueError('Explicit exact failed-intent/data review required')
    path = root / '.install-intent.json'
    value = read(path)
    if not value or value['phase'] != 'failed' or expected != digest(path):
        raise ValueError('Only exact-CAS terminal failure may be quarantined')
    release = Path(value['release'])
    if release.parent != root / 'releases' or (root / 'current').resolve() != release:
        raise ValueError('Failed selection is not the current immutable release')
    directory(release)
    if fingerprint(release, value['inputs'].keys()) != value['inputs']:
        raise ValueError('Failed release input binding changed')
    plans = selected_quarantine_plans(release)
    os.chdir('/')
    # Disable boot/upgrade triggers before stopping. Never touch a unit that is
    # not named by this root-owned selected release (or its own target/timer).
    failures = []
    if not unconfigured_unit(['systemctl'], 'webservices-auto-update.timer'):
        timer = subprocess.run(['systemctl', 'disable', '--now', 'webservices-auto-update.timer'],
                               capture_output=True, text=True, timeout=30)
        if timer.returncode: failures.append('timer')
    for label, command, units in plans:
        actor = offline_actor(release, label)
        if actor is not None:
            linger = subprocess.run(['loginctl', 'disable-linger', actor['user']], capture_output=True, text=True, timeout=15)
            disabled = subprocess.run(offline_control(command) + ['disable', 'webservices.target', 'podman.socket'],
                                     capture_output=True, text=True, timeout=30)
            if linger.returncode or disabled.returncode: failures.append(label)
            continue
        disabled = subprocess.run(command + ['disable', 'webservices.target'],
                                  capture_output=True, text=True, timeout=30)
        loaded = [unit for unit in units if not unconfigured_unit(command, unit)]
        stopped = (subprocess.run(command + ['--no-block', 'stop', *loaded],
                                  capture_output=True, text=True, timeout=60) if loaded else None)
        if disabled.returncode or (stopped is not None and stopped.returncode):
            failures.append(label)
    if failures:
        raise ValueError('Failed selected-unit quarantine incomplete; no automatic restart')
    deadline = time.monotonic() + wait_seconds
    while True:
        try:
            verifier(release)
            break
        except ValueError:
            if time.monotonic() >= deadline:
                raise ValueError('Selected release has running units/jobs or boot triggers') from None
            time.sleep(2)
    if digest(path) != expected or (root / 'current').resolve() != release:
        raise ValueError('Failed selection changed during quarantine')
    return {'release': release.name, 'quarantined': True, 'dataPreserved': True,
            'intentRetired': False, 'forceUsed': False}


def retire_failed(root, expected, reviewed, verifier=verify_quarantined):
    directory(root)
    if not reviewed:
        raise ValueError('Explicit data/recovery review required; no automatic compatibility claim')
    path = root / '.install-intent.json'
    value = read(path)
    if not value or value['phase'] != 'failed' or expected != digest(path):
        raise ValueError('Only exact-CAS terminal failure may be retired')
    release = Path(value['release'])
    if release.parent != root / 'releases': raise ValueError('Failed receipt escaped release root')
    directory(release)
    if fingerprint(release, value['inputs'].keys()) != value['inputs']: raise ValueError('Failed release input binding changed')
    verifier(release)
    retired = dict(value, phase='retired-failed', steps=value['steps'] + ['retired-failed'],
                   dataPreserved=True, dataCompatibilityProved=False, retiredIntentSha256=expected)
    write(release / 'installation-receipt.json', retired)
    write(path, retired)
    return retired


def native_finance_owner(release, old):
    """Compile ONLY the selected immutable complete liveOps closure."""
    owner = native_file_owner(); native = owner.native
    bundle_body = native.read_file(release / 'bundle.json')
    if native.sha(bundle_body) != old.get('inputs', {}).get('bundle.json'):
        raise ValueError('Original selected finance bundle input SHA differs')
    pins = native.strict(bundle_body).get('liveOps')
    if (not isinstance(pins, dict) or not pins
            or any(not re.fullmatch(r'ops/[A-Za-z0-9_.-]+', name) or not re.fullmatch('[a-f0-9]{64}', digest)
                   for name, digest in pins.items())):
        raise ValueError('Complete pinned finance operation sources required')
    if set(native.children(release / 'ops')) != {name[4:] for name in pins}:
        raise ValueError('Selected finance operation namespace differs')
    bodies = {}
    for name, expected in sorted(pins.items()):
        body = native.read_file(release / name)
        if native.sha(body) != expected: raise ValueError('Selected finance operation source SHA differs')
        bodies[name] = body
    name = 'ops/native-finance-ownership.py'
    if name not in bodies: raise ValueError('Selected release lacks native finance owner')
    spec = importlib.util.spec_from_file_location('journal_native_finance_owner', release / name)
    module = importlib.util.module_from_spec(spec)
    exec(compile(bodies[name], str(release / name), 'exec'), module.__dict__)
    return module


def publish_native_finance(root, release, action, expected=''):
    """Original retained lifecycle only: arm/capture under the canonical FD9."""
    if action not in ('arm', 'capture'): raise ValueError('Exact native finance action required')
    native_stop_selection(root, release)  # Existing full-source/NSS/marker/unit reader.
    reader = native_file_owner(); o, p = reader.o, reader.p
    o.lock_held(root)
    with p.directory(root) as root_fd, p.directory(release) as release_fd:
        raw, _ = p.read_at(root_fd, '.install-intent.json', private=True)
        receipt, _ = p.read_at(release_fd, 'installation-receipt.json', private=True)
        old = p.strict(raw); current = p.current_record(root_fd)
        if (raw != receipt or old.get('phase') != 'starting' or old.get('release') != str(release)
                or type(old.get('schemaVersion')) is not int or old['schemaVersion'] != 1
                or current is None or current['target'] not in (str(release), 'releases/' + release.name)
                or (expected and p.sha(raw) != expected)):
            raise ValueError('Exact starting native finance dual-record/current CAS required')
        owner = native_finance_owner(release, old)
        result = owner.transact(root, release, old, action)
        if type(result) is not owner.RootFinanceResult:
            raise ValueError('Only exact process-local native finance result may publish')
        try:
            field = 'financeOwnershipCustody' if action == 'arm' else 'nativeFinanceOwnershipReceipt'
            if result.field != field or not isinstance(result.record, dict):
                raise ValueError('Native finance result field/schema differs')
            result.recheck()
            if (p.read_at(root_fd, '.install-intent.json', private=True)[0] != raw
                    or p.read_at(release_fd, 'installation-receipt.json', private=True)[0] != raw
                    or p.current_record(root_fd) != current):
                raise ValueError('Native finance pre-publication CAS changed')
            value = dict(old, **{field: result.record})
            o.lock_held(root)
            write(release / 'installation-receipt.json', value)
            if p.read_at(root_fd, '.install-intent.json', private=True)[0] != raw:
                raise ValueError('Native finance publication interrupted/changed')
            o.lock_held(root)
            write(root / '.install-intent.json', value)
            reference = result.publish(value)
            if type(reference) is not owner.RootFinanceReference:
                raise ValueError('Exact Root-issued physical finance reference required')
            reference.recheck(value)
            prepared_raw, _ = p.read_at(root_fd, '.install-intent.json', private=True)
            if (p.strict(prepared_raw) != value
                    or p.read_at(release_fd, 'installation-receipt.json', private=True)[0] != prepared_raw
                    or p.current_record(root_fd) != current):
                raise ValueError('Native finance physical-reference publication CAS changed')
            final = dict(value, nativeFinanceReference=reference.record)
            o.lock_held(root)
            write(release / 'installation-receipt.json', final)
            if p.read_at(root_fd, '.install-intent.json', private=True)[0] != prepared_raw:
                raise ValueError('Native finance reference final publication interrupted')
            o.lock_held(root)
            write(root / '.install-intent.json', final)
            final_raw, _ = p.read_at(root_fd, '.install-intent.json', private=True)
            if (p.strict(final_raw) != final
                    or final_raw != p.read_at(release_fd, 'installation-receipt.json', private=True)[0]
                    or p.current_record(root_fd) != current):
                raise ValueError('Native finance final dual records/current differ')
            return {field: result.record, 'nativeFinanceReference': reference.record}
        finally: result.close()


def native_recovery_owner():
    source = Path(__file__).with_name('native-recovery-owner.py')
    spec = importlib.util.spec_from_file_location('journal_native_recovery_owner', source)
    owner = importlib.util.module_from_spec(spec)
    exec(compile(source.read_bytes(), str(source), 'exec'), owner.__dict__)
    return owner


def prepare_native_recovery(root, expected_intent_sha256, operation, operations):
    """Publish SOURCE custody, never a serialized stopped-operation permit.

    Caller retains the actual canonical FD9 flock OFD. Return a process-local
    typed lease; only the new recovery dispatch consumes it. Normal phase,
    projection, runtime, readiness and reset owners are deliberately unchanged.
    """
    owner = native_recovery_owner()
    lease = owner.capture(root, expected_intent_sha256, operation, operations)
    lease._owner = owner
    try:
        lease.guard()
        old = lease.intent
        new = dict(old, recoveryCustody=lease.custody)
        if 'recoveryCustody' in old and old['recoveryCustody'] != lease.custody:
            raise ValueError('Original recovery source custody drift; no rebase/adoption')
        intent_path, receipt_path = Path(root) / '.install-intent.json', lease.release / 'installation-receipt.json'
        raw = operations.body(intent_path, private=True)
        if (owner.h.sha(raw) != expected_intent_sha256
                or operations.body(receipt_path, private=True) != raw):
            raise ValueError('Recovery dual-record publication CAS changed')
        lease.api.o.lock_held(Path(root))
        if new != old:
            write(receipt_path, new)
            # A crash/mismatch leaves an inert dual-record mismatch, never a
            # usable lease or automatic rollback over another Root writer.
            if operations.body(intent_path, private=True) != raw or read(receipt_path) != new:
                raise ValueError('Recovery publication interrupted/changed')
            lease.api.o.lock_held(Path(root))
            write(intent_path, new)
        if operations.body(intent_path, private=True) != operations.body(receipt_path, private=True):
            raise ValueError('Recovery publication did not produce identical Root records')
        lease.bind_published(new)
        return lease
    except BaseException:
        lease.close()
        raise


def native_recovery(root, expected_intent_sha256, operation, operations):
    """Complete one native backup/restore under the caller's existing FD9."""
    lease = prepare_native_recovery(root, expected_intent_sha256, operation, operations)
    return lease._owner.execute(lease)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--inspect', action='store_true')
    parser.add_argument('--project-domain')
    parser.add_argument('--prepare-seafile', action='store_true')
    parser.add_argument('--complete-clean-reset', action='store_true')
    parser.add_argument('--install-selected-files', action='store_true')
    parser.add_argument('--stop-selection', action='store_true')
    parser.add_argument('--project-rootful-environment', action='store_true')
    parser.add_argument('--install-runtime-environment-units', action='store_true')
    parser.add_argument('--seal-runtime-environment-copies', action='store_true')
    parser.add_argument('--native-finance-arm', action='store_true')
    parser.add_argument('--native-finance-capture', action='store_true')
    parser.add_argument('--scope')
    parser.add_argument('--assert-domain-offline')
    parser.add_argument('--retire-failed', default='')
    parser.add_argument('--retire-unselected', default='')
    parser.add_argument('--retire-empty-preparation', default='')
    parser.add_argument('--seal-unselected', default='')
    parser.add_argument('--quarantine-failed', default='')
    parser.add_argument('--reviewed-data-state', action='store_true')
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--release', type=Path)
    parser.add_argument('--phase', choices=PHASES)
    parser.add_argument('--expected', default='')
    args = parser.parse_args()
    if os.geteuid() != 0: parser.error('Root-owned installation journal required')
    actions = (args.inspect, bool(args.project_domain), args.prepare_seafile, args.complete_clean_reset, args.install_selected_files, args.stop_selection,
               args.project_rootful_environment, args.install_runtime_environment_units, args.seal_runtime_environment_copies,
               args.native_finance_arm, args.native_finance_capture,
               bool(args.assert_domain_offline), bool(args.retire_failed), bool(args.retire_unselected), bool(args.retire_empty_preparation),
               bool(args.seal_unselected), bool(args.quarantine_failed), args.phase is not None)
    if sum(actions) != 1: parser.error('Exactly one canonical journal operation required')
    try:
        if args.retire_failed or args.quarantine_failed or args.retire_unselected or args.seal_unselected or args.retire_empty_preparation:
            if sum(bool(v) for v in (args.retire_failed, args.quarantine_failed, args.retire_unselected, args.seal_unselected, args.retire_empty_preparation)) != 1:
                raise ValueError('One exact recovery operation at a time')
            directory(args.root)
            lock = args.root / '.install.lock'
            fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
                    raise ValueError('Unsafe installation lock')
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                if args.retire_unselected and fd != 9:
                    # The publication owners observe the canonical same-process
                    # FD9 lease; they never acquire a substitute lock.
                    os.dup2(fd, 9, inheritable=False); os.close(fd); fd = 9
                if args.retire_empty_preparation:
                    result = retire_empty_preparation(args.root, args.bundle, args.retire_empty_preparation, args.reviewed_data_state)
                elif args.seal_unselected:
                    result = seal_unselected(args.root, args.seal_unselected, args.reviewed_data_state)
                elif args.retire_unselected:
                    result = retire_unselected(args.root, args.retire_unselected, args.reviewed_data_state)
                elif args.quarantine_failed:
                    result = quarantine_failed(args.root, args.quarantine_failed, args.reviewed_data_state)
                else:
                    result = retire_failed(args.root, args.retire_failed, args.reviewed_data_state)
                print(json.dumps(result, sort_keys=True))
            finally: os.close(fd)
        elif args.prepare_seafile:
            if args.release is None or args.bundle is not None or args.expected or args.reviewed_data_state or args.scope is not None:
                raise ValueError('One exact source-bound native Seafile preparation required')
            print(json.dumps(prepare_seafile(args.root, args.release), sort_keys=True))
        elif args.native_finance_arm or args.native_finance_capture:
            if args.release is None or args.bundle is not None or args.reviewed_data_state or args.scope is not None:
                raise ValueError('One source-bound original native finance operation required')
            print(json.dumps(publish_native_finance(args.root, args.release,
                'arm' if args.native_finance_arm else 'capture', args.expected), sort_keys=True))
        elif args.install_runtime_environment_units or args.seal_runtime_environment_copies:
            if args.release is None or args.bundle is not None or args.expected or args.reviewed_data_state:
                raise ValueError('One source-bound runtime environment operation required')
            operation = publish_runtime_environment_units if args.install_runtime_environment_units else seal_runtime_environment_copies
            print(json.dumps(operation(args.root, args.release), sort_keys=True))
        elif args.project_rootful_environment:
            if args.release is None or args.bundle is not None or args.expected or args.reviewed_data_state:
                raise ValueError('One source-bound persistent rootful environment projection required')
            print(json.dumps(project_rootful_environment(args.root, args.release), sort_keys=True))
        elif args.stop_selection:
            if args.release is None or args.bundle is not None or args.scope is None:
                raise ValueError('One exact source-bound stop scope required')
            selected = native_stop_selection(args.root, args.release)
            if args.scope not in selected['scopes']: raise ValueError('Unknown selected stop scope')
            print('\n'.join(selected['scopes'][args.scope]['units']))
        elif args.install_selected_files:
            if args.release is None or args.bundle is not None or args.expected or args.reviewed_data_state:
                raise ValueError('One source-bound selected-file publication required')
            print(json.dumps(install_selected_files(args.root, args.release), sort_keys=True))
        elif args.complete_clean_reset:
            if args.phase is not None or args.inspect or args.project_domain or args.assert_domain_offline:
                raise ValueError('One canonical complete-clean operation required')
            print(json.dumps(complete_clean_reset(args.root, args.expected), sort_keys=True))
        elif args.assert_domain_offline:
            if args.bundle is None or args.phase is not None or args.project_domain:
                raise ValueError('Offline actor preparation requires one source-bound operation')
            print(json.dumps(assert_domain_offline(args.bundle, args.assert_domain_offline), sort_keys=True))
        elif args.project_domain:
            if args.release is None or args.inspect or args.phase is not None:
                raise ValueError('One preparing projection operation required')
            print(json.dumps(project_domain(args.root, args.release, args.project_domain), sort_keys=True))
        elif args.inspect:
            directory(args.root)
            path = args.root / '.install-intent.json'
            value = read(path)
            print(json.dumps({'journal': value, 'sha256': digest(path) if value else None}, sort_keys=True))
        else:
            if args.bundle is None or args.release is None or args.phase is None:
                raise ValueError('Journal inputs required')
            update(args.root, args.bundle, args.release, args.phase, args.expected)
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        # Trusted ops guard locations ONLY. Never exception data, source lines,
        # private paths, locals, values or an untrusted traceback rendering.
        frames = []; trace = error.__traceback__
        while trace:
            code = trace.tb_frame.f_code; source = Path(code.co_filename)
            if source.parent == Path(__file__).parent:
                frames.append(source.name + ':' + str(trace.tb_lineno) + ':' + code.co_name)
            trace = trace.tb_next
        if frames: print('guard: ' + ' > '.join(frames[-16:]), file=sys.stderr)
        raise SystemExit('Installation journal refused; inspect before retry') from None

if __name__ == '__main__': main()
