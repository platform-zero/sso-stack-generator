#!/usr/bin/env python3
"""Root-only exact-CAS deletion of ONE drifted pending experimental registry image.

Not deploy/repair/retry/adoption: keeps selected pins and completed progress unchanged.
The existing inert-retirement operation must subsequently retire the selected venue.
No containers, foreign objects, alternate aliases, production graphs, force or backups.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys


class Refused(Exception):
    pass


def require(value):
    if not value:
        raise Refused()


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def protected_tree(path):
    path = Path(path)
    require(path.is_absolute() and str(path) == os.path.realpath(path))
    for item in [path, *path.parents]:
        info = item.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)


def protected_file(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                and not before.st_mode & 0o022 and 0 < before.st_size <= maximum)
        chunks = []; budget = maximum + 1
        while budget:
            part = os.read(fd, min(65536, budget))
            if not part:
                break
            chunks.append(part); budget -= len(part)
        raw = b''.join(chunks)
        after = os.fstat(fd)
        def stable(info):
            return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                    info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        require(stable(before) == stable(after) and len(raw) == before.st_size)
        return raw
    finally:
        os.close(fd)


def load_registry(bundle):
    protected_tree(bundle)
    ops = Path(bundle) / 'ops'
    protected_tree(ops)
    # -B prevents cache WRITES, not reads. Reject caches throughout the complete
    # protected transitive local import tree BEFORE any selected code executes.
    require(sys.dont_write_bytecode and sys.pycache_prefix is None)
    for directory, dirs, files in os.walk(ops, followlinks=False):
        protected_tree(directory)
        for name in dirs:
            require(name != '__pycache__')
            protected_tree(Path(directory) / name)
        for name in files:
            path = Path(directory) / name
            require(path.suffix not in ('.pyc', '.pyo') and not path.is_symlink())
            if path.suffix == '.py':
                protected_file(path, 1024 * 1024)
    path = ops / 'venue-registry-images.py'
    spec = importlib.util.spec_from_file_location('failed_registry_selected_source', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def root_admission():
    require(os.geteuid() == 0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode)
    require(Path('/proc/self/uid_map').read_bytes().split() == [b'0', b'0', b'4294967295'])
    require(os.stat('/proc/self/ns/user').st_ino == os.stat('/proc/1/ns/user').st_ino)
    path = Path(__file__)
    protected_tree(path.parent)
    protected_file(path, 262144)


def retire(bundle, selector, ledger, reviewed_sha, provenance_sha, actual_id):
    root_admission()
    require(re.fullmatch('[0-9a-f]{64}', reviewed_sha) and re.fullmatch('[0-9a-f]{64}', provenance_sha)
            and re.fullmatch('sha256:[0-9a-f]{64}', actual_id))
    bundle = Path(bundle); ledger = Path(ledger)
    protected_tree(ledger.parent)
    require(stat.S_IMODE(ledger.lstat().st_mode) == 0o600)
    initial = protected_file(ledger, 64 * 1024 * 1024)
    require(hashlib.sha256(initial).hexdigest() == reviewed_sha)
    json.loads(initial, object_pairs_hook=unique)
    provenance = protected_file(bundle / 'source-provenance.json', 262144)
    require(hashlib.sha256(provenance).hexdigest() == provenance_sha)
    registry = load_registry(bundle)
    p, data, plan, source = registry.journal(bundle, selector, None, ledger)
    lifecycle = registry.load('failed_pending_lifecycle', 'venue-start-quarantine.py')
    context = lifecycle.host_context(bundle, plan)
    with lifecycle.lifecycle(context):
        require(registry.stage.sha(p) == reviewed_sha)
        p, data, plan, source = registry.journal(bundle, selector, None, ledger)
        require(registry.stage.sha(p) == reviewed_sha)
        registry.composite.units.units_idle(plan)
        require(data.get('venueRegistryPhase') == 'preparing' and not data.get('venueStartPhase')
                and data.get('venueRegistryPlan') == source['imageIds']
                and data.get('venueRegistryFrozenSha256') == source['frozenRegistrySha256'])
        verified = data.get('venueRegistryVerified')
        require(type(verified) is dict and all(source['imageIds'].get(k) == v for k, v in verified.items()))
        pending = data.get('venueRegistryPending')
        require(type(pending) is str and pending in source['imageIds'] and pending not in verified)
        user, separator, ref = pending.partition('|')
        require(separator and not ref.startswith('sha256:') and actual_id not in source['imageIds'].values())
        roots = registry.command_graphs(bundle, plan)
        require(user in roots)
        command = roots[user][1]
        base = {'schemaVersion': 1, 'pending': pending, 'selectedImageId': source['imageIds'][pending],
                'retiredImageId': actual_id, 'verifiedSha256': hashlib.sha256(json.dumps(verified,
                sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
                'sourceProvenanceSha256': provenance_sha, 'operationSourceSha256': digest(__file__)}
        prior = data.get('venueRegistryFailedPendingRetirement')
        if prior is not None:
            require(type(prior) is dict and set(prior) == set(base) | {'phase', 'ledgerSha256Before'}
                    and prior.get('phase') in ('intent', 'delete-issued')
                    and all(prior.get(k) == v for k, v in base.items())
                    and type(prior.get('ledgerSha256Before')) is str
                    and re.fullmatch('[0-9a-f]{64}', prior['ledgerSha256Before']))
        identity = registry.pulled(command, ref)
        # Durable issued-before-rm marker makes deletion at-most-once. A present
        # object after issued is ambiguous/recreated, NEVER a silent second rm.
        issued = prior is not None and prior['phase'] == 'delete-issued'
        require((issued and identity is None) or (not issued and identity == actual_id))
        epoch = reviewed_sha
        def check_epoch():
            require(registry.stage.sha(p) == epoch)
            require(stat.S_IMODE(p.lstat().st_mode) == 0o600)
            raw = protected_file(p, 64 * 1024 * 1024)
            require(hashlib.sha256(raw).hexdigest() == epoch)
        def write_owned():
            nonlocal epoch
            check_epoch()
            expected = hashlib.sha256((json.dumps(data, sort_keys=True, indent=2) + '\n').encode()).hexdigest()
            registry.stage.write_ledger(p, data)
            # Bind the bytes WE wrote, never adopt an arbitrary postwrite SHA.
            epoch = expected
            check_epoch()
        def exact_alias():
            aliases = registry.graph.run(command + ['image', 'inspect', '--format', '{{json .RepoTags}}', actual_id], timeout=30)
            require(aliases.returncode == 0 and len(aliases.stdout) <= 16384
                    and json.loads(aliases.stdout, object_pairs_hook=unique) == [ref])
        inventory = dict(verified)
        if identity is not None:
            inventory[pending] = actual_id  # Deletion-only inventory; NEVER verified/pin promotion.
        registry.reserve()
        registry.probe(bundle, plan, data, inventory)  # ALL8 exact IDs, no containers/pods/foreign volumes/networks.
        check_epoch()
        if identity is not None:
            exact_alias()
        if prior is None:
            data['venueRegistryFailedPendingRetirement'] = {**base, 'phase': 'intent', 'ledgerSha256Before': reviewed_sha}
            write_owned()
        if not issued:
            registry.reserve()
            registry.composite.units.units_idle(plan)
            require(registry.pulled(command, ref) == actual_id)
            registry.probe(bundle, plan, data, inventory)
            exact_alias()
            check_epoch()
            data['venueRegistryFailedPendingRetirement']['phase'] = 'delete-issued'
            write_owned()
            # Revalidate even AFTER our own intent mutation, directly before rm.
            registry.composite.units.units_idle(plan)
            registry.probe(bundle, plan, data, inventory)
            require(registry.pulled(command, ref) == actual_id)
            exact_alias()
            check_epoch()
            result = registry.graph.run(command + ['image', 'rm', actual_id], timeout=60)
            require(result.returncode == 0)
        registry.probe(bundle, plan, data, verified)
        require(registry.pulled(command, ref) is None)
        registry.composite.units.units_idle(plan)
        check_epoch()
        # Preserve original pending+expected+actual+before-CAS as failed evidence.
        # Registry stays PREPARING and verified count is NEVER incremented.
        data['venueRegistryFailedPendingRetirement']['phase'] = 'retired-drifted-pending'
        data['venueRegistryPreparationAbandoned'] = True
        data.pop('venueRegistryPending')
        write_owned()
        return {'scope': 'one exact failed experimental pending image retired ONLY; normal inert retirement still required',
                'verifiedImagesUnchanged': len(verified), 'registryPhase': 'preparing',
                'activationAuthorized': False, 'acceptedIntegratedInstalls': 0, 'backupsCreated': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ('bundle', 'selector', 'ledger', 'reviewed-sha', 'provenance-sha', 'actual-id'):
        parser.add_argument('--' + field, required=True)
    args = parser.parse_args()
    try:
        result = retire(args.bundle, args.selector, args.ledger, args.reviewed_sha, args.provenance_sha, args.actual_id)
    except Exception:
        # Never print exception/input/private journal bodies.
        raise SystemExit('failed pending registry retirement refused; intent/evidence retained') from None
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
