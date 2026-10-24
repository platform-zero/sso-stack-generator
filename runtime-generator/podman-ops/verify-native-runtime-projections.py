#!/usr/bin/env python3
"""Read-only canonical per-domain projection checks under existing FD9.

verify_prepared(root, release, intent) checks preparing/units-selected/building/
starting/active source custody only; it never reads or restores runtime files.
verify_running(root, release, intent) checks starting/active, including restored
named runtime env files. bind_retired_current(root, release, intent) supplies
separate source-only retired-current custody before any projections exist;
full verification never skips projection/environment checks. No Session, stopped-system gate, process query, write,
copy, runtime creation or admission token. The journal owner serializes callers.
Two complete sweeps pin observations across the call; running restored files may
have fresh inodes, unlike immutable source and persistent-store file seals.
"""
import importlib.util
import os
from pathlib import Path
import stat
import struct
import sys
import time


def load(name, filename):
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


e = load('_native_projection_verify_env', 'native-projected-env-owner.py')
o, p = e.owner, e.p
require, Refused = o.require, o.Refused
DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
ROOT_ONLY = {'aggregateSha256', 'destination', 'projectionSha256', 'custodySha256',
             'ownershipHandoff', 'environmentHandoff', 'projectionCustody', 'runtimeCustody',
             'environmentStoreHandoff'}


def digest(value):
    return isinstance(value, str) and p.re.fullmatch('[a-f0-9]{64}', value) is not None


class Snapshot:
    def __init__(self, root, release, intent, running, deadline, source_bundle=None):
        self.root, self.release = p.canonical(str(root)), p.canonical(str(release))
        self.source_bundle = p.canonical(str(source_bundle)) if source_bundle is not None else None
        self.intent = p.strict(p.encoded(intent)); self.running = running
        self.fds = []; self.observed = {}; self.deadline = deadline
        self.pointer_choices = {'old', 'selected'}

    def close(self):
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds = []

    def remember(self, path, value):
        self.observed[str(path)] = value
        require(time.monotonic() < self.deadline, 'projection verification deadline exceeded')

    def child(self, parent, name, directory=False):
        fd = p.child_open(parent, name, DIR if directory else FILE)
        self.fds.append(fd)
        return fd

    def absolute(self, path, operator=None):
        fd, pins = o.open_absolute(path, operator)
        self.fds.append(fd)
        for name, record in pins.items():
            self.remember(name, record)
        return fd

    def record(self, fd, *, full=False):
        value = p.custody_record(fd)
        if full:
            value['identity'] = list(p.identity(os.fstat(fd)))
        return value

    def regular(self, parent, name, uid, gid, mode, sha=None, original=None):
        fd = self.child(parent, name)
        before = os.fstat(fd)
        record = self.record(fd, full=True)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_size <= p.MAX_FILE
                and (record['uid'], record['gid'], record['mode']) == (uid, gid, mode)
                and not record['acl'] and not record['defaultAcl'], 'selected file custody differs')
        if original is not None:
            require(record == original, 'original selected inode/mount/ACL differs')
        body = os.pread(fd, p.MAX_FILE + 1, 0)
        require(len(body) == before.st_size and len(body) <= p.MAX_FILE
                and self.record(fd, full=True) == record, 'selected bytes changed during read')
        if sha is not None:
            require(digest(sha) and p.sha(body) == sha, 'selected file SHA differs')
        check = self.child(parent, name)
        require(self.record(check, full=True) == record, 'selected pathname raced')
        return body, record

    def scope_marker(self, parent, operator):
        # ONLY the canonical marker in the already selected scope may retain
        # its native inherited, fully masked operator ACL. Regular source and
        # receipt files keep their unconditional no-ACL policy.
        require((operator.pw_uid, operator.pw_gid) == (1000, 1000), 'marker operator differs')
        fd = self.child(parent, o.storage.MARKER)
        info = os.fstat(fd); p.controlled(info, private=True)
        record = self.record(fd, full=True)
        rows = ((1, 6, 0xffffffff), (2, 7, 1000), (4, 7, 0xffffffff),
                (16, 0, 0xffffffff), (32, 0, 0xffffffff))
        native_acl = (struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *row) for row in rows)).hex()
        require(record['uid'] == 0 and record['gid'] in (0, operator.pw_gid)
                and record['mode'] == 0o600 and record['acl'] in ('', native_acl)
                and not record['defaultAcl'], 'canonical private marker profile differs')
        body = os.pread(fd, p.MAX_FILE + 1, 0)
        require(len(body) == info.st_size and len(body) <= p.MAX_FILE
                and self.record(fd, full=True) == record, 'marker changed during read')
        named = self.child(parent, o.storage.MARKER)
        require(self.record(named, full=True) == record, 'marker pathname raced')
        return body, record, fd

    def root_file(self, parent, name):
        # Descriptor-walk root-only intermediates; require a regular nlink=1
        # leaf with no ACL, and compare held/named inode identities.
        parts = name.split('/'); fd = parent
        for part in parts[:-1]:
            fd = self.child(fd, part, True)
            o.root_directory(os.fstat(fd))
            require(not self.record(fd)['acl'] and not self.record(fd)['defaultAcl'],
                    'root source ancestor ACL differs')
        leaf = self.child(fd, parts[-1]); info = os.fstat(leaf)
        p.controlled(info, private=name in ('.install-intent.json', 'installation-receipt.json', o.storage.MARKER))
        mode = stat.S_IMODE(info.st_mode)
        body, rec = self.regular(fd, parts[-1], 0, info.st_gid, mode)
        require(rec == self.record(leaf, full=True), 'root source pathname changed')
        return body, rec

    def pointer(self, fd, path, expected, original=False, owners=(0,), candidate=None):
        actual = p.current_record(fd)
        if candidate is not None:
            old_target = None
            if actual is not None:
                target = actual['target']
                old_target = p.canonical(target) if target.startswith('/') else path / p.relative(target)
            old = actual == expected if original else (actual is None if expected is None else
                  actual is not None and old_target == expected and actual['identity'][2] in owners)
            selected = (actual is not None and actual['target'] == str(candidate)
                        and actual['identity'][2] in owners)
            self.pointer_choices &= ({'old'} if old else set()) | ({'selected'} if selected else set())
            require(self.pointer_choices, 'incoherent preparing old/selected pointer set')
        elif original:
            require(actual == expected, 'original preparing current pointer differs')
        elif expected is None:
            require(actual is None, 'unexpected preparing current pointer')
        else:
            require(actual is not None and actual['target'] == str(expected)
                    and actual['identity'][2] in owners, 'selected current pointer differs')
        self.remember(path / 'current', actual)

    def accounts(self, rows):
        require(isinstance(rows, list) and len(rows) == len(o.native.IDENTITIES)
                and {r['name'] for r in rows} == set(o.native.IDENTITIES),
                'exact canonical seven domain inventory required')
        operator = o.pwd.getpwuid(1000)
        require(operator.pw_uid == operator.pw_gid == 1000
                and set(o.grp.getgrgid(1000).gr_mem) <= {operator.pw_name}
                and all(a.pw_name == operator.pw_name for a in o.pwd.getpwall() if a.pw_gid == 1000),
                'operator account/group writer differs')
        result, ids, ranges = {}, set(), []
        for row in rows:
            uid, user = o.native.IDENTITIES[row['name']]
            account, group = o.pwd.getpwnam(user), o.grp.getgrnam(user)
            require(type(row['uid']) is int and (row['uid'], row['user']) == (uid, user)
                    and (account.pw_uid, account.pw_name, account.pw_dir) == (uid, user, '/home/' + user)
                    and o.pwd.getpwuid(uid).pw_name == user and account.pw_gid == group.gr_gid > 0
                    and o.grp.getgrgid(group.gr_gid).gr_name == user,
                    'canonical actor account/group differs')
            start = o.storage.namespace_root_id(user)
            require('subuidStart' not in row or type(row['subuidStart']) is int and row['subuidStart'] == start,
                    'canonical actor subordinate declaration differs')
            result[row['name']] = account
            ids.update((uid, start)); ranges.append(start)
            self.remember('account:' + user, [uid, account.pw_gid, account.pw_dir, start, 65536])
        ranges.sort()
        require(all(a + 65536 <= b for a, b in zip(ranges, ranges[1:])), 'canonical subordinate ranges overlap')
        self.remember('namespace-root-ids', sorted(ids))
        return operator, result, ids

    def graph(self, scope_fd, scope, row, account, proof, operator, ids):
        state = p.canonical(row['stateRoot']); slot = state / 'releases' / self.release.name
        custody = proof.get('projectionCustody')
        require(isinstance(custody, dict) and set(custody) == {'schemaVersion', 'selection', 'operatorUid',
                'operatorGid', 'actorGid', 'directories', 'current'} and custody.get('schemaVersion') == 1
                and digest(proof.get('custodySha256'))
                and p.sha(p.encoded(custody)) == proof['custodySha256']
                and custody.get('selection') == dict(release=str(self.release), destination=str(slot / 'runtime'),
                    domain=row['name'], user=row['user'], uid=row['uid'], scopeMarkerSha256=self.marker_sha)
                and (custody.get('operatorUid'), custody.get('operatorGid'), custody.get('actorGid'))
                == (operator.pw_uid, operator.pw_gid, account.pw_gid), 'per-domain source custody binding differs')
        current = custody['current']
        if current is not None:
            require(isinstance(current, dict) and set(current) == {'identity', 'target'}
                    and isinstance(current['identity'], list) and len(current['identity']) == 9
                    and current['identity'][2] in (0, row['uid']) and current['identity'][5] == 1
                    and stat.S_ISLNK(current['identity'][4]), 'original actor pointer seal differs')
            target = current['target']
            old = p.canonical(target) if target.startswith('/') else state / p.relative(target)
            require(old.parent == state / 'releases' and old != slot, 'original actor pointer target differs')
        roots = {p.canonical(row[k]) for k in ('stateRoot', 'graphRoot', 'volumeRoot')}
        paths = {scope, state / 'releases', slot}
        for node in (*roots, slot):
            require(node != scope and node.is_relative_to(scope), 'selected root escapes scope')
            while node != scope:
                paths.add(node); node = node.parent
        require(set(custody.get('directories', {})) == {str(n) for n in paths},
                'exact per-domain source custody graph required')
        handles = {scope: scope_fd}
        for node in sorted(paths, key=lambda n: len(n.parts)):
            fd = handles[node] if node == scope else self.child(handles[node.parent], node.name, True)
            handles[node] = fd; rec = self.record(fd)
            expected = custody['directories'][str(node)]
            if node == slot:
                require((expected['uid'], expected['gid'], expected['mode']) == (0, 0, 0o700),
                        'original root slot custody required')
                expected = dict(expected, uid=row['uid'], gid=account.pw_gid, mode=0o700)
            require(rec == expected, 'original source graph inode/mount/ACL differs')
            if node in roots or node in (slot, state / 'releases'):
                p.custody_permissions(rec, row['uid'], account.pw_gid, set())
            elif node != scope and (rec['uid'], rec['gid'], rec['mode']) == (0, 1000, 0o2770):
                p.custody_permissions(rec, 0, 1000, ids, root_ancestor=True, operator_uid=operator.pw_uid)
            elif node == scope / 'volumes' and node == p.canonical(row['volumeRoot']).parent and rec['uid'] == 0:
                p.custody_permissions(rec, 0, operator.pw_gid, ids, root_ancestor=True,
                                      operator_uid=operator.pw_uid)
                require(rec['mode'] == 0o755, 'public volume-parent mode differs')
            else:
                p.custody_permissions(rec, operator.pw_uid, operator.pw_gid, ids, operator=True)
                require(rec['mode'] == 0o2770, 'operator source graph mode differs')
            self.remember(node, rec)
        self.pointer(handles[state], state, custody.get('current') if self.intent['phase'] == 'preparing' else slot,
                     original=self.intent['phase'] == 'preparing', owners=(0, row['uid']),
                     candidate=slot if self.intent['phase'] == 'preparing' else None)
        return handles[state], handles[slot], slot

    def runtime_tree(self, slot_fd, slot, row, account, proof, services):
        files, directories = proof.get('files'), proof.get('directories')
        seals = proof.get('runtimeCustody')
        require(isinstance(files, dict) and isinstance(directories, list)
                and len(directories) == len(set(directories)) and isinstance(seals, dict),
                'durable runtime tree seal required')
        files = dict(files, **{'projection.json': proof.get('projectionSha256')})
        dirs = {''} | set(directories)
        require('' not in directories and not (set(files) & dirs) and set(seals) == set(files) | dirs
                and {'configs', 'service-env'} <= dirs and len(seals) <= o.MAX_NODES,
                'exact runtime custody namespace differs')
        mounts = p.config_mounts(services)
        for rel in set(files) | (dirs - {''}):
            p.relative(rel)
            require(str(Path(rel).parent) in ('.', *dirs), 'runtime parent seal absent')
            if rel not in ('configs', 'service-env', 'projection.json'):
                require(rel.startswith('configs/') or rel.startswith('service-env/'), 'unselected runtime path')
                if rel.startswith('configs/'):
                    name = rel[len('configs/'):]
                    require(any(name == m or name.startswith(m + '/') or m.startswith(name + '/') for m in mounts),
                            'config path outside selected mounts')
        env_names = {name + '.env' for name, service in services.items() if p.declarations(service)}
        require({n for n in files if n.startswith('service-env/')} == {'service-env/' + n for n in env_names}
                and not any(n.startswith('service-env/') for n in dirs), 'service-env exact set differs')
        if not services:
            require(set(files) == {'projection.json'} and dirs == {'', 'configs', 'service-env'},
                    'empty domain has private source material')
        handles = {}
        total = 0
        for rel in sorted(dirs, key=lambda n: (n.count('/'), len(n))):
            parent = str(Path(rel).parent)
            parent = '' if parent == '.' else parent
            fd = self.child(slot_fd, 'runtime', True) if not rel else self.child(handles[parent], Path(rel).name, True)
            rec = self.record(fd, full=True)
            mode = 0o755 if rel == 'configs' or rel.startswith('configs/') else 0o700
            require(rec == seals[rel] and (rec['uid'], rec['gid'], rec['mode']) == (row['uid'], account.pw_gid, mode)
                    and not rec['acl'] and not rec['defaultAcl'], 'original runtime directory custody differs')
            expected = {Path(n).name for n in set(files) | dirs if n and str(Path(n).parent) == (rel or '.')}
            require(set(os.listdir(fd)) == expected, 'runtime exact child namespace differs')
            handles[rel] = fd; self.remember(slot / 'runtime' / rel, rec)
        metadata = None
        for rel, sha in sorted(files.items()):
            seal = seals[rel]
            mode = seal.get('mode')
            require(mode in ((0o644, 0o755) if rel.startswith('configs/') else (0o600,)), 'runtime file mode differs')
            parent = str(Path(rel).parent); parent = '' if parent == '.' else parent
            body, rec = self.regular(handles[parent], Path(rel).name, row['uid'], account.pw_gid, mode, sha, seal)
            total += len(body); require(total <= o.MAX_TOTAL and len(seals) <= o.MAX_NODES, 'runtime tree bound exceeded')
            if rel.startswith('configs/'):
                require(mode == (0o755 if body.startswith(b'#!') else 0o644), 'projected config executable mode differs')
            if rel == 'projection.json':
                metadata = p.strict(body)
            self.remember(slot / 'runtime' / rel, rec)
        require(metadata == {k: v for k, v in proof.items() if k not in ROOT_ONLY}, 'projection metadata/root seal differs')
        return env_names, seals

    def env_file(self, parent, name, uid, gid, seal, *, original=True):
        require(isinstance(seal, dict) and digest(seal.get('sha256')), 'environment record required')
        body, record = self.regular(parent, name, uid, gid, 0o600, seal['sha256'])
        pin = dict(identity=record['identity'], mountId=record['mountId'], sha256=p.sha(body),
                   mode=0o600, uid=uid, gid=gid, acl='', defaultAcl='')
        require(not original or pin == seal, 'environment original file proof differs')
        return pin

    def environment(self, state_fd, row, account, proof, env_names, seals):
        handoff = proof.get('environmentStoreHandoff')
        projection = {k: v for k, v in proof.items() if k != 'environmentStoreHandoff'}
        state = p.canonical(row['stateRoot']); slot = state / 'releases' / self.release.name
        require(isinstance(handoff, dict) and handoff.get('schemaVersion') == 1
                and handoff.get('kind') == 'domain-persistent-environment' and handoff.get('status') == 'completed'
                and handoff.get('release') == str(self.release) and handoff.get('domain') == row['name']
                and (handoff.get('uid'), handoff.get('gid')) == (row['uid'], account.pw_gid)
                and handoff.get('inputs') == self.intent['inputs']
                and handoff.get('scopeMarkerSha256') == self.marker_sha
                and handoff.get('custodySha256') == proof['custodySha256']
                and handoff.get('sourceProjectionSha256') == p.sha(p.encoded(projection))
                and handoff.get('sourceDirectory') == str(slot / 'runtime/service-env')
                and handoff.get('stateStore') == str(state / 'runtime-env')
                and handoff.get('runtimeStore') == '/run/user/' + str(row['uid']) + '/webservices'
                and handoff.get('runtimeDeferred') is True and handoff.get('activationAuthorized') is False
                and handoff.get('readinessAuthorized') is False and handoff.get('removeUnselected') is False
                and digest(handoff.get('intentSha256')) and handoff.get('receiptSha256') == handoff['intentSha256']
                and isinstance(handoff.get('files'), dict) and set(handoff['files']) == env_names
                and isinstance(handoff.get('sourceFiles'), dict) and set(handoff['sourceFiles']) == env_names,
                'completed per-domain environment proof binding differs')
        expected_env = {name: dict(sha256=proof['files']['service-env/' + name], mode=0o600) for name in env_names}
        require(proof.get('environmentHandoff') == dict(status='canonical-owner-copy-required',
                sourceDirectory=str(slot / 'runtime/service-env'), stateStore=str(state / 'runtime-env'),
                runtimeStore=handoff['runtimeStore'], files=expected_env, uid=row['uid'], gid=account.pw_gid,
                directoryMode=0o700, ensurePrivateStores=True, aggregateAllowed=False, removeUnselected=False),
                'producer environment handoff differs')
        if not env_names:
            require(handoff.get('store') is None, 'empty environment store proof differs')
            return
        store = self.child(state_fd, 'runtime-env', True)
        record = self.record(store)
        p.custody_permissions(record, row['uid'], account.pw_gid, set())
        require(not record['acl'] and not record['defaultAcl'] and record == handoff.get('store'),
                'persistent environment store original custody differs')
        self.remember(state / 'runtime-env', record)
        for name in sorted(env_names):
            source = handoff['sourceFiles'][name]; seal = seals['service-env/' + name]
            require(source == dict(identity=seal['identity'], mountId=seal['mountId'],
                    sha256=proof['files']['service-env/' + name], uid=row['uid'], gid=account.pw_gid,
                    mode=0o600, acl='', defaultAcl=''), 'environment source inode proof differs')
            pin = handoff['files'][name]
            require(pin.get('sha256') == source['sha256'], 'persistent environment source SHA differs')
            value = self.env_file(store, name, row['uid'], account.pw_gid, pin)
            self.remember(state / 'runtime-env' / name, value)
        if self.running:
            self.restored(row, account, handoff)

    def restored(self, row, account, handoff):
        base = Path('/run/user'); parent = self.absolute(base)
        # logind mounts a separate tmpfs at this EXACT UID runtime root.
        # Permit that boundary only, no symlinks; NO_XDEV still applies to
        # webservices and every selected leaf below the validated actor root.
        actor = os.open(str(row['uid']), DIR, dir_fd=parent)
        self.fds.append(actor)
        rec = self.record(actor)
        p.custody_permissions(rec, row['uid'], account.pw_gid, set())
        require(not rec['acl'] and not rec['defaultAcl'], 'runtime user directory ACL differs')
        named = os.open(str(row['uid']), DIR, dir_fd=parent)
        self.fds.append(named)
        require(self.record(named) == rec, 'runtime user mount/path raced')
        self.remember(base / str(row['uid']), rec)
        store = self.child(actor, 'webservices', True); rec = self.record(store)
        p.custody_permissions(rec, row['uid'], account.pw_gid, set())
        require(not rec['acl'] and not rec['defaultAcl'], 'restored runtime store ACL differs')
        self.remember(Path(handoff['runtimeStore']), rec)
        for name, seal in sorted(handoff['files'].items()):
            value = self.env_file(store, name, row['uid'], account.pw_gid, seal, original=False)
            # Fresh restored inodes are allowed, aliasing original source/store is not.
            ids = [handoff['files'][name]['identity'][:2], handoff['sourceFiles'][name]['identity'][:2]]
            require(value['identity'][:2] not in ids, 'restored environment aliases persistent/source inode')
            self.remember(Path(handoff['runtimeStore']) / name, value)

    def stop_only_previous(self, root_fd, manifest, marker):
        """Bind ONLY protected root/current; never a rollback/start authority.

        Retired source is permitted with previousRelease=None, without changing
        that field or consuming any candidate custody flag. Active previous
        source still requires the existing exact previousRelease claim. The
        source plan is produced by OUR current native-selection module, never
        by importing or executing code from the selected old release.
        """
        current = p.current_record(root_fd)
        if current is None or self.intent['phase'] != 'preparing':
            return self.intent.get('previousRelease')
        target = current['target']
        previous = p.canonical(target) if target.startswith('/') else self.root / p.relative(target)
        if previous == self.release:
            return self.intent.get('previousRelease')
        claim = self.intent.get('previousRelease')
        require(current['identity'][2:4] == [0, 0]
                and previous.parent == self.root / 'releases'
                and (claim is None or claim == str(previous)),
                'stop-only source must derive from protected same-root current')
        # Unlike the above-root mount walk, every edge from metadata root to
        # this exact old release and all its inputs must remain NO_XDEV.
        releases = self.child(root_fd, 'releases', True)
        old_fd = self.child(releases, previous.name, True)
        o.root_directory(os.fstat(releases)); o.root_directory(os.fstat(old_fd), private=True)
        for path, fd in ((self.root / 'releases', releases), (previous, old_fd)):
            record = self.record(fd)
            require(not record['acl'] and not record['defaultAcl'], 'stop-only source directory ACL differs')
            self.remember(path, record)
        absolute = self.absolute(previous)
        require(self.record(absolute) == self.record(old_fd), 'stop-only source ancestry/path changed')
        raw, receipt_pin = self.root_file(old_fd, 'installation-receipt.json')
        require(receipt_pin['gid'] == 0, 'stop-only receipt group differs')
        value = p.strict(raw)
        require(isinstance(value, dict) and type(value.get('schemaVersion')) is int
                and value['schemaVersion'] == 1 and value.get('release') == str(previous)
                and ((claim is None and value.get('phase') in ('retired-failed', 'retired-clean'))
                     or (claim == str(previous) and value.get('phase') == 'active')),
                'stop-only retired receipt or exact active previous claim required')
        pins = value.get('inputs')
        require(isinstance(pins, dict) and set(pins) == p.INPUTS
                and all(pins[n] is not None for n in p.REQUIRED), 'complete stop-only source pins required')
        documents = {}
        for name, sha in sorted(pins.items()):
            try:
                body, pin = self.root_file(old_fd, name)
            except FileNotFoundError:
                require(sha is None, 'stop-only pinned input missing')
                continue
            require(pin['gid'] == 0 and digest(sha) and p.sha(body) == sha, 'stop-only source input custody/SHA differs')
            documents[name] = body; self.remember(previous / name, pin)
        old_manifest, metadata, bundle, provenance = (p.strict(documents[n]) for n in
            ('site/manifest.json', 'podman-domains.json', 'bundle.json', 'source-provenance.json'))
        rows = metadata.get('domains')
        require(old_manifest.get('deploymentMode') == metadata.get('deploymentMode')
                == bundle.get('deploymentMode') == 'standalone'
                and old_manifest.get('site') == manifest.get('site')
                and old_manifest.get('installerStateRoot', '/var/lib/webservices')
                == metadata.get('installerStateRoot') == str(self.root)
                and old_manifest.get('storageScope') == metadata.get('storageScope') == marker['scope']
                and provenance.get('manifestSha256') == pins['site/manifest.json']
                and bundle.get('sourceProvenanceSha256') == pins['source-provenance.json']
                and bundle.get('irSha256') == pins['stack.ir.json']
                and isinstance(provenance.get('generatorCommit'), str)
                and p.re.fullmatch('[a-f0-9]{40}', provenance['generatorCommit'])
                and isinstance(rows, list) and len(rows) == len(o.native.IDENTITIES)
                and sorted([{k: row[k] for k in ('name', 'user', 'uid', 'stateRoot', 'graphRoot', 'volumeRoot')}
                            for row in rows], key=lambda row: row['name']) == marker['domains'],
                'stop-only source provenance/site/scope/canonical marker differs')
        for row in rows:
            start = o.storage.namespace_root_id(row['user'])
            require('subuidStart' not in row or type(row['subuidStart']) is int and row['subuidStart'] == start,
                    'stop-only subordinate declaration/current allocation differs')
        # Previous policy tolerates historical absent unmanaged build pairs
        # (including Huly build={}); it never applies old activation gates.
        plan = o.native.source_plan(previous, previous=True)
        quad = self.child(old_fd, 'quadlet', True)
        o.root_directory(os.fstat(quad))
        rec = self.record(quad)
        require(not rec['acl'] and not rec['defaultAcl'] and set(os.listdir(quad)) == set(plan['scopes']),
                'stop-only source Quadlet scopes differ')
        self.remember(previous / 'quadlet', rec)
        for scope, entry in sorted(plan['scopes'].items()):
            scope_fd = self.child(quad, scope, True); o.root_directory(os.fstat(scope_fd))
            rec = self.record(scope_fd)
            require(not rec['acl'] and not rec['defaultAcl']
                    and set(os.listdir(scope_fd)) == {Path(n).name for n in entry['files']},
                    'stop-only source Quadlet namespace differs')
            self.remember(previous / 'quadlet' / scope, rec)
            for name, seal in sorted(entry['files'].items()):
                body, pin = self.root_file(scope_fd, Path(name).name)
                require(pin['gid'] == 0 and p.sha(body) == seal['sha256'], 'stop-only source Quadlet custody/SHA differs')
                self.remember(previous / name, pin)
        require(self.root_file(old_fd, 'installation-receipt.json') == (raw, receipt_pin)
                and p.current_record(root_fd) == current, 'stop-only receipt/current changed during source binding')
        self.remember(previous / 'installation-receipt.json', receipt_pin)
        self.remember('stop-only-previous-source', dict(release=str(previous), source=plan))
        self.remember(self.root / 'current', current)
        return str(previous)

    def candidate_binding(self):
        require(os.geteuid() == 0 and self.release.parent == self.root / 'releases', 'exact root release required')
        phase = self.intent.get('phase')
        require(self.intent.get('schemaVersion') == 1 and type(self.intent['schemaVersion']) is int
                and self.intent.get('release') == str(self.release)
                and phase in (('starting', 'active') if self.running else ('preparing', 'units-selected', 'building', 'starting', 'active')),
                'projection verification phase differs')
        o.lock_held(self.root)
        root_fd = self.absolute(self.root); release_fd = self.absolute(self.release)
        o.root_directory(os.fstat(release_fd), private=True)
        raw, pin = self.root_file(root_fd, '.install-intent.json')
        receipt, rpin = self.root_file(release_fd, 'installation-receipt.json')
        require(raw == receipt and p.strict(raw) == self.intent, 'exact root receipt/intent CAS differs')
        self.remember(self.root / '.install-intent.json', pin)
        self.remember(self.release / 'installation-receipt.json', rpin)
        inputs = self.intent.get('inputs')
        require(isinstance(inputs, dict) and set(inputs) == p.INPUTS
                and all(inputs[n] is not None for n in p.REQUIRED), 'full root input pins required')
        source_fd, source_path = release_fd, self.release
        if self.source_bundle is not None:
            # Early directory/account preparation has an intentionally empty
            # receipt leaf. Bind its ORIGINAL separate sealed staging inputs,
            # not nonexistent copied source and never a caller-issued permit.
            require(not self.running and phase == 'preparing'
                    and not self.source_bundle.is_relative_to(self.root)
                    and not self.root.is_relative_to(self.source_bundle), 'separate early preparing source required')
            require(sorted(os.listdir(release_fd)) == ['installation-receipt.json'],
                    'early preparing release must contain only its receipt')
            source_fd = self.absolute(self.source_bundle); source_path = self.source_bundle
            o.root_directory(os.fstat(source_fd), private=True)
            require(not p.acl_bytes(source_fd, 'system.posix_acl_access')
                    and not p.acl_bytes(source_fd, 'system.posix_acl_default'), 'early source directory ACL differs')
        bodies = {}
        for name, sha in sorted(inputs.items()):
            try:
                body, record = self.root_file(source_fd, name)
            except FileNotFoundError:
                require(sha is None, 'pinned source input missing')
                continue
            require(digest(sha) and p.sha(body) == sha, 'root source input SHA differs')
            bodies[name] = body; self.remember(source_path / name, record)
        metadata, manifest, ir = (p.strict(bodies[n]) for n in ('podman-domains.json', 'site/manifest.json', 'stack.ir.json'))
        require(metadata.get('deploymentMode') == manifest.get('deploymentMode') == 'standalone'
                and metadata.get('installerStateRoot') == str(self.root)
                and manifest.get('installerStateRoot', '/var/lib/webservices') == str(self.root)
                and manifest.get('storageScope') == metadata.get('storageScope'), 'standalone source authority differs')
        rows = metadata.get('domains'); operator, accounts, ids = self.accounts(rows)
        scope = p.canonical(metadata['storageScope']['root'])
        require(not scope.is_relative_to(self.root) and not self.root.is_relative_to(scope), 'root/scope overlap')
        parent = self.absolute(scope.parent, operator); scope_fd = self.child(parent, scope.name, True)
        scope_pin = self.record(scope_fd)
        p.custody_permissions(scope_pin, operator.pw_uid, operator.pw_gid, ids, operator=True)
        require(scope_pin['mode'] == 0o2770, 'canonical marker scope custody differs')
        self.remember(scope, scope_pin)
        marker, marker_pin, marker_fd = self.scope_marker(scope_fd, operator)
        expected_marker = dict(schemaVersion=1, kind='standalone-stack-storage', site=manifest['site'],
            scope=metadata['storageScope'], domains=sorted([{k: row[k] for k in
                ('name', 'user', 'uid', 'stateRoot', 'graphRoot', 'volumeRoot')} for row in rows], key=lambda row: row['name']),
            roots=sorted(row[k] for row in rows for k in ('stateRoot', 'graphRoot', 'volumeRoot')))
        require(p.strict(marker) == expected_marker, 'canonical scope marker differs')
        self.marker_sha = p.sha(marker); self.remember(scope / o.storage.MARKER, marker_pin)
        prior = self.intent.get('previousRelease')
        if prior is not None:
            prior = p.canonical(prior)
            require(prior.parent == self.root / 'releases' and prior != self.release, 'previous root pointer escapes')
        return dict(root_fd=root_fd, release_fd=release_fd, raw=raw, pin=pin, receipt=receipt, rpin=rpin,
                    inputs=inputs, metadata=metadata, manifest=manifest, ir=ir, rows=rows, operator=operator,
                    accounts=accounts, ids=ids, scope=scope, scope_fd=scope_fd, marker=expected_marker,
                    marker_fd=marker_fd, marker_pin=marker_pin, marker_body=marker)

    def final_controls(self, binding):
        require(self.root_file(binding['root_fd'], '.install-intent.json') == (binding['raw'], binding['pin'])
                and self.root_file(binding['release_fd'], 'installation-receipt.json')
                == (binding['receipt'], binding['rpin']), 'root control changed during source/projection sweep')
        # Rewalk the absolute selected namespace, without rebasing observations,
        # and compare BOTH the original held marker and its current named inode.
        parent, pins = o.open_absolute(binding['scope'].parent, binding['operator'])
        self.fds.append(parent)
        require(all(self.observed.get(str(path)) == record for path, record in pins.items()),
                'marker ancestor namespace changed')
        named_scope = self.child(parent, binding['scope'].name, True)
        require(self.record(named_scope) == self.observed[str(binding['scope'])]
                == self.record(binding['scope_fd']), 'marker scope namespace changed')
        require(self.record(binding['marker_fd'], full=True) == binding['marker_pin']
                and self.scope_marker(named_scope, binding['operator'])[:2]
                == (binding['marker_body'], binding['marker_pin']), 'original marker custody changed')
        o.lock_held(self.root)

    def retired_binding(self):
        require(self.intent.get('phase') == 'preparing' and self.intent.get('previousRelease') is None,
                'retired current source binding requires preparing without active previous claim')
        binding = self.candidate_binding()
        previous = self.stop_only_previous(binding['root_fd'], binding['manifest'], binding['marker'])
        require(previous is not None and 'stop-only-previous-source' in self.observed,
                'retired binding requires protected old current, not absent/candidate current')
        current = self.observed[str(self.root / 'current')]
        require(p.current_record(binding['root_fd']) == current, 'retired current changed during source-only binding')
        self.final_controls(binding)
        # Candidate records MUST match on every call, but their legitimate
        # journal rewrites are not part of stable stop-only source custody.
        excluded = {str(self.root / '.install-intent.json'), str(self.release / 'installation-receipt.json')}
        custody = {key: value for key, value in self.observed.items() if key not in excluded}
        return dict(schemaVersion=1, kind='retired-current-source-custody', release=previous,
                    candidateRelease=str(self.release), candidateInputs=self.intent['inputs'], current=current,
                    source=self.observed['stop-only-previous-source']['source'], custody=custody,
                    scopeMarkerSha256=self.marker_sha, projectionAuthorized=False, environmentAuthorized=False,
                    readinessAuthorized=False, activationAuthorized=False, resetAuthorized=False)

    def sweep(self):
        binding = self.candidate_binding()
        root_fd, scope_fd = binding['root_fd'], binding['scope_fd']
        manifest, ir, rows = binding['manifest'], binding['ir'], binding['rows']
        operator, accounts, ids = binding['operator'], binding['accounts'], binding['ids']
        scope, inputs, phase = binding['scope'], binding['inputs'], self.intent['phase']
        old_current = self.stop_only_previous(root_fd, manifest, binding['marker'])
        self.pointer(root_fd, self.root, (p.canonical(old_current) if old_current is not None else None)
                     if phase == 'preparing' else self.release,
                     candidate=self.release if phase == 'preparing' else None)
        projections = self.intent.get('domainRuntimeProjections')
        require(isinstance(projections, dict) and set(projections) == {row['name'] for row in rows},
                'all seven completed domain projections required')
        for row in sorted(rows, key=lambda row: row['name']):
            proof = projections[row['name']]; account = accounts[row['name']]
            require(isinstance(proof, dict), 'domain projection object required')
            services = {n: s for n, s in ir['services'].items()
                        if s.get('placement') == 'rootless' and s.get('rootlessDomain') == row['name']}
            require(isinstance(row['services'], list) and len(row['services']) == len(set(row['services']))
                    and set(row['services']) == set(services), 'domain selected service set differs')
            expected = dict(schemaVersion=1, kind='domain-runtime-projection', release=str(self.release),
                domain=row['name'], user=row['user'], uid=row['uid'], stateRoot=row['stateRoot'],
                destination=str(Path(row['stateRoot']) / 'releases' / self.release.name / 'runtime'),
                scopeMarkerSha256=self.marker_sha, inputs=inputs, services=sorted(services),
                configMounts=p.config_mounts(services), activationAuthorized=False)
            require(all(proof.get(k) == v for k, v in expected.items())
                    and proof.get('activationAuthorized') is False
                    and digest(proof.get('intentSha256')) and proof.get('receiptSha256') == proof['intentSha256']
                    and proof.get('ownershipHandoff') == dict(uid=row['uid'], gid=account.pw_gid,
                        releaseMode=0o700, runtimeMode=0o700, activationAuthorized=False), 'root domain projection binding differs')
            state_fd, slot_fd, slot = self.graph(scope_fd, scope, row, account, proof, operator, ids)
            names, seals = self.runtime_tree(slot_fd, slot, row, account, proof, services)
            self.environment(state_fd, row, account, proof, names, seals)
        # Final root-control read under the very same inherited lock.
        self.final_controls(binding)
        return self.observed


def verify(root, release, intent, running):
    baseline = None
    deadline = time.monotonic() + 120
    # Freeze caller authority ONCE, not separately for each sweep.
    intent = p.strict(p.encoded(intent))
    for _ in range(2):
        snapshot = Snapshot(root, release, intent, running, deadline)
        try:
            observed = snapshot.sweep()
        finally:
            snapshot.close()
        require(baseline is None or baseline == observed, 'projection/environment changed between complete sweeps')
        baseline = observed
    return dict(schemaVersion=1, kind='native-runtime-projection-observation',
                domains=sorted(intent['domainRuntimeProjections']), runningEnvironmentChecked=running,
                bindingSha256=p.sha(p.encoded(baseline)), activationAuthorized=False, readinessAuthorized=False)


def bind_retired_current(root, release, intent, source_bundle=None):
    """Source-only original retired-current custody, even before projections.

    Returned equality excludes candidate journal bytes/inodes, NOT their check.
    No graph/runtime/projection/environment/start/reset authority is supplied.
    Early receipt-only callers MUST supply their separate sealed source bundle;
    all source hashes still bind to the exact real preparing dual records.
    The caller may retain and compare this stable custody as the preparing
    journal legitimately acquires projectionCustody/domainRuntimeProjections.
    """
    intent = p.strict(p.encoded(intent)); baseline = None
    deadline = time.monotonic() + 120
    for _ in range(2):
        snapshot = Snapshot(root, release, intent, False, deadline, source_bundle=source_bundle)
        try:
            result = snapshot.retired_binding()
        finally:
            snapshot.close()
        require(baseline is None or baseline == result, 'retired source custody changed between complete sweeps')
        baseline = result
    return baseline


def verify_prepared(root, release, intent):
    return verify(root, release, intent, False)


def verify_running(root, release, intent):
    return verify(root, release, intent, True)
