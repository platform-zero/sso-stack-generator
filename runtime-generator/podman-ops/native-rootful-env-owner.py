#!/usr/bin/env python3
"""Canonical same-process rootful service-env PERSISTENT handoff, not activation.

prepare_custody(root, release, intent) retains FDs. The journal seals exactly
 dict(intent, rootfulEnvCustody=custody) in BOTH preparing records under FD9.
copy_environment(root, release, new_intent) consumes that retained session and
returns a completed root-only proof; only the journal writes root records.
verify_environment(root, release, intent) independently observes persistent
source/store original pins, safely while services/actors are active. It returns
only a durable binding digest and false activation/readiness authority; no live
/run environment or application data is read. projectionSources retains the
original source-only physical footprint, excluding candidate journal controls.
No ENV_DIR, templates, CLI, runtime copy, manager start, root config export,
recursive chown, parent repair, unselected-name read/prune or readiness grant.
"""
import importlib.util
import os
from pathlib import Path
import secrets
import stat
import sys
import time


def load(name, filename):
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


m = load('_rootful_env_native_files', 'native-install-files.py')
v = m.v
o, p = v.o, v.p
require, Refused = o.require, o.Refused
DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
RESET = 'complete-clean-reset dependency: selected rootful environment lacks exact canonical copy authority'
_sessions = {}


def forbidden(key):
    # Preserve projector parsing/expansion and root-only classification. The
    # explicitly rootful-only STACK_DERIVATION family is never app material.
    return p.root_only(key, {'STACK_DERIVATION'}) or key.upper().startswith('STACK_DERIVATION_')


class Session:
    def __init__(self, root, release, intent):
        self.root, self.release = p.canonical(str(root)), p.canonical(str(release))
        self.prior = p.strict(p.encoded(intent)); self.expected = self.prior
        self.fds = []; self.deadline = time.monotonic() + 120; self.closed = False
        self.record_pins = None; self.root_pin = None; self.source_pin = None; self.marker_sha = None
        self.projection_pin = None; self.plan = None; self.store = None; self.store_pin = None
        self.names_before = set(); self.original = {}; self.published = {}; self.stages = {}
        try:
            require(os.geteuid() == 0 and self.release.parent == self.root / 'releases'
                    and self.prior.get('phase') == 'preparing' and self.prior.get('release') == str(self.release)
                    and 'rootfulEnvCustody' not in self.prior and 'rootfulEnvironmentStoreHandoff' not in self.prior,
                    'fresh preparing rootful environment transaction required')
            self.root_fd, self.root_chain = o.open_absolute(self.root); self.fds.append(self.root_fd)
            self.release_fd, self.release_chain = o.open_absolute(self.release); self.fds.append(self.release_fd)
            self.root_pin = p.custody_record(self.root_fd)
            require((self.root_pin['uid'], self.root_pin['gid']) == (0, 0)
                    and self.root_pin['mode'] in (0o700, 0o755)
                    and not self.root_pin['acl'] and not self.root_pin['defaultAcl'], 'unsafe root metadata custody')
            o.root_directory(os.fstat(self.release_fd), private=True)
            releases = self.child(self.root_fd, 'releases', True)
            o.root_directory(os.fstat(releases))
            rec = p.custody_record(releases)
            require(not rec['acl'] and not rec['defaultAcl'], 'metadata releases ACL differs')
            edge = self.child(releases, self.release.name, True)
            require(p.custody_record(edge) == p.custody_record(self.release_fd),
                    'rootful source release is not exact NO_XDEV metadata-root child')
            self.verify()
            self.custody = dict(schemaVersion=1, kind='rootful-environment-custody', release=str(self.release),
                stateStore=str(self.root / 'runtime-env'), inputs=self.expected['inputs'], rootDirectory=self.root_pin,
                scopeMarkerSha256=self.marker_sha,
                requiredRootMode=0o700, projectionBindingSha256=p.sha(p.encoded(self.projection_pin)),
                selectionSha256=p.sha(p.encoded(self.plan)), projectionSources=self.projection_pin, current=self.current,
                source=self.source_pin, files={name: {'sha256': p.sha(body), 'mode': 0o600}
                                              for name, body in sorted(self.payloads.items())},
                activationAuthorized=False, readinessAuthorized=False)
        except BaseException:
            self.close(); raise

    def close(self):
        if not self.closed:
            for fd in reversed(self.fds): os.close(fd)
            self.fds = []; self.closed = True

    def child(self, fd, name, directory=False):
        child = p.child_open(fd, name, DIR if directory else FILE)
        self.fds.append(child)
        return child

    def projection(self):
        snap = v.Snapshot(self.root, self.release, self.expected, False, self.deadline)
        try:
            observed = snap.sweep()  # Real all-seven projection + env authority.
            excluded = {str(self.root / '.install-intent.json'), str(self.release / 'installation-receipt.json')}
            result = {key: value for key, value in observed.items() if key not in excluded}
            # Only an intentional tightening of this exact root inode is
            # permitted between prepare and copy. The writer never chmods it.
            result[str(self.root)] = dict(result[str(self.root)], mode=0o700)
            return result
        finally:
            snap.close()

    def root_read(self, name, optional=False):
        fd = self.release_fd
        parts = p.relative(name).split('/')
        try:
            for part in parts[:-1]:
                fd = self.child(fd, part, True)
                o.root_directory(os.fstat(fd))
                rec = p.custody_record(fd)
                require(not rec['acl'] and not rec['defaultAcl'], 'root source directory ACL differs')
            leaf = self.child(fd, parts[-1])
        except FileNotFoundError:
            require(optional, 'required rootful source absent')
            return None
        mode = stat.S_IMODE(os.fstat(leaf).st_mode)
        require(mode in (0o600, 0o644), 'rootful source file mode differs')
        body, rec = m.regular(leaf, 0, 0, mode)
        if name == 'runtime/stack.env': require(mode == 0o600, 'aggregate must remain root private')
        return body, rec

    def sources(self, ir):
        services = {name: service for name, service in ir['services'].items()
                    if service.get('placement') != 'rootless'}
        declarations = {}
        for name, service in sorted(services.items()):
            require(p.IDENT.fullmatch(name), 'invalid rootful service name')
            selected = p.declarations(service)
            if selected: declarations[name] = selected
        pin = dict(services=sorted(services), declarationsSha256=p.sha(p.encoded(declarations)), aggregate=None, ownerRealm=None)
        payloads = {}; used = set()
        if declarations:
            aggregate = self.root_read('runtime/stack.env')
            pin['aggregate'] = aggregate[1]
            values = p.env_values(aggregate[0])
            realm = self.root_read('runtime/configs/' + p.IDP_REALM, optional=True)
            material, passwords = p.owner_import_material(self.release)
            require((realm is None and material is None) or (realm is not None and material is not None
                    and realm[0] == material[0] and realm[1]['identity'] == list(material[1])),
                    'native owner import source changed')
            pin['ownerRealm'] = realm[1] if realm is not None else None
            banned = [form for key, value in values.items() if forbidden(key) and value for form in p.secret_forms(value)]
            banned.extend(passwords)
            for name, declaration in sorted(declarations.items()):
                lines = []
                for key, template in sorted(declaration.items()):
                    require(not forbidden(key), 'root-only rootful output declaration')
                    lines.append(key + '=' + p.expand(template, values, forbidden, used))
                body = ('\n'.join(lines) + '\n').encode()
                require(not any(value in body for value in banned), 'root-only or owner password present in rootful app environment')
                payloads[name + '.env'] = body
        require(len(payloads) <= o.MAX_NODES and sum(map(len, payloads.values())) <= o.MAX_TOTAL,
                'rootful environment projection exceeds bound')
        pin['environmentInputs'] = sorted(used)
        return payloads, pin

    def selection(self, previous):
        plan = m.native.selection(self.release, previous)
        # Candidate receipt bytes are checked EXACTLY against expected journal
        # records below. Its SHA legitimately changes when custody is sealed;
        # only that candidate SHA is not immutable source-selection authority.
        require(plan['sources']['candidate']['receipt']['phase'] == 'preparing',
                'rootful candidate source receipt phase differs')
        plan['sources']['candidate']['receipt'] = {'phase': 'preparing'}
        return plan

    def verify(self, write=False):
        require(not self.closed and time.monotonic() < self.deadline, 'rootful environment custody expired')
        o.lock_held(self.root)
        allowed_root = dict(self.root_pin, mode=0o700)
        actual = p.custody_record(self.root_fd)
        require(actual == allowed_root or (not write and actual == self.root_pin),
                'root metadata must be bound private0700 before environment write')
        root_fd, root_chain = o.open_absolute(self.root)
        try:
            expected_chain = dict(self.root_chain); expected_chain[self.root] = actual
            require(root_chain == expected_chain and p.custody_record(root_fd) == actual, 'root metadata ancestry changed')
        finally: os.close(root_fd)
        release_fd, release_chain = o.open_absolute(self.release)
        try:
            expected_chain = dict(self.release_chain); expected_chain[self.root] = actual
            require(release_chain == expected_chain, 'root release ancestry/inode/mount changed')
        finally: os.close(release_fd)
        snapshot = v.Snapshot(self.root, self.release, self.expected, False, self.deadline)
        try:
            binding = snapshot.candidate_binding()
            raw, record, receipt_record = binding['raw'], binding['pin'], binding['rpin']
            observed_records = (record, receipt_record)
            if self.record_pins is None: self.record_pins = observed_records
            require(observed_records == self.record_pins, 'root preparing record inode CAS changed')
            self.cas = p.sha(raw)
            candidate = p.strict(snapshot.root_file(self.release_fd, 'bundle.json')[0])
            provenance = p.strict(snapshot.root_file(self.release_fd, 'source-provenance.json')[0])
            require(candidate.get('backend') == 'podman' and candidate.get('deploymentMode') == 'standalone'
                    and candidate.get('sourceProvenanceSha256') == self.expected['inputs']['source-provenance.json']
                    and candidate.get('irSha256') == self.expected['inputs']['stack.ir.json']
                    and provenance.get('manifestSha256') == self.expected['inputs']['site/manifest.json'],
                    'rootful source provenance differs')
            ir = binding['ir']
            if self.marker_sha is None: self.marker_sha = snapshot.marker_sha
            require(self.marker_sha == snapshot.marker_sha, 'rootful canonical marker hash changed')
        finally: snapshot.close()
        projection = self.projection()
        if self.projection_pin is None: self.projection_pin = projection
        require(projection == self.projection_pin, 'all-domain/source projection custody changed')
        current = p.current_record(self.root_fd)
        if self.plan is None:
            self.current = current
            previous = None
            if current is not None:
                target = current['target']; path = p.canonical(target) if target.startswith('/') else self.root / p.relative(target)
                if path != self.release: previous = path
            self.previous = previous
            self.plan = self.selection(previous)
        require(current == self.current and self.selection(self.previous) == self.plan,
                'rootful stop-only source selection/current changed')
        m.stopped(self.release, self.plan)  # Actual canonical rootful unit/job + seven offline actor gate.
        payloads, source = self.sources(ir)
        if self.source_pin is None:
            self.source_pin, self.payloads = source, payloads
        require(source == self.source_pin and payloads == self.payloads, 'rootful aggregate/declaration/owner source changed')
        if self.store is not None:
            require(p.custody_record(self.store) == self.store_pin, 'held rootful environment store changed')
            named = self.child(self.root_fd, 'runtime-env', True)
            require(p.custody_record(named) == self.store_pin, 'rootful store pathname/mount changed')
            require(set(os.listdir(self.store)) == self.names_before | set(self.stages), 'rootful store namespace changed')
            for name, record in {**self.original, **self.published, **self.stages}.items():
                self.file_at(name, record)
        # Recheck controls AFTER subprocess gate and private source reads.
        snap = v.Snapshot(self.root, self.release, self.expected, False, self.deadline)
        try:
            require(snap.root_file(self.root_fd, '.install-intent.json') == (raw, observed_records[0])
                    and snap.root_file(self.release_fd, 'installation-receipt.json') == (raw, observed_records[1]),
                    'root preparing records changed during source observation')
        finally: snap.close()
        o.lock_held(self.root)

    def file_at(self, name, record):
        fd = self.child(self.store, name)
        require(list(p.identity(os.fstat(fd))) == record['identity']
                and p.mount_id(fd) == record['mountId'], 'rootful environment original inode/mount CAS differs')
        actual = m.regular(fd, 0, 0, 0o600, record['sha256'])[1]
        require(actual == record, 'rootful environment original file CAS differs')

    def old_authority(self):
        if self.previous is None: return {}
        snap = v.Snapshot(self.root, self.release, self.expected, False, self.deadline)
        try:
            fd, _ = o.open_absolute(self.previous)
            try: body, _ = snap.root_file(fd, 'installation-receipt.json')
            finally: os.close(fd)
        finally: snap.close()
        value = p.strict(body); proof = value.get('rootfulEnvironmentStoreHandoff')
        custody = value.get('rootfulEnvCustody')
        if not isinstance(proof, dict) or not isinstance(custody, dict): return {}
        require(proof.get('schemaVersion') == 1 and proof.get('kind') == 'rootful-persistent-environment'
                and proof.get('status') == 'completed' and proof.get('release') == str(self.previous)
                and proof.get('inputs') == value['inputs'] and proof.get('stateStore') == str(self.root / 'runtime-env')
                and custody.get('schemaVersion') == 1 and custody.get('kind') == 'rootful-environment-custody'
                and custody.get('release') == str(self.previous) and custody.get('inputs') == value['inputs']
                and custody.get('stateStore') == str(self.root / 'runtime-env') and custody.get('requiredRootMode') == 0o700
                and custody.get('activationAuthorized') is False and custody.get('readinessAuthorized') is False
                and all(custody.get('rootDirectory', {}).get(k) == self.root_pin[k] for k in ('dev', 'ino', 'uid', 'gid'))
                and proof.get('source') == custody.get('source') and proof.get('current') == custody.get('current')
                and proof.get('scopeMarkerSha256') == custody.get('scopeMarkerSha256') == self.marker_sha
                and proof.get('sourceCustodySha256') == p.sha(p.encoded(custody))
                and proof.get('store') == self.store_pin and proof.get('runtimeDeferred') is True
                and proof.get('activationAuthorized') is False and proof.get('readinessAuthorized') is False,
                RESET)
        files = proof.get('files', {})
        require(isinstance(files, dict) and all(record.get('sha256') == custody.get('files', {}).get(name, {}).get('sha256')
                for name, record in files.items()), RESET)
        return files

    def copy(self, intent):
        value = p.strict(p.encoded(intent))
        require(value == dict(self.prior, rootfulEnvCustody=self.custody), 'rootful preparing seal changed beyond exact custody')
        self.expected = value; self.record_pins = None
        self.verify(write=True)
        if not self.payloads: return self.result()
        try:
            os.stat('runtime-env', dir_fd=self.root_fd, follow_symlinks=False)
        except FileNotFoundError:
            self.verify(write=True)
            os.mkdir('runtime-env', 0o700, dir_fd=self.root_fd)
            os.fsync(self.root_fd)
        self.store = self.child(self.root_fd, 'runtime-env', True)
        self.store_pin = p.custody_record(self.store)
        require((self.store_pin['uid'], self.store_pin['gid'], self.store_pin['mode']) == (0, 0, 0o700)
                and not self.store_pin['acl'] and not self.store_pin['defaultAcl'], 'private rootful environment store required')
        self.names_before = set(os.listdir(self.store))
        authority = self.old_authority() if set(self.payloads) & self.names_before else {}
        for name in sorted(set(self.payloads) & self.names_before):
            require(name in authority, RESET)
            self.original[name] = authority[name]; self.file_at(name, authority[name])
        for name, body in sorted(self.payloads.items()):
            self.verify(write=True)
            stage = '.rootful-env-' + secrets.token_hex(16)
            fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.store)
            self.fds.append(fd)
            before = os.fstat(fd)
            require((before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode), before.st_nlink) == (0, 0, 0o600, 1)
                    and not p.acl_bytes(fd, 'system.posix_acl_access') and not p.acl_bytes(fd, 'system.posix_acl_default'),
                    'new rootful stage custody/ACL differs')
            view = memoryview(body)
            while view:
                count = os.write(fd, view); require(count > 0, 'rootful environment short write'); view = view[count:]
            os.fsync(fd)
            read = self.child(self.store, stage)
            record = m.regular(read, 0, 0, 0o600, p.sha(body))[1]
            self.stages[stage] = record; self.verify(write=True)
            old = self.original.get(name)
            m.rename(self.store, stage, name, exchange=old is not None)
            if old is not None:
                displaced_identity = list(p.identity(os.stat(stage, dir_fd=self.store, follow_symlinks=False)))
                try:
                    # Never inspect a foreign displaced name's private bytes.
                    require(displaced_identity[:-1] == old['identity'][:-1], 'rootful displaced inode CAS differs')
                    displaced = self.child(self.store, stage)
                    actual = m.regular(displaced, 0, 0, 0o600, old['sha256'])[1]
                    require(m.renamed(actual, old), 'rootful exchange displaced CAS differs')
                except (Refused, ValueError, OSError):
                    self.restore_exchange(stage, name, record, displaced_identity)
                    raise Refused('rootful exchange CAS refused; original name restored; private stage retained') from None
                self.stages[stage] = actual
            else:
                self.stages.pop(stage)
            published = self.child(self.store, name)
            current = m.regular(published, 0, 0, 0o600, p.sha(body))[1]
            require(m.renamed(current, record), 'published rootful inode changed')
            self.published[name] = current; self.original.pop(name, None); self.names_before.add(name)
            if old is not None:
                self.verify(write=True); self.file_at(stage, actual)
                os.unlink(stage, dir_fd=self.store); self.stages.pop(stage)
            os.fsync(self.store); self.verify(write=True)
        return self.result()

    def restore_exchange(self, stage, name, staged, displaced):
        current = list(p.identity(os.stat(name, dir_fd=self.store, follow_symlinks=False)))
        actual = list(p.identity(os.stat(stage, dir_fd=self.store, follow_symlinks=False)))
        require(current[:-1] == staged['identity'][:-1] and actual == displaced,
                'rootful exchange raced again; both inodes retained for canonical disposition')
        m.rename(self.store, stage, name, exchange=True); os.fsync(self.store)
        require(list(p.identity(os.stat(name, dir_fd=self.store, follow_symlinks=False)))[:-1] == displaced[:-1],
                'rootful exchange restoration CAS differs')

    def result(self):
        self.verify(write=True)
        return dict(schemaVersion=1, kind='rootful-persistent-environment', status='completed', release=str(self.release),
            inputs=self.expected['inputs'], sourceCustodySha256=p.sha(p.encoded(self.custody)), scopeMarkerSha256=self.marker_sha,
            source=self.source_pin, current=self.current, stateStore=str(self.root / 'runtime-env'),
            store=self.store_pin, files=self.published, runtimeDeferred=True,
            activationAuthorized=False, readinessAuthorized=False, removeUnselected=False)


class EnvironmentObservation:
    """Active-safe persistent/source FD observation; never constructs Session."""
    child = Session.child
    close = Session.close
    sources = Session.sources

    def __init__(self, root, release, intent, deadline):
        self.root, self.release = p.canonical(str(root)), p.canonical(str(release))
        self.expected = p.strict(p.encoded(intent)); self.deadline = deadline
        self.fds = []; self.closed = False
        self.custody = self.expected.get('rootfulEnvCustody')
        self.proof = self.expected.get('rootfulEnvironmentStoreHandoff')
        require(isinstance(self.custody, dict) and isinstance(self.proof, dict),
                'rootful environment source custody and completed handoff required')

    def parent(self, anchor, relative):
        parts = p.relative(relative).split('/'); fd = anchor
        for part in parts[:-1]:
            fd = self.child(fd, part, True); o.root_directory(os.fstat(fd))
            rec = p.custody_record(fd)
            require(not rec['acl'] and not rec['defaultAcl'], 'rootful consumer source parent ACL differs')
        return fd, parts[-1]

    def pinned_file(self, anchor, relative, expected, sha):
        require(isinstance(expected, dict), 'original rootful source/file inode proof required')
        parent, name = self.parent(anchor, relative)
        original = {key: value for key, value in expected.items() if key != 'sha256'}
        # Actual verifier primitive checks original identity BEFORE bytes and
        # reopens the exact named no-follow/no-cross-mount leaf AFTER reading.
        body, record = self.base.regular(parent, name, 0, 0, original['mode'], sha, original)
        return body, dict(record, sha256=p.sha(body))

    def root_read(self, name, optional=False):
        key = 'aggregate' if name == 'runtime/stack.env' else 'ownerRealm'
        expected = self.custody['source'].get(key)
        if expected is None:
            require(optional, 'unsealed aggregate source')
            try:
                parent, leaf = self.parent(self.release_fd, name)
                self.child(parent, leaf)
            except FileNotFoundError:
                return None
            raise Refused('unsealed optional rootful source appeared')
        require(expected.get('mode') in (0o600, 0o644)
                and (key != 'aggregate' or expected['mode'] == 0o600), 'rootful private source mode differs')
        return self.pinned_file(self.release_fd, name, expected, expected['sha256'])

    def previous(self, original, binding):
        """Revalidate SOURCE old custody, never require it as live current."""
        current = self.custody.get('current')
        if current is None:
            require('stop-only-previous-source' not in original, 'unexpected old source custody')
            return None, {}
        require(isinstance(current, dict) and set(current) == {'identity', 'target'}
                and len(current['identity']) == 9 and current['identity'][2:4] == [0, 0]
                and stat.S_ISLNK(current['identity'][4]) and current['identity'][5] == 1,
                'rootful original source current custody differs')
        target = current['target']
        previous = p.canonical(target) if target.startswith('/') else self.root / p.relative(target)
        # A selected candidate at prepare time has no previous SOURCE.
        if previous == self.release:
            require('stop-only-previous-source' not in original, 'unexpected previous source footprint')
            return None, {}
        require(previous.parent == self.root / 'releases', 'old rootful source escapes metadata root')
        selected = original.get('stop-only-previous-source')
        require(isinstance(selected, dict) and selected.get('release') == str(previous)
                and isinstance(selected.get('source'), dict), 'original stop-only source plan required')
        source = selected['source']
        releases = self.child(binding['root_fd'], 'releases', True)
        old = self.child(releases, previous.name, True)
        observed = {}
        def directory(path, fd):
            o.root_directory(os.fstat(fd), private=path == previous)
            rec = p.custody_record(fd)
            require(rec == original.get(str(path)) and not rec['acl'] and not rec['defaultAcl'],
                    'old rootful source directory original inode/mount/ACL differs')
            observed[str(path)] = rec
        directory(previous, old)
        receipt_name = 'installation-receipt.json'
        body, record = self.pinned_file(old, receipt_name, original.get(str(previous / receipt_name)),
                                        source['receipt']['sha256'])
        observed[str(previous / receipt_name)] = {k: value for k, value in record.items() if k != 'sha256'}
        receipt = p.strict(body); pins = receipt.get('inputs')
        phase = receipt.get('phase'); claim = self.expected.get('previousRelease')
        require(receipt.get('release') == str(previous) and type(receipt.get('schemaVersion')) is int
                and receipt['schemaVersion'] == 1
                and ((phase == 'active' and claim == str(previous)) or
                     (phase in ('retired-failed', 'retired-clean') and claim is None))
                and isinstance(pins, dict) and set(pins) == p.INPUTS
                and all(pins[name] is not None for name in p.REQUIRED), 'old rootful source receipt/pins differ')
        documents = {}
        for name, sha in sorted(pins.items()):
            if sha is None:
                try:
                    parent, leaf = self.parent(old, name); self.child(parent, leaf)
                except FileNotFoundError: continue
                raise Refused('old pinned absent source appeared')
            body, record = self.pinned_file(old, name, original.get(str(previous / name)), sha)
            documents[name] = p.strict(body) if name in p.REQUIRED else None
            observed[str(previous / name)] = {k: value for k, value in record.items() if k != 'sha256'}
        manifest, metadata, bundle, provenance = (documents[name] for name in
            ('site/manifest.json', 'podman-domains.json', 'bundle.json', 'source-provenance.json'))
        require(manifest.get('site') == binding['manifest']['site']
                and manifest.get('deploymentMode') == metadata.get('deploymentMode') == bundle.get('deploymentMode') == 'standalone'
                and manifest.get('installerStateRoot', '/var/lib/webservices') == metadata.get('installerStateRoot') == str(self.root)
                and manifest.get('storageScope') == metadata.get('storageScope') == binding['marker']['scope']
                and sorted([{k: row[k] for k in ('name', 'user', 'uid', 'stateRoot', 'graphRoot', 'volumeRoot')}
                            for row in metadata['domains']], key=lambda row: row['name']) == binding['marker']['domains']
                and provenance.get('manifestSha256') == pins['site/manifest.json']
                and bundle.get('sourceProvenanceSha256') == pins['source-provenance.json']
                and bundle.get('irSha256') == pins['stack.ir.json'], 'old rootful source provenance/marker differs')
        for row in metadata['domains']:
            require('subuidStart' not in row or type(row['subuidStart']) is int
                    and row['subuidStart'] == o.storage.namespace_root_id(row['user']), 'old source subordinate allocation differs')
        quad = self.child(old, 'quadlet', True); directory(previous / 'quadlet', quad)
        require(set(os.listdir(quad)) == set(source['scopes']), 'old source scope namespace differs')
        for scope, entry in sorted(source['scopes'].items()):
            fd = self.child(quad, scope, True); directory(previous / 'quadlet' / scope, fd)
            require(set(os.listdir(fd)) == {Path(name).name for name in entry['files']}, 'old source file namespace differs')
            for name, seal in sorted(entry['files'].items()):
                _, record = self.pinned_file(old, name, original.get(str(previous / name)), seal['sha256'])
                observed[str(previous / name)] = {k: value for k, value in record.items() if k != 'sha256'}
        require({key for key in original if key == str(previous) or key.startswith(str(previous) + '/')}
                == set(observed), 'original old source footprint incomplete or enlarged')
        require(m.native.source_plan(previous, previous=True) == source, 'old stop-only source plan changed')
        observed['stop-only-previous-source'] = selected
        return previous, observed

    def sweep(self):
        phase = self.expected.get('phase')
        require(phase in ('preparing', 'units-selected', 'building', 'starting', 'active'), 'rootful observation phase differs')
        # candidate_binding is SOURCE ONLY even in running phases. Do not call
        # running readiness or restored /run checks from this persistent API.
        self.base = v.Snapshot(self.root, self.release, self.expected, phase in ('starting', 'active'), self.deadline)
        physical = v.Snapshot(self.root, self.release, self.expected, False, self.deadline)
        try:
            binding = self.base.candidate_binding()
            self.release_fd = binding['release_fd']
            root_record = p.custody_record(binding['root_fd'])
            custody, proof = self.custody, self.proof
            require(custody.get('schemaVersion') == 1 and custody.get('kind') == 'rootful-environment-custody'
                    and custody.get('release') == str(self.release) and custody.get('inputs') == self.expected['inputs']
                    and custody.get('stateStore') == str(self.root / 'runtime-env') and custody.get('requiredRootMode') == 0o700
                    and custody['rootDirectory'].get('mode') in (0o700, 0o755)
                    and root_record == dict(custody['rootDirectory'], mode=0o700)
                    and custody.get('scopeMarkerSha256') == self.base.marker_sha
                    and custody.get('activationAuthorized') is False and custody.get('readinessAuthorized') is False,
                    'rootful source custody/root directory differs')
            original = custody.get('projectionSources')
            require(isinstance(original, dict) and p.sha(p.encoded(original)) == custody.get('projectionBindingSha256'),
                    'durable original rootful source footprint required')
            previous, old_observed = self.previous(original, binding)
            plan = m.native.selection(self.release, previous)
            # ONLY candidate journal phase/SHA are metadata writes, not source
            # footprint. Old receipts and all selected source hashes stay exact.
            plan['sources']['candidate']['receipt'] = {'phase': 'preparing'}
            require(p.sha(p.encoded(plan)) == custody.get('selectionSha256'), 'rootful source selection changed')
            if phase == 'preparing':
                self.base.pointer(binding['root_fd'], self.root, custody.get('current'), original=True, candidate=self.release)
            else:
                self.base.pointer(binding['root_fd'], self.root, self.release)
            physical.pointer_choices = self.base.pointer_choices
            physical.marker_sha = self.base.marker_sha
            projections = self.expected.get('domainRuntimeProjections')
            require(isinstance(projections, dict) and set(projections) == {row['name'] for row in binding['rows']},
                    'all seven rootful source domain projections required')
            for row in sorted(binding['rows'], key=lambda row: row['name']):
                domain = projections[row['name']]
                services = {name: service for name, service in binding['ir']['services'].items()
                            if service.get('placement') == 'rootless' and service.get('rootlessDomain') == row['name']}
                account = binding['accounts'][row['name']]
                state, slot_fd, slot = physical.graph(binding['scope_fd'], binding['scope'], row, account, domain,
                                                      binding['operator'], binding['ids'])
                names, seals = physical.runtime_tree(slot_fd, slot, row, account, domain, services)
                physical.environment(state, row, account, domain, names, seals)  # Persistent ONLY, no actor runtime.
            observed = dict(self.base.observed, **physical.observed)
            live_pointers = {str(self.root / 'current'): observed[str(self.root / 'current')]}
            observed[str(self.root / 'current')] = custody.get('current')  # SOURCE, not live old pointer requirement.
            for row in binding['rows']:
                key = str(Path(row['stateRoot']) / 'current')
                live_pointers[key] = observed[key]
                observed[key] = projections[row['name']]['projectionCustody']['current']
            excluded = {str(self.root / '.install-intent.json'), str(self.release / 'installation-receipt.json')}
            observed = {key: value for key, value in observed.items() if key not in excluded}
            observed.update(old_observed)
            require(observed == original, 'original rootful physical source/namespace/marker custody changed')
            payloads, source = self.sources(binding['ir'])
            expected_files = {name: {'sha256': p.sha(body), 'mode': 0o600} for name, body in payloads.items()}
            require(custody.get('source') == source and custody.get('files') == expected_files
                    and proof.get('schemaVersion') == 1 and proof.get('kind') == 'rootful-persistent-environment'
                    and proof.get('status') == 'completed' and proof.get('release') == str(self.release)
                    and proof.get('inputs') == self.expected['inputs']
                    and proof.get('sourceCustodySha256') == p.sha(p.encoded(custody))
                    and proof.get('scopeMarkerSha256') == self.base.marker_sha
                    and proof.get('source') == source and proof.get('current') == custody.get('current')
                    and proof.get('stateStore') == str(self.root / 'runtime-env') and proof.get('runtimeDeferred') is True
                    and proof.get('activationAuthorized') is False and proof.get('readinessAuthorized') is False
                    and proof.get('removeUnselected') is False and isinstance(proof.get('files'), dict)
                    and set(proof['files']) == set(expected_files), 'rootful completed handoff/source payload binding differs')
            files = {}; store_record = None
            if payloads:
                store = self.child(binding['root_fd'], 'runtime-env', True)
                store_record = p.custody_record(store)
                require(store_record == proof.get('store') and (store_record['uid'], store_record['gid'], store_record['mode']) == (0, 0, 0o700)
                        and not store_record['acl'] and not store_record['defaultAcl'], 'original rootful persistent store differs')
                for name, seal in sorted(expected_files.items()):
                    require(proof['files'][name].get('mode') == 0o600, 'rootful persistent file must remain private0600')
                    _, record = self.pinned_file(store, name, proof['files'][name], seal['sha256'])
                    require(record == proof['files'][name], 'original rootful persistent file differs')
                    files[name] = record
            else:
                require(proof.get('store') is None, 'empty rootful handoff unexpectedly owns store')
            self.base.final_controls(binding)
            require(p.current_record(binding['root_fd']) == live_pointers[str(self.root / 'current')],
                    'live candidate root pointer changed during rootful observation')
            transient = dict(records=[binding['pin'], binding['rpin']], intentSha256=p.sha(binding['raw']), pointers=live_pointers)
            durable = dict(sourceFootprint=observed, source=source, selection=plan, store=store_record, files=files,
                           sourceCustodySha256=proof['sourceCustodySha256'])
            return durable, transient
        finally:
            physical.close(); self.base.close()


def verify_environment(root, release, intent):
    """Active-safe persistent-only binding; metadata phases may legitimately advance.

    No writer Session, actor inactivity, boot/API observation, runtime data read,
    copy, journal write or readiness/activation grant. Exact current records and
    live selected pointers are checked per call but not hashed as source epochs.
    """
    intent = p.strict(p.encoded(intent)); deadline = time.monotonic() + 120
    baseline = None
    for _ in range(2):
        observation = EnvironmentObservation(root, release, intent, deadline)
        try: result = observation.sweep()
        finally: observation.close()
        require(baseline is None or baseline == result, 'rootful source/store/current/CAS changed between observations')
        baseline = result
    return dict(schemaVersion=1, kind='rootful-persistent-environment-observation',
                bindingSha256=p.sha(p.encoded(baseline[0])), activationAuthorized=False, readinessAuthorized=False)


def prepare_custody(root, release, intent):
    key = (str(root), str(release))
    require(key not in _sessions, 'unconsumed rootful environment custody already exists')
    session = Session(root, release, intent); _sessions[key] = session
    return p.strict(p.encoded(session.custody))


def copy_environment(root, release, intent):
    session = _sessions.pop((str(root), str(release)), None)
    require(session is not None, 'same-process retained rootful environment custody FDs required')
    try: return session.copy(intent)
    finally: session.close()
