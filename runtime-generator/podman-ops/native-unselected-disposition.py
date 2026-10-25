#!/usr/bin/env python3
"""Exact journal-owned published/never-selected synthetic file disposition.

No CLI, graph/data deletion, account/permission repair or service stop/start.
The journal alone publishes terminal receipts. Preserve failed controls and use
an exact write-ahead cursor for interrupted displacement/unlink recovery.
"""
import importlib.util
import os
from pathlib import Path
import sys
import time
import subprocess


def load(name, filename):
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


m = load('_unselected_files', 'native-install-files.py')
r = load('_unselected_environment', 'native-rootful-env-owner.py')
o, p, native, storage = m.o, m.p, m.native, m.storage
require, Refused = m.require, m.Refused
DIR, FILE = m.DIR, m.FILE
PROGRESS = 'native-unselected-disposition.json'
ORIGINAL = 'never-selected-original-failure.json'


def reserves(root, scope):
    body = Path('/proc/meminfo').read_text()
    memory = [int(line.split()[1]) * 1024 for line in body.splitlines() if line.startswith('MemAvailable:')]
    require(len(body) <= 65536 and len(memory) == 1 and memory[0] >= 16 * 1024**3,
            'disposition memory reserve unavailable')
    for path, floor in ((Path('/'), 50), (scope, 100), (root, 50)):
        space = os.statvfs(path)
        require(space.f_bavail * space.f_frsize >= floor * 1024**3 and space.f_favail >= 32,
                'disposition physical filesystem reserve unavailable')


def unpublished_triggers():
    units = ('webservices-runtime-env.service', 'webservices-auto-update.service', 'webservices-auto-update.timer')
    result = subprocess.run(['systemctl', 'show', *units, '-p', 'Id', '-p', 'LoadState', '-p', 'ActiveState',
        '-p', 'MainPID', '-p', 'Job', '-p', 'FragmentPath', '-p', 'UnitFileState'],
        capture_output=True, text=True, timeout=15)
    require(result.returncode == 0 and len(result.stdout) <= 65536, 'unpublished trigger observation unavailable')
    rows = [dict(line.split('=', 1) for line in block.splitlines() if '=' in line)
            for block in result.stdout.strip().split('\n\n') if block]
    require(len(rows) == len(units) and {row.get('Id') for row in rows} == set(units)
            and all(row.get('LoadState') == 'not-found' and row.get('ActiveState') == 'inactive'
                and row.get('MainPID', '') in ('', '0') and row.get('Job') == ''
                and row.get('FragmentPath') == '' and row.get('UnitFileState', '') in ('', 'not-found') for row in rows),
            'never-published runtime/updater trigger exists or remains active')


def publication(value):
    require(value.get('schemaVersion') == 1 and type(value['schemaVersion']) is int
            and value.get('phase') == 'failed' and value.get('steps') == ['preparing', 'failed']
            and value.get('previousRelease') is None
            and not any(key in value for key in ('nativeRuntimeEnvUnitCustody', 'nativeRuntimeEnvUnits',
                'nativeRuntimeEnvironmentCopies', 'readiness', 'nativeSeafilePreparation')),
            'exact never-selected failed file preparation required')
    custody, proof = value.get('nativeUnitFileCustody'), value.get('nativeUnitFiles')
    env, handoff = value.get('rootfulEnvCustody'), value.get('rootfulEnvironmentStoreHandoff')
    require(all(isinstance(item, dict) for item in (custody, proof, env, handoff)),
            'original completed unit and Root environment custody required')
    for item in (custody, proof, env, handoff):
        require(item.get('schemaVersion') == 1 and item.get('release') == value['release']
                and item.get('inputs') == value['inputs'] and item.get('activationAuthorized') is False
                and item.get('readinessAuthorized') is False, 'original publication authority differs')
    require(custody.get('kind') == 'native-unit-file-custody'
            and proof.get('kind') == 'native-selected-unit-files' and proof.get('status') == 'completed'
            and proof.get('custodySha256') == p.sha(p.encoded(custody))
            and proof.get('selectionSha256') == custody.get('selectionSha256')
            and proof.get('scopeMarkerSha256') == custody.get('scopeMarkerSha256')
            and custody.get('nonInventoryOwned') is False and proof.get('nonInventoryOwned') is False
            and proof.get('automaticRestart') is False and proof.get('applicationAcceptance') is False
            and proof.get('unchanged') == [] and proof.get('removedPreviousOnly') == []
            and isinstance(proof.get('files'), dict) and proof['files'] == proof.get('published')
            and isinstance(custody.get('files'), dict)
            and all(row.get('before') is None for row in custody['files'].values()),
            'only wholly new exact completed selected publication can be disposed')
    require(env.get('kind') == 'rootful-environment-custody'
            and handoff.get('kind') == 'rootful-persistent-environment' and handoff.get('status') == 'completed'
            and handoff.get('sourceCustodySha256') == p.sha(p.encoded(env))
            and handoff.get('runtimeDeferred') is True and handoff.get('removeUnselected') is False
            and handoff.get('source') == env.get('source') and handoff.get('current') == env.get('current')
            and handoff.get('scopeMarkerSha256') == env.get('scopeMarkerSha256') == custody.get('scopeMarkerSha256')
            and isinstance(env.get('files'), dict) and isinstance(handoff.get('files'), dict)
            and set(env['files']) == set(handoff['files']), 'Root environment handoff binding differs')
    return custody, proof, env, handoff


def plan_identity(expected, proof, handoff):
    root = Path(proof['release']).parent.parent
    environment = {str(root / 'runtime-env' / name): pin for name, pin in handoff['files'].items()}
    paths = sorted([*proof['files'], *environment])
    require(len(set(paths)) == len(paths) and 0 < len(paths) <= 2048, 'disposition authorities overlap or exceed bound')
    return paths, p.sha(p.encoded(dict(intentSha256=expected, units=proof['files'], environment=environment, paths=paths)))


def report(expected, plan_sha, proof, handoff):
    return dict(schemaVersion=1, kind='never-selected-file-disposition', status='completed',
        originalIntentSha256=expected, planSha256=plan_sha, unitFiles=len(proof['files']),
        rootEnvironmentFiles=len(handoff['files']), dataPreserved=True,
        activationAuthorized=False, applicationAcceptance=False, automaticRestart=False)


class Disposition(m.Session):
    def __init__(self, root, release, value, expected):
        m.descriptor_capacity()
        self.root, self.release = p.canonical(str(root)), p.canonical(str(release))
        self.prior = self.expected = native.strict(p.encoded(value)); self.expected_sha = expected
        self.deadline = time.monotonic() + 900
        self.fds, self.chains, self.source_dirs, self.source_files = [], {}, {}, {}
        self.dest_dirs, self.entries, self.states, self.stages = {}, {}, {}, {}
        self.read_dirs, self.override_guards = {}, {}
        self.record_pins = None; self.closed = False; self.marker_fd = None; self.control_fds = None
        self.progress_fd = None; self.current_fd = None
        self.environment_entries = {}; self.removed = []; self.progress_pin = None
        try:
            self.original_custody, self.proof, self.env_custody, self.env_proof = publication(value)
            require(os.geteuid() == 0 and self.root == m.v.FAILED_ROOT
                    and self.release.parent == self.root / 'releases' and value['release'] == str(self.release)
                    and native.HEX.fullmatch(expected), 'exact synthetic failed release required')
            self.root_fd = self.absolute(self.root); self.release_fd = self.absolute(self.release)
            o.root_directory(os.fstat(self.root_fd), private=True); o.root_directory(os.fstat(self.release_fd), private=True)
            self.releases_fd = self.hold(p.child_open(self.root_fd, 'releases', DIR))
            edge = self.hold(p.child_open(self.releases_fd, self.release.name, DIR))
            require(p.custody_record(edge) == p.custody_record(self.release_fd), 'failed release edge differs')
            self.check_records()
            self.scope, self.operator, self.marker = storage.authority(self.release)
            require(self.scope == m.v.FAILED_SCOPE and self.marker['scope']['dataClass'] == 'synthetic',
                    'only fixed synthetic data scope supported')
            self.metadata = self.json_source(self.release_fd, 'podman-domains.json')
            self.manifest = self.json_source(self.release_fd, 'site/manifest.json')
            self.rows = self.metadata['domains']; self.accounts = self.account_snapshot()
            require(self.accounts == self.original_custody.get('accounts'), 'original seven actor identities differ')
            parent = self.absolute(self.scope.parent, self.operator)
            self.scope_fd = self.hold(p.child_open(parent, self.scope.name, DIR)); self.scope_pin = p.custody_record(self.scope_fd)
            body, self.marker_pin = self.root_read(self.scope_fd, storage.MARKER, private=True); self.marker_sha = p.sha(body)
            require(p.strict(body) == self.marker and self.marker_sha == self.original_custody['scopeMarkerSha256'], 'original marker differs')
            self.current = p.current_record(self.root_fd)
            require(self.current == self.original_custody.get('current') == self.env_custody.get('current'), 'original current pointer differs')
            if self.current is not None:
                self.current_fd = self.hold(os.open('current', os.O_PATH | os.O_NOFOLLOW, dir_fd=self.root_fd))
                require(list(p.identity(os.fstat(self.current_fd))) == self.current['identity'], 'held current differs')
            self.previous = self.previous_release(); self.previous_fd = self.absolute(self.previous) if self.previous else None
            self.previous_inputs = self.previous_authority() if self.previous else None
            if self.previous:
                body, _ = self.root_read(self.previous_fd, 'installation-receipt.json', private=True)
                require(p.strict(body).get('phase') == 'retired-clean', 'retained current must be clean-retired')
            self.plan = native.selection(self.release, self.previous)
            old = self.original_custody.get('stopOnlyPrevious')
            require(old == (dict(release=str(self.previous), source=self.plan['sources']['previous']) if self.previous else None)
                    and self.proof.get('stopOnlyPrevious') == (str(self.previous) if self.previous else None), 'original stop-only source differs')
            self.pin_sources(); self.prepare_destinations(); self.override_snapshot(); self.bind_publication()
            self.projection_pin = self.projection_snapshot()
            require(p.sha(p.encoded(self.projection_pin)) == self.original_custody.get('projectionBindingSha256')
                    == self.env_custody.get('projectionBindingSha256'), 'original all-domain source footprint differs')
            self.bind_environment()
            self.paths, self.plan_sha = plan_identity(expected, self.proof, self.env_proof)
            self.progress = self.read_progress(); self.validate_progress(); self.verify(quiescent=True)
            reserves(self.root, self.scope)
        except BaseException:
            self.close(); raise

    def check_records(self):
        self.alive(); o.lock_held(self.root)
        body, ip = self.root_read(self.root_fd, '.install-intent.json', private=True)
        receipt, rp = self.root_read(self.release_fd, 'installation-receipt.json', private=True)
        require(body == receipt and native.strict(body) == self.expected and p.sha(body) == self.expected_sha,
                'original failed dual-record SHA CAS required')
        pins = {'intent': ip, 'receipt': rp}
        if self.record_pins is None:
            self.record_pins = pins; self.original_raw = body
            self.control_fds = [self.hold(p.child_open(parent, name, FILE)) for parent, name in
                ((self.root_fd, '.install-intent.json'), (self.release_fd, 'installation-receipt.json'))]
        require(pins == self.record_pins and all(m.regular(fd, 0, 0, 0o600)[1] == pin for fd, pin in
                zip(self.control_fds, (ip, rp))), 'failed held/named record inode CAS differs')
        observed = self.inputs(self.release_fd, self.expected['inputs'])
        if not hasattr(self, 'input_pins'): self.input_pins = observed
        require(observed == self.input_pins, 'failed immutable inputs differ')

    def projection_snapshot(self):
        snap = m.v.Snapshot(self.root, self.release, self.expected, False, self.deadline, failed_preparation=True)
        try:
            observed = snap.sweep()
            excluded = {str(self.root / '.install-intent.json'), str(self.release / 'installation-receipt.json')}
            return {key: val for key, val in observed.items() if key not in excluded}
        finally: snap.close()

    def bind_publication(self):
        originals = self.original_custody['files']
        require(set(originals) == {str(path) for path in self.entries}, 'original unit inventory enlarged or incomplete')
        candidates = set()
        for path, item in self.entries.items():
            original = dict(originals[str(path)]); original.pop('stage', None); original.pop('before', None)
            require(original == item['public'], 'original unit path/source/owner authority differs')
            if item['candidate'] is not None: candidates.add(str(path))
            else: require(self.states[path] is None, 'previous-only file appeared')
        require(candidates == set(self.proof['files']), 'completed publication does not cover exact source candidates')
        require({str(path): pin for path, (_, pin) in self.dest_dirs.items()} == self.original_custody['directories'],
                'original installed parent custody differs')

    def derive_environment(self):
        snap = m.v.Snapshot(self.root, self.release, self.expected, False, self.deadline, failed_preparation=True)
        observation = r.EnvironmentObservation(self.root, self.release, self.expected, self.deadline)
        try:
            binding = snap.candidate_binding(); observation.base = snap; observation.release_fd = binding['release_fd']
            payloads, source = observation.sources(binding['ir'])
            require(source == self.env_custody['source'] and self.env_custody['files'] == {
                name: dict(mode=0o600, sha256=p.sha(body)) for name, body in payloads.items()}, 'Root derived payload/source differs')
            return payloads
        finally: observation.close(); snap.close()

    def bind_environment(self):
        require(self.env_custody.get('stateStore') == self.env_proof.get('stateStore') == str(self.root / 'runtime-env')
                and self.env_custody.get('requiredRootMode') == 0o700, 'Root environment store authority differs')
        payloads = self.derive_environment()
        self.store = self.hold(p.child_open(self.root_fd, 'runtime-env', DIR)); self.store_pin = p.custody_record(self.store)
        require(self.store_pin == self.env_proof.get('store') and self.store_pin['mode'] == 0o700
                and self.store_pin['uid'] == self.store_pin['gid'] == 0
                and not self.store_pin['acl'] and not self.store_pin['defaultAcl'], 'original Root store differs')
        for name, pin in self.env_proof['files'].items():
            require(p.relative(name) == name and '/' not in name and name in payloads
                    and pin['sha256'] == self.env_custody['files'][name]['sha256'], 'Root derived filename differs')
            try: fd = self.hold(p.child_open(self.store, name, FILE))
            except FileNotFoundError: fd = None
            self.environment_entries[self.root / 'runtime-env' / name] = dict(parent=self.store, held=fd, pin=pin)

    def read_progress(self):
        try: body, pin = self.root_read(self.release_fd, PROGRESS, private=True)
        except FileNotFoundError:
            require(self.progress_pin is None, 'original cursor disappeared')
            return dict(schemaVersion=1, kind='never-selected-file-disposition', intentSha256=self.expected_sha,
                planSha256=self.plan_sha, removed=[], pending=None, status='prepared')
        require(self.progress_pin is None or self.progress_pin == pin, 'original cursor inode changed')
        if self.progress_pin is None:
            self.progress_fd = self.hold(p.child_open(self.release_fd, PROGRESS, FILE))
        self.progress_pin = pin
        require(m.regular(self.progress_fd, 0, 0, 0o600)[1] == pin, 'held cursor inode differs')
        return p.strict(body)

    def validate_progress(self):
        value = self.progress
        require(set(value) == {'schemaVersion', 'kind', 'intentSha256', 'planSha256', 'removed', 'pending', 'status'}
                and value['schemaVersion'] == 1 and value['kind'] == 'never-selected-file-disposition'
                and value['intentSha256'] == self.expected_sha and value['planSha256'] == self.plan_sha
                and value['status'] in ('prepared', 'removing', 'completed') and isinstance(value['removed'], list)
                and value['removed'] == self.paths[:len(value['removed'])]
                and len(value['removed']) <= len(self.paths), 'disposition cursor differs from exact source plan')
        remaining = self.paths[len(value['removed']):]
        require(value['pending'] is None or remaining and value['pending'] == remaining[0], 'pending disposition path differs')
        require(value['status'] != 'completed' or not remaining and value['pending'] is None, 'incomplete disposition cannot report completion')
        self.removed = list(value['removed'])

    def stage_name(self, text):
        return '.unselected-' + self.plan_sha[:16] + '-' + p.sha(text.encode())[:16]

    def verify(self, full=False, quiescent=False):
        # Preserve the publisher's source/marker/account/override/FD/CAS checks.
        # Failed observation is source-only, never normal native admission.
        super().verify(full=False, quiescent=quiescent)
        require(self.current_fd is None or list(p.identity(os.fstat(self.current_fd))) == self.current['identity'],
                'held original current was removed or replaced')
        require(not os.path.lexists(self.root / 'previous')
                and all(not os.path.lexists(Path(row['stateRoot']) / name) for row in self.rows for name in ('current', 'previous')),
                'never-selected preparation has an actor selection or previous pointer')
        if quiescent:
            o.journal.verify_quarantined(self.release, allow_unconfigured=True)
            unpublished_triggers()
        require(self.projection_snapshot() == self.projection_pin, 'original all-domain source custody changed')
        self.derive_environment()
        named = p.child_open(self.root_fd, 'runtime-env', DIR)
        try: require(p.custody_record(named) == self.store_pin == p.custody_record(self.store), 'Root store parent changed')
        finally: os.close(named)
        names = set()
        for text in self.paths:
            path = Path(text); pending = self.progress['pending'] == text
            environment = path in self.environment_entries
            item = self.environment_entries[path] if environment else self.entries[path]
            pin = item['pin'] if environment else self.proof['files'][text]
            parent = self.store if environment else self.dest_dirs[path.parent][0]
            try:
                check = p.child_open(parent, path.name, FILE)
                try: actual = m.regular(check, pin['uid'], pin['gid'], pin['mode'])[1]
                finally: os.close(check)
            except FileNotFoundError: actual = None
            if environment and actual is not None: names.add(path.name)
            if text in self.removed: require(actual is None, 'disposed file reappeared')
            elif not (pending and actual is None):
                require(actual == pin and item['held'] is not None
                        and m.regular(item['held'], pin['uid'], pin['gid'], pin['mode'], pin['sha256'])[1] == pin,
                        'original published file inode/hash/mount/ACL differs')
            stage = self.stage_name(text)
            try:
                check = p.child_open(parent, stage, FILE)
                try:
                    staged = m.regular(check, pin['uid'], pin['gid'], pin['mode'], pin['sha256'])[1]
                    require(pending and actual is None and m.renamed(staged, pin), 'unowned displaced file appeared')
                finally: os.close(check)
                if environment: names.add(stage)
            except FileNotFoundError: pass
        require(set(os.listdir(self.store)) == names, 'Root store namespace changed')
        require(self.read_progress() == self.progress, 'disposition cursor CAS changed')

    def persist(self):
        reserves(self.root, self.scope)
        require(self.read_progress() == self.saved_progress, 'disposition write-ahead CAS differs')
        name = '.unselected-cursor-' + os.urandom(16).hex()
        fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=self.release_fd)
        try:
            view = memoryview(p.encoded(self.progress))
            while view:
                count = os.write(fd, view); require(count > 0, 'cursor write incomplete'); view = view[count:]
            os.fsync(fd)
        finally: os.close(fd)
        os.rename(name, PROGRESS, src_dir_fd=self.release_fd, dst_dir_fd=self.release_fd); os.fsync(self.release_fd)
        self.saved_progress = p.strict(p.encoded(self.progress)); self.progress_pin = None
        require(self.read_progress() == self.progress, 'published cursor differs')

    def run(self):
        self.saved_progress = p.strict(p.encoded(self.progress))
        try: body, _ = self.root_read(self.release_fd, ORIGINAL, private=True)
        except FileNotFoundError:
            fd = os.open(ORIGINAL, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=self.release_fd)
            try:
                with os.fdopen(os.dup(fd), 'wb') as out: out.write(self.original_raw); out.flush(); os.fsync(out.fileno())
            finally: os.close(fd)
            os.fsync(self.release_fd); body, _ = self.root_read(self.release_fd, ORIGINAL, private=True)
        require(body == self.original_raw, 'preserved failed controls differ')
        for text in self.paths[len(self.removed):]:
            self.verify(quiescent=True)
            self.progress.update(pending=text, status='removing'); self.persist(); self.verify(quiescent=True)
            path = Path(text); environment = path in self.environment_entries
            parent = self.store if environment else self.dest_dirs[path.parent][0]
            pin = self.environment_entries[path]['pin'] if environment else self.proof['files'][text]
            stage = self.stage_name(text)
            try: os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError: pass  # Only a durable exact pending path permits this.
            else:
                m.rename(parent, path.name, stage); os.fsync(parent)
                check = p.child_open(parent, stage, FILE)
                try:
                    actual = m.regular(check, pin['uid'], pin['gid'], pin['mode'], pin['sha256'])[1]
                    if not m.renamed(actual, pin):
                        m.rename(parent, stage, path.name); os.fsync(parent)
                        raise Refused('displaced identity differs; original name restored')
                finally: os.close(check)
            if not environment: self.states[path] = None; self.entries[path]['held'] = None
            self.verify(quiescent=True)
            try: check = p.child_open(parent, stage, FILE)
            except FileNotFoundError: pass  # Interrupted after unlink before cursor advancement.
            else:
                try:
                    actual = m.regular(check, pin['uid'], pin['gid'], pin['mode'], pin['sha256'])[1]
                    require(m.renamed(actual, pin), 'displaced original custody changed before unlink')
                    os.unlink(stage, dir_fd=parent); os.fsync(parent)
                finally: os.close(check)
            self.removed.append(text); self.progress.update(removed=list(self.removed), pending=None); self.persist()
        self.progress['status'] = 'completed'; self.persist(); self.verify(quiescent=True)
        # The host manager may still cache generated fragments whose Quadlet
        # source was just removed. Reload only after exact stopped/trigger gates;
        # never start an actor manager or revive a predecessor.
        result = subprocess.run(['systemctl', 'daemon-reload'], capture_output=True, text=True, timeout=60)
        require(result.returncode == 0, 'Root generated-unit unpublication incomplete')
        self.verify(quiescent=True)
        return report(self.expected_sha, self.plan_sha, self.proof, self.env_proof)


def dispose(root, release, value, expected):
    session = Disposition(root, release, value, expected)
    try: return session.run()
    finally: session.close()


def completed_report(root, release, value, expected):
    """Read-only terminal-leaf interruption check; supplies no deletion authority."""
    custody, proof, env, handoff = publication(value)
    require(root == m.v.FAILED_ROOT and release.parent == root / 'releases'
            and str(release) == value['release'] and native.HEX.fullmatch(expected), 'exact terminal scope required')
    o.lock_held(root)
    with p.directory(root) as fd:
        o.root_directory(os.fstat(fd), private=True)
        require(p.current_record(fd) == custody.get('current') == env.get('current'), 'original current changed')
        store = p.child_open(fd, 'runtime-env', DIR)
        try:
            require(p.custody_record(store) == handoff.get('store') and not os.listdir(store),
                    'completed Root store custody or absence differs')
        finally: os.close(store)
    paths, plan_sha = plan_identity(expected, proof, handoff)
    with p.directory(release) as fd:
        raw, _ = p.read_at(fd, ORIGINAL, private=True)
        require(p.sha(raw) == expected and p.strict(raw) == value, 'preserved original controls differ')
        body, _ = p.read_at(fd, PROGRESS, private=True)
    require(p.strict(body) == dict(schemaVersion=1, kind='never-selected-file-disposition', intentSha256=expected,
        planSha256=plan_sha, removed=paths, pending=None, status='completed'), 'exact complete cursor required')
    # No mutations in this branch. The journal additionally rechecks inputs,
    # original current pointer and canonical stopped/configuration absence.
    for text in paths:
        path = Path(text)
        require(not os.path.lexists(path) and not os.path.lexists(path.parent / (
            '.unselected-' + plan_sha[:16] + '-' + p.sha(text.encode())[:16])), 'disposed file or stage reappeared')
    return report(expected, plan_sha, proof, handoff)
