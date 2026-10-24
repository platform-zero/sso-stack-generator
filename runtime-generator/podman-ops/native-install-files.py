#!/usr/bin/env python3
"""In-process selected Quadlet/target publisher for the EXISTING installer.

prepare_custody(root, release, prior_intent) retains FDs and returns metadata.
The journal owner must seal prior+nativeUnitFileCustody identically in BOTH
preparing records, then call project_and_handoff(root, release, new_intent) in
THIS process under inherited FD9. No CLI, lock acquisition, journal write,
service mutation, restart, previous-source code execution or admission token.

Only native-selection inventory files are owned here. Parents must already be
provisioned. Runtime-env helper/drop-in/updater files are NOT in that inventory;
this module neither adopts nor publishes them. Existing affecting overrides
refuse and require the separate owning-file transaction. Failures retain inert
stages and the journal owner's durable custody record; no automatic recovery.
"""
import ctypes
import errno
import os
from pathlib import Path
import secrets
import stat
import struct
import subprocess
import time
import importlib.util
import sys


def load(name, filename):
    source = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, source)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(source.read_bytes(), str(source), 'exec'), module.__dict__)
    return module


o = load('_native_install_file_owner', 'native-runtime-projection-owner.py')
v = load('_native_install_file_projections', 'verify-native-runtime-projections.py')
p, native, storage = o.p, o.native, o.storage
require, Refused = o.require, o.Refused
HOST = Path('/')  # Fixed production namespace; no caller/env override.
DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
_sessions = {}


def renamed(actual, original):
    """rename may change ctime, but no other sealed inode property."""
    return actual == dict(original, identity=original['identity'][:-1] + [actual['identity'][-1]])


def rename(parent, source, destination, exchange=False):
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.renameat2(parent, os.fsencode(source), parent, os.fsencode(destination),
                           2 if exchange else 1)  # EXCHANGE or NOREPLACE; never blind replace.
    if result:
        raise OSError(ctypes.get_errno(), 'selected unit file atomic rename refused')


def regular(fd, uid, gid, mode, digest=None):
    before = os.fstat(fd)
    record = dict(p.custody_record(fd), identity=list(p.identity(before)))
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_size <= native.LIMIT and (before.st_uid, before.st_gid,
            stat.S_IMODE(before.st_mode)) == (uid, gid, mode)
            and not record['acl'] and not record['defaultAcl'], 'selected file custody differs')
    body = os.pread(fd, native.LIMIT + 1, 0)
    require(len(body) == before.st_size and len(body) <= native.LIMIT
            and list(p.identity(os.fstat(fd))) == record['identity'], 'selected file changed during read')
    record['sha256'] = p.sha(body)
    require(digest is None or record['sha256'] == digest, 'selected file SHA differs')
    return body, record


def stopped(release, plan):
    """Canonical read-only observations ONLY; never revive an actor manager."""
    for name in native.IDENTITIES:
        o.inactive(release, name)
    units = plan['scopes']['rootful']['units']
    result = subprocess.run(['systemctl', 'show', *units, '-p', 'Id', '-p', 'Names',
        '-p', 'LoadState', '-p', 'ActiveState', '-p', 'MainPID', '-p', 'Job',
        '-p', 'DropInPaths', '-p', 'SourcePath', '-p', 'FragmentPath'],
        capture_output=True, text=True, timeout=15)
    require(result.returncode == 0, 'rootful selected stopped observation unavailable')
    blocks = [dict(line.split('=', 1) for line in block.splitlines() if '=' in line)
              for block in result.stdout.strip().split('\n\n') if block]
    require(len(blocks) == len(units) and {b.get('Id') for b in blocks} == set(units),
            'rootful selected observation identity differs')
    sources = {}
    for source in plan['sources'].values():
        entry = source['scopes']['rootful']
        for rel, seal in entry['files'].items():
            sources.setdefault(seal['unit'], set()).add(str(native.destination('rootful', entry, rel)))
    for props in blocks:
        unit = props['Id']
        require(props.get('LoadState') in ('loaded', 'not-found')
                and props.get('ActiveState') in ('inactive', 'failed')
                and props.get('MainPID') in ('', '0') and props.get('Job') == ''
                and props.get('DropInPaths') == '' and set(props.get('Names', '').split()) <= {unit},
                'rootful selected unit active, aliased, overridden or pending')
        if props['LoadState'] == 'loaded':
            require(set(props.get('Names', '').split()) == {unit}, 'loaded selected unit names differ')
            if unit.endswith('.target'):
                require(props.get('FragmentPath') in sources[unit] and props.get('SourcePath') == '',
                        'rootful selected target fragment differs')
            else:
                require(props.get('SourcePath') in sources[unit]
                        and any(props.get('FragmentPath') == str(HOST / 'run/systemd' / folder / unit)
                                for folder in ('generator', 'generator.early', 'generator.late')),
                        'rootful selected generated fragment/source differs')
    jobs = subprocess.run(['systemctl', 'list-jobs', '--no-legend', '--no-pager'],
                          capture_output=True, text=True, timeout=15)
    require(jobs.returncode == 0 and not any(set(line.split()) & set(units)
            for line in jobs.stdout.splitlines()), 'rootful selected job remains')


class Session:
    def __init__(self, root, release, prior):
        self.root, self.release = p.canonical(str(root)), p.canonical(str(release))
        self.prior = native.strict(p.encoded(prior)); self.expected = self.prior
        self.deadline = time.monotonic() + 120
        self.fds, self.chains, self.source_dirs, self.source_files = [], {}, {}, {}
        self.dest_dirs, self.entries, self.states, self.stages = {}, {}, {}, {}
        self.read_dirs, self.override_guards = {}, {}
        self.record_pins = None; self.closed = False; self.marker_fd = None
        try:
            require(os.geteuid() == 0 and self.release.parent == self.root / 'releases'
                    and type(prior.get('schemaVersion')) is int and prior['schemaVersion'] == 1
                    and prior.get('phase') == 'preparing' and prior.get('release') == str(self.release)
                    and 'nativeUnitFileCustody' not in prior and 'nativeUnitFiles' not in prior,
                    'fresh exact preparing root transaction required')
            self.root_fd = self.absolute(self.root)
            self.release_fd = self.absolute(self.release)
            o.root_directory(os.fstat(self.root_fd), private=True)
            o.root_directory(os.fstat(self.release_fd), private=True)
            self.releases_fd = self.hold(p.child_open(self.root_fd, 'releases', DIR))
            releases_pin = p.custody_record(self.releases_fd)
            o.root_directory(os.fstat(self.releases_fd))
            require(not releases_pin['acl'] and not releases_pin['defaultAcl'], 'metadata releases ACL differs')
            self.candidate_edge = self.hold(p.child_open(self.releases_fd, self.release.name, DIR))
            require(p.custody_record(self.candidate_edge) == p.custody_record(self.release_fd),
                    'candidate is not the exact NO_XDEV metadata-root release')
            self.check_records()
            self.scope, self.operator, self.marker = storage.authority(self.release)
            self.metadata = self.json_source(self.release_fd, 'podman-domains.json')
            self.manifest = self.json_source(self.release_fd, 'site/manifest.json')
            require(self.metadata.get('installerStateRoot') == self.manifest.get('installerStateRoot', '/var/lib/webservices')
                    == str(self.root) and self.metadata.get('storageScope') == self.manifest.get('storageScope')
                    == self.marker['scope'] and self.scope == p.canonical(self.marker['scope']['root'])
                    and not self.scope.is_relative_to(self.root) and not self.root.is_relative_to(self.scope),
                    'canonical metadata/storage root binding differs')
            rows = self.metadata.get('domains')
            require(isinstance(rows, list) and len(rows) == len(native.IDENTITIES)
                    and {r['name'] for r in rows} == set(native.IDENTITIES), 'seven canonical actors required')
            self.rows = rows; self.accounts = self.account_snapshot()
            parent = self.absolute(self.scope.parent, self.operator)
            self.scope_fd = self.hold(p.child_open(parent, self.scope.name, DIR))
            self.scope_pin = p.custody_record(self.scope_fd)
            require((self.scope_pin['uid'], self.scope_pin['gid'], self.scope_pin['mode']) == (1000, 1000, 0o2770),
                    'canonical operator scope custody differs')
            ids = {item['uid'] for item in self.accounts.values()} | {item['subuidStart'] for item in self.accounts.values()}
            p.custody_permissions(self.scope_pin, 1000, 1000, ids, operator=True)
            storage.marker(self.scope, self.marker)
            marker_body, self.marker_pin = self.root_read(self.scope_fd, storage.MARKER, private=True)
            require(p.strict(marker_body) == self.marker, 'storage marker differs')
            self.marker_sha = p.sha(marker_body)
            self.current = p.current_record(self.root_fd)
            self.previous = self.previous_release()
            self.previous_fd = self.absolute(self.previous) if self.previous else None
            self.previous_inputs = None
            if self.previous:
                o.root_directory(os.fstat(self.previous_fd), private=True)
                self.previous_edge = self.hold(p.child_open(self.releases_fd, self.previous.name, DIR))
                require(p.custody_record(self.previous_edge) == p.custody_record(self.previous_fd),
                        'previous is not the exact NO_XDEV metadata-root release')
                self.previous_inputs = self.previous_authority()
            self.plan = native.selection(self.release, self.previous)
            self.validation = native.validate_installed(self.release, self.previous)
            require(self.validation['plan'] == self.plan, 'installed validation source plan differs')
            self.pin_sources()
            self.projection_pin = self.projection_snapshot()
            self.prepare_destinations()
            self.override_snapshot()
            stopped(self.release, self.plan)
            self.custody = dict(schemaVersion=1, kind='native-unit-file-custody', release=str(self.release),
                stopOnlyPrevious=dict(release=str(self.previous), source=self.plan['sources']['previous']) if self.previous else None,
                current=self.current,
                inputs=self.expected['inputs'], scopeMarkerSha256=self.marker_sha,
                selectionSha256=p.sha(p.encoded(self.plan)), projectionBindingSha256=p.sha(p.encoded(self.projection_pin)),
                accounts=self.accounts, directories={str(path): pin for path, (_, pin) in self.dest_dirs.items()},
                files={str(path): dict(item['public'], before=self.states[path], stage=item['stage'])
                       for path, item in self.entries.items()},
                nonInventoryOwned=False, activationAuthorized=False, readinessAuthorized=False)
            self.verify(full=True)
        except BaseException:
            self.close()
            raise

    def hold(self, fd):
        self.fds.append(fd)
        return fd

    def close(self):
        if not self.closed:
            for fd in reversed(self.fds):
                os.close(fd)
            self.fds = []; self.closed = True

    def alive(self):
        require(not self.closed and time.monotonic() < self.deadline, 'selected unit file custody expired')

    def absolute(self, path, operator=None):
        fd, pins = o.open_absolute(path, operator)
        self.chains[(path, operator is not None)] = pins
        return self.hold(fd)

    def root_read(self, parent, name, private=False):
        parts = p.relative(name).split('/'); fd = parent; opened = []
        anchor = os.fstat(parent)
        try:
            for index, part in enumerate(parts[:-1]):
                fd = p.child_open(fd, part, DIR); opened.append(fd)
                rec = p.custody_record(fd)
                o.root_directory(os.fstat(fd))
                require(not rec['acl'] and not rec['defaultAcl'], 'root input ancestor ACL differs')
                key = (anchor.st_dev, anchor.st_ino, '/'.join(parts[:index + 1]))
                saved = self.read_dirs.setdefault(key, rec)
                require(rec == saved, 'root input ancestor inode/mount changed')
            child = p.child_open(fd, parts[-1], FILE); opened.append(child)
            info = os.fstat(child)
            p.controlled(info, private=private)
            scope_marker = (private and parent == getattr(self, 'scope_fd', None) and name == storage.MARKER)
            if scope_marker:
                # Only this selected scope's original marker may retain the
                # native0600/mask0 inheritance; all other inputs remain gid0,
                # noACL through the unchanged regular() contract.
                require((self.operator.pw_uid, self.operator.pw_gid) == (1000, 1000), 'marker operator differs')
                rows = ((1, 6, 0xffffffff), (2, 7, 1000), (4, 7, 0xffffffff),
                        (16, 0, 0xffffffff), (32, 0, 0xffffffff))
                native_acl = (struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *r) for r in rows)).hex()
                rec = dict(p.custody_record(child), identity=list(p.identity(info)))
                require(info.st_gid in (0, self.operator.pw_gid) and rec['mode'] == 0o600
                        and rec['acl'] in ('', native_acl) and not rec['defaultAcl'], 'private scope marker profile differs')
                body = os.pread(child, native.LIMIT + 1, 0)
                require(len(body) == info.st_size and len(body) <= native.LIMIT
                        and dict(p.custody_record(child), identity=list(p.identity(os.fstat(child)))) == rec,
                        'private scope marker read CAS changed')
                if self.marker_fd is None:
                    self.marker_fd = self.hold(os.dup(child))
                require(dict(p.custody_record(self.marker_fd), identity=list(p.identity(os.fstat(self.marker_fd)))) == rec,
                        'original held scope marker changed')
            else:
                require(info.st_gid == 0 and stat.S_IMODE(info.st_mode) in (0o400, 0o444, 0o600, 0o644),
                        'root input group/mode differs')
                body, rec = regular(child, 0, 0, stat.S_IMODE(info.st_mode))
            again = p.child_open(fd, parts[-1], FILE); opened.append(again)
            require(list(p.identity(os.fstat(again))) == rec['identity'], 'root input path raced')
            if scope_marker:
                require(dict(p.custody_record(again), identity=list(p.identity(os.fstat(again)))) == rec,
                        'private scope marker named CAS changed')
                rec['sha256'] = p.sha(body)
            return body, rec
        finally:
            for child in reversed(opened):
                os.close(child)

    def json_source(self, parent, name):
        return native.strict(self.root_read(parent, name)[0])

    def inputs(self, fd, inputs):
        require(isinstance(inputs, dict) and set(inputs) == p.INPUTS
                and all(inputs[name] is not None for name in p.REQUIRED), 'full source input pins required')
        result = {}
        for name, digest in sorted(inputs.items()):
            try:
                body, pin = self.root_read(fd, name)
            except FileNotFoundError:
                require(digest is None, 'required pinned input absent')
                result[name] = None
                continue
            require(isinstance(digest, str) and native.HEX.fullmatch(digest)
                    and p.sha(body) == digest, 'source input pin differs')
            result[name] = pin
        return result

    def check_records(self):
        self.alive(); o.lock_held(self.root)
        body, ip = self.root_read(self.root_fd, '.install-intent.json', private=True)
        receipt, rp = self.root_read(self.release_fd, 'installation-receipt.json', private=True)
        require(body == receipt and native.strict(body) == self.expected, 'identical preparing records CAS required')
        pins = {'intent': ip, 'receipt': rp}
        if self.record_pins is None:
            self.record_pins = pins
        require(pins == self.record_pins, 'preparing root records inode changed')
        observed = self.inputs(self.release_fd, self.expected.get('inputs'))
        if not hasattr(self, 'input_pins'):
            self.input_pins = observed
        require(observed == self.input_pins, 'candidate source input inode changed')
        self.cas = p.sha(body)

    def account_snapshot(self):
        operator = o.pwd.getpwuid(1000)
        require((operator.pw_uid, operator.pw_gid, operator.pw_name) == (1000, 1000, self.operator.pw_name)
                and set(o.grp.getgrgid(1000).gr_mem) <= {operator.pw_name}
                and all(a.pw_name == operator.pw_name for a in o.pwd.getpwall() if a.pw_gid == 1000),
                'canonical operator writer differs')
        result = {}
        for row in self.rows:
            uid, user = native.IDENTITIES[row['name']]
            account, group = o.pwd.getpwnam(user), o.grp.getgrnam(user)
            start = storage.namespace_root_id(user)
            require(type(row['uid']) is int and (row['uid'], row['user']) == (uid, user)
                    and (account.pw_uid, account.pw_name, account.pw_dir) == (uid, user, '/home/' + user)
                    and o.pwd.getpwuid(uid).pw_name == user and account.pw_gid == group.gr_gid > 0
                    and o.grp.getgrgid(group.gr_gid).gr_name == user
                    and ('subuidStart' not in row or row['subuidStart'] == start), 'canonical actor identity/range differs')
            result[row['name']] = dict(uid=uid, user=user, gid=account.pw_gid, home=account.pw_dir, subuidStart=start)
        starts = sorted(r['subuidStart'] for r in result.values())
        require(all(a + 65536 <= b for a, b in zip(starts, starts[1:])), 'actor subordinate ranges overlap')
        return result

    def previous_release(self):
        claim = self.expected.get('previousRelease')
        if self.current is None:
            require(claim is None, 'canonical current absent but previous claimed')
            return None
        require(self.current['identity'][2:4] == [0, 0], 'canonical current pointer owner differs')
        target = self.current['target']
        path = p.canonical(target) if target.startswith('/') else self.root / p.relative(target)
        require(path.parent == self.root / 'releases' and path != self.release
                and (claim is None or str(path) == claim),
                'previous must derive only from protected canonical current')
        return path

    def previous_authority(self):
        body, receipt_pin = self.root_read(self.previous_fd, 'installation-receipt.json', private=True)
        value = native.strict(body)
        require(type(value.get('schemaVersion')) is int and value['schemaVersion'] == 1
                and value.get('release') == str(self.previous)
                and value.get('phase') in ('active', 'retired-failed', 'retired-clean'),
                'previous receipt not eligible stop-only source')
        claim = self.expected.get('previousRelease')
        require((claim is None and value['phase'] in ('retired-failed', 'retired-clean'))
                or (claim == str(self.previous) and value['phase'] == 'active'),
                'active previous provenance differs from stop-only retired source')
        pins = self.inputs(self.previous_fd, value.get('inputs'))
        manifest = self.json_source(self.previous_fd, 'site/manifest.json')
        metadata = self.json_source(self.previous_fd, 'podman-domains.json')
        bundle = self.json_source(self.previous_fd, 'bundle.json')
        provenance = self.json_source(self.previous_fd, 'source-provenance.json')
        # Previous is SOURCE/STOP-ONLY: do not run its old activation gates or code.
        require(manifest.get('deploymentMode') == metadata.get('deploymentMode') == bundle.get('deploymentMode') == 'standalone'
                and manifest.get('site') == self.manifest.get('site')
                and manifest.get('installerStateRoot', '/var/lib/webservices') == metadata.get('installerStateRoot') == str(self.root)
                and manifest.get('storageScope') == metadata.get('storageScope') == self.marker['scope']
                and provenance.get('manifestSha256') == value['inputs']['site/manifest.json']
                and bundle.get('sourceProvenanceSha256') == value['inputs']['source-provenance.json']
                and bundle.get('irSha256') == value['inputs']['stack.ir.json']
                and isinstance(provenance.get('generatorCommit'), str)
                and native.re.fullmatch('[a-f0-9]{40}', provenance['generatorCommit'])
                and sorted([{k: r[k] for k in ('name', 'user', 'uid', 'stateRoot', 'graphRoot', 'volumeRoot')}
                            for r in metadata['domains']], key=lambda r: r['name']) == self.marker['domains'],
                'previous source provenance/same-scope marker differs')
        return dict(receipt=receipt_pin, inputs=pins)

    def pin_sources(self):
        for key, source in self.plan['sources'].items():
            fd = self.release_fd if key == 'candidate' else self.previous_fd
            quad = self.hold(p.child_open(fd, 'quadlet', DIR))
            quad_pin = p.custody_record(quad)
            o.root_directory(os.fstat(quad))
            require(not quad_pin['acl'] and not quad_pin['defaultAcl'], 'source Quadlet root ACL differs')
            self.source_dirs[(key, 'quadlet')] = (quad, p.custody_record(quad), set(source['scopes']))
            for scope, entry in source['scopes'].items():
                parent = self.hold(p.child_open(quad, scope, DIR))
                rec = p.custody_record(parent)
                o.root_directory(os.fstat(parent))
                require(not rec['acl'] and not rec['defaultAcl'], 'source Quadlet directory ACL differs')
                self.source_dirs[(key, scope)] = (parent, rec, {Path(rel).name for rel in entry['files']})
                for rel, seal in entry['files'].items():
                    child = self.hold(p.child_open(parent, Path(rel).name, FILE))
                    mode = stat.S_IMODE(os.fstat(child).st_mode)
                    require(mode in (0o400, 0o444, 0o600, 0o644), 'source file mode differs')
                    _, pin = regular(child, 0, 0, mode, seal['sha256'])
                    self.source_files[(key, rel)] = (child, parent, Path(rel).name, pin)

    def projection_snapshot(self):
        # The existing read-only verifier owns projection/env proof semantics,
        # including empty domains. Our selected source/destination FDs remain
        # retained separately; these observations must stay equal across calls.
        snap = v.Snapshot(self.root, self.release, self.expected, False, self.deadline)
        try:
            observed = snap.sweep()
            excluded = {str(self.root / '.install-intent.json'), str(self.release / 'installation-receipt.json')}
            return {key: value for key, value in observed.items() if key not in excluded}
        finally:
            snap.close()

    def actor_directories(self, entry):
        if not entry['uid']:
            return {}
        actor = self.accounts[entry['scope'].removeprefix('rootless-')]
        home = HOST / 'home' / actor['user']
        paths = {home / suffix for suffix in
                ('', '.config', '.config/containers', '.config/containers/systemd',
                 '.config/systemd', '.config/systemd/user', '.config/systemd/user.control',
                 '.local', '.local/share', '.local/share/systemd', '.local/share/systemd/user')}
        runtime = HOST / 'run/user' / str(actor['uid'])
        paths.update(runtime / suffix for suffix in ('', 'systemd', 'systemd/user', 'systemd/user.control',
                     'systemd/transient', 'containers', 'containers/systemd'))
        return {path: (actor['uid'], actor['gid']) for path in paths}

    def open_host(self, path, entry, missing=False):
        """Fixed host namespace; private exceptions ONLY canonical actor homes.

        Mount crossings are permitted only above /etc or /home anchors. All
        edges below those roots use openat2 NO_XDEV, including destination leaf.
        """
        allowed = self.actor_directories(entry)
        fd = os.open('/', DIR); current = Path('/'); anchored = False
        try:
            for part in path.parts[1:]:
                current /= part
                try:
                    child = p.child_open(fd, part, DIR) if anchored else os.open(part, DIR, dir_fd=fd)
                except FileNotFoundError:
                    require(missing, 'canonical destination parent must be pre-provisioned')
                    return os.dup(fd), current.parent, part
                os.close(fd); fd = child
                rec = p.custody_record(fd)
                require(not rec['acl'] and not rec['defaultAcl'], 'host directory ACL differs')
                if current in allowed:
                    uid, gid = allowed[current]
                    home = HOST / 'home' / entry['user']
                    public_config = {home / suffix for suffix in ('.config', '.config/containers',
                        '.config/containers/systemd', '.config/systemd', '.config/systemd/user')}
                    modes = (0o700, 0o750, 0o755) if current in public_config else (0o700,)
                    require((rec['uid'], rec['gid']) == (uid, gid) and rec['mode'] in modes,
                            'canonical actor home/config parent custody differs')
                else:
                    o.root_directory(os.fstat(fd))
                anchored |= current in (HOST / 'etc', HOST / 'home')
            result = os.dup(fd)
            return (result, path, None) if missing else result
        finally:
            os.close(fd)

    def prepare_destinations(self):
        for source_key, source in self.plan['sources'].items():
            for scope, raw in source['scopes'].items():
                entry = dict(raw, scope=scope)
                gid = 0 if scope == 'rootful' else self.accounts[scope.removeprefix('rootless-')]['gid']
                for rel, seal in raw['files'].items():
                    path = native.destination(scope, raw, rel)
                    expected = (HOST / 'etc/systemd/system' if path.name.endswith('.target') else HOST / 'etc/containers/systemd') if scope == 'rootful' else (
                        HOST / 'home' / raw['user'] / ('.config/systemd/user' if path.name.endswith('.target') else '.config/containers/systemd'))
                    require(path == expected / Path(rel).name, 'selection destination differs from canonical host root')
                    if path.parent not in self.dest_dirs:
                        parent = self.hold(self.open_host(path.parent, entry))
                        self.dest_dirs[path.parent] = (parent, p.custody_record(parent))
                    item = self.entries.setdefault(path, dict(entry=entry, uid=raw['uid'], gid=gid, candidate=None,
                        hashes=set(), stage='.native-unit-files-' + secrets.token_hex(16),
                        public=dict(scope=scope, unit=seal['unit'], relative=rel, uid=raw['uid'], gid=gid, mode=0o644)))
                    require((item['uid'], item['gid'], item['public']['unit']) == (raw['uid'], gid, seal['unit']),
                            'selected destination identity collision')
                    item['hashes'].add(seal['sha256'])
                    if source_key == 'candidate':
                        item['candidate'] = self.source_files[(source_key, rel)]
                        item['public']['candidateSha256'] = seal['sha256']
        for path, item in self.entries.items():
            item['public']['removePreviousOnly'] = item['candidate'] is None
            pin = self.destination_record(path)
            require(pin is None or pin['sha256'] in item['hashes'], 'exact destination is not selected source bytes')
            self.states[path] = pin
            item['held'] = None
            parent = self.dest_dirs[path.parent][0]
            if pin is not None:
                item['held'] = self.hold(p.child_open(parent, path.name, FILE))
                require(regular(item['held'], item['uid'], item['gid'], 0o644)[1] == pin,
                        'destination changed while retaining original FD')
            try:
                os.stat(item['stage'], dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise Refused('new inert stage name collision')

    def destination_record(self, path):
        item = self.entries[path]; parent = self.dest_dirs[path.parent][0]
        try:
            child = p.child_open(parent, path.name, FILE)
        except FileNotFoundError:
            return None
        try:
            _, pin = regular(child, item['uid'], item['gid'], 0o644)
            return pin
        finally:
            os.close(child)

    @staticmethod
    def dropin_names(name):
        stem, suffix = name.rsplit('.', 1)
        result = {name + '.d', suffix + '.d'}
        while '-' in stem:
            stem = stem.rsplit('-', 1)[0]
            result.add(stem + '-.' + suffix + '.d')
        return result

    def absent(self, path, entry):
        parent, anchor, absent = self.open_host(path.parent, entry, missing=True)
        name = absent or path.name
        try:
            try:
                os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                if anchor not in self.override_guards:
                    self.override_guards[anchor] = (self.hold(os.dup(parent)), p.custody_record(parent), entry, set())
                self.override_guards[anchor][3].add(name)
                return
            raise Refused('selected unit override/drop-in collision; separate owning-file disposition required')
        finally:
            os.close(parent)

    def verify_overrides(self):
        for path, (fd, saved, entry, names) in self.override_guards.items():
            check = self.open_host(path, entry)
            try:
                require(p.custody_record(fd) == p.custody_record(check) == saved,
                        'override search ancestor inode/mount/ACL changed')
                for name in names:
                    try:
                        os.stat(name, dir_fd=fd, follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    raise Refused('selected override/drop-in appeared; separate owning-file disposition required')
            finally:
                os.close(check)

    def override_snapshot(self):
        for scope, raw in self.plan['scopes'].items():
            entry = dict(raw, scope=scope)
            system = [HOST / name for name in ('etc/systemd/system', 'run/systemd/system',
                'usr/lib/systemd/system', 'usr/local/lib/systemd/system', 'etc/systemd/system.control',
                'run/systemd/system.control', 'run/systemd/transient')] if scope == 'rootful' else [
                HOST / 'home' / raw['user'] / name for name in ('.config/systemd/user', '.config/systemd/user.control',
                                                              '.local/share/systemd/user')]
            quad = [HOST / 'etc/containers/systemd', HOST / 'run/containers/systemd',
                    HOST / 'usr/share/containers/systemd'] if scope == 'rootful' else [
                HOST / 'home' / raw['user'] / '.config/containers/systemd',
                HOST / 'etc/containers/systemd/users' / str(raw['uid']), HOST / 'etc/containers/systemd/users',
                HOST / 'usr/share/containers/systemd/users']
            if scope != 'rootful':
                system += [HOST / name for name in ('etc/systemd/user', 'run/systemd/user',
                    'usr/lib/systemd/user', 'usr/local/lib/systemd/user')]
                runtime = HOST / 'run/user' / str(raw['uid'])
                system += [runtime / name for name in ('systemd/user', 'systemd/user.control', 'systemd/transient')]
                quad.append(runtime / 'containers/systemd')
            relatives = set()
            for source in self.plan['sources'].values():
                relatives.update(source['scopes'].get(scope, {}).get('files', {}))
            for rel in relatives:
                filename = Path(rel).name
                canonical = native.destination(scope, raw, rel)
                for folder in quad if not filename.endswith('.target') else ():
                    if folder / filename != canonical:
                        self.absent(folder / filename, entry)
                    for name in self.dropin_names(filename):
                        self.absent(folder / name, entry)
            for unit in raw['units']:
                for folder in system:
                    if not (unit.endswith('.target') and folder / unit in self.entries):
                        self.absent(folder / unit, entry)
                    for name in self.dropin_names(unit) | {unit + suffix for suffix in ('.wants', '.requires', '.upholds')}:
                        self.absent(folder / name, entry)

    def verify(self, full=False, quiescent=False):
        self.alive(); self.check_records()
        require(self.account_snapshot() == self.accounts, 'account/range custody changed')
        for (path, operator), saved in self.chains.items():
            fd, pins = o.open_absolute(path, self.operator if operator else None)
            try:
                require(pins == saved, 'root/external directory mount/inode/ACL changed')
            finally:
                os.close(fd)
        require(p.current_record(self.root_fd) == self.current, 'canonical current pointer changed')
        scope_parent, _ = o.open_absolute(self.scope.parent, self.operator)
        try:
            scope_check = p.child_open(scope_parent, self.scope.name, DIR)
            try:
                require(p.custody_record(scope_check) == self.scope_pin == p.custody_record(self.scope_fd),
                        'held/named storage scope changed')
            finally:
                os.close(scope_check)
        finally:
            os.close(scope_parent)
        body, pin = self.root_read(self.scope_fd, storage.MARKER, private=True)
        require(pin == self.marker_pin and p.sha(body) == self.marker_sha, 'scope marker CAS changed')
        if self.previous:
            require(self.previous_authority() == self.previous_inputs, 'previous receipt/source custody changed')
        for (key, name), (fd, pin, names) in self.source_dirs.items():
            require(p.custody_record(fd) == pin and set(os.listdir(fd)) == names, 'sealed source directory changed')
            parent = (self.release_fd if key == 'candidate' else self.previous_fd) if name == 'quadlet' else self.source_dirs[(key, 'quadlet')][0]
            check = p.child_open(parent, name, DIR)
            try:
                require(p.custody_record(check) == pin, 'sealed source directory moved')
            finally:
                os.close(check)
        for fd, parent, name, pin in self.source_files.values():
            require(list(p.identity(os.fstat(fd))) == pin['identity'] and p.custody_record(fd) == {
                key: value for key, value in pin.items() if key not in ('sha256', 'identity')}, 'held source file changed')
            check = p.child_open(parent, name, FILE)
            try:
                require(list(p.identity(os.fstat(check))) == pin['identity'], 'source file path changed')
                if full:
                    require(regular(check, 0, 0, pin['mode'], pin['sha256'])[1] == pin, 'source file bytes changed')
            finally:
                os.close(check)
        for path, (fd, pin) in self.dest_dirs.items():
            item = next(e for dest, e in self.entries.items() if dest.parent == path)
            check = self.open_host(path, item['entry'])
            try:
                require(p.custody_record(fd) == p.custody_record(check) == pin, 'destination directory moved/mounted/ACL changed')
            finally:
                os.close(check)
        for path, expected in self.states.items():
            item = self.entries[path]
            if expected is not None:
                require(item['held'] is not None and regular(item['held'], item['uid'], item['gid'],
                        0o644, expected['sha256'])[1] == expected, 'held destination inode CAS changed')
            require(self.destination_record(path) == expected, 'destination inode/bytes CAS changed')
        for (parent_path, name), pin in self.stages.items():
            item = next(e for dest, e in self.entries.items() if dest.parent == parent_path and e['stage'] == name)
            fd = p.child_open(self.dest_dirs[parent_path][0], name, FILE)
            try:
                require(regular(fd, item['uid'], item['gid'], 0o644, pin['sha256'])[1] == pin,
                        'inert stage inode CAS changed')
            finally:
                os.close(fd)
        if full:
            expected_plan = native.strict(p.encoded(self.plan))
            expected_plan['sources']['candidate']['receipt'] = dict(sha256=self.cas, phase='preparing')
            require(native.selection(self.release, self.previous) == expected_plan, 'source selection changed')
            require(self.projection_snapshot() == self.projection_pin, 'completed projections/env custody changed')
        self.verify_overrides()
        if quiescent:
            stopped(self.release, self.plan)
        self.alive()

    def stage(self, path):
        item = self.entries[path]; source, _, _, pin = item['candidate']
        parent = self.dest_dirs[path.parent][0]
        fd = self.hold(os.open(item['stage'], os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW,
                               0o600, dir_fd=parent))
        initial = os.fstat(fd)
        require(stat.S_ISREG(initial.st_mode) and initial.st_nlink == 1 and initial.st_size == 0
                and (initial.st_uid, initial.st_gid, stat.S_IMODE(initial.st_mode)) == (0, 0, 0o600),
                'fresh selected stage custody differs')
        require(initial.st_dev == os.fstat(parent).st_dev and p.mount_id(fd) == p.mount_id(parent),
                'new selected stage crosses mount')
        body, _ = regular(source, 0, 0, pin['mode'], pin['sha256'])
        # Fresh leaf only. Never remove inherited ACLs or repair an old inode.
        require(not p.acl_bytes(fd, 'system.posix_acl_access') and not p.acl_bytes(fd, 'system.posix_acl_default'),
                'new selected stage inherited ACL')
        view = memoryview(body)
        while view:
            count = os.write(fd, view)
            require(count > 0, 'selected stage short write')
            view = view[count:]
        os.fchown(fd, item['uid'], item['gid']); os.fchmod(fd, 0o644); os.fsync(fd)
        _, staged = regular(fd, item['uid'], item['gid'], 0o644, pin['sha256'])
        self.stages[path.parent, item['stage']] = staged
        os.fsync(parent)
        return staged

    def apply(self, intent):
        new = native.strict(p.encoded(intent))
        require(new == dict(self.prior, nativeUnitFileCustody=self.custody),
                'journal changed beyond exact same-process unit file custody')
        self.expected = new; self.record_pins = None
        self.verify(full=True, quiescent=True)
        published, removed, unchanged = {}, [], []
        for path, item in sorted(self.entries.items()):
            old = self.states[path]
            if item['candidate'] is None or (old is not None and old['sha256'] == item['public']['candidateSha256']):
                continue
            self.stage(path)
        self.verify(full=True, quiescent=True)
        for path, item in sorted(self.entries.items()):
            old = self.states[path]; parent = self.dest_dirs[path.parent][0]; stage = item['stage']
            if item['candidate'] is not None and old is not None and old['sha256'] == item['public']['candidateSha256']:
                unchanged.append(str(path)); continue
            if item['candidate'] is None and old is None:
                continue
            self.verify(quiescent=True)
            if item['candidate'] is None:
                rename(parent, path.name, stage)
                displaced_id = list(p.identity(os.stat(stage, dir_fd=parent, follow_symlinks=False)))
                try:
                    require(displaced_id[:-1] == old['identity'][:-1], 'previous-only displaced inode differs')
                    child = p.child_open(parent, stage, FILE)
                    try:
                        _, displaced = regular(child, item['uid'], item['gid'], 0o644, old['sha256'])
                        require(renamed(displaced, old), 'previous-only displaced custody differs')
                    finally:
                        os.close(child)
                except (ValueError, OSError):
                    require(list(p.identity(os.stat(stage, dir_fd=parent, follow_symlinks=False))) == displaced_id,
                            'previous-only displaced path raced again; stage retained')
                    rename(parent, stage, path.name); os.fsync(parent)
                    raise Refused('previous-only CAS refused; original name restored without overwrite') from None
                self.states[path] = None; item['held'] = None; self.stages[path.parent, stage] = displaced
                self.verify(quiescent=True)
                self.check_stage(path, displaced)
                os.unlink(stage, dir_fd=parent); self.stages.pop((path.parent, stage))
                removed.append(str(path))
            else:
                staged = self.stages[path.parent, stage]
                rename(parent, stage, path.name, exchange=old is not None)
                displaced = None
                if old is not None:
                    displaced_id = list(p.identity(os.stat(stage, dir_fd=parent, follow_symlinks=False)))
                    try:
                        require(displaced_id[:-1] == old['identity'][:-1], 'exchange displaced inode differs')
                        child = p.child_open(parent, stage, FILE)
                        try:
                            _, displaced = regular(child, item['uid'], item['gid'], 0o644, old['sha256'])
                            require(renamed(displaced, old), 'exchange displaced custody differs')
                        finally:
                            os.close(child)
                    except (ValueError, OSError):
                        self.restore_exchange(parent, stage, path.name, staged, displaced_id)
                        raise Refused('selected exchange CAS refused; original name restored; inert stage retained') from None
                actual = self.destination_record(path)
                require(actual is not None and renamed(actual, staged), 'published selected inode CAS differs')
                self.states[path] = actual
                item['held'] = self.hold(p.child_open(parent, path.name, FILE))
                require(regular(item['held'], item['uid'], item['gid'], 0o644)[1] == actual,
                        'published selected FD changed')
                self.stages.pop((path.parent, stage))
                if old is not None:
                    self.stages[path.parent, stage] = displaced
                    self.verify(quiescent=True)
                    self.check_stage(path, displaced)
                    os.unlink(stage, dir_fd=parent); self.stages.pop((path.parent, stage))
                published[str(path)] = actual
            os.fsync(parent)
            self.verify()
        self.verify(full=True, quiescent=True)
        return dict(schemaVersion=1, kind='native-selected-unit-files', status='completed', release=str(self.release),
            stopOnlyPrevious=str(self.previous) if self.previous else None,
            inputs=self.expected['inputs'], intentSha256=self.cas, receiptSha256=self.cas,
            custodySha256=p.sha(p.encoded(self.custody)), scopeMarkerSha256=self.marker_sha,
            selectionSha256=p.sha(p.encoded(self.plan)), files={str(path): pin for path, pin in self.states.items() if pin},
            published=published, removedPreviousOnly=removed, unchanged=unchanged,
            activationAuthorized=False, readinessAuthorized=False, applicationAcceptance=False,
            nonInventoryOwned=False, automaticRestart=False)

    def check_stage(self, path, expected):
        item = self.entries[path]
        child = p.child_open(self.dest_dirs[path.parent][0], item['stage'], FILE)
        try:
            require(regular(child, item['uid'], item['gid'], 0o644, expected['sha256'])[1] == expected,
                    'displaced selected stage CAS changed before unlink')
        finally:
            os.close(child)

    def restore_exchange(self, parent, stage, name, staged, displaced_id):
        actual = list(p.identity(os.stat(name, dir_fd=parent, follow_symlinks=False)))
        displaced = list(p.identity(os.stat(stage, dir_fd=parent, follow_symlinks=False)))
        require(actual[:-1] == staged['identity'][:-1] and displaced == displaced_id,
                'exchange raced again; both inodes retained for canonical disposition')
        rename(parent, stage, name, exchange=True); os.fsync(parent)
        require(list(p.identity(os.stat(name, dir_fd=parent, follow_symlinks=False)))[:-1] == displaced_id[:-1],
                'exchange restoration CAS differs; canonical disposition required')


def prepare_custody(root, release, prior_intent):
    key = (str(root), str(release))
    require(key not in _sessions, 'unconsumed selected file custody already exists')
    session = Session(root, release, prior_intent)
    _sessions[key] = session
    return native.strict(p.encoded(session.custody))


def project_and_handoff(root, release, new_intent):
    key = (str(root), str(release))
    session = _sessions.pop(key, None)
    require(session is not None, 'same-process selected file custody FDs required')
    try:
        return session.apply(new_intent)
    finally:
        session.close()
