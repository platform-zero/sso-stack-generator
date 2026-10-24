#!/usr/bin/env python3
"""Seal only selected synthetic installer metadata, never readiness or reset.

seal(root, bundle) -> metadata-only proof; CLI --root/--bundle. The driver must
inherit its existing exclusive canonical installer flock on FD9. No lock is
created/acquired, journal rewritten, actor observed, or release/data tree fixed.
Only the held metadata-root FD may transition root:root0755 -> root:root0700.
Retired source is inventoried with native-selection's previous-source policy;
it is never required to pass a new activation gate or contain private DAG nodes.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import stat
import struct
import time

_source = Path(__file__).with_name('native-runtime-projection-owner.py')
_spec = importlib.util.spec_from_file_location('_metadata_owner_adapter', _source)
o = importlib.util.module_from_spec(_spec)
exec(compile(_source.read_bytes(), str(_source), 'exec'), o.__dict__)
p, native, journal, storage = o.p, o.native, o.journal, o.storage
v = o.load('_metadata_profile', 'verify-agent-vm-bundle.py')
Refusal, require = p.Refusal, o.require
DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
MAX_NODES, MAX_SECONDS = 10000, 120
ROOT_KEYS = ('stateRoot', 'graphRoot', 'volumeRoot')


def record(fd):
    return dict(p.custody_record(fd), identity=list(p.identity(os.fstat(fd))))


def sealed_directory(fd, private=False):
    o.root_directory(os.fstat(fd), private=private)
    require(not p.acl_bytes(fd, 'system.posix_acl_access')
            and not p.acl_bytes(fd, 'system.posix_acl_default'), 'metadata/source directory ACL differs')
    require(not os.fstat(fd).st_mode & 0o7000, 'special metadata/source directory mode')


class Source:
    """Only explicit source pins and quadlets; no old runtime/config/data walk."""
    def __init__(self, owner, path, fd):
        self.owner, self.path, self.fd = owner, path, fd
        self.pins, self.absent, self.bodies, self.names = {}, set(), {}, {}
        self.pins[''] = record(fd)

    def check_directory(self, fd, name):
        sealed_directory(fd)
        value = record(fd)
        require(name not in self.pins or self.pins[name] == value, 'source directory CAS changed')
        self.pins[name] = value

    def read(self, name, private=False, missing=False):
        self.owner.tick(); p.relative(name)
        require(name in self.pins or len(self.pins) < MAX_NODES, 'selected source node bound exceeded')
        fd = os.dup(self.fd)
        prefix = ''
        try:
            for part in name.split('/')[:-1]:
                prefix += ('/' if prefix else '') + part
                try:
                    child = p.child_open(fd, part, DIRECTORY)
                except FileNotFoundError:
                    require(missing, 'required selected source missing')
                    self.absent.add(name); return None
                os.close(fd); fd = child
                self.check_directory(fd, prefix)
            try:
                child = p.child_open(fd, name.split('/')[-1], FILE)
            except FileNotFoundError:
                require(missing, 'required selected source missing')
                self.absent.add(name); return None
            try:
                info = os.fstat(child)
                p.controlled(info, private=private)
                access = p.acl_bytes(child, 'system.posix_acl_access')
                default = p.acl_bytes(child, 'system.posix_acl_default')
                if self.path == getattr(self.owner, 'scope', None) and name == storage.MARKER:
                    # Native creation in the2770 operator scope inherits its
                    # GID and latent operator ACL;0600 gives that ACL mask0.
                    # Preserve this EXACT finite private profile, never clear
                    # ACLs/change ownership or apply it to source/receipt files.
                    entries = [(1, 6, 0xffffffff), (2, 7, 1000), (4, 7, 0xffffffff),
                               (16, 0, 0xffffffff), (32, 0, 0xffffffff)]
                    native_acl = struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *row) for row in entries)
                    require(private and info.st_gid in (0, 1000) and stat.S_IMODE(info.st_mode) == 0o600
                            and access in (b'', native_acl) and not default,
                            'native scope marker private profile differs')
                else:
                    require(info.st_gid == 0 and not info.st_mode & 0o7000
                            and not access and not default, 'source file group/mode/ACL differs')
                before = record(child)
                data = bytearray()
                while len(data) <= p.MAX_FILE:
                    chunk = os.read(child, min(65536, p.MAX_FILE + 1 - len(data)))
                    if not chunk: break
                    data.extend(chunk)
                require(len(data) == info.st_size and len(data) <= p.MAX_FILE
                        and record(child) == before, 'selected source read CAS changed')
                require(name not in self.pins or self.pins[name] == before, 'selected source inode CAS changed')
                self.pins[name] = before
                self.bodies[name] = p.sha(bytes(data))
                return bytes(data)
            finally:
                os.close(child)
        finally:
            os.close(fd)

    def quadlets(self):
        def visit(fd, prefix, depth):
            self.owner.tick()
            require(depth <= 3 and len(self.pins) < MAX_NODES, 'quadlet source exceeds bound')
            self.check_directory(fd, prefix)
            names = sorted(os.listdir(fd))
            require(len(names) <= MAX_NODES, 'quadlet namespace exceeds bound')
            self.names[prefix] = names
            for name in names:
                p.relative(name); require('/' not in name, 'ambiguous source name')
                path = prefix + '/' + name
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    child = p.child_open(fd, name, DIRECTORY)
                    try: visit(child, path, depth + 1)
                    finally: os.close(child)
                else:
                    require(stat.S_ISREG(info.st_mode), 'linked/special quadlet source')
                    self.read(path)
            require(names == sorted(os.listdir(fd)), 'quadlet namespace CAS changed')
        fd = p.child_open(self.fd, 'quadlet', DIRECTORY)
        try: visit(fd, 'quadlet', 0)
        finally: os.close(fd)

    def protected_tree(self):
        """Candidate only: bounded root-sealed metadata walk, no payload reads."""
        found = {}
        def visit(fd, name, depth):
            self.owner.tick()
            require(depth <= 48 and len(found) < MAX_NODES, 'candidate source exceeds bound')
            info = os.fstat(fd)
            if stat.S_ISDIR(info.st_mode):
                sealed_directory(fd)
            else:
                p.controlled(info)
                require(info.st_gid == 0 and not info.st_mode & 0o7000
                        and not p.acl_bytes(fd, 'system.posix_acl_access')
                        and not p.acl_bytes(fd, 'system.posix_acl_default'), 'candidate source protection differs')
            found[name] = record(fd)
            if stat.S_ISDIR(info.st_mode):
                names = sorted(os.listdir(fd))
                require(len(names) <= MAX_NODES, 'candidate namespace exceeds bound')
                for child_name in names:
                    p.relative(child_name); require('/' not in child_name, 'ambiguous candidate name')
                    info = os.stat(child_name, dir_fd=fd, follow_symlinks=False)
                    require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), 'candidate source link/special inode')
                    child = p.child_open(fd, child_name, FILE)
                    try: visit(child, name + '/' + child_name, depth + 1)
                    finally: os.close(child)
                require(names == sorted(os.listdir(fd)), 'candidate namespace CAS changed')
            require(record(fd) == found[name], 'candidate source CAS changed')
        visit(self.fd, '', 0)
        return found

    def snapshot(self):
        return dict(pins=self.pins, absent=sorted(self.absent), bodies=self.bodies, names=self.names)


class Sealing:
    def __init__(self, root, bundle):
        self.root, self.bundle = p.canonical(str(root)), p.canonical(str(bundle))
        require(self.root != Path('/') and self.bundle != Path('/')
                and not self.root.is_relative_to(self.bundle) and not self.bundle.is_relative_to(self.root),
                'separate selected candidate required')
        self.deadline, self.fds = time.monotonic() + MAX_SECONDS, []
        try:
            require(os.geteuid() == 0, 'root metadata ownership required')
            self.root_fd, self.root_ancestry = self.anchor(self.root)
            self.root_pin = record(self.root_fd)
            self.root_mode(self.root_fd)
            o.lock_held(self.root)
            self.lock_pin = self.lock_snapshot()
            self.root_names = sorted(os.listdir(self.root_fd))
            require(len(self.root_names) <= MAX_NODES, 'metadata namespace exceeds bound')
            self.bundle_fd, self.bundle_ancestry = self.anchor(self.bundle)
            source = Source(self, self.root, self.root_fd)
            body = source.read('.install-intent.json', private=True)
            self.intent_body, self.intent = body, p.strict(body)
            self.intent_pin = source.pins['.install-intent.json']
            require(isinstance(self.intent, dict) and type(self.intent.get('schemaVersion')) is int
                    and self.intent['schemaVersion'] == 1 and self.intent.get('phase') in journal.PHASES,
                    'selected old canonical intent required')
            self.release = p.canonical(self.intent['release'])
            require(self.release.parent == self.root / 'releases', 'selected old release escapes metadata')
            self.release_parent = p.child_open(self.root_fd, 'releases', DIRECTORY); self.fds.append(self.release_parent)
            sealed_directory(self.release_parent)
            self.parent_pin = record(self.release_parent)
            self.release_fd = p.child_open(self.release_parent, self.release.name, DIRECTORY); self.fds.append(self.release_fd)
            sealed_directory(self.release_fd, private=True)
            self.candidate, self.old = self.source(self.bundle, self.bundle_fd), self.source(self.release, self.release_fd, self.intent)
            def metadata_identity(binding):
                return dict(site=binding['site'], scope=binding['scope'], domains=[
                    {key: value for key, value in row.items() if key != 'subuidStart'}
                    for row in binding['domains']])
            require(metadata_identity(self.candidate['binding']) == metadata_identity(self.old['binding']),
                    'candidate/selected site scope allocation differs')
            desired = {row['name']: row['subuidStart'] for row in self.candidate['binding']['domains']}
            require(all(row['subuidStart'] is None or row['subuidStart'] == desired[row['name']]
                        for row in self.old['binding']['domains']), 'declared previous namespace allocation differs')
            # Missing historical ranges stay UNKNOWN, never filled from the
            # candidate/NSS. This metadata-only proof grants no actor/data op.
            self.binding = self.candidate['binding']
            self.scope = p.canonical(self.binding['scope']['root'])
            require(not any(a.is_relative_to(b) or b.is_relative_to(a)
                            for a in (self.root, self.bundle) for b in (self.scope,)), 'metadata/source scope overlap')
            self.operator = o.pwd.getpwuid(1000)
            require(self.operator.pw_uid == self.operator.pw_gid == 1000
                    and set(o.grp.getgrgid(1000).gr_mem) <= {self.operator.pw_name}
                    and all(account.pw_name == self.operator.pw_name
                            for account in o.pwd.getpwall() if account.pw_gid == 1000),
                    'operator group contains foreign metadata-scope writers')
            parent, self.scope_ancestry = self.anchor(self.scope.parent, self.operator)
            self.scope_fd = p.child_open(parent, self.scope.name, DIRECTORY); self.fds.append(self.scope_fd)
            self.scope_pin = record(self.scope_fd)
            require((self.scope_pin['uid'], self.scope_pin['gid'], self.scope_pin['mode']) == (1000, 1000, 0o2770),
                    'selected synthetic scope custody differs')
            actors = {row['uid'] for row in self.binding['domains']} | {row['subuidStart'] for row in self.binding['domains']}
            p.custody_permissions(self.scope_pin, 1000, 1000, actors, operator=True)
            marker = Source(self, self.scope, self.scope_fd)
            self.marker_body = marker.read(storage.MARKER, private=True)
            expected_rows = [{key: row[key] for key in ('name', 'user', 'uid', *ROOT_KEYS)} for row in self.binding['domains']]
            expected = dict(schemaVersion=1, kind='standalone-stack-storage', site=self.binding['site'],
                scope=self.binding['scope'], domains=expected_rows,
                roots=sorted(row[key] for row in expected_rows for key in ROOT_KEYS))
            require(p.strict(self.marker_body) == expected, 'selected synthetic scope marker differs')
            self.marker_snapshot = marker.snapshot()
            self.current = self.current_snapshot()
            self.verify()
        except BaseException:
            self.close(); raise

    def tick(self):
        require(time.monotonic() < self.deadline, 'metadata sealing deadline exceeded')

    def close(self):
        for fd in self.fds: os.close(fd)
        self.fds = []

    def anchor(self, path, operator=None):
        fd, pins = o.open_absolute(path, operator)
        self.fds.append(fd)
        return fd, pins

    def root_mode(self, fd):
        sealed_directory(fd)
        require(stat.S_IMODE(os.fstat(fd).st_mode) in (0o755, 0o700), 'metadata root must be exactly 0755 or 0700')

    def lock_snapshot(self):
        o.lock_held(self.root)
        s = Source(self, self.root, self.root_fd)
        require(s.read('.install.lock', private=True) == b'', 'canonical lock file must be empty')
        # Root's deliberate mode/ctime transition is verified separately; only
        # the unchanged lock inode, not its containing root, is pinned here.
        return s.pins['.install.lock']

    def source(self, path, fd, intent=None):
        s = Source(self, path, fd)
        pins = {name: s.read(name, missing=name not in p.REQUIRED) for name in sorted(p.INPUTS)}
        hashes = {name: p.sha(body) if body is not None else None for name, body in pins.items()}
        if intent is not None:
            require(isinstance(intent.get('inputs'), dict) and intent['inputs'] == hashes,
                    'selected old complete source fingerprint differs')
            require(s.read('installation-receipt.json', private=True) == self.intent_body,
                    'selected old intent/receipt bytes differ')
        else:
            s.read('installation-receipt.json', private=True, missing=True)
        manifest = p.strict(pins['site/manifest.json'])
        metadata = p.strict(pins['podman-domains.json'])
        require(isinstance(manifest, dict) and isinstance(metadata, dict)
                and isinstance(manifest.get('storageScope'), dict), 'selected source profile objects required')
        require(manifest.get('installerStateRoot') == metadata.get('installerStateRoot') == str(self.root)
                and manifest.get('deploymentMode') == metadata.get('deploymentMode') == 'standalone'
                and manifest.get('storageScope') == metadata.get('storageScope')
                and manifest.get('storageScope', {}).get('dataClass') == 'synthetic'
                and isinstance(manifest.get('site'), str) and bool(manifest['site']),
                'selected synthetic profile/root binding differs')
        rows = metadata.get('domains')
        require(isinstance(rows, list) and len(rows) == len(native.IDENTITIES)
                and all(isinstance(row, dict) and isinstance(row.get('name'), str) for row in rows)
                and {row['name'] for row in rows} == set(native.IDENTITIES), 'complete canonical actor allocation required')
        identities = []
        for row in sorted(rows, key=lambda row: row['name']):
            uid, user = native.IDENTITIES[row['name']]
            legacy_unspecified = intent is not None and 'subuidStart' not in row
            require(type(row.get('uid')) is int and (row['uid'], row.get('user')) == (uid, user)
                    and (legacy_unspecified or (type(row.get('subuidStart')) is int
                         and 100000 <= row['subuidStart'] <= 2**32 - 65537)),
                    'canonical actor allocation differs')
            identities.append(dict({key: row[key] for key in ('name', 'user', 'uid', *ROOT_KEYS)},
                                   subuidStart=row.get('subuidStart')))
        starts = sorted(row['subuidStart'] for row in identities if row['subuidStart'] is not None)
        require(all(a + 65536 <= b for a, b in zip(starts, starts[1:])), 'overlapping declared actor allocation')
        scope = p.canonical(manifest['storageScope']['root'])
        roots = [p.canonical(row[key]) for row in identities for key in ROOT_KEYS]
        require(all(path != scope and path.is_relative_to(scope) for path in roots)
                and len(set(roots)) == len(roots)
                and not any(a != b and a.is_relative_to(b) for a in roots for b in roots),
                'declared private source DAG escapes or overlaps scope')
        # This owner's sole mutation is metadata privacy, not application
        # admission. Keep the SAME canonical source/profile/provenance/ops
        # checks as normal verify(), without executing its application mount
        # policy. Actual dev16 legacy Huly and the on-demand CI result bind
        # correctly fail activation, but cannot authorize or block this chmod.
        # Normal installation still calls full verify(); all proof authority
        # flags below remain false. Old receipt/source selection is mandatory.
        v.standalone_metadata_source(path)
        s.quadlets()
        plan = native.source_plan(path, previous=intent is not None)
        candidate_tree = s.protected_tree() if intent is None else None
        return dict(binding=dict(site=manifest['site'], scope=manifest['storageScope'], domains=identities),
                    inputs=hashes, snapshot=s.snapshot(), source=plan, candidateTree=candidate_tree)

    def current_snapshot(self):
        pointers = {}
        allowed = {self.release}
        previous = self.intent.get('previousRelease')
        if previous is not None:
            previous = p.canonical(previous)
            require(previous.parent == self.root / 'releases' and previous != self.release, 'previous metadata binding differs')
            allowed.add(previous)
        for name in ('current', 'previous'):
            try:
                info = os.stat(name, dir_fd=self.root_fd, follow_symlinks=False)
            except FileNotFoundError:
                pointers[name] = None; continue
            require(stat.S_ISLNK(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_nlink == 1,
                    'metadata pointer custody differs')
            target = os.readlink(name, dir_fd=self.root_fd)
            path = p.canonical(target) if target.startswith('/') else self.root / p.relative(target)
            require(path in allowed, 'metadata pointer not selected by old intent')
            pointers[name] = dict(identity=list(p.identity(info)), target=target)
        return pointers

    def verify(self):
        self.tick(); self.root_mode(self.root_fd)
        require(record(self.root_fd) == self.root_pin, 'metadata held inode/ACL/mount CAS changed')
        for path, old in ((self.root, self.root_ancestry), (self.bundle, self.bundle_ancestry)):
            fd, pins = o.open_absolute(path)
            try: require(pins == old, 'metadata/source ancestry CAS changed')
            finally: os.close(fd)
        require(self.lock_snapshot() == self.lock_pin, 'canonical lock CAS changed')
        require(sorted(os.listdir(self.root_fd)) == self.root_names, 'metadata namespace CAS changed')
        root = Source(self, self.root, self.root_fd)
        require(root.read('.install-intent.json', private=True) == self.intent_body
                and root.pins['.install-intent.json'] == self.intent_pin, 'selected intent CAS changed')
        require(record(self.release_parent) == self.parent_pin, 'selected release parent CAS changed')
        fd = p.child_open(self.root_fd, 'releases', DIRECTORY)
        try: require(record(fd) == self.parent_pin, 'selected release parent path CAS changed')
        finally: os.close(fd)
        fd = p.child_open(self.release_parent, self.release.name, DIRECTORY)
        try:
            require(record(fd) == self.old['snapshot']['pins'][''], 'selected old release path CAS changed')
        finally: os.close(fd)
        require(self.source(self.bundle, self.bundle_fd) == self.candidate
                and self.source(self.release, self.release_fd, self.intent) == self.old, 'selected source CAS changed')
        parent, pins = o.open_absolute(self.scope.parent, self.operator)
        try:
            require(pins == self.scope_ancestry, 'selected scope ancestry CAS changed')
            fd = p.child_open(parent, self.scope.name, DIRECTORY)
            try: require(record(fd) == self.scope_pin, 'selected scope inode/ACL/mount CAS changed')
            finally: os.close(fd)
        finally: os.close(parent)
        marker = Source(self, self.scope, self.scope_fd)
        require(marker.read(storage.MARKER, private=True) == self.marker_body
                and marker.snapshot() == self.marker_snapshot, 'selected marker CAS changed')
        require(self.current_snapshot() == self.current, 'metadata current pointer CAS changed')
        require(self.lock_snapshot() == self.lock_pin, 'final canonical lock CAS changed')
        require(self.operator == o.pwd.getpwuid(1000)
                and set(o.grp.getgrgid(1000).gr_mem) <= {self.operator.pw_name}
                and all(account.pw_name == self.operator.pw_name
                        for account in o.pwd.getpwall() if account.pw_gid == 1000),
                'operator scope writer authority CAS changed')

    def run(self):
        self.verify()
        before = self.root_pin
        changed = before['mode'] == 0o755
        if changed:
            os.fchmod(self.root_fd, 0o700)
            os.fsync(self.root_fd)
            after = record(self.root_fd)
            require(after['mode'] == 0o700, 'metadata privacy transition failed')
            require({key: value for key, value in before.items() if key not in ('mode', 'identity')}
                    == {key: value for key, value in after.items() if key not in ('mode', 'identity')},
                    'metadata transition changed inode/mount/ACL authority')
            old_identity, new_identity = before['identity'], after['identity']
            require(all(a == b for index, (a, b) in enumerate(zip(old_identity, new_identity))
                        if index not in (4, 8)), 'metadata transition changed unrelated inode metadata')
            # p.identity order: dev,ino,uid,gid,mode,nlink,size,mtime,ctime.
            self.root_pin = after
            self.root_ancestry[self.root] = p.custody_record(self.root_fd)
        self.verify()
        return dict(schemaVersion=1, kind='native-metadata-privacy-transition', root=str(self.root),
            bundle=str(self.bundle), selectedRelease=str(self.release), phase=self.intent['phase'],
            intentSha256=p.sha(self.intent_body), scopeMarkerSha256=p.sha(self.marker_body),
            candidateInputs=self.candidate['inputs'], selectedInputs=self.old['inputs'],
            historicalNamespaceStarts={row['name']: row['subuidStart'] for row in self.old['binding']['domains']},
            current=self.current, before=before, after=self.root_pin, changed=changed,
            readinessAuthorized=False, activationAuthorized=False, resetAuthorized=False)


def seal(root, bundle):
    owner = Sealing(root, bundle)
    try: return owner.run()
    finally: owner.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--bundle', required=True, type=Path)
    args = parser.parse_args()
    try:
        print(p.encoded(seal(args.root, args.bundle)).decode(), end='')
    except (ValueError, OSError, KeyError, TypeError):
        parser.exit(1, 'native metadata privacy transition refused\n')


if __name__ == '__main__':
    main()
