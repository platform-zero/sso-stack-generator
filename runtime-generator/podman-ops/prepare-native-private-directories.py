#!/usr/bin/env python3
"""Provision only the selected source-declared private storage DAG.

prepare(bundle, domain, root) -> metadata-only proof. CLI: --bundle --domain --root.
Called inside native ensure_rootless_domain AFTER exact account/subid validation
and assert_domain_offline, BEFORE any mkdir/chown/graph/config writes. Inherited
FD9 remains the existing installer flock; this helper never acquires a lease,
writes a journal, copies a release, changes phases, starts actors or fixes old
private trees. The preparing intent fingerprints BUNDLE, not the still-empty
selected root release. Both root records must already exist and be identical.

Only newly mkdirat-created, FD-pinned, empty root-owned inodes have inherited
ACLs/SGID removed. Existing bad private directories require complete-clean-reset
through the canonical installer, never migration, recursive chmod or adoption.
Failure leaves any newly created inert paths for that installer's disposition.
"""
import argparse
import errno
import importlib.util
import os
from pathlib import Path
import stat
import struct
import time

_source = Path(__file__).with_name('native-runtime-projection-owner.py')
_spec = importlib.util.spec_from_file_location('_private_directory_owner', _source)
o = importlib.util.module_from_spec(_spec)
exec(compile(_source.read_bytes(), str(_source), 'exec'), o.__dict__)
p, storage, journal, native = o.p, o.storage, o.journal, o.native
v = o.load('_private_directory_boundaries', 'verify-agent-vm-bundle.py')
Refused, require = p.Refusal, o.require
MAX_NODES = 10000
MAX_SECONDS = 120
DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
RESET = 'complete-clean-reset dependency: existing selected private directory has unsafe ownership/mode/ACL; never adopted or repaired'
KEYS = ('stateRoot', 'graphRoot', 'volumeRoot')


def record(fd):
    value = p.custody_record(fd)
    value['identity'] = list(p.identity(os.fstat(fd)))
    return value


def private(fd, uid, gid):
    value = record(fd)
    require(stat.S_ISDIR(os.fstat(fd).st_mode)
            and (value['uid'], value['gid'], value['mode']) == (uid, gid, 0o700)
            and not value['acl'] and not value['defaultAcl'], RESET)
    return value


def root_private(fd):
    o.root_directory(os.fstat(fd), private=True)
    require(not p.acl_bytes(fd, 'system.posix_acl_access')
            and not p.acl_bytes(fd, 'system.posix_acl_default'), 'root metadata/source ACL differs')


def derive(scope, rows, selected):
    """Derive the ALL-domain DAG; only selected edges may subsequently be made."""
    require(isinstance(rows, list) and len(rows) == len(native.IDENTITIES)
            and {r['name'] for r in rows} == set(native.IDENTITIES), 'exact canonical domain inventory required')
    roots, parents = {}, set()
    for row in rows:
        for key in KEYS:
            path = p.canonical(row[key])
            require(path != scope and path.is_relative_to(scope), 'declared private root escapes marker scope')
            require(len(path.parts) - len(scope.parts) <= 32, 'source DAG exceeds depth bound')
            require(path not in roots, 'aliased private roots are ambiguous')
            roots[path] = row['name']
            node = path.parent
            while node != scope:
                parents.add(node); node = node.parent
    require(not (set(roots) & parents), 'private/shared DAG overlap requires explicit source correction')
    private_paths = {p.canonical(selected[key]) for key in KEYS}
    state = p.canonical(selected['stateRoot'])
    private_paths.update((state / 'releases', state / 'runtime-env'))
    require(all(not any(path != other and path.is_relative_to(other)
                        for other in roots if other != state) for path in private_paths),
            'derived private child overlaps another declared root')
    shared = {scope}
    for leaf in (p.canonical(selected[key]) for key in KEYS):
        node = leaf.parent
        while node != scope:
            require(node in parents, 'shared ancestor lacks all-domain source authority')
            shared.add(node); node = node.parent
    require(len(shared | private_paths) <= MAX_NODES, 'selected DAG exceeds node bound')
    return shared, private_paths


class Preparation:
    def __init__(self, bundle, domain, root):
        self.bundle, self.root = p.canonical(str(bundle)), p.canonical(str(root))
        self.domain, self.deadline = domain, time.monotonic() + MAX_SECONDS
        self.fds, self.pins, self.names, self.created = {}, {}, {}, set()
        self.anchors, self.root_pins, self.source_pins = {}, None, None
        self.closed = False
        try:
            require(os.geteuid() == 0 and self.bundle != self.root, 'root and a separate sealed stage are required')
            o.lock_held(self.root)
            self.root_fd, self.root_pins = o.open_absolute(self.root)
            self.anchors[self.root] = self.root_fd
            root_private(self.root_fd)
            self.bundle_fd, self.bundle_pins = o.open_absolute(self.bundle)
            self.anchors[self.bundle] = self.bundle_fd
            o.root_directory(os.fstat(self.bundle_fd))
            self.source_pins = self.source_snapshot()
            self.intent_body, self.intent_pin = self.read_file(self.root_fd, '.install-intent.json', True)
            self.intent = p.strict(self.intent_body)
            require(isinstance(self.intent, dict) and type(self.intent.get('schemaVersion')) is int
                    and self.intent['schemaVersion'] == 1 and self.intent.get('phase') == 'preparing',
                    'canonical preparing intent required')
            self.release = p.canonical(self.intent['release'])
            require(self.release.parent == self.root / 'releases' and self.bundle != self.release
                    and not self.bundle.is_relative_to(self.release), 'new selected release/source binding differs')
            self.release_fd, self.release_pins = o.open_absolute(self.release)
            self.anchors[self.release] = self.release_fd
            root_private(self.release_fd)
            # The journal has created the receipt, but Native has NOT copied the
            # source into this new leaf. Do not fingerprint this empty release.
            require(self.children(self.release_fd) == ['installation-receipt.json'],
                    'selected root release is not the empty derived receipt leaf')
            self.receipt_body, self.receipt_pin = self.read_file(self.release_fd, 'installation-receipt.json', True)
            require(self.receipt_body == self.intent_body, 'preparing receipt/intent bytes differ')
            self.inputs = self.input_snapshot()
            self.metadata = self.json_source('podman-domains.json')
            self.manifest = self.json_source('site/manifest.json')
            self.ir = self.json_source('stack.ir.json')
            provenance = self.json_source('source-provenance.json')
            build = self.json_source('bundle.json')
            require(self.metadata.get('schemaVersion') == 1
                    and self.metadata.get('deploymentMode') == self.manifest.get('deploymentMode')
                    == build.get('deploymentMode') == 'standalone' and build.get('backend') == 'podman'
                    and 'venue' not in self.metadata and 'agentVmSpec' not in self.manifest
                    and self.metadata.get('installerStateRoot') == self.manifest.get('installerStateRoot') == str(self.root),
                    'sealed standalone root metadata binding differs')
            require(provenance.get('manifestSha256') == self.inputs['site/manifest.json']['sha256']
                    and build.get('sourceProvenanceSha256') == self.inputs['source-provenance.json']['sha256']
                    and build.get('irSha256') == self.inputs['stack.ir.json']['sha256'],
                    'sealed standalone source provenance differs')
            require(not any(name in self.source_pins for name in ('site/agent-vm.json',
                    'site/agent-vm.provenance.json', 'maintenance-workspaces.json', 'software-workspaces.json')),
                    'managed role inputs are forbidden')
            config = self.manifest.get('storageScope')
            require(isinstance(config, dict) and set(config) == {'root', 'dataClass'}
                    and config['dataClass'] in ('synthetic', 'production')
                    and self.metadata.get('storageScope') == config, 'source storage scope differs')
            self.scope = p.canonical(config['root'])
            require(not any(a.is_relative_to(b) or b.is_relative_to(a)
                            for a in (self.root, self.bundle) for b in (self.scope,)),
                    'metadata/sealed source and storage scope overlap')
            # Reuse the canonical pure standalone bind-boundary validator. The
            # full site's location grammar is already enforced by NativeBootstrap;
            # this helper additionally binds the exact root argument to BOTH inputs.
            v.standalone_boundaries(self.ir, self.metadata, self.scope)
            self.rows = self.metadata['domains']
            selected = [row for row in self.rows if row.get('name') == domain]
            require(len(selected) == 1, 'unselected domain')
            self.row = selected[0]
            require(sorted(self.row.get('services', [])) == sorted(name for name, service in self.ir['services'].items()
                    if service.get('placement') == 'rootless' and service.get('rootlessDomain') == domain),
                    'selected source service membership differs')
            self.shared, self.private = derive(self.scope, self.rows, self.row)
            self.operator = o.pwd.getpwuid(1000)
            require(self.operator.pw_uid == self.operator.pw_gid == 1000, 'canonical operator identity differs')
            self.accounts, self.ranges = self.account_snapshot()
            self.execute_ids = {account['uid'] for account in self.accounts.values()} | set(self.ranges.values())
            self.actor = self.accounts[domain]
            identities = [{key: row[key] for key in ('name', 'user', 'uid', *KEYS)} for row in self.rows]
            self.marker = dict(schemaVersion=1, kind='standalone-stack-storage', site=self.manifest['site'],
                scope=config, domains=sorted(identities, key=lambda row: row['name']),
                roots=sorted(row[key] for row in self.rows for key in KEYS))
            parent, self.external_pins = o.open_absolute(self.scope.parent, self.operator)
            try:
                fd = p.child_open(parent, self.scope.name, DIRECTORY)
            finally:
                os.close(parent)
            self.fds[self.scope] = fd
            self.shared_permissions(self.scope, fd)
            self.pins[self.scope] = record(fd)
            self.names[self.scope] = self.children(fd)
            marker_body, self.marker_pin = self.read_file(fd, storage.MARKER, True)
            require(p.strict(marker_body) == self.marker, 'exact canonical scope marker differs')
            self.marker_sha = p.sha(marker_body)
            self.root_current = p.current_record(self.root_fd)
            o.Session.check_current(self, self.root_current, self.root, self.release, (0,))
            self.actor_current = None
            self.state = p.canonical(self.row['stateRoot'])
            # Preflight EVERY existing selected path before making any inode.
            for node in sorted((self.shared | self.private) - {self.scope}, key=lambda node: (len(node.parts), str(node))):
                if node.parent not in self.fds:
                    continue
                try:
                    fd = p.child_open(self.fds[node.parent], node.name, DIRECTORY)
                except FileNotFoundError:
                    continue
                self.fds[node] = fd
                self.validate(node, fd)
                self.pins[node] = record(fd)
                if any(other.parent == node for other in self.shared | self.private):
                    self.names[node] = self.children(fd)
            if self.state in self.fds:
                self.actor_current = p.current_record(self.fds[self.state])
                o.Session.check_current(self, self.actor_current, self.state,
                                        self.state / 'releases' / self.release.name, (0, self.actor['uid']))
            self.previous = self.previous_snapshot()
            self.verify()
        except BaseException:
            self.close()
            raise

    @property
    def expected(self):
        return self.intent  # canonical check_current's exact preparing binding

    def close(self):
        if not self.closed:
            for fd in (*self.fds.values(), *self.anchors.values()):
                os.close(fd)
            self.closed = True

    def tick(self):
        require(not self.closed and time.monotonic() < self.deadline, 'private directory preparation deadline exceeded')

    def children(self, fd):
        self.tick()
        names = sorted(os.listdir(fd))
        require(len(names) <= MAX_NODES, 'directory namespace exceeds bound')
        for name in names:
            p.relative(name)
            require('/' not in name, 'ambiguous directory name')
        return names

    def read_file(self, fd, name, private_file=False):
        p.relative(name)
        before = os.stat(name, dir_fd=fd, follow_symlinks=False)
        p.controlled(before, private=private_file)
        scope_marker = (private_file and name == storage.MARKER
                        and fd == self.fds.get(getattr(self, 'scope', None)))
        require(before.st_gid in (0, 1000) if scope_marker else before.st_gid == 0,
                'root file group differs')
        body, identity = p.read_at(fd, name, private=private_file)
        require(p.identity(before) == identity, 'root file pre-open inode CAS differs')
        child = p.child_open(fd, name, FILE)
        try:
            require(list(identity) == list(p.identity(os.fstat(child))), 'root file inode CAS differs')
            observed = record(child)
            if scope_marker:
                # Only the exact held selected scope's original0600 marker may
                # retain native operator-GID/mask0 inheritance. Never normalize
                # it or extend this profile to receipts/source/other paths.
                require((self.operator.pw_uid, self.operator.pw_gid) == (1000, 1000), 'marker operator differs')
                rows = ((1, 6, 0xffffffff), (2, 7, 1000), (4, 7, 0xffffffff),
                        (16, 0, 0xffffffff), (32, 0, 0xffffffff))
                native_acl = (struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *row) for row in rows)).hex()
                require((observed['uid'], observed['mode']) == (0, 0o600)
                        and observed['gid'] in (0, 1000) and observed['acl'] in ('', native_acl)
                        and not observed['defaultAcl'], 'private scope marker profile differs')
            else:
                require(observed['gid'] == 0 and not observed['acl'] and not observed['defaultAcl'],
                        'root file ownership/ACL/CAS differs')
            require(observed == record(child), 'root file metadata CAS differs')
            pin = dict(identity=list(identity), mountId=p.mount_id(child), sha256=p.sha(body))
            if scope_marker:
                pin.update(acl=observed['acl'], defaultAcl=observed['defaultAcl'])
            return body, pin
        finally:
            os.close(child)

    def json_source(self, name):
        return p.strict(self.read_file(self.bundle_fd, name)[0])

    def source_snapshot(self):
        """Bounded metadata walk: root-sealed source only, never host data/home."""
        found = {}
        def visit(fd, prefix, depth):
            self.tick()
            require(depth <= 48 and len(found) < MAX_NODES, 'sealed source tree exceeds bound')
            info = os.fstat(fd)
            isdir = stat.S_ISDIR(info.st_mode)
            require(info.st_uid == info.st_gid == 0 and not info.st_mode & 0o7022
                    and (isdir or stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
                    and not p.acl_bytes(fd, 'system.posix_acl_access')
                    and not p.acl_bytes(fd, 'system.posix_acl_default'), 'source is not root-sealed/no-link/no-ACL')
            found[prefix] = record(fd)
            if isdir:
                names = self.children(fd)
                for name in names:
                    before = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    require(stat.S_ISDIR(before.st_mode) or stat.S_ISREG(before.st_mode),
                            'sealed source contains a symlink or special inode')
                    child = p.child_open(fd, name, FILE)
                    try:
                        require(p.identity(os.fstat(child)) == p.identity(before), 'source pre-open inode CAS differs')
                        visit(child, prefix + ('/' if prefix else '') + name, depth + 1)
                    finally:
                        os.close(child)
                require(names == self.children(fd), 'source namespace changed')
            require(found[prefix] == record(fd), 'sealed source inode changed')
        visit(self.bundle_fd, '', 0)
        return found

    def input_snapshot(self):
        inputs = self.intent.get('inputs')
        require(isinstance(inputs, dict) and set(inputs) == p.INPUTS
                and all(inputs[name] is not None for name in p.REQUIRED), 'complete preparing input fingerprint required')
        observed = {}
        for name, digest in sorted(inputs.items()):
            try:
                body, pin = self.read_file(self.bundle_fd, name)
            except FileNotFoundError:
                require(digest is None, 'required sealed input disappeared')
                observed[name] = None
                continue
            require(isinstance(digest, str) and p.re.fullmatch('[a-f0-9]{64}', digest)
                    and p.sha(body) == digest, 'preparing fingerprint differs from sealed BUNDLE')
            observed[name] = pin
        require(journal.fingerprint(self.bundle) == inputs, 'canonical BUNDLE fingerprint differs')
        return observed

    def account_snapshot(self):
        operator = o.pwd.getpwuid(1000)
        require((operator.pw_uid, operator.pw_gid, operator.pw_name)
                == (1000, 1000, self.operator.pw_name)
                and set(o.grp.getgrgid(1000).gr_mem) <= {operator.pw_name}
                and all(account.pw_name == operator.pw_name for account in o.pwd.getpwall() if account.pw_gid == 1000),
                'operator group contains a foreign writer')
        accounts, ranges = {}, {}
        for row in self.rows:
            uid, user = native.IDENTITIES[row['name']]
            account, group = o.pwd.getpwnam(user), o.grp.getgrnam(user)
            require(type(row['uid']) is int and (row['uid'], row['user']) == (uid, user)
                    and (account.pw_uid, account.pw_name, account.pw_dir) == (uid, user, '/home/' + user)
                    and o.pwd.getpwuid(uid).pw_name == user and account.pw_gid == group.gr_gid > 0
                    and o.grp.getgrgid(group.gr_gid).gr_name == user, 'canonical actor account/group differs')
            start = storage.namespace_root_id(user)
            require('subuidStart' not in row or type(row['subuidStart']) is int and row['subuidStart'] == start,
                    'source subordinate UID/GID range differs')
            accounts[row['name']] = dict(uid=uid, gid=account.pw_gid, user=user, home=account.pw_dir)
            ranges[row['name']] = start
        require(len(set(ranges.values())) == len(ranges), 'canonical actor subordinate ranges overlap')
        return accounts, ranges

    def shared_permissions(self, path, fd):
        value = record(fd)
        require(stat.S_ISDIR(os.fstat(fd).st_mode), 'shared ancestor is not a directory')
        if path != self.scope and (value['uid'], value['gid'], value['mode']) == (0, 1000, 0o2770):
            p.custody_permissions(value, 0, 1000, self.execute_ids, root_ancestor=True, operator_uid=1000)
            return
        if (path == self.scope / 'volumes' == p.canonical(self.row['volumeRoot']).parent
                and (value['uid'], value['gid'], value['mode']) == (0, 1000, 0o755)):
            p.custody_permissions(value, 0, 1000, self.execute_ids, root_ancestor=True, operator_uid=1000)
            require(bool(value['acl']) and bool(value['defaultAcl']), 'old public volumes parent lacks exact ACL authority')
            entries = o.acl_entries(bytes.fromhex(value['acl']))
            require(entries.get((2, 1000)) == 7 and entries.get((4, 0xffffffff)) == 7
                    and all(entries.get((2, row['uid'])) == 1 for row in self.rows),
                    'old public volumes parent differs from selected canonical policy')
            return
        require((value['uid'], value['gid'], value['mode']) == (1000, 1000, 0o2770),
                'existing shared ancestor owner/group/mode differs; preserved')
        p.custody_permissions(value, 1000, 1000, self.execute_ids, operator=True)

    def validate(self, path, fd):
        if path in self.private:
            private(fd, self.actor['uid'], self.actor['gid'])
        else:
            self.shared_permissions(path, fd)

    def previous_snapshot(self):
        previous = self.intent.get('previousRelease')
        if previous is None:
            return None
        path = p.canonical(previous)
        require(path.parent == self.root / 'releases' and path != self.release, 'previous root binding differs')
        fd, pins = o.open_absolute(path)
        try:
            body, receipt = self.read_file(fd, 'installation-receipt.json', True)
            old = p.strict(body)
            require(isinstance(old, dict) and old.get('schemaVersion') == 1 and old.get('phase') == 'active'
                    and old.get('release') == str(path) and isinstance(old.get('inputs'), dict),
                    'previous current lacks canonical active receipt')
            inputs = {}
            require(set(old['inputs']) == p.INPUTS, 'previous receipt full pins required')
            for name, digest in old['inputs'].items():
                try:
                    data, seal = self.read_file(fd, name)
                except FileNotFoundError:
                    require(digest is None, 'previous pinned input disappeared')
                    inputs[name] = None
                    continue
                require(p.sha(data) == digest, 'previous root input changed')
                inputs[name] = seal
            return dict(ancestry={str(key): value for key, value in pins.items()}, receipt=receipt, inputs=inputs)
        finally:
            os.close(fd)

    def verify(self):
        self.tick(); o.lock_held(self.root)
        for path, old_pins in ((self.root, self.root_pins), (self.release, self.release_pins), (self.bundle, self.bundle_pins)):
            fd, pins = o.open_absolute(path)
            try:
                require(pins == old_pins and record(fd) == record(self.anchors[path]), 'root/source path ancestry CAS changed')
                if path != self.bundle:
                    root_private(fd)
            finally:
                os.close(fd)
        require(self.source_snapshot() == self.source_pins, 'sealed source tree CAS changed')
        require(self.read_file(self.root_fd, '.install-intent.json', True) == (self.intent_body, self.intent_pin)
                and self.read_file(self.release_fd, 'installation-receipt.json', True) == (self.receipt_body, self.receipt_pin)
                and self.children(self.release_fd) == ['installation-receipt.json'], 'preparing root record/receipt CAS changed')
        require(self.input_snapshot() == self.inputs, 'sealed input inode/hash CAS changed')
        require(self.account_snapshot() == (self.accounts, self.ranges), 'account/subordinate authority CAS changed')
        journal.assert_domain_offline(self.bundle, self.domain)
        # The canonical offline observer reads path-based source and system
        # identity tables. Seal both sides of that observation as well; its
        # success must not hide a last-check source/journal/account replacement.
        require(self.read_file(self.root_fd, '.install-intent.json', True) == (self.intent_body, self.intent_pin)
                and self.read_file(self.release_fd, 'installation-receipt.json', True) == (self.receipt_body, self.receipt_pin),
                'preparing root record/receipt CAS changed')
        require(self.source_snapshot() == self.source_pins and self.input_snapshot() == self.inputs,
                'sealed source tree/input CAS changed after offline observation')
        require(self.account_snapshot() == (self.accounts, self.ranges), 'account/subordinate authority CAS changed')
        require(p.current_record(self.root_fd) == self.root_current, 'root current pointer CAS changed')
        require(self.previous_snapshot() == self.previous, 'previous root receipt/inputs changed')
        parent, pins = o.open_absolute(self.scope.parent, self.operator)
        try:
            require(pins == self.external_pins, 'above-scope ancestry/mount/ACL CAS changed')
            fd = p.child_open(parent, self.scope.name, DIRECTORY)
            try:
                require(record(fd) == self.pins[self.scope], 'scope inode/mount/ACL CAS changed')
            finally:
                os.close(fd)
        finally:
            os.close(parent)
        body, seal = self.read_file(self.fds[self.scope], storage.MARKER, True)
        require(seal == self.marker_pin and p.sha(body) == self.marker_sha, 'scope marker CAS changed')
        inodes = set()
        for path, fd in self.fds.items():
            require(record(fd) == self.pins[path], 'held selected inode/mount/ACL CAS changed')
            self.validate(path, fd)
            inode = (os.fstat(fd).st_dev, os.fstat(fd).st_ino)
            require(inode not in inodes, 'selected directory alias/hardlink')
            inodes.add(inode)
            if path != self.scope:
                child = p.child_open(self.fds[path.parent], path.name, DIRECTORY)
                try:
                    require(record(child) == self.pins[path], 'selected path inode CAS changed')
                finally:
                    os.close(child)
            if path in self.names:
                require(self.children(fd) == self.names[path], 'selected parent namespace changed')
        if self.state in self.fds:
            require(p.current_record(self.fds[self.state]) == self.actor_current, 'actor current pointer CAS changed')

    def create(self, path):
        self.verify()
        parent = self.fds[path.parent]
        require(path.name not in self.names[path.parent], 'new selected path already exists; no adoption')
        # mkdirat is exclusive (EEXIST is always a refusal). No mkdir -p, and
        # nothing opens or clears ACLs on an already existing private inode.
        os.mkdir(path.name, mode=0o700, dir_fd=parent)
        fd = p.child_open(parent, path.name, DIRECTORY)
        self.fds[path] = fd
        initial = os.fstat(fd)
        require(initial.st_uid == 0 and stat.S_ISDIR(initial.st_mode) and initial.st_nlink == 2
                and stat.S_IMODE(initial.st_mode) in (0o700, 0o2700)
                and not self.children(fd), 'new derived inode is not empty root-owned private staging')
        seen = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        require(p.identity(seen) == p.identity(initial), 'new derived mkdir/open inode CAS changed')
        for attribute in ('system.posix_acl_access', 'system.posix_acl_default'):
            try:
                os.removexattr(fd, attribute)
            except OSError as error:
                if error.errno != errno.ENODATA:
                    raise
        uid, gid, mode = ((self.actor['uid'], self.actor['gid'], 0o700) if path in self.private
                          else (1000, 1000, 0o2770))
        os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
        require(not p.acl_bytes(fd, 'system.posix_acl_access')
                and not p.acl_bytes(fd, 'system.posix_acl_default'), 'new derived inode ACL removal failed')
        self.validate(path, fd)
        os.fsync(fd); os.fsync(parent)
        expected_names = sorted([*self.names[path.parent], path.name])
        require(self.children(parent) == expected_names, 'mkdir changed unrelated selected namespace')
        # Only the known mkdir edge may change its parent's metadata. All
        # permissions, mount, inode and ACL bytes must still be identical.
        after = record(parent)
        require({key: value for key, value in after.items() if key != 'identity'}
                == {key: value for key, value in self.pins[path.parent].items() if key != 'identity'},
                'mkdir changed parent authority')
        self.pins[path.parent] = after
        self.names[path.parent] = expected_names
        self.pins[path] = record(fd)
        self.names[path] = []
        self.created.add(path)
        self.verify()

    def run(self):
        for path in sorted((self.shared | self.private) - {self.scope}, key=lambda path: (len(path.parts), str(path))):
            if path not in self.fds:
                self.create(path)
        self.verify()
        return dict(schemaVersion=1, kind='native-private-directories', domain=self.domain,
            user=self.actor['user'], uid=self.actor['uid'], gid=self.actor['gid'], root=str(self.root),
            bundle=str(self.bundle), release=str(self.release), inputs=self.intent['inputs'],
            intentSha256=p.sha(self.intent_body), receiptSha256=p.sha(self.receipt_body),
            scopeMarkerSha256=self.marker_sha, rootCurrent=self.root_current, actorCurrent=self.actor_current,
            previousRelease=self.intent.get('previousRelease'), accounts=self.accounts, subordinateStarts=self.ranges,
            directories={str(path): dict(self.pins[path], created=path in self.created)
                         for path in sorted(self.fds)}, activationAuthorized=False)


def prepare(bundle, domain, root):
    preparation = Preparation(bundle, domain, root)
    try:
        return preparation.run()
    finally:
        preparation.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--domain', required=True)
    parser.add_argument('--root', required=True, type=Path)
    args = parser.parse_args()
    try:
        print(p.encoded(prepare(args.bundle, args.domain, args.root)).decode(), end='')
    except (ValueError, OSError, KeyError, TypeError) as error:
        # Never format exception data, paths, locals or source lines. Operator
        # diagnostics identify only trusted ops code guards (basename/line/name).
        message = RESET if isinstance(error, Refused) and str(error) == RESET else 'native private directory preparation refused'
        frames = []; tb = error.__traceback__
        while tb is not None:
            code = tb.tb_frame.f_code
            if Path(code.co_filename).parent == Path(__file__).parent:
                frames.append(f'{Path(code.co_filename).name}:{tb.tb_lineno}:{code.co_name}')
            tb = tb.tb_next
        parser.exit(1, message + '\n' + 'guard: ' + ' > '.join(frames[-16:]) + '\n')


if __name__ == '__main__':
    main()
