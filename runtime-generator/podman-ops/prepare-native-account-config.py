#!/usr/bin/env python3
"""Positive-only native actor account configuration, not runtime activation.

prepare(root,bundle,domain); CLI --root/--bundle/--domain. Borrow the existing
canonical inherited FD9 flock, never acquire/create a lock or revive a manager.
BUNDLE is a separate root-sealed source; the selected preparing root release
still contains ONLY its private receipt. No graph/private-scope requirement,
rootful-store dependency, marker upgrade, account creation or recursive action.

Only five source-derived .config directories and two fixed static files are
addressed. Existing safe actor directories retain all metadata and their other
names are NOT enumerated/read. Existing files must be byte-identical; they are
never replaced. New files publish fully fsynced anonymous O_TMPFILE inodes via
an exclusive link to the exact destination, not a visible partial file/stage.
"""
import argparse
import errno
import importlib.util
import os
from pathlib import Path
import stat
import time

_source = Path(__file__).with_name('native-runtime-projection-owner.py')
_spec = importlib.util.spec_from_file_location('_account_config_canonical', _source)
o = importlib.util.module_from_spec(_spec)
exec(compile(_source.read_bytes(), str(_source), 'exec'), o.__dict__)
p, storage, native, journal = o.p, o.storage, o.native, o.journal
v = o.load('_account_config_profile', 'verify-agent-vm-bundle.py')
Refusal, require = p.Refusal, o.require
HOME_PARENT = Path('/home')  # fixed production path, never a caller override
DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
CONFIG_DIRS = ('.config', '.config/containers', '.config/containers/systemd', '.config/systemd', '.config/systemd/user')
MAX_NODES, MAX_SECONDS = 10000, 120


def record(fd):
    return dict(p.custody_record(fd), identity=list(p.identity(os.fstat(fd))))


def root_directory(fd, private=False):
    o.root_directory(os.fstat(fd), private=private)
    require(not p.acl_bytes(fd, 'system.posix_acl_access')
            and not p.acl_bytes(fd, 'system.posix_acl_default')
            and not os.fstat(fd).st_mode & 0o7000, 'root source/metadata directory ACL/mode differs')


def configurations(row):
    """Exact bytes shared with the existing standalone installer contract."""
    graph = p.canonical(row['graphRoot'])
    return {'storage.conf': ('[storage]\ndriver = "overlay"\ngraphroot = ' + p.json.dumps(str(graph)) + '\n').encode(),
            'containers.conf': b'[network]\ndefault_rootless_network_cmd = "pasta"\npasta_options = ["--map-host-loopback", "169.254.1.2"]\n'}


class Preparation:
    def __init__(self, root, bundle, domain):
        self.root, self.bundle = p.canonical(str(root)), p.canonical(str(bundle))
        self.domain, self.deadline = domain, time.monotonic() + MAX_SECONDS
        self.fds, self.anchors, self.dirs, self.pins, self.created = [], {}, {}, {}, set()
        self.files = {}
        try:
            require(os.geteuid() == 0 and self.root != self.bundle
                    and not self.bundle.is_relative_to(self.root) and not self.root.is_relative_to(self.bundle),
                    'root and separate sealed account-config source required')
            self.root_fd = self.anchor(self.root); root_directory(self.root_fd, private=True)
            o.lock_held(self.root)
            self.bundle_fd = self.anchor(self.bundle); root_directory(self.bundle_fd)
            self.tree = self.source_tree()
            self.intent_body, self.intent_pin = self.read_root(self.root_fd, '.install-intent.json', private=True)
            self.intent = p.strict(self.intent_body)
            require(isinstance(self.intent, dict) and type(self.intent.get('schemaVersion')) is int
                    and self.intent['schemaVersion'] == 1 and self.intent.get('phase') == 'preparing',
                    'canonical preparing account-config intent required')
            self.release = p.canonical(self.intent['release'])
            require(self.release.parent == self.root / 'releases' and not self.bundle.is_relative_to(self.release),
                    'selected preparing root release differs')
            self.release_fd = self.anchor(self.release); root_directory(self.release_fd, private=True)
            require(self.names(self.release_fd) == ['installation-receipt.json'], 'selected root release must remain receipt-only')
            self.receipt_body, self.receipt_pin = self.read_root(self.release_fd, 'installation-receipt.json', private=True)
            require(self.receipt_body == self.intent_body, 'private preparing intent/receipt bytes differ')
            self.inputs = self.input_snapshot()
            self.manifest = p.strict(self.read_root(self.bundle_fd, 'site/manifest.json')[0])
            self.metadata = p.strict(self.read_root(self.bundle_fd, 'podman-domains.json')[0])
            ir = p.strict(self.read_root(self.bundle_fd, 'stack.ir.json')[0])
            require(isinstance(self.manifest, dict) and isinstance(self.metadata, dict)
                    and self.manifest.get('deploymentMode') == self.metadata.get('deploymentMode') == 'standalone'
                    and self.manifest.get('installerStateRoot') == self.metadata.get('installerStateRoot') == str(self.root),
                    'standalone account-config source/root binding differs')
            v.verify(self.bundle)
            self.source_plan = native.source_plan(self.bundle)
            self.rows = self.metadata.get('domains')
            require(isinstance(self.rows, list) and len(self.rows) == len(native.IDENTITIES)
                    and all(isinstance(row, dict) and isinstance(row.get('name'), str) for row in self.rows)
                    and {row['name'] for row in self.rows} == set(native.IDENTITIES), 'all seven canonical source actors required')
            selected = [row for row in self.rows if row['name'] == domain]
            require(len(selected) == 1, 'unselected account-config domain')
            self.row = selected[0]
            require(sorted(self.row.get('services', [])) == sorted(name for name, service in ir['services'].items()
                    if service.get('placement') == 'rootless' and service.get('rootlessDomain') == domain),
                    'selected source membership differs')
            self.configs = configurations(self.row)
            self.operator = o.pwd.getpwuid(1000)
            self.accounts, self.ranges = self.account_snapshot()
            self.actor = self.accounts[domain]
            self.current = p.current_record(self.root_fd)
            o.Session.check_current(self, self.current, self.root, self.release, (0,))
            if self.current is not None: require(self.current['identity'][3] == 0, 'root current group differs')
            self.previous = self.previous_snapshot()
            # Reuse ONLY canonical source/marker authority; no private graph
            # Session/custody, rootful profile or new marker schema is required.
            scope, operator, self.marker_expected = storage.authority(self.bundle)
            require(str(scope) == self.manifest['storageScope']['root']
                    and (operator.pw_uid, operator.pw_gid) == (1000, 1000), 'canonical scope operator differs')
            self.scope = scope
            require(not any(a.is_relative_to(b) or b.is_relative_to(a)
                            for a in (self.root, self.bundle) for b in (self.scope,)), 'source/metadata scope overlap')
            parent = self.anchor(self.scope.parent, self.operator)
            self.scope_fd = self.child(parent, self.scope.name)
            scope_record = p.custody_record(self.scope_fd)
            require((scope_record['uid'], scope_record['gid'], scope_record['mode']) == (1000, 1000, 0o2770),
                    'selected marked scope custody differs')
            p.custody_permissions(scope_record, 1000, 1000,
                {account['uid'] for account in self.accounts.values()} | set(self.ranges.values()), operator=True)
            self.scope_pin = record(self.scope_fd)
            self.marker_body, self.marker_pin = self.read_root(self.scope_fd, storage.MARKER, private=True)
            require(p.encoded(p.strict(self.marker_body)) == p.encoded(self.marker_expected),
                    'canonical source-bound scope marker differs')
            home_parent = self.anchor(HOME_PARENT)
            self.home = HOME_PARENT / self.actor['user']
            self.home_fd = self.child(home_parent, self.actor['user'])
            self.dirs[self.home] = self.home_fd
            self.actor_directory(self.home, self.home_fd)
            self.pins[self.home] = record(self.home_fd)
            # Preflight EVERY present derived directory/file before any write.
            # Do not list/read home, .config, unit entries or any unknown name.
            for relative in CONFIG_DIRS:
                path = self.home / relative
                if path.parent not in self.dirs: continue
                try: fd = self.child(self.dirs[path.parent], path.name)
                except FileNotFoundError: continue
                self.actor_directory(path, fd)
                self.dirs[path], self.pins[path] = fd, record(fd)
            self.config_parent = self.home / '.config/containers'
            if self.config_parent in self.dirs:
                for name, body in self.configs.items():
                    value = self.actor_file(name, body, missing=True)
                    if value is not None: self.files[name] = dict(value, created=False, sha256=p.sha(body))
            self.verify()
        except BaseException:
            self.close(); raise

    @property
    def expected(self): return self.intent

    def tick(self): require(time.monotonic() < self.deadline, 'account-config deadline exceeded')

    def close(self):
        for fd in self.fds: os.close(fd)
        self.fds = []

    def anchor(self, path, operator=None):
        fd, pins = o.open_absolute(path, operator)
        self.fds.append(fd); self.anchors[path] = pins
        return fd

    def child(self, parent, name):
        fd = p.child_open(parent, name, DIRECTORY)
        self.fds.append(fd); return fd

    def names(self, fd):
        self.tick()
        names = sorted(os.listdir(fd))
        require(len(names) <= MAX_NODES, 'source namespace exceeds bound')
        for name in names:
            p.relative(name); require('/' not in name, 'ambiguous source name')
        return names

    def read_root(self, parent, name, private=False):
        p.relative(name)
        walk = os.dup(parent)
        ancestors = {'': record(parent)}
        try:
            prefix = ''
            for part in name.split('/')[:-1]:
                child = p.child_open(walk, part, DIRECTORY)
                os.close(walk); walk = child
                root_directory(walk)
                prefix += ('/' if prefix else '') + part
                ancestors[prefix] = record(walk)
            fd = p.child_open(walk, name.split('/')[-1], FILE)
        finally: os.close(walk)
        try:
            info = os.fstat(fd); p.controlled(info, private=private)
            require(info.st_gid == 0 and not info.st_mode & 0o7000
                    and not p.acl_bytes(fd, 'system.posix_acl_access')
                    and not p.acl_bytes(fd, 'system.posix_acl_default'), 'root source/record file custody differs')
            before = record(fd); data = bytearray()
            while len(data) <= p.MAX_FILE:
                chunk = os.read(fd, min(65536, p.MAX_FILE + 1 - len(data)))
                if not chunk: break
                data.extend(chunk)
            require(len(data) == info.st_size and len(data) <= p.MAX_FILE and record(fd) == before,
                    'root source/record file read CAS changed')
            return bytes(data), dict(before, ancestors=ancestors)
        finally: os.close(fd)

    def source_tree(self):
        """Only metadata of ROOT-SEALED BUNDLE; never home/scope data walks."""
        found = {}
        def visit(fd, prefix, depth):
            self.tick()
            require(depth <= 48 and len(found) < MAX_NODES, 'sealed source exceeds bound')
            info = os.fstat(fd)
            if stat.S_ISDIR(info.st_mode): root_directory(fd)
            else:
                p.controlled(info)
                require(info.st_gid == 0 and not info.st_mode & 0o7000
                        and not p.acl_bytes(fd, 'system.posix_acl_access')
                        and not p.acl_bytes(fd, 'system.posix_acl_default'), 'sealed source file custody differs')
            found[prefix] = record(fd)
            if stat.S_ISDIR(info.st_mode):
                names = self.names(fd)
                for name in names:
                    info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), 'sealed source link/special inode')
                    child = p.child_open(fd, name, FILE)
                    try: visit(child, prefix + '/' + name, depth + 1)
                    finally: os.close(child)
                require(names == self.names(fd), 'sealed source namespace changed')
            require(found[prefix] == record(fd), 'sealed source inode CAS changed')
        visit(self.bundle_fd, '', 0)
        return found

    def input_snapshot(self):
        expected = self.intent.get('inputs')
        require(isinstance(expected, dict) and set(expected) == p.INPUTS
                and all(expected[name] is not None for name in p.REQUIRED), 'full canonical input fingerprint required')
        observed = {}
        for name, digest in sorted(expected.items()):
            try: body, pin = self.read_root(self.bundle_fd, name)
            except FileNotFoundError:
                require(digest is None, 'pinned source disappeared'); observed[name] = None; continue
            require(isinstance(digest, str) and p.re.fullmatch('[a-f0-9]{64}', digest) and p.sha(body) == digest,
                    'preparing fingerprint differs from sealed BUNDLE')
            observed[name] = pin
        require(journal.fingerprint(self.bundle) == expected, 'canonical sealed BUNDLE fingerprint differs')
        return observed

    def account_snapshot(self):
        operator = o.pwd.getpwuid(1000)
        require((operator.pw_uid, operator.pw_gid, operator.pw_name) == (1000, 1000, self.operator.pw_name)
                and set(o.grp.getgrgid(1000).gr_mem) <= {operator.pw_name}
                and all(account.pw_name == operator.pw_name for account in o.pwd.getpwall() if account.pw_gid == 1000),
                'foreign operator group writer')
        accounts, ranges = {}, {}
        for row in self.rows:
            uid, user = native.IDENTITIES[row['name']]
            account, group = o.pwd.getpwnam(user), o.grp.getgrnam(user)
            require(type(row['uid']) is int and (row['uid'], row['user']) == (uid, user)
                    and (account.pw_uid, account.pw_name, account.pw_dir) == (uid, user, '/home/' + user)
                    and o.pwd.getpwuid(uid).pw_name == user and account.pw_gid == group.gr_gid > 0
                    and o.grp.getgrgid(group.gr_gid).gr_name == user, 'canonical actor UID/user/home/primary group differs')
            start = storage.namespace_root_id(user)
            require('subuidStart' not in row or type(row['subuidStart']) is int and row['subuidStart'] == start,
                    'canonical actor source/subid range differs')
            accounts[row['name']] = dict(uid=uid, gid=group.gr_gid, user=user, home=account.pw_dir)
            ranges[row['name']] = start
        require(len(set(ranges.values())) == len(ranges), 'actor subid allocations overlap')
        return accounts, ranges

    def previous_snapshot(self):
        previous = self.intent.get('previousRelease')
        if previous is None: return None
        previous = p.canonical(previous)
        require(previous.parent == self.root / 'releases' and previous != self.release, 'previous root source binding differs')
        fd, ancestry = o.open_absolute(previous)
        try:
            root_directory(fd, private=True)
            body, receipt = self.read_root(fd, 'installation-receipt.json', private=True)
            value = p.strict(body)
            require(isinstance(value, dict) and type(value.get('schemaVersion')) is int
                    and value['schemaVersion'] == 1 and value.get('phase') == 'active'
                    and value.get('release') == str(previous) and isinstance(value.get('inputs'), dict)
                    and set(value['inputs']) == p.INPUTS, 'previous root receipt/full source pins differ')
            inputs = {}
            for name, digest in value['inputs'].items():
                try: data, pin = self.read_root(fd, name)
                except FileNotFoundError:
                    require(digest is None, 'previous pinned input disappeared'); inputs[name] = None; continue
                require(p.sha(data) == digest, 'previous root source hash differs'); inputs[name] = pin
            return dict(receipt=receipt, receiptSha256=p.sha(body), inputs=inputs,
                        ancestry={str(key): value for key, value in ancestry.items()})
        finally: os.close(fd)

    def actor_directory(self, path, fd):
        value = record(fd)
        require(stat.S_ISDIR(os.fstat(fd).st_mode) and value['uid'] == self.actor['uid']
                and value['gid'] == self.actor['gid']
                and value['mode'] in ((0o700,) if path == self.home else (0o700, 0o750, 0o755))
                and not value['acl'] and not value['defaultAcl'], 'existing actor account directory unsafe; never repaired/adopted')
        return value

    def actor_file(self, name, expected, missing=False):
        try: fd = p.child_open(self.dirs[self.config_parent], name, FILE)
        except FileNotFoundError:
            require(missing, 'pinned actor config missing'); return None
        try:
            info = os.fstat(fd); before = record(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == len(expected)
                    and (before['uid'], before['gid'], before['mode']) == (self.actor['uid'], self.actor['gid'], 0o600)
                    and not before['acl'] and not before['defaultAcl'], 'existing actor static config custody/size differs; never replaced')
            body = bytearray()
            while len(body) <= len(expected):
                data = os.read(fd, len(expected) + 1 - len(body))
                if not data: break
                body.extend(data)
            require(bytes(body) == expected and record(fd) == before, 'existing actor static config source bytes/CAS differ; never replaced')
            actual = os.stat(name, dir_fd=self.dirs[self.config_parent], follow_symlinks=False)
            require(p.identity(actual) == p.identity(info), 'actor static config path inode CAS changed')
            return before
        finally: os.close(fd)

    def verify(self):
        self.tick(); o.lock_held(self.root)
        root_directory(self.root_fd, private=True); root_directory(self.release_fd, private=True)
        for path, old in self.anchors.items():
            fd, pins = o.open_absolute(path, self.operator if path == self.scope.parent else None)
            try: require(pins == old, 'account-config source/home/metadata ancestry CAS changed')
            finally: os.close(fd)
        require(self.source_tree() == self.tree and self.input_snapshot() == self.inputs, 'account-config sealed source CAS changed')
        require(self.read_root(self.root_fd, '.install-intent.json', private=True) == (self.intent_body, self.intent_pin)
                and self.read_root(self.release_fd, 'installation-receipt.json', private=True) == (self.receipt_body, self.receipt_pin)
                and self.names(self.release_fd) == ['installation-receipt.json'], 'account-config preparing records CAS changed')
        require(self.account_snapshot() == (self.accounts, self.ranges), 'account-config account/subid CAS changed')
        journal.assert_domain_offline(self.bundle, self.domain)  # read-only canonical observer, never a new lease
        # The observer must not hide a last-check source/record/account change.
        require(self.source_tree() == self.tree and self.input_snapshot() == self.inputs
                and self.read_root(self.root_fd, '.install-intent.json', private=True) == (self.intent_body, self.intent_pin)
                and self.read_root(self.release_fd, 'installation-receipt.json', private=True) == (self.receipt_body, self.receipt_pin)
                and self.account_snapshot() == (self.accounts, self.ranges), 'account-config post-offline authority CAS changed')
        require(p.current_record(self.root_fd) == self.current and self.previous_snapshot() == self.previous,
                'account-config current/previous source CAS changed')
        parent, _ = o.open_absolute(self.scope.parent, self.operator)
        try:
            fd = p.child_open(parent, self.scope.name, DIRECTORY)
            try: require(record(fd) == self.scope_pin, 'account-config scope path/ACL/mount CAS changed')
            finally: os.close(fd)
        finally: os.close(parent)
        require(self.read_root(self.scope_fd, storage.MARKER, private=True) == (self.marker_body, self.marker_pin),
                'account-config source marker CAS changed')
        parent, _ = o.open_absolute(HOME_PARENT)
        try:
            fd = p.child_open(parent, self.actor['user'], DIRECTORY)
            try: require(record(fd) == self.pins[self.home], 'account-config home path CAS changed')
            finally: os.close(fd)
        finally: os.close(parent)
        for path, fd in self.dirs.items():
            require(self.actor_directory(path, fd) == self.pins[path], 'account-config held directory CAS changed')
            if path != self.home:
                other = p.child_open(self.dirs[path.parent], path.name, DIRECTORY)
                try: require(record(other) == self.pins[path], 'account-config directory path CAS changed')
                finally: os.close(other)
        if self.config_parent in self.dirs:
            for name, expected in self.configs.items():
                current = self.actor_file(name, expected, missing=True)
                if name in self.files:
                    require(current == {key: value for key, value in self.files[name].items() if key not in ('created', 'sha256')},
                            'account-config static file inode CAS changed')
                else: require(current is None, 'actor config appeared; never adopted during preparation')

    def update_parent(self, path, before, directory=False):
        fd = self.dirs[path]
        after = record(fd)
        require({key: value for key, value in before.items() if key != 'identity'}
                == {key: value for key, value in after.items() if key != 'identity'}
                and os.fstat(fd).st_nlink == before['identity'][5] + (1 if directory else 0),
                'new account-config edge changed parent custody/namespace unexpectedly')
        self.pins[path] = after

    def create_directory(self, path):
        self.verify(); parent = self.dirs[path.parent]; before = self.pins[path.parent]
        os.mkdir(path.name, mode=0o700, dir_fd=parent)  # exclusive, never mkdir -p/adopt
        fd = self.child(parent, path.name)
        info = os.fstat(fd)
        require(info.st_uid == 0 and stat.S_ISDIR(info.st_mode) and info.st_nlink == 2
                and stat.S_IMODE(info.st_mode) in (0o700, 0o2700) and not os.listdir(fd), 'new account directory is not empty root-owned staging')
        require(p.identity(info) == p.identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'new account directory mkdir/open CAS changed')
        for attribute in ('system.posix_acl_access', 'system.posix_acl_default'):
            try: os.removexattr(fd, attribute)
            except OSError as error:
                if error.errno != errno.ENODATA: raise
        os.fchown(fd, self.actor['uid'], self.actor['gid']); os.fchmod(fd, 0o700)
        self.dirs[path], self.pins[path] = fd, self.actor_directory(path, fd)
        self.created.add(path); os.fsync(fd); os.fsync(parent)
        self.update_parent(path.parent, before, directory=True)
        self.verify()

    def create_file(self, name, body):
        self.verify(); parent = self.dirs[self.config_parent]; before = self.pins[self.config_parent]
        fd = os.open('.', os.O_RDWR | os.O_TMPFILE | os.O_CLOEXEC, 0o600, dir_fd=parent)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 0 and info.st_size == 0
                    and not p.acl_bytes(fd, 'system.posix_acl_access') and not p.acl_bytes(fd, 'system.posix_acl_default'),
                    'new anonymous account config not private root-owned staging')
            view = memoryview(body)
            while view:
                count = os.write(fd, view); require(count > 0, 'account config write stalled'); view = view[count:]
            os.fchown(fd, self.actor['uid'], self.actor['gid']); os.fchmod(fd, 0o600); os.fsync(fd)
            require(record(parent) == before, 'account config parent CAS changed before atomic publication')
            # /proc/self/fd addresses ONLY this held anonymous inode. Linux
            # linkat via os.link follows that known FD and refuses EEXIST; no
            # untrusted source symlink, named stage, rename or replace occurs.
            os.link('/proc/self/fd/' + str(fd), name, dst_dir_fd=parent, follow_symlinks=True)
            require(os.fstat(fd).st_nlink == 1, 'atomic config publication link count differs')
            published = record(fd)
            os.fsync(parent)
            require(self.actor_file(name, body) == published, 'new atomic config published inode CAS differs')
            self.files[name] = dict(published, created=True, sha256=p.sha(body))
            self.update_parent(self.config_parent, before)
        finally: os.close(fd)
        self.verify()

    def run(self):
        for relative in CONFIG_DIRS:
            path = self.home / relative
            if path not in self.dirs: self.create_directory(path)
        for name, body in self.configs.items():
            if name not in self.files: self.create_file(name, body)
        self.verify()
        return dict(schemaVersion=1, kind='native-account-config', root=str(self.root), bundle=str(self.bundle),
            release=str(self.release), domain=self.domain, user=self.actor['user'], uid=self.actor['uid'], gid=self.actor['gid'],
            home=str(self.home), inputs=self.intent['inputs'], inputFiles=self.inputs,
            bundlePin=self.tree[''], sourceTreeSha256=p.sha(p.encoded(self.tree)),
            sourcePlanSha256=p.sha(p.encoded(self.source_plan)),
            intentSha256=p.sha(self.intent_body), intentPin=self.intent_pin,
            receiptSha256=p.sha(self.receipt_body), receiptPin=self.receipt_pin,
            scopeMarkerSha256=p.sha(self.marker_body), scopeMarkerPin=self.marker_pin,
            rootCurrent=self.current, previousRelease=self.intent.get('previousRelease'), previousSource=self.previous,
            accounts=self.accounts, subordinateStarts=self.ranges,
            directories={str(path): dict(self.pins[path], created=path in self.created) for path in sorted(self.dirs)},
            files={str(self.config_parent / name): value for name, value in self.files.items()}, activationAuthorized=False)


def prepare(root, bundle, domain):
    owner = Preparation(root, bundle, domain)
    try: return owner.run()
    finally: owner.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--domain', required=True)
    args = parser.parse_args()
    try: print(p.encoded(prepare(args.root, args.bundle, args.domain)).decode(), end='')
    except (ValueError, OSError, KeyError, TypeError): parser.exit(1, 'native account configuration refused\n')


if __name__ == '__main__':
    main()
