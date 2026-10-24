#!/usr/bin/env python3
"""In-process custody adapter for the EXISTING preparing installer transaction.

prepare_custody(root, release, prior_intent, domain) returns projectionCustody.
The journal must write it, unchanged, into BOTH preparing records, then call
project_and_handoff(root, release, new_intent, domain) IN THE SAME PROCESS.
Only the journal writes records. FD9 must retain its inherited exclusive flock.
There is no CLI, admission token, lock acquisition, service control or cleanup.

The projection helper still needs the narrow open_scope_parent compatibility
hook documented in the handoff. Without it, real operator-owned /mnt/stack
ancestry is intentionally refused, NOT silently monkeypatched or bypassed.
"""
import contextlib
import importlib.util
import os
from pathlib import Path
import pwd
import grp
import stat
import struct
import sys
import time


def load(name, filename):
    source = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, source)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(source.read_bytes(), str(source), 'exec'), module.__dict__)
    return module


p = load('_native_projection_helper', 'project-domain-runtime.py')
storage = load('_native_projection_storage', 'grant-rootless-volume-parent-traverse.py')
journal = load('_native_projection_journal', 'install-journal.py')
native = load('_native_projection_selection', 'native-selection.py')
Refused = p.Refusal
EXTERNAL_OPERATOR = Path('/mnt/stack')
MAX_NODES = 10000
MAX_TOTAL = 64 * 1024 * 1024
_sessions = {}


def require(condition, message):
    if not condition:
        raise Refused(message)


def root_directory(info, private=False):
    p.controlled(info, directory=True, private=private)
    require(info.st_gid == 0, 'root authority group differs')


def root_chain(path):
    for node in (*reversed(path.parents), path):
        root_directory(node.lstat())


def lock_held(root):
    """Observe inherited FD9's flock; never obtain even a substitute lock."""
    root_chain(root)
    with p.directory(root) as parent:
        fd = p.child_open(parent, '.install.lock', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            p.controlled(info, private=True)
            require(info.st_gid == 0 and p.identity(info) == p.identity(os.fstat(9)),
                    'canonical inherited lock FD9 differs')
            with open('/proc/self/fdinfo/9', encoding='ascii') as source:
                body = source.read(65537)
            locks = [line.split() for line in body.splitlines() if line.startswith('lock:')]
            require(len(body) <= 65536 and len(locks) == 1 and len(locks[0]) >= 9
                    and locks[0][2:5] == ['FLOCK', 'ADVISORY', 'WRITE'],
                    'FD9 lacks inherited exclusive installer lease')
            inode = locks[0][6].split(':')
            require(len(inode) == 3 and int(inode[0], 16) == os.major(info.st_dev)
                    and int(inode[1], 16) == os.minor(info.st_dev) and int(inode[2]) == info.st_ino,
                    'FD9 flock inode differs')
        finally:
            os.close(fd)


def acl_entries(body):
    require(len(body) >= 4 and (len(body) - 4) % 8 == 0
            and struct.unpack('<I', body[:4])[0] == 2, 'invalid exact ancestry ACL')
    rows = {}
    for offset in range(4, len(body), 8):
        tag, rights, identifier = struct.unpack('<HHI', body[offset:offset + 8])
        require((tag, identifier) not in rows and rights <= 7, 'ambiguous ancestry ACL')
        rows[tag, identifier] = rights
    return rows


def external_permissions(path, record, operator):
    """Only the independently reviewed canonical external operator ancestor.

    Do NOT pass this public parent to safe_parent (which correctly requires
    private scoped parents), change it, or generalize group-write admission.
    Every ACL entry including default ACL is exact and subsequently FD-pinned.
    """
    require(path == EXTERNAL_OPERATOR and operator.pw_uid == 1000 and operator.pw_gid == 1000
            and (record['uid'], record['gid'], record['mode']) == (1000, 1000, 0o2775),
            'unreviewed external operator ancestry')
    undefined = 0xffffffff
    expected = {(1, undefined): 7, (2, 1000): 7, (4, undefined): 7,
                (16, undefined): 7, (32, undefined): 5}
    access = acl_entries(bytes.fromhex(record['acl']))
    if (8, 1000) in access:
        expected[8, 1000] = 7
    require(access == expected, 'external operator access ACL differs')
    p.operator_defaults(record['defaultAcl'], operator.pw_uid, operator.pw_gid)


def open_absolute(path, operator=None):
    """No-follow absolute ancestor walk; mount crossings only ABOVE scope.

    All crossed ancestors are pinned with kernel mount IDs and both ACLs.
    Scope entry and edges BELOW it use the helper's NO_XDEV openat2 instead.
    """
    path = p.canonical(str(path))
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    pins = {Path('/'): p.custody_record(fd)}
    try:
        root_directory(os.fstat(fd))
        current = Path('/')
        for name in path.parts[1:]:
            current /= name
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
            record = p.custody_record(fd)
            if current == EXTERNAL_OPERATOR and operator is not None:
                external_permissions(current, record, operator)
            else:
                root_directory(os.fstat(fd))
                require(not record['defaultAcl'] and not record['acl'], 'unexpected root ancestry ACL')
            pins[current] = record
        return fd, pins
    except BaseException:
        os.close(fd)
        raise


def inactive(release, domain):
    """Reuse only the canonical journal's read-only stopped-actor gate.

    A running user manager is NOT revived, stopped or considered a lease here.
    The installer must already have stopped it and disabled its boot/API paths.
    No boolean caller flag is accepted as evidence.
    """
    label = 'rootless-' + domain
    plans = [item for item in journal.selected_quarantine_plans(release) if item[0] == label]
    require(len(plans) == 1, 'canonical selected actor gate unavailable')
    row = journal.offline_actor(release, label)
    require(row is not None, 'selected actor manager is not already stopped')
    journal.verify_offline_actor(row, plans[0][1])


_retired_source_verifier = None


def retired_current_source(root, release, intent, source_bundle=None):
    """Source-only terminal-current custody; never runtime/inactive admission.

    Lazy import avoids the verifier's read-only owner dependency forming an
    import cycle. Its API verifies exact FD9/records/source/marker every call.
    """
    global _retired_source_verifier
    if _retired_source_verifier is None:
        _retired_source_verifier = load('_projection_retired_source', 'verify-native-runtime-projections.py')
    if source_bundle is None:
        return _retired_source_verifier.bind_retired_current(root, release, intent)
    return _retired_source_verifier.bind_retired_current(root, release, intent, source_bundle=source_bundle)


class Session:
    def __init__(self, root, release, prior, domain):
        self.root, self.release = p.canonical(str(root)), p.canonical(str(release))
        self.prior = p.strict(p.encoded(prior))
        self.domain, self.fds, self.records = domain, {}, {}
        self.deadline = time.monotonic() + 120
        self.expected = self.prior
        self.source_pin = None
        self.retired_current = None
        self.input_pins = None
        self.release_pins = None
        self.allowed_changes = {}
        self.project_in_progress = False
        self.stage_fd, self.stage_name, self.stage_record = None, None, None
        self.closed = False
        try:
            require(os.geteuid() == 0 and self.release.parent == self.root / 'releases',
                    'root and exact installer release required')
            require(type(prior.get('schemaVersion')) is int and prior['schemaVersion'] == 1
                    and prior.get('phase') == 'preparing' and prior.get('release') == str(self.release),
                    'exact preparing intent required')
            root_chain(self.release)
            root_directory(self.release.lstat(), private=True)
            self.check_records()
            self.metadata = self.json_source('podman-domains.json')
            self.ir = self.json_source('stack.ir.json')
            self.manifest = self.json_source('site/manifest.json')
            require(self.metadata.get('deploymentMode') == self.manifest.get('deploymentMode') == 'standalone'
                    and type(self.metadata.get('schemaVersion')) is int
                    and self.metadata['schemaVersion'] == 1 and 'venue' not in self.metadata
                    and self.metadata.get('installerStateRoot') == str(self.root), 'standalone root binding differs')
            # Canonical authority validates full bundle provenance and scope;
            # it performs no grant/prepare operation in this adapter.
            self.scope, self.operator, self.marker = storage.authority(self.release)
            require(self.operator.pw_uid == self.operator.pw_gid == 1000
                    and self.manifest.get('storageScope') == self.metadata.get('storageScope')
                    == self.marker['scope'] and self.scope == p.canonical(self.marker['scope']['root'])
                    and not self.root.is_relative_to(self.scope) and not self.scope.is_relative_to(self.root),
                    'operator or installer/storage separation differs')
            rows = self.metadata['domains']
            require(len(rows) == len(native.IDENTITIES) and {row['name'] for row in rows} == set(native.IDENTITIES),
                    'only the seven canonical new actors are supported')
            self.accounts, self.execute_ids = {}, set()
            for row in rows:
                uid, user = native.IDENTITIES[row['name']]
                account, group = pwd.getpwnam(user), grp.getgrnam(user)
                require((row['uid'], row['user']) == (uid, user)
                        and account.pw_uid == uid and account.pw_name == pwd.getpwuid(uid).pw_name == user
                        and account.pw_dir == '/home/' + user and account.pw_gid == group.gr_gid > 0
                        and grp.getgrgid(group.gr_gid).gr_name == user,
                        'canonical actor account/group tables differ')
                self.accounts[row['name']] = account
                self.execute_ids.update((uid, storage.namespace_root_id(user)))
            selected = [row for row in rows if row['name'] == domain]
            require(len(selected) == 1, 'unselected actor')
            self.row = selected[0]; self.actor = self.accounts[domain]
            self.state = p.canonical(self.row['stateRoot'])
            self.slot = self.state / 'releases' / self.release.name
            self.destination = self.slot / 'runtime'
            self.services = {key: value for key, value in self.ir['services'].items()
                             if value.get('placement') == 'rootless' and value.get('rootlessDomain') == domain}
            require(sorted(self.services) == sorted(self.row['services']), 'selected service ownership differs')
            self.pin_graph()
            storage.marker(self.scope, self.marker)
            with self.open_scope() as fd:
                body, self.marker_identity = p.read_at(fd, storage.MARKER, private=True)
            require(p.strict(body) == self.marker, 'canonical marker differs')
            self.marker_sha = p.sha(body)
            self.root_fd, self.root_pins = open_absolute(self.root)
            self.fds[self.root] = self.root_fd
            self.root_current = p.current_record(self.root_fd)
            self.actor_current = p.current_record(self.fds[self.state])
            self.check_current(self.root_current, self.root, self.release, (0,))
            self.check_current(self.actor_current, self.state, self.slot, (0, self.row['uid']))
            self.public_pin = self.public_payload()
            self.custody = dict(schemaVersion=1,
                selection=dict(release=str(self.release), destination=str(self.destination), domain=domain,
                               user=self.row['user'], uid=self.row['uid'], scopeMarkerSha256=self.marker_sha),
                operatorUid=self.operator.pw_uid, operatorGid=self.operator.pw_gid,
                actorGid=self.actor.pw_gid,
                directories={str(path): record for path, record in self.records.items()},
                current=self.actor_current)
            self.verify()
        except BaseException:
            self.close()
            raise

    def close(self):
        if not self.closed:
            for fd in self.fds.values():
                os.close(fd)
            if self.stage_fd is not None:
                os.close(self.stage_fd)
            self.closed = True

    def time_left(self):
        require(not self.closed and time.monotonic() < self.deadline, 'projection custody deadline expired')

    def json_source(self, name):
        with p.directory(self.release) as fd:
            return p.strict(p.read_at(fd, name)[0])

    def check_accounts(self):
        require(pwd.getpwuid(1000).pw_name == self.operator.pw_name
                and set(grp.getgrgid(1000).gr_mem) <= {self.operator.pw_name}
                and all(account.pw_name == self.operator.pw_name for account in pwd.getpwall()
                        if account.pw_gid == 1000), 'operator group has a foreign writer')
        execute_ids = set()
        for name, saved in self.accounts.items():
            uid, user = native.IDENTITIES[name]
            account, group = pwd.getpwnam(user), grp.getgrnam(user)
            require((account.pw_uid, account.pw_gid, account.pw_dir, account.pw_name)
                    == (uid, saved.pw_gid, '/home/' + user, user)
                    and pwd.getpwuid(uid).pw_name == user and group.gr_gid == saved.pw_gid
                    and grp.getgrgid(group.gr_gid).gr_name == user, 'actor account/group authority changed')
            execute_ids.update((uid, storage.namespace_root_id(user)))
        require(execute_ids == self.execute_ids, 'mapped namespace-root authority changed')

    def check_records(self):
        self.time_left(); lock_held(self.root)
        root_chain(self.release)
        root_directory(self.release.lstat(), private=True)
        with p.directory(self.root) as fd:
            body, _ = p.read_at(fd, '.install-intent.json', private=True)
        release_fd, release_pins = open_absolute(self.release)
        os.close(release_fd)
        if self.release_pins is None:
            self.release_pins = release_pins
        require(release_pins == self.release_pins, 'root source release inode/mount changed')
        with p.directory(self.release) as fd:
            receipt, _ = p.read_at(fd, 'installation-receipt.json', private=True)
            require(body == receipt and p.strict(body) == self.expected, 'preparing receipt/intent CAS differs')
            inputs = self.expected.get('inputs')
            require(isinstance(inputs, dict) and set(inputs) == p.INPUTS, 'full installation input pins required')
            require(all(inputs[name] is not None for name in p.REQUIRED), 'required input pinned absent')
            observed = {}
            for name, digest in inputs.items():
                if digest is None:
                    try:
                        p.read_at(fd, name)
                    except FileNotFoundError:
                        continue
                    raise Refused('pinned absent input appeared')
                content, seen = p.read_at(fd, name)
                require(isinstance(digest, str) and p.re.fullmatch('[a-f0-9]{64}', digest)
                        and p.sha(content) == digest, 'full source input hash differs')
                observed[name] = seen
            if self.input_pins is None:
                self.input_pins = observed
            require(observed == self.input_pins, 'source input inode changed')
        self.cas = p.sha(body)

    def pin_graph(self):
        parent, self.external_pins = open_absolute(self.scope.parent, self.operator)
        try:
            self.fds[self.scope] = p.child_open(parent, self.scope.name,
                                                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        finally:
            os.close(parent)
        actor_roots = {p.canonical(self.row[key]) for key in ('stateRoot', 'graphRoot', 'volumeRoot')}
        paths = {self.scope, self.state / 'releases', self.slot}
        for node in (*actor_roots, self.slot):
            require(node != self.scope and node.is_relative_to(self.scope), 'selected root escapes scope')
            while node != self.scope:
                paths.add(node); node = node.parent
        for node in sorted(paths, key=lambda path: len(path.parts)):
            if node != self.scope:
                self.fds[node] = p.child_open(self.fds[node.parent], node.name,
                                              os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            fd = self.fds[node]; record = p.custody_record(fd)
            require(stat.S_ISDIR(os.fstat(fd).st_mode), 'selected graph inode class differs')
            if node == self.slot:
                root_directory(os.fstat(fd), private=True)
                require(not record['acl'] and not record['defaultAcl'], 'fresh release has inherited ACL')
                try:
                    os.stat('runtime', dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise Refused('fresh selected runtime must be absent')
            elif node in actor_roots or node == self.state / 'releases':
                p.custody_permissions(record, self.row['uid'], self.actor.pw_gid, set())
            elif (node == self.scope / 'volumes' and node == p.canonical(self.row['volumeRoot']).parent
                  and (record['uid'], record['gid'], record['mode']) == (0, self.operator.pw_gid, 0o755)):
                # Sole selected shared public-traversal parent. Preserve its
                # effective nonwriting mask and exact operator-only defaults;
                # private actor roots/new leaves above remain strict no-ACL.
                p.custody_permissions(record, 0, self.operator.pw_gid, self.execute_ids,
                                      root_ancestor=True, operator_uid=self.operator.pw_uid)
            else:
                storage.safe_parent(node, self.operator)
                require((record['uid'], record['gid'], record['mode']) == (1000, 1000, 0o2770),
                        'exact scoped operator custody differs')
                p.custody_permissions(record, 1000, 1000, self.execute_ids, operator=True)
            self.records[node] = record

    @contextlib.contextmanager
    def open_scope(self):
        yield self.fds[self.scope]

    @contextlib.contextmanager
    def open_scope_parent(self, scope):
        """Narrow helper compatibility hook; never a free ancestor allowlist.

        Main must route BOTH Custody.bind and Custody.verify scope-parent opens
        through this hook. Existing strict CLI behavior must remain unchanged.
        """
        require(p.canonical(str(scope)) == self.scope, 'foreign scope parent request')
        self.verify()
        fd, pins = open_absolute(self.scope.parent, self.operator)
        try:
            require(pins == self.external_pins, 'external ancestry inode/mount/ACL changed')
            yield fd
        finally:
            os.close(fd)
        self.verify()

    def projection_execute_ids(self, marker):
        """Canonical actor + keep-id namespace-root execute-only ACL IDs."""
        require(marker == self.marker, 'foreign actor ACL authority request')
        self.verify()
        return frozenset(self.execute_ids)

    def check_current(self, record, root, new, owners):
        if record is None:
            require(root != self.root or self.expected.get('previousRelease') is None,
                    'prior root release pointer absent')
            return
        require(set(record) == {'identity', 'target'} and record['identity'][2] in owners,
                'current pointer ownership differs')
        target = record['target']
        path = p.canonical(target) if target.startswith('/') else root / p.relative(target)
        require(path.parent == root / 'releases' and path != new, 'current must name only an old release')
        if root == self.root:
            if self.expected.get('previousRelease') is None:
                # A terminal synthetic release can remain current after clean
                # reset. Preserve previousRelease=None (NO rollback grant).
                # Full protected source custody, not the phase label alone,
                # is independently derived and rechecked throughout this FD
                # transaction; all existing inactive/actor gates still apply.
                self.retired_current = p.strict(p.encoded(
                    retired_current_source(self.root, self.release, self.expected,
                                           source_bundle=getattr(self, 'bundle', None))))
                require(self.retired_current.get('release') == str(path), 'retired current source differs')
            else:
                require(str(path) == self.expected.get('previousRelease'), 'prior/new root current binding differs')

    def public_payload(self):
        """Validate, never chown/copy, the pre-provisioned public-only skeleton."""
        result, total = {}, 0
        def visit(fd, prefix=''):
            nonlocal total
            for name in sorted(os.listdir(fd)):
                p.relative(name)
                rel = prefix + name
                if not prefix and name == 'runtime':
                    continue
                if (not prefix and self.project_in_progress
                        and p.re.fullmatch(r'\.domain-projection-[a-f0-9]{32}', name)):
                    # The trusted projector creates one private inert stage.
                    # It is never public payload, adopted, handed off or swept.
                    # Initial preparation rejects ALL pre-existing such names.
                    require(self.stage_name in (None, name), 'more than one fresh projector stage')
                    child = p.child_open(fd, name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    try:
                        root_directory(os.fstat(child), private=True)
                        record = p.custody_record(child)
                        require(not record['acl'] and not record['defaultAcl'], 'private projector stage ACL differs')
                        if self.stage_fd is None:
                            self.stage_fd, self.stage_name, self.stage_record = os.dup(child), name, record
                        require(record == self.stage_record == p.custody_record(self.stage_fd),
                                'private projector stage inode changed')
                    finally:
                        os.close(child)
                    continue
                require(rel == 'build' or rel.startswith('build/') or rel == 'site'
                        or rel == 'site/components.lock.json' or rel == 'quadlet'
                        or rel == 'quadlet/rootless-' + self.domain
                        or rel.startswith('quadlet/rootless-' + self.domain + '/'),
                        'fresh actor release contains non-public payload path')
                require(not (name == '.env' or name.endswith(('.env', '.env.template'))
                             or 'sops' in name.lower() or name == 'stack.env'),
                        'aggregate/secret input in actor public payload')
                child = p.child_open(fd, name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                try:
                    info = os.fstat(child)
                    p.controlled(info, directory=stat.S_ISDIR(info.st_mode))
                    require(info.st_gid == 0 and not p.acl_bytes(child, 'system.posix_acl_access')
                            and not p.acl_bytes(child, 'system.posix_acl_default'), 'public payload custody differs')
                    require(len(result) < MAX_NODES, 'public payload exceeds file bound')
                    result[rel] = (p.identity(info), None)
                    if stat.S_ISDIR(info.st_mode):
                        visit(child, rel + '/')
                    else:
                        body, seen = p.read_at(fd, name)
                        total += len(body)
                        require(total <= MAX_TOTAL, 'public payload exceeds byte bound')
                        with p.directory(self.release) as source:
                            source_body, _ = p.read_at(source, rel)
                        require(body == source_body, 'actor public payload differs from exact source')
                        result[rel] = (seen, p.sha(body))
                finally:
                    os.close(child)
        visit(self.fds[self.slot])
        return result

    def source_snapshot(self):
        if not self.services:
            return None
        with p.subtree(self.release, 'runtime') as fd:
            aggregate = p.read_at(fd, 'stack.env', private=True)
        mounts = p.config_mounts(self.services)
        selected = ({}, set(), {})
        if mounts:
            with p.subtree(self.release, 'runtime/configs') as fd:
                selected = p.read_tree(fd, mounts)
        owner_material = p.owner_import_material(self.release)
        # The public skeleton is not an alternative route for master/owner bytes.
        denied = [form for key, value in p.env_values(aggregate[0]).items() if p.root_only(key, ()) and value
                  for form in p.secret_forms(value)] + list(owner_material[1])
        with p.directory(self.release) as fd:
            for name, (_, digest) in self.public_pin.items():
                if digest is not None:
                    body, _ = p.read_at(fd, name)
                    require(not any(secret in body for secret in denied), 'root-only material in public actor payload')
        return aggregate, selected, owner_material

    def verify(self):
        self.check_records()
        self.check_accounts()
        if self.retired_current is not None:
            require(retired_current_source(self.root, self.release, self.expected,
                                           source_bundle=getattr(self, 'bundle', None)) == self.retired_current,
                    'retired stop-only source/current custody changed')
        fd, pins = open_absolute(self.scope.parent, self.operator)
        try:
            require(pins == self.external_pins, 'external ancestor identity/ACL/mount differs')
            child = p.child_open(fd, self.scope.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                require(p.custody_record(child) == self.records[self.scope], 'scope path moved')
            finally:
                os.close(child)
        finally:
            os.close(fd)
        for node, original in self.records.items():
            expected = self.allowed_changes.get(node, original)
            require(p.custody_record(self.fds[node]) == expected, 'held selected directory changed')
            if node != self.scope:
                child = p.child_open(self.fds[node.parent], node.name,
                                     os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    require(p.custody_record(child) == expected, 'selected directory path moved')
                finally:
                    os.close(child)
        fd, pins = open_absolute(self.root)
        try:
            require(pins == self.root_pins and p.current_record(fd) == self.root_current,
                    'root metadata ancestry/current changed')
        finally:
            os.close(fd)
        require(p.current_record(self.fds[self.state]) == self.actor_current, 'actor old/current pointer changed')
        body, seen = p.read_at(self.fds[self.scope], storage.MARKER, private=True)
        require(seen == self.marker_identity and p.sha(body) == self.marker_sha, 'scope marker changed')
        require(self.public_payload() == self.public_pin, 'public skeleton changed')
        if self.source_pin is not None:
            require(self.source_snapshot() == self.source_pin, 'selected source runtime changed')
        inactive(self.release, self.domain)
        self.time_left()

    def verify_projection(self, selection):
        expected = dict(self.custody['selection'], receiptSha256=self.cas, intentSha256=self.cas,
                        custodySha256=p.sha(p.encoded(self.custody)))
        require(selection == expected, 'projection callback selection/CAS differs')
        self.verify()
        # Explicitly return None: never a boolean admission result.

    def project(self, new_intent):
        new = p.strict(p.encoded(new_intent))
        require(new == dict(self.prior, projectionCustody=self.custody),
                'new preparing intent changed beyond same-transaction custody')
        self.expected = new
        self.verify()
        self.source_pin = self.source_snapshot()
        self.verify()
        self.project_in_progress = True
        proof = p.project(self.release, self.destination, self.domain, self.row['user'], self.row['uid'],
                          self.state, self.cas, self.marker_sha, custody_lease=self)
        self.project_in_progress = False
        self.verify()
        return self.handoff(proof)

    def handoff(self, proof):
        """Seal exact emitted tree, retain all FDs, transfer selected inodes only."""
        expected_pins = dict(intentSha256=self.cas, receiptSha256=self.cas,
                             scopeMarkerSha256=self.marker_sha, inputs=self.expected['inputs'],
                             release=str(self.release), domain=self.domain, user=self.row['user'],
                             uid=self.row['uid'], stateRoot=str(self.state))
        require(all(proof.get(key) == value for key, value in expected_pins.items())
                and proof.get('schemaVersion') == 1 and proof.get('kind') == 'domain-runtime-projection'
                and proof.get('destination') == str(self.destination) and proof.get('activationAuthorized') is False
                and proof.get('configMounts') == p.config_mounts(self.services)
                and proof.get('services') == sorted(self.services), 'projector proof binding differs')
        files = dict(proof['files']); files['projection.json'] = proof['projectionSha256']
        directories = set(proof['directories']) | {''}
        require(directories == {'', 'configs', 'service-env'} | {str(Path(name).parent) for name in files
                    if '/' in name} | {d for d in directories if d.startswith('configs/')},
                'unexpected projected directory namespace')
        handles, pins, parents = {}, {}, {}
        total = 0
        try:
            handles[''] = p.child_open(self.fds[self.slot], 'runtime', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            def visit(fd, prefix=''):
                nonlocal total
                for name in sorted(os.listdir(fd)):
                    p.relative(name); rel = prefix + name
                    child = p.child_open(fd, name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    handles[rel] = child; parents[rel] = (prefix.rstrip('/'), name)
                    info = os.fstat(child)
                    require(len(handles) <= MAX_NODES, 'projection exceeds node bound')
                    if stat.S_ISDIR(info.st_mode):
                        require(rel in directories, 'unsealed projected directory')
                        visit(child, rel + '/')
                    else:
                        require(rel in files, 'unsealed projected file')
                        body, seen = p.read_at(fd, name)
                        total += len(body)
                        require(total <= MAX_TOTAL and p.sha(body) == files[rel]
                                and seen == p.identity(info), 'projected file hash differs')
            visit(handles[''])
            require(set(handles) == set(files) | directories, 'projection tree differs from exact seal')
            for rel, fd in handles.items():
                info = os.fstat(fd)
                p.controlled(info, directory=rel in directories, private=rel in directories)
                if rel not in directories:
                    require(stat.S_IMODE(info.st_mode) == (0o700 if rel.startswith('configs/')
                            and os.pread(fd, 2, 0) == b'#!' else 0o600), 'unsealed initial projected mode')
                require(info.st_gid == 0 and not p.acl_bytes(fd, 'system.posix_acl_access')
                        and not p.acl_bytes(fd, 'system.posix_acl_default'), 'projected ACL/group differs')
                pins[rel] = p.identity(info)
            metadata = os.pread(handles['projection.json'], p.MAX_FILE + 1, 0)
            expected_metadata = {key: value for key, value in proof.items()
                                 if key not in ('aggregateSha256', 'destination', 'projectionSha256')}
            require(p.strict(metadata) == expected_metadata, 'actor projection metadata differs')
            def recheck():
                self.verify()
                for rel, fd in handles.items():
                    require(p.identity(os.fstat(fd)) == pins[rel]
                            and not p.acl_bytes(fd, 'system.posix_acl_access')
                            and not p.acl_bytes(fd, 'system.posix_acl_default'), 'held projected inode/ACL changed')
                    if rel:
                        parent, name = parents[rel]
                        child = p.child_open(handles[parent], name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    else:
                        child = p.child_open(self.fds[self.slot], 'runtime', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    try:
                        require(p.identity(os.fstat(child)) == pins[rel], 'projected mounted path changed')
                    finally:
                        os.close(child)
                    if rel in directories:
                        expected_names = {Path(item).name for item in handles if item and parents[item][0] == rel}
                        require(set(os.listdir(fd)) == expected_names, 'unsealed child appeared')
                    else:
                        require(p.sha(os.pread(fd, p.MAX_FILE + 1, 0)) == files[rel], 'projected bytes changed')
            # Config bind roots must be readable by declared nonroot payload UIDs.
            # Their outer actor release stays 0700; env metadata stays private.
            for rel in sorted(handles, key=lambda name: (-name.count('/'), name)):
                recheck()
                fd = handles[rel]
                mode = (0o755 if rel == 'configs' or rel.startswith('configs/') and rel in directories else
                        0o755 if rel.startswith('configs/') and os.pread(fd, 2, 0) == b'#!' else
                        0o644 if rel.startswith('configs/') else 0o700 if rel in directories else 0o600)
                os.fchown(fd, self.row['uid'], self.actor.pw_gid)
                os.fchmod(fd, mode); os.fsync(fd)
                actual = os.fstat(fd)
                require((actual.st_uid, actual.st_gid, stat.S_IMODE(actual.st_mode))
                        == (self.row['uid'], self.actor.pw_gid, mode)
                        and (actual.st_dev, actual.st_ino) == pins[rel][:2], 'exact actor inode handoff failed')
                pins[rel] = p.identity(actual)
                recheck()
            # Last and only ownership operation outside the sealed runtime tree.
            recheck()
            os.fchown(self.fds[self.slot], self.row['uid'], self.actor.pw_gid)
            os.fchmod(self.fds[self.slot], 0o700); os.fsync(self.fds[self.slot])
            expected_slot = dict(self.records[self.slot], uid=self.row['uid'], gid=self.actor.pw_gid, mode=0o700)
            require(p.custody_record(self.fds[self.slot]) == expected_slot, 'exact private actor release handoff failed')
            self.allowed_changes[self.slot] = expected_slot
            recheck()
            env_files = {Path(name).name: {'sha256': digest, 'mode': 0o600}
                         for name, digest in files.items() if name.startswith('service-env/')}
            # Main may copy ONLY these exact files using its existing env-store
            # owner. We deliberately do not replace/adopt an actor-writable store.
            return dict(proof, custodySha256=p.sha(p.encoded(self.custody)),
                        projectionCustody=p.strict(p.encoded(self.custody)),
                        runtimeCustody={name: dict(p.custody_record(fd),
                            identity=list(p.identity(os.fstat(fd))))
                            for name, fd in handles.items()},
                        ownershipHandoff={'uid': self.row['uid'], 'gid': self.actor.pw_gid,
                        'releaseMode': 0o700, 'runtimeMode': 0o700, 'activationAuthorized': False},
                        environmentHandoff={'status': 'canonical-owner-copy-required',
                        'sourceDirectory': str(self.destination / 'service-env'),
                        'stateStore': str(self.state / 'runtime-env'),
                        'runtimeStore': '/run/user/' + str(self.row['uid']) + '/webservices',
                        'files': env_files, 'uid': self.row['uid'], 'gid': self.actor.pw_gid,
                        'directoryMode': 0o700, 'ensurePrivateStores': True,
                        'aggregateAllowed': False, 'removeUnselected': False})
        finally:
            for fd in handles.values():
                os.close(fd)


def prepare_custody(root, release, prior_intent, domain):
    key = (str(root), str(release), domain)
    require(key not in _sessions, 'unconsumed projection custody already exists')
    session = Session(root, release, prior_intent, domain)
    _sessions[key] = session
    return p.strict(p.encoded(session.custody))


def project_and_handoff(root, release, new_intent, domain):
    key = (str(root), str(release), domain)
    session = _sessions.pop(key, None)
    require(session is not None, 'same-process preparing custody FDs required')
    try:
        return session.project(new_intent)
    finally:
        session.close()
