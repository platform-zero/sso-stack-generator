#!/usr/bin/env python3
"""Canonical, in-process persistent service-env copy; no CLI or activation.

copy_environment(root, release, intent, domain) is called by install-journal.py
AFTER project_and_handoff and AFTER identical preparing receipt/intent records
contain domainRuntimeProjections[domain]. FD9 remains the canonical installer
flock. The journal, not this module, records the result in
 domainRuntimeProjections[domain].environmentStoreHandoff. No callbacks, flags, journal writes,
manager starts, runtime directory creation, secret derivation or aggregate reads.

Fresh actor-owned 0700 runtime-env stores work directly. Existing selected files
require an exact completed copy proof in the current or previous canonical root
receipt. Legacy files without that authority require complete-clean-reset via
the existing installer; they are never adopted or deleted here. Failed private
stages are retained as inert evidence, never swept or logged with their values.
"""
import ctypes
import os
from pathlib import Path
import secrets
import stat

# Reuse the owning implementation, not a caller-supplied adapter or lease.
import importlib.util
import sys
_source = Path(__file__).with_name('native-runtime-projection-owner.py')
_spec = importlib.util.spec_from_file_location('_canonical_environment_projection_owner', _source)
owner = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = owner
exec(compile(_source.read_bytes(), str(_source), 'exec'), owner.__dict__)
p, Refused, require = owner.p, owner.Refused, owner.require
RESET = 'complete-clean-reset dependency: existing selected environment lacks exact canonical copy authority'
FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK


def file_record(fd, uid, gid, digest=None):
    before = os.fstat(fd)
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) == (uid, gid, 0o600)
            and before.st_size <= p.MAX_FILE, 'environment inode/UID/GID/mode/nlink differs')
    require(not p.acl_bytes(fd, 'system.posix_acl_access')
            and not p.acl_bytes(fd, 'system.posix_acl_default'), 'environment file ACL differs')
    body = os.pread(fd, p.MAX_FILE + 1, 0)
    require(len(body) <= p.MAX_FILE and p.identity(before) == p.identity(os.fstat(fd)),
            'environment inode changed during read')
    actual = p.sha(body)
    require(digest is None or actual == digest, 'environment source SHA differs')
    return body, dict(identity=list(p.identity(before)), mountId=p.mount_id(fd), sha256=actual,
                      mode=0o600, uid=uid, gid=gid, acl='', defaultAcl='')


def rename(parent, source, destination, exchange=False):
    """Kernel no-replace for fresh names; exchange + displaced-inode CAS otherwise."""
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.renameat2(parent, os.fsencode(source), parent, os.fsencode(destination),
                            2 if exchange else 1)
    if result:
        raise OSError(ctypes.get_errno(), 'environment atomic publication refused')


class Copy(owner.Session):
    def check_records(self):
        super().check_records()
        observed = {}
        for parent, name in ((self.root, '.install-intent.json'),
                             (self.release, 'installation-receipt.json')):
            with p.directory(parent) as fd:
                child = p.child_open(fd, name, FLAGS)
                try:
                    p.controlled(os.fstat(child), private=True)
                    require(not p.acl_bytes(child, 'system.posix_acl_access')
                            and not p.acl_bytes(child, 'system.posix_acl_default'),
                            'root preparing record ACL differs')
                    observed[name] = p.identity(os.fstat(child))
                finally:
                    os.close(child)
        if self.record_pins is None:
            self.record_pins = observed
        require(observed == self.record_pins, 'root receipt/intent inode ABA changed')

    def pin_graph(self):
        # Exactly the root-sealed pre-handoff graph, with ONLY the proven slot
        # ownership change. The general projector's fresh-root0700 rule remains
        # unchanged; this narrow consumer does not weaken it.
        custody = self.expected.get('projectionCustody', {})
        require(isinstance(custody, dict) and custody.get('schemaVersion') == 1,
                'root-sealed projection custody required')
        parent, self.external_pins = owner.open_absolute(self.scope.parent, self.operator)
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
        require(set(custody.get('directories', {})) == {str(path) for path in paths},
                'root-sealed selected graph differs')
        for node in sorted(paths, key=lambda path: len(path.parts)):
            if node != self.scope:
                self.fds[node] = p.child_open(self.fds[node.parent], node.name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            fd = self.fds[node]; record = p.custody_record(fd)
            require(stat.S_ISDIR(os.fstat(fd).st_mode), 'selected graph inode class differs')
            expected = custody['directories'][str(node)]
            if node == self.slot:
                require((expected['uid'], expected['gid'], expected['mode']) == (0, 0, 0o700),
                        'pre-handoff slot authority differs')
                expected = dict(expected, uid=self.row['uid'], gid=self.actor.pw_gid, mode=0o700)
            if node in actor_roots or node in (self.slot, self.state / 'releases'):
                p.custody_permissions(record, self.row['uid'], self.actor.pw_gid, set())
            elif (node == self.scope / 'volumes' and node == p.canonical(self.row['volumeRoot']).parent
                  and (record['uid'], record['gid'], record['mode']) == (0, self.operator.pw_gid, 0o755)):
                # Same sole public-traversal exception as the owning projector.
                # Pin exact mask/defaults; never unmask, clear or change them.
                p.custody_permissions(record, 0, self.operator.pw_gid, self.execute_ids,
                                      root_ancestor=True, operator_uid=self.operator.pw_uid)
            else:
                owner.storage.safe_parent(node, self.operator)
                require((record['uid'], record['gid'], record['mode']) == (1000, 1000, 0o2770),
                        'exact scoped operator custody differs')
                p.custody_permissions(record, 1000, 1000, self.execute_ids, operator=True)
            require(record == expected, 'root-sealed graph inode/mount/ACL changed')
            self.records[node] = record

    def __init__(self, root, release, intent, domain):
        self.extra_fds = []
        self.record_pins = None
        try:
            super().__init__(root, release, intent, domain)
            sealed = self.expected.get('domainRuntimeProjections', {}).get(domain)
            require(isinstance(sealed, dict), 'journalled domain projection required before environment copy')
            self.proof = {key: value for key, value in sealed.items() if key != 'environmentStoreHandoff'}
            proof, custody = self.proof, self.expected['projectionCustody']
            require(custody['selection'] == dict(release=str(self.release), destination=str(self.destination),
                    domain=domain, user=self.row['user'], uid=self.row['uid'], scopeMarkerSha256=self.marker_sha)
                    and custody['current'] == self.actor_current
                    and (custody['operatorUid'], custody['operatorGid'], custody['actorGid'])
                    == (1000, 1000, self.actor.pw_gid), 'root-sealed selection differs')
            expected = dict(schemaVersion=1, kind='domain-runtime-projection', release=str(self.release),
                domain=domain, user=self.row['user'], uid=self.row['uid'], stateRoot=str(self.state),
                destination=str(self.destination), scopeMarkerSha256=self.marker_sha,
                inputs=self.expected['inputs'], services=sorted(self.services),
                configMounts=p.config_mounts(self.services), custodySha256=p.sha(p.encoded(custody)),
                activationAuthorized=False)
            require(all(proof.get(k) == v for k, v in expected.items())
                    and type(proof.get('schemaVersion')) is int
                    and proof.get('activationAuthorized') is False
                    and isinstance(proof.get('projectionSha256'), str)
                    and p.re.fullmatch('[a-f0-9]{64}', proof['projectionSha256'])
                    and proof.get('intentSha256') == proof.get('receiptSha256')
                    and isinstance(proof.get('receiptSha256'), str)
                    and p.re.fullmatch('[a-f0-9]{64}', proof['receiptSha256']),
                    'root domain projection binding differs')
            require(proof.get('ownershipHandoff') == dict(uid=self.row['uid'], gid=self.actor.pw_gid,
                    releaseMode=0o700, runtimeMode=0o700, activationAuthorized=False)
                    and proof['ownershipHandoff']['activationAuthorized'] is False,
                    'canonical ownership handoff required')
            files = proof.get('files')
            require(isinstance(files, dict), 'root projection file seal absent')
            env = {}
            for rel, digest in files.items():
                p.relative(rel)
                require(isinstance(digest, str) and p.re.fullmatch('[a-f0-9]{64}', digest),
                        'root projection SHA differs')
                if rel.startswith('service-env/'):
                    name = rel[len('service-env/'):]
                    require(name.endswith('.env') and p.IDENT.fullmatch(name[:-4])
                            and name[:-4] in self.services, 'unselected service environment name')
                    env[name] = dict(sha256=digest, mode=0o600)
            require(set(env) == {name + '.env' for name, service in self.services.items()
                                if p.declarations(service)}, 'selected environment declaration set differs')
            require(len(env) <= owner.MAX_NODES, 'environment file count exceeds bound')
            self.names = env
            handoff = dict(status='canonical-owner-copy-required',
                sourceDirectory=str(self.destination / 'service-env'), stateStore=str(self.state / 'runtime-env'),
                runtimeStore='/run/user/' + str(self.row['uid']) + '/webservices', files=env,
                uid=self.row['uid'], gid=self.actor.pw_gid, directoryMode=0o700,
                ensurePrivateStores=True, aggregateAllowed=False, removeUnselected=False)
            require(proof.get('environmentHandoff') == handoff, 'root environment handoff differs')
            self.runtime_fd = self.open_private(self.fds[self.slot], 'runtime')
            metadata_fd = p.child_open(self.runtime_fd, 'projection.json', FLAGS)
            self.extra_fds.append(metadata_fd)
            body, self.metadata_pin = file_record(metadata_fd, self.row['uid'], self.actor.pw_gid,
                                                  proof.get('projectionSha256'))
            metadata = {key: value for key, value in proof.items() if key not in
                ('aggregateSha256', 'destination', 'projectionSha256', 'custodySha256',
                 'ownershipHandoff', 'environmentHandoff', 'projectionCustody', 'runtimeCustody')}
            require(p.strict(body) == metadata, 'sourceProjection metadata differs from root seal')
            self.metadata_fd = metadata_fd
            self.source_fd = self.open_private(self.runtime_fd, 'service-env')
            self.source_pins = {}; self.source_handles = {}
            require(set(os.listdir(self.source_fd)) == set(self.names), 'source environment namespace differs')
            total = 0
            for name, seal in sorted(self.names.items()):
                fd = p.child_open(self.source_fd, name, FLAGS); self.extra_fds.append(fd)
                body, record = file_record(fd, self.row['uid'], self.actor.pw_gid, seal['sha256'])
                total += len(body)
                require(total <= owner.MAX_TOTAL, 'environment copy exceeds byte bound')
                self.source_handles[name] = fd; self.source_pins[name] = record
            self.directory_pins = {self.runtime_fd: p.custody_record(self.runtime_fd),
                                   self.source_fd: p.custody_record(self.source_fd)}
            self.store_fd = None; self.store_pin = None
            self.published = {}; self.stages = {}; self.original = {}
            self.previous_sources = {}; self.previous_release = None; self.previous_release_pins = None
            self.verify_copy()
        except BaseException:
            self.close()
            raise

    def close(self):
        for fd in self.extra_fds:
            os.close(fd)
        self.extra_fds = []
        super().close()

    def open_private(self, parent, name):
        fd = p.child_open(parent, name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.extra_fds.append(fd)
        record = p.custody_record(fd)
        require(not record['defaultAcl'], 'unsafeInheritedDefaultACL')
        p.custody_permissions(record, self.row['uid'], self.actor.pw_gid, set())
        require(not record['acl'], 'private environment directory ACL differs')
        return fd

    def path_pin(self, parent, name, expected, directory=False):
        fd = p.child_open(parent, name, FLAGS | (os.O_DIRECTORY if directory else 0))
        try:
            if directory:
                actual = p.custody_record(fd)
            else:
                # Check authority BEFORE reading bytes. A foreign replacement
                # is not permission to inspect/adopt its environment contents.
                require(list(p.identity(os.fstat(fd))) == expected['identity']
                        and p.mount_id(fd) == expected['mountId'],
                        'environment path inode/mount/bytes CAS changed')
                actual = file_record(fd, self.row['uid'], self.actor.pw_gid, expected['sha256'])[1]
            require(actual == expected, 'environment path inode/mount/bytes CAS changed')
        finally:
            os.close(fd)

    def verify_copy(self):
        self.verify()  # FD9, identical root records, full input pins, accounts,
        # ranges, marker, ancestry, stopped actor/manager and both current CAS.
        for fd, pin in self.directory_pins.items():
            require(p.custody_record(fd) == pin, 'held environment directory changed')
        self.path_pin(self.fds[self.slot], 'runtime', self.directory_pins[self.runtime_fd], True)
        self.path_pin(self.runtime_fd, 'service-env', self.directory_pins[self.source_fd], True)
        require(set(os.listdir(self.source_fd)) == set(self.names), 'source environment namespace changed')
        self.path_pin(self.runtime_fd, 'projection.json', self.metadata_pin)
        for name, pin in self.source_pins.items():
            require(file_record(self.source_handles[name], self.row['uid'], self.actor.pw_gid,
                    pin['sha256'])[1] == pin, 'held source environment changed')
            self.path_pin(self.source_fd, name, pin)
        if self.store_fd is not None:
            require(p.custody_record(self.store_fd) == self.store_pin, 'held persistent store changed')
            self.path_pin(self.fds[self.state], 'runtime-env', self.store_pin, True)
            require(set(os.listdir(self.store_fd)) == self.store_names | set(self.stages),
                    'persistent store namespace changed')
            for name, pin in {**self.original, **self.published, **self.stages}.items():
                self.path_pin(self.store_fd, name, pin)
        if self.previous_release is not None:
            fd, pins = owner.open_absolute(self.previous_release)
            try:
                require(pins == self.previous_release_pins, 'previous canonical release ancestry changed')
                for name, (digest, identity) in self.previous_sources.items():
                    if digest is None:
                        try:
                            p.read_at(fd, name)
                        except FileNotFoundError:
                            continue
                        raise Refused('previous pinned absent input appeared')
                    body, seen = p.read_at(fd, name, private=name == 'installation-receipt.json')
                    require(seen == identity and p.sha(body) == digest,
                            'previous canonical receipt/input CAS changed')
            finally:
                os.close(fd)

    def previous_authority(self):
        """Root receipts only. No directory scan/adoption or actor metadata trust."""
        candidates = [(self.release, self.expected)]
        previous = self.expected.get('previousRelease')
        if previous is not None:
            path = p.canonical(previous)
            require(path.parent == self.root / 'releases' and path != self.release,
                    'previous environment authority escapes root')
            owner.root_chain(path)
            owner.root_directory(path.lstat(), private=True)
            previous_fd, self.previous_release_pins = owner.open_absolute(path)
            os.close(previous_fd)
            self.previous_release = path
            with p.directory(path) as fd:
                body, identity = p.read_at(fd, 'installation-receipt.json', private=True)
                self.previous_sources['installation-receipt.json'] = (p.sha(body), identity)
                value = p.strict(body)
                require(value.get('release') == str(path) and value.get('phase') == 'active'
                        and value.get('schemaVersion') == 1, 'previous canonical receipt differs')
                inputs = value.get('inputs', {})
                require(set(inputs) == p.INPUTS, RESET)
                for name, digest in inputs.items():
                    if digest is None:
                        try:
                            p.read_at(fd, name)
                        except FileNotFoundError:
                            self.previous_sources[name] = (None, None)
                            continue
                        raise Refused('previous pinned absent input appeared')
                    content, identity = p.read_at(fd, name)
                    require(p.sha(content) == digest, 'previous core/input SHA differs')
                    self.previous_sources[name] = (digest, identity)
            candidates.append((path, value))
        result = {}
        for path, value in candidates:
            sealed = value.get('domainRuntimeProjections', {}).get(self.domain)
            if not isinstance(sealed, dict):
                continue
            proof = sealed.get('environmentStoreHandoff')
            if not isinstance(proof, dict):
                continue
            projection = {key: item for key, item in sealed.items() if key != 'environmentStoreHandoff'}
            require(proof.get('schemaVersion') == 1 and proof.get('status') == 'completed'
                    and proof.get('kind') == 'domain-persistent-environment'
                    and proof.get('release') == str(path) and proof.get('domain') == self.domain
                    and proof.get('stateStore') == str(self.state / 'runtime-env')
                    and proof.get('scopeMarkerSha256') == self.marker_sha
                    and proof.get('uid') == self.row['uid'] and proof.get('gid') == self.actor.pw_gid
                    and proof.get('sourceProjectionSha256') == p.sha(p.encoded(projection))
                    and proof.get('inputs') == value['inputs']
                    and proof.get('activationAuthorized') is False
                    and proof.get('readinessAuthorized') is False and proof.get('runtimeDeferred') is True
                    and proof.get('intentSha256') == proof.get('receiptSha256')
                    and isinstance(proof.get('intentSha256'), str)
                    and p.re.fullmatch('[a-f0-9]{64}', proof['intentSha256'])
                    and proof.get('sourceDirectory') == str(self.state / 'releases' / path.name
                                                            / 'runtime/service-env')
                    and proof.get('store') == self.store_pin
                    and projection.get('release') == str(path) and projection.get('domain') == self.domain
                    and projection.get('uid') == self.row['uid'] and projection.get('user') == self.row['user']
                    and projection.get('stateRoot') == str(self.state)
                    and projection.get('scopeMarkerSha256') == self.marker_sha
                    and projection.get('inputs') == value['inputs']
                    and projection.get('activationAuthorized') is False, RESET)
            for name, record in proof.get('files', {}).items():
                require(isinstance(name, str) and name.endswith('.env')
                        and p.IDENT.fullmatch(name[:-4]) and record.get('sha256')
                        == projection.get('files', {}).get('service-env/' + name), RESET)
                if name in self.names:
                    result.setdefault(name, record)
        return result

    def copy(self):
        self.verify_copy()
        if not self.names:
            return self.result()  # No store creation, aggregate or secret read.
        state_fd = self.fds[self.state]
        require(not p.acl_bytes(state_fd, 'system.posix_acl_default'), 'unsafeInheritedDefaultACL')
        try:
            os.stat('runtime-env', dir_fd=state_fd, follow_symlinks=False)
        except FileNotFoundError:
            self.verify_copy()
            os.mkdir('runtime-env', 0o700, dir_fd=state_fd)
            fd = p.child_open(state_fd, 'runtime-env', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self.extra_fds.append(fd)
            owner.root_directory(os.fstat(fd), private=True)
            require(not p.acl_bytes(fd, 'system.posix_acl_access')
                    and not p.acl_bytes(fd, 'system.posix_acl_default'), 'unsafeInheritedDefaultACL')
            os.fchmod(fd, 0o700); os.fchown(fd, self.row['uid'], self.actor.pw_gid)
            os.fsync(fd); os.fsync(state_fd)
        self.store_fd = self.open_private(state_fd, 'runtime-env')
        self.store_pin = p.custody_record(self.store_fd)
        self.store_names = set(os.listdir(self.store_fd))
        # Preserve every unselected name without opening it. Never enumerate a
        # sibling store, follow its contents, copy it, or blanket-delete it.
        authority = self.previous_authority() if set(self.names) & self.store_names else {}
        for name in sorted(set(self.names) & self.store_names):
            require(name in authority, RESET)
            self.original[name] = authority[name]
            self.path_pin(self.store_fd, name, authority[name])
        self.verify_copy()
        for name, seal in sorted(self.names.items()):
            self.verify_copy()
            stage = '.projected-env-' + secrets.token_hex(16)
            fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=self.store_fd)
            self.extra_fds.append(fd)
            # A new stage is root-private until the exact bytes are durable.
            p.controlled(os.fstat(fd), private=True)
            require(os.fstat(fd).st_gid == 0 and not p.acl_bytes(fd, 'system.posix_acl_access')
                    and not p.acl_bytes(fd, 'system.posix_acl_default'), 'unsafeInheritedDefaultACL')
            body, record = file_record(self.source_handles[name], self.row['uid'], self.actor.pw_gid,
                                       seal['sha256'])
            require(record == self.source_pins[name], 'source changed before write')
            view = memoryview(body)
            while view:
                count = os.write(fd, view)
                require(count > 0, 'environment short write')
                view = view[count:]
            os.fchmod(fd, 0o600); os.fchown(fd, self.row['uid'], self.actor.pw_gid); os.fsync(fd)
            # Reopen read-only with no-follow and NO_XDEV; retain write FD only
            # for inode comparison, never report plaintext or environment keys.
            read_fd = p.child_open(self.store_fd, stage, FLAGS); self.extra_fds.append(read_fd)
            _, staged = file_record(read_fd, self.row['uid'], self.actor.pw_gid, seal['sha256'])
            require(staged['identity'] == list(p.identity(os.fstat(fd))), 'private stage inode changed')
            self.stages[stage] = staged
            self.verify_copy()
            old = self.original.get(name)
            rename(self.store_fd, stage, name, exchange=old is not None)
            # Exchange is a CAS only after the displaced inode is verified.
            # A raced foreign name is restored with an exact two-inode exchange
            # (never unlinked/read/adopted). If either name races again, retain
            # both as evidence and refuse further mutation.
            displaced = None
            if old is not None:
                displaced_identity = list(p.identity(os.stat(stage, dir_fd=self.store_fd,
                                                              follow_symlinks=False)))
                try:
                    require(displaced_identity[:-1] == old['identity'][:-1],
                            'displaced environment CAS differs')
                    displaced_fd = p.child_open(self.store_fd, stage, FLAGS)
                    self.extra_fds.append(displaced_fd)
                    _, displaced = file_record(displaced_fd, self.row['uid'], self.actor.pw_gid, old['sha256'])
                    require(self.same_renamed_inode(displaced, old), 'displaced environment CAS differs')
                except (Refused, OSError):
                    self.restore_exchange(stage, name, staged, displaced_identity)
                    raise Refused('environment exchange CAS refused; original name restored; private stage retained') from None
            published_fd = p.child_open(self.store_fd, name, FLAGS); self.extra_fds.append(published_fd)
            _, published = file_record(published_fd, self.row['uid'], self.actor.pw_gid, seal['sha256'])
            require(self.same_renamed_inode(published, staged), 'published environment inode changed')
            self.stages.pop(stage)
            self.published[name] = published
            self.store_names.add(name)
            self.original.pop(name, None)
            if old is not None:
                # Only the verified displaced selected inode, never unselected
                # siblings, is removed after the stopped-actor/receipt recheck.
                self.stages[stage] = displaced
                self.verify_copy()
                self.path_pin(self.store_fd, stage, displaced)
                os.unlink(stage, dir_fd=self.store_fd)
                self.stages.pop(stage)
            os.fsync(self.store_fd)
            self.verify_copy()
        return self.result()

    def restore_exchange(self, stage, name, staged, displaced_identity):
        current = list(p.identity(os.stat(name, dir_fd=self.store_fd, follow_symlinks=False)))
        displaced = list(p.identity(os.stat(stage, dir_fd=self.store_fd, follow_symlinks=False)))
        require(current[:-1] == staged['identity'][:-1] and displaced == displaced_identity,
                'environment exchange CAS failed again; both inodes retained for canonical disposition')
        rename(self.store_fd, stage, name, exchange=True)
        os.fsync(self.store_fd)
        require(list(p.identity(os.stat(name, dir_fd=self.store_fd, follow_symlinks=False)))[:-1]
                == displaced_identity[:-1], 'environment exchange restoration CAS differs')

    @staticmethod
    def same_renamed_inode(actual, before):
        # rename changes ctime, not dev/inode/uid/gid/mode/nlink/size/mtime,
        # mount ID, ACL or SHA. Both records are independently FD validated.
        adjusted = dict(before, identity=before['identity'][:-1] + [actual['identity'][-1]])
        return actual == adjusted

    def result(self):
        self.verify_copy()
        return dict(schemaVersion=1, kind='domain-persistent-environment', status='completed',
            release=str(self.release), domain=self.domain, uid=self.row['uid'], gid=self.actor.pw_gid,
            inputs=self.expected['inputs'], intentSha256=self.cas, receiptSha256=self.cas,
            scopeMarkerSha256=self.marker_sha, custodySha256=self.proof['custodySha256'],
            sourceProjectionSha256=p.sha(p.encoded(self.proof)),
            sourceDirectory=str(self.destination / 'service-env'), sourceFiles=self.source_pins,
            stateStore=str(self.state / 'runtime-env'), store=self.store_pin, files=self.published,
            runtimeStore='/run/user/' + str(self.row['uid']) + '/webservices', runtimeDeferred=True,
            activationAuthorized=False, readinessAuthorized=False, removeUnselected=False)


def copy_environment(root, release, intent, domain):
    """Return non-secret persistent-copy proof; journal retains sole authority."""
    operation = Copy(root, release, intent, domain)
    try:
        return operation.copy()
    finally:
        operation.close()
