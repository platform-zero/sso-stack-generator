#!/usr/bin/env python3
"""Stage exact standalone domain config/env; never activate or change ownership.

CLI requires the existing installer's preparing intent/receipt CAS and storage
marker hash. Destination MUST be <selected stateRoot>/releases/<release>/runtime,
absent, under a root-owned private pre-chown release. The CLI retains strict
root-controlled ancestry. The in-process custody_lease API additionally accepts
only the exact graph pinned by projectionCustody in that same root receipt;
operator/actor-owned ancestors are not inferred or adopted from disk. Optional
open_scope_parent(scope) and projection_execute_ids(marker) hooks delegate exact
external ancestry and mapped-root IDs to that same adapter, never CLI allowances.
It publishes configs/ and
service-env/<service>.env in ONE no-replace rename. Existing releases/current,
data, caches, units and the installation journal are never written. The caller
must retain its installer lock and inactive/pre-chown gate throughout the call;
this helper is not an admission authority or an independent installer.

Only IR environment declarations (including generated health input aliases) are
projected. There is no stack.env output, runner exception, source-template copy,
or arbitrary env-file input. Extra module-required inputs must first be declared
in owning module IR. Root-only derivation material is forbidden by key AND value;
nonstandard root-only keys must be supplied with --root-only-env-key (names only).
"""
import argparse
import contextlib
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import errno
import struct

OWNER = 0                         # tests mock ownership; never a CLI override
MAX_FILE = 32 * 1024 * 1024
IDP_REALM = 'keycloak/realm/webservices-realm.json'
NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_.-]*\Z')
IDENT = re.compile(r'[a-z][a-z0-9-]{0,63}\Z')
INPUTS = {'bundle.json', 'stack.ir.json', 'source-provenance.json',
          'podman-domains.json', 'site/agent-vm.json', 'site/agent-vm.provenance.json',
          'site/manifest.json', 'site/components.lock.json',
          'site/global.settings/registry-image-ids.json',
          'site/global.settings/webservices.sops.json',
          'site/global.settings/build-base-image-ids.json'}
REQUIRED = {'bundle.json', 'stack.ir.json', 'source-provenance.json',
            'podman-domains.json', 'site/manifest.json'}


class Refusal(ValueError):
    pass


def sha(body):
    return hashlib.sha256(body).hexdigest()


def canonical(value):
    if (not isinstance(value, str) or not value.startswith('/') or value == '/'
            or str(Path(value)) != value or any(x in ('.', '..', '') for x in value.split('/')[1:])):
        raise Refusal('noncanonical absolute path')
    return Path(value)


def relative(value):
    if (not isinstance(value, str) or not value or value.startswith('/')
            or any(x in ('', '.', '..') for x in value.split('/')) or '\\' in value
            or any(ord(x) < 32 for x in value)):
        raise Refusal('noncanonical relative config path')
    return value


def identity(s):
    return (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode,
            s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def controlled(s, directory=False, private=False):
    if (s.st_uid != OWNER or s.st_mode & 0o022
            or (private and stat.S_IMODE(s.st_mode) != (0o700 if directory else 0o600))
            or not (stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode))
            or (not directory and (s.st_nlink != 1 or s.st_size > MAX_FILE))):
        raise Refusal('source/staging ownership, mode or inode class differs')


@contextlib.contextmanager
def directory(path, custody=None):
    """No-follow open of EVERY component, not Path.resolve containment."""
    path = canonical(str(path))
    if custody is not None:
        with custody.open(path) as fd:
            yield fd
        return
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        controlled(os.fstat(fd), directory=True)
        yield fd
    finally:
        os.close(fd)


def trusted_chain(path):
    # A root-owned leaf under an actor-writable ancestor is not an authority.
    for parent in (*reversed(path.parents), path):
        controlled(parent.lstat(), directory=True)


def child_open(parent, name, flags):
    # openat2 is deliberately required: no symlinks, bind mounts (including
    # same-filesystem bind aliases), or filesystem crossings below a trusted FD.
    class How(ctypes.Structure):
        _fields_ = [('flags', ctypes.c_uint64), ('mode', ctypes.c_uint64), ('resolve', ctypes.c_uint64)]
    how = How(flags, 0, 0x08 | 0x04 | 0x01)  # BENEATH | NO_SYMLINKS | NO_XDEV
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.syscall(ctypes.c_long(437), ctypes.c_int(parent),
                          ctypes.c_char_p(os.fsencode(name)), ctypes.byref(how), ctypes.sizeof(how))
    if result < 0:
        code = ctypes.get_errno()
        raise OSError(code, 'safe source open refused')
    return result


@contextlib.contextmanager
def subtree(root, name):
    relative(name)
    with directory(root) as parent:
        fd = child_open(parent, name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            controlled(os.fstat(fd), directory=True)
            yield fd
        finally:
            os.close(fd)


def read_at(root, name, private=False):
    relative(name)
    parts = name.split('/')
    fd = os.dup(root)
    try:
        for part in parts[:-1]:
            child = child_open(fd, part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            controlled(os.fstat(child), directory=True)
            os.close(fd)
            fd = child
        file_fd = child_open(fd, parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(file_fd)
            controlled(before, private=private)
            chunks = []
            total = 0
            while True:
                chunk = os.read(file_fd, 65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_FILE:
                    raise Refusal('selected file exceeds bound')
                chunks.append(chunk)
            if identity(before) != identity(os.fstat(file_fd)):
                raise Refusal('selected file changed while reading')
            return b''.join(chunks), identity(before)
        finally:
            os.close(file_fd)
    finally:
        os.close(fd)


def strict(body):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Refusal('duplicate JSON key')
            result[key] = value
        return result
    return json.loads(body, object_pairs_hook=pairs)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def root_only(key, extra):
    upper = key.upper()
    # A module's encryption derivation SALT is not the root derivation master.
    return (key in extra or 'ROOT_ONLY' in upper or 'DERIVATION_MASTER' in upper
            or 'MASTER_DERIVATION' in upper
            or re.fullmatch(r'(?:P0|STACK|PLATFORM)(?:_[A-Z0-9]+)*_DERIVATION_(?:KEY|SEED)', upper) is not None)


def env_values(body):
    values = {}
    for line in body.decode().splitlines():
        if not line or line.startswith('#'):
            continue
        key, sep, value = line.partition('=')
        if not sep or not NAME.fullmatch(key) or key in values or '\x00' in value:
            raise Refusal('ambiguous aggregate environment')
        values[key] = value.replace('$$', '$')
    return values


def expand(template, values, forbidden, used, depth=0):
    """Bounded nested ${KEY}, ${KEY:-fallback}, ${KEY:?message}; no eval.

    Inserted secret bytes are NEVER interpreted as another template. Defaults
    may themselves contain expressions, as current Keycloak URL declarations do.
    """
    if depth > 16:
        raise Refusal('environment expression nesting exceeds bound')
    out = []
    index = 0
    while index < len(template):
        if template.startswith('$$', index):
            out.append('$'); index += 2
        elif template.startswith('${', index):
            end = index + 2
            nesting = 1
            while end < len(template) and nesting:
                if template.startswith('${', end):
                    nesting += 1; end += 2
                elif template[end] == '}':
                    nesting -= 1
                    if nesting:
                        end += 1
                else:
                    end += 1
            if nesting:
                raise Refusal('unterminated environment expression')
            expression = template[index + 2:end]
            match = re.fullmatch(r'([A-Za-z_][A-Za-z0-9_.-]*)(?:(:-|:\?)(.*))?', expression, re.S)
            if not match or forbidden(match[1]):
                raise Refusal('unsupported or root-only environment reference')
            key, operator, fallback = match.groups()
            used.add(key)
            value = values.get(key, '')
            if not value:
                if operator == ':-':
                    value = expand(fallback, values, forbidden, used, depth + 1)
                elif operator == ':?':
                    raise Refusal('required selected environment input absent')
                elif key not in values:
                    raise Refusal('undeclared/missing rendered environment input')
            out.append(value); index = end + 1
        else:
            out.append(template[index]); index += 1
    result = ''.join(out)
    if any(c in result for c in ('\n', '\r', '\x00')):
        raise Refusal('multiline selected environment')
    return result


def declarations(service):
    env = service.get('environment', {})
    if not isinstance(env, dict):
        raise Refusal('environment declaration must be a map')
    env = dict(env)
    health = service.get('health') or {}
    if health and not health.get('disable'):
        test = health.get('test', [])
        if test and test != ['NONE']:
            if (not isinstance(test, list) or len(test) < 2
                    or any(not isinstance(x, str) for x in test)):
                raise Refusal('unsupported health declaration')
            pattern = r'(?<!\$)\$(?:\{([A-Z_][A-Z0-9_]*)|([A-Z_][A-Z0-9_]*))'
            if test[0] == 'CMD-SHELL' and len(test) == 2:
                for match in re.finditer(pattern, test[1]):
                    key = match[1] or match[2]
                    alias = 'P0_HEALTH_INPUT_' + key
                    if alias in service.get('environment', {}):
                        raise Refusal('reserved health alias collision')
                    env[alias] = '${' + key + '}'
            elif test[0] != 'CMD' or any(re.search(pattern, x) for x in test[1:]):
                raise Refusal('unsupported health environment interpolation')
    result = {}
    for key, value in env.items():
        if not NAME.fullmatch(key) or isinstance(value, (dict, list)):
            raise Refusal('unsupported environment declaration')
        result[key] = ('${' + key + '}' if value is None else
                       str(value).lower() if isinstance(value, bool) else str(value).replace('\n', '\\n'))
    return result


def config_mounts(services):
    mounts = set()
    for service in services.values():
        for mount in service.get('volumes', []):
            source = mount.split(':', 1)[0] if isinstance(mount, str) else mount.get('source', '')
            if not isinstance(source, str):
                raise Refusal('invalid config mount source')
            if source.startswith('./configs/'):
                if isinstance(mount, dict) and mount.get('type', 'bind') != 'bind':
                    raise Refusal('config source must be a bind mount')
                mounts.add(relative(source[len('./configs/'):]))
            elif (source.startswith(('./configs', 'configs/', './runtime/configs', 'runtime/'))
                  or '/configs/' in source or source.endswith('/stack.env')):
                raise Refusal('noncanonical config or aggregate environment mount')
    # Nested exact mounts are redundant only when their selected ancestor really
    # is a directory. read_tree below verifies the full declared subtree.
    return sorted(mounts)


def read_tree(root, selected):
    files, dirs, records = {}, set(), {}

    def visit(fd, name, rel):
        before = os.stat(name, dir_fd=fd, follow_symlinks=False)
        controlled(before, directory=stat.S_ISDIR(before.st_mode))
        records[rel] = identity(before)
        if stat.S_ISDIR(before.st_mode):
            child = child_open(fd, name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                if identity(os.fstat(child)) != identity(before):
                    raise Refusal('config directory changed')
                dirs.add(rel)
                names = sorted(os.listdir(child))
                for item in names:
                    relative(item)
                    visit(child, item, rel + '/' + item)
                if names != sorted(os.listdir(child)) or identity(os.fstat(child)) != identity(before):
                    raise Refusal('config subtree changed')
            finally:
                os.close(child)
        else:
            body, seen = read_at(fd, name)
            if seen != identity(before):
                raise Refusal('config file changed')
            files[rel] = body

    for mount in selected:
        fd = os.dup(root)
        try:
            prefix = []
            for part in mount.split('/')[:-1]:
                child = child_open(fd, part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                controlled(os.fstat(child), directory=True)
                os.close(fd); fd = child
                prefix.append(part)
                records['/'.join(prefix)] = identity(os.fstat(fd))
                dirs.add('/'.join(prefix))
            visit(fd, mount.split('/')[-1], mount)
        finally:
            os.close(fd)
    return files, dirs, records


def acl_bytes(fd, name):
    try:
        return os.getxattr(fd, name)
    except OSError as error:
        if error.errno != errno.ENODATA:
            raise
        return b''


def mount_id(fd):
    # Kernel FD metadata, not a pathname resolution through /proc/self/fd.
    with open('/proc/self/fdinfo/' + str(fd), encoding='ascii') as info:
        rows = [line.split()[1] for line in info if line.startswith('mnt_id:')]
    if len(rows) != 1:
        raise Refusal('kernel mount identity unavailable')
    return int(rows[0])


def custody_record(fd):
    s = os.fstat(fd)
    return dict(dev=s.st_dev, ino=s.st_ino, uid=s.st_uid, gid=s.st_gid,
                mode=stat.S_IMODE(s.st_mode), mountId=mount_id(fd),
                acl=acl_bytes(fd, 'system.posix_acl_access').hex(),
                defaultAcl=acl_bytes(fd, 'system.posix_acl_default').hex())


def operator_defaults(body, uid, gid):
    """Only canonical operator/group writers; receipt pins the exact ACL bytes.

    Defaults are not ignored or applied to actor roots/new releases. A scope
    may retain its existing operator-only rw[-x] inheritance, never actor or
    public defaults. Canonical account/group membership remains lease authority.
    """
    acl = bytes.fromhex(body)
    if len(acl) < 4 or (len(acl) - 4) % 8 or struct.unpack('<I', acl[:4])[0] != 2:
        raise Refusal('unexpected operator default ACL')
    entries = {}
    for offset in range(4, len(acl), 8):
        tag, permission, identifier = struct.unpack('<HHI', acl[offset:offset + 8])
        if (tag, identifier) in entries:
            raise Refusal('ambiguous operator default ACL')
        entries[tag, identifier] = permission
    undefined = 0xffffffff
    expected = {(1, undefined), (2, uid), (4, undefined),
                (16, undefined), (32, undefined)}
    # A redundant named owning-group entry is optional. Linux commonly emits
    # only group:: for this exact canonical GID; no foreign group is admitted.
    if (8, gid) in entries:
        expected.add((8, gid))
    if (set(entries) != expected or entries[1, undefined] != 7 or entries[32, undefined] != 0
            or any(entries[key] not in (6, 7) for key in expected - {(1, undefined), (32, undefined)})):
        raise Refusal('foreign or noncanonical operator default ACL')


def custody_permissions(record, owner, gid, actors, operator=False, root_ancestor=False,
                        operator_uid=None):
    # Native delegated shared ancestors may be Root-owned while retaining the
    # operator's exact SGID/mask7 policy. This is NEVER a private leaf, scope,
    # source-file or generic writable-root exception: callers select ancestry
    # from the protected all-domain DAG and supply canonical traversal IDs.
    native_shared = (root_ancestor and not operator
                     and (owner, gid, operator_uid) == (0, 1000, 1000)
                     and (record['uid'], record['gid'], record['mode']) == (0, 1000, 0o2770))
    valid_mode = (native_shared or not record['mode'] & 0o022 and record['mode'] & 0o700 == 0o700
                  if root_ancestor else record['mode'] in ((0o700, 0o2770) if operator else (0o700,)))
    if (record['uid'] != owner or record['gid'] != gid or not valid_mode):
        raise Refusal('exact selected custody owner/group/mode required')
    if native_shared:
        default_rows = ((1, 7, 0xffffffff), (2, 7, 1000), (4, 7, 0xffffffff),
                        (16, 7, 0xffffffff), (32, 0, 0xffffffff))
        native_default = (struct.pack('<I', 2)
                          + b''.join(struct.pack('<HHI', *row) for row in default_rows)).hex()
        if not record['acl'] or record['defaultAcl'] != native_default:
            raise Refusal('native shared ancestor requires exact access/default ACL')
    if record['defaultAcl']:
        if operator and record['mode'] == 0o2770:
            operator_defaults(record['defaultAcl'], owner, gid)
        elif root_ancestor and operator_uid is not None:
            # This exact selected root-controlled public-traversal intermediate
            # may retain operator-only defaults; derived private children are
            # sealed separately. Effective access still forbids group writes.
            operator_defaults(record['defaultAcl'], operator_uid, gid)
        else:
            raise Refusal('unexpected selected custody default ACL')
    acl = bytes.fromhex(record['acl'])
    if not acl:
        return
    if not (operator or root_ancestor) or len(acl) < 4 or (len(acl) - 4) % 8 or struct.unpack('<I', acl[:4])[0] != 2:
        raise Refusal('unexpected custody ACL')
    entries = {}
    for offset in range(4, len(acl), 8):
        tag, permission, identifier = struct.unpack('<HHI', acl[offset:offset + 8])
        if (tag, identifier) in entries or permission > 7:
            raise Refusal('ambiguous custody ACL')
        entries[tag, identifier] = permission
        if tag == 2:
            # Only the receipt's canonical operator may have a named writer
            # entry. Root intermediates retain their non-writing effective
            # mask (e.g. operator rw- masked r-- on public volume traversal).
            canonical_operator = owner if operator else operator_uid
            if identifier == canonical_operator and (operator or root_ancestor):
                if permission not in ((7,) if operator else (6, 7)):
                    raise Refusal('unexpected canonical operator ACL')
            elif identifier not in actors or permission != 1:
                raise Refusal('foreign or non-traversal actor ACL')
        elif tag not in (1, 4, 16, 32) or identifier != 0xffffffff:
            raise Refusal('foreign custody ACL class')
    basic = {tag: permission for (tag, _), permission in entries.items() if tag != 2}
    if native_shared and (entries.get((2, 1000)) != 7 or basic.get(4) != 7):
        raise Refusal('native shared ancestor operator/group policy differs')
    if (set(basic) != {1, 4, 16, 32} or basic[1] != 7
            or basic[32] != (record['mode'] & 7 if root_ancestor else 0)
            or basic[16] != ((record['mode'] >> 3) & 7)
            or (not root_ancestor and basic[4] not in (0, 7))):
        raise Refusal('unexpected custody ACL permissions')


def current_record(fd):
    try:
        s = os.stat('current', dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISLNK(s.st_mode) or s.st_nlink != 1:
        raise Refusal('unexpected current pointer inode')
    target = os.readlink('current', dir_fd=fd)
    return dict(identity=list(identity(s)), target=target)


class Custody:
    """FD-pinned selected graph under an existing canonical installer lease.

    The trusted in-process lease adapter MUST hold the existing journal lock and
    inactive actor/trigger gate through projection AND the later ownership handoff.
    verify_projection(selection) must revalidate that existing authority or raise;
    it is not permission to stop actors, change ACLs or acquire a replacement lock.
    The root receipt/intent must already contain projectionCustody:
      schemaVersion=1; selection={release,destination,domain,user,uid,
      scopeMarkerSha256}; operatorUid/operatorGid/actorGid; directories={absolute
      path: custody_record(existing_fd)}; current=current_record(state_root_fd).
    directories is EXACTLY scope, selected state/graph/volume roots and their
    scope-relative ancestors, stateRoot/releases and the new root:root0700 release.
    Operator2770 parents may retain exact receipt-pinned defaults with ONLY the
    canonical operator and canonical group as named rw[-x] writers, no others.
    Actor roots and the new release never allow extended/default ACLs.
    current is absent (null) or the pinned exact previous release symlink; it is
    only observed, never followed or changed. No other symlinks are accepted.
    The installer writes these fields via its EXISTING receipt/CAS mechanism,
    after marker validation and without adopting nonempty unclaimed trees.
    verify_projection receives selection plus exact intent/receipt/custody hashes
    and must return None or raise. It must validate freshness, exclusive journal
    lease and inactive selected actor/trigger custody, including later handoff.
    No custody authority is derived from writable directory contents. CLI cannot
    manufacture this adapter or supply a free-form plan.
    """
    def __init__(self, lease):
        if not callable(getattr(lease, 'verify_projection', None)):
            raise Refusal('canonical installer custody lease adapter required')
        self.lease, self.fds, self.records = lease, {}, {}
        self.proof = None

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        for fd in self.fds.values():
            os.close(fd)

    def bind(self, receipt, scope, selected, marker, destination, marker_sha, receipt_sha, intent_sha):
        proof = receipt.get('projectionCustody')
        selection = dict(release=receipt['release'], destination=str(destination),
                         domain=selected['name'], user=selected['user'], uid=selected['uid'],
                         scopeMarkerSha256=marker_sha)
        keys = {'schemaVersion', 'selection', 'operatorUid', 'operatorGid', 'actorGid',
                'directories', 'current'}
        if (not isinstance(proof, dict) or set(proof) != keys or type(proof['schemaVersion']) is not int or proof['schemaVersion'] != 1
                or encoded(proof['selection']) != encoded(selection)
                or any(type(proof[k]) is not int or proof[k] <= 0
                       for k in ('operatorUid', 'operatorGid', 'actorGid'))
                or proof['operatorUid'] in {OWNER, selected['uid']}):
            raise Refusal('exact receipt-backed projection custody required')
        paths = {scope, destination.parent, destination.parent.parent}
        actor_roots = {canonical(selected[k]) for k in ('stateRoot', 'graphRoot', 'volumeRoot')}
        for node in (*actor_roots, destination.parent):
            while node != scope:
                paths.add(node)
                node = node.parent
                if not node.is_relative_to(scope):
                    raise Refusal('custody path escapes exact scope')
        if set(proof['directories']) != {str(node) for node in paths}:
            raise Refusal('custody must cover only the exact selected root graph')
        lease_selection = dict(selection, receiptSha256=receipt_sha, intentSha256=intent_sha,
                               custodySha256=sha(encoded(proof)))
        if self.proof is not None:
            if proof != self.proof or lease_selection != self.selection:
                raise Refusal('receipt custody changed')
            self.verify()
            return
        self.proof, self.selection = proof, lease_selection
        self.scope, self.state, self.slot = scope, canonical(selected['stateRoot']), destination.parent
        self.check_lease()
        # External ancestry may be opened only by the canonical adapter's
        # exact FD custody hook; a hook refusal must never fall back to strict
        # pathname opening (or any permission relaxation).
        with self.open_scope_parent() as parent:
            self.fds[scope] = child_open(parent, scope.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        execute_hook = getattr(self.lease, 'projection_execute_ids', None)
        actors = (execute_hook(marker) if execute_hook is not None
                  else {row['uid'] for row in marker['domains']})
        for node in sorted(paths, key=lambda n: len(n.parts)):
            if node != scope:
                self.fds[node] = child_open(self.fds[node.parent], node.name,
                                           os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            record = custody_record(self.fds[node])
            if encoded(record) != encoded(proof['directories'][str(node)]) or not stat.S_ISDIR(os.fstat(self.fds[node]).st_mode):
                raise Refusal('receipt custody inode/mount/ACL differs')
            if node == destination.parent:
                controlled(os.fstat(self.fds[node]), directory=True, private=True)
                custody_permissions(record, OWNER, OWNER, set())
            elif node in actor_roots or node == destination.parent.parent:
                custody_permissions(record, selected['uid'], proof['actorGid'], set())
            elif node != scope and (record['uid'], record['gid'], record['mode']) == (0, 1000, 0o2770):
                custody_permissions(record, OWNER, proof['operatorGid'], actors,
                                    root_ancestor=True, operator_uid=proof['operatorUid'])
            elif node != scope and record['uid'] == OWNER:
                controlled(os.fstat(self.fds[node]), directory=True)
                custody_permissions(record, OWNER, record['gid'], actors,
                                    root_ancestor=True, operator_uid=proof['operatorUid'])
            else:
                custody_permissions(record, proof['operatorUid'], proof['operatorGid'],
                                    actors, operator=True)
            self.records[node] = record
        current = proof['current']
        if current is not None:
            target = current.get('target', '')
            if target.startswith('/'):
                target_path = canonical(target)
                valid = target_path.parent == self.state / 'releases' and target_path != destination.parent
            else:
                valid = (relative(target).split('/')[0] == 'releases' and len(target.split('/')) == 2
                         and target != 'releases/' + destination.parent.name)
            if not valid or current['identity'][2] not in (OWNER, selected['uid']):
                raise Refusal('current pointer is not an exact previous release')
        # Pin the root private marker inode as well as its expected bytes/hash.
        body, self.marker_identity = read_at(self.fds[scope], '.stack-installation.json', private=True)
        if sha(body) != marker_sha or strict(body) != marker:
            raise Refusal('custody marker differs')
        self.verify()

    @contextlib.contextmanager
    def open_scope_parent(self):
        hook = getattr(self.lease, 'open_scope_parent', None)
        if hook is not None:
            with hook(self.scope) as parent:
                yield parent
        else:
            trusted_chain(self.scope.parent)
            with directory(self.scope.parent) as parent:
                yield parent

    def check_lease(self):
        if self.lease.verify_projection(dict(self.selection)) is not None:
            raise Refusal('canonical lease verification must raise on failure, not return admission')

    def verify(self):
        self.check_lease()
        # Rewalk through the same canonical authority and compare every held
        # FD, not just the leaf. Never adopt a renamed/reparented/replaced graph.
        scope_fd = None
        try:
            with self.open_scope_parent() as parent:
                scope_fd = child_open(parent, self.scope.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            if custody_record(scope_fd) != self.records[self.scope]:
                raise Refusal('selected scope moved or changed')
        finally:
            if scope_fd is not None:
                os.close(scope_fd)
        for node, held in self.fds.items():
            if custody_record(held) != self.records[node]:
                raise Refusal('held custody ownership/mode/ACL/mount changed')
            if node != self.scope:
                fd = child_open(self.fds[node.parent], node.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    if custody_record(fd) != self.records[node]:
                        raise Refusal('custody path renamed or reparented')
                finally:
                    os.close(fd)
        if encoded(current_record(self.fds[self.state])) != encoded(self.proof['current']):
            raise Refusal('current pointer changed')
        body, seen = read_at(self.fds[self.scope], '.stack-installation.json', private=True)
        if seen != self.marker_identity or sha(body) != self.selection['scopeMarkerSha256']:
            raise Refusal('marker custody changed')

    @contextlib.contextmanager
    def open(self, path):
        if path not in self.fds:
            raise Refusal('unselected custody path')
        self.verify()
        fd = os.dup(self.fds[path])
        try:
            yield fd
        finally:
            os.close(fd)


def binding(release, destination, domain, user, uid, state_root, intent_sha, marker_sha,
            custody=None):
    """Bind to existing standalone journal, not a caller-written replacement plan."""
    release, destination, state_root = map(lambda x: canonical(str(x)), (release, destination, state_root))
    trusted_chain(release)
    if custody is None:
        trusted_chain(destination.parent)
    with directory(release) as source:
        receipt_bytes, _ = read_at(source, 'installation-receipt.json', private=True)
        receipt = strict(receipt_bytes)
        if (receipt.get('schemaVersion') != 1 or receipt.get('phase') != 'preparing'
                or receipt.get('release') != str(release)):
            raise Refusal('exact preparing receipt required')
        inputs = receipt.get('inputs', {})
        if not REQUIRED <= set(inputs) <= INPUTS:
            raise Refusal('missing or unknown installation input pins')
        for name, digest in inputs.items():
            if digest is None:
                try:
                    read_at(source, name)
                except FileNotFoundError:
                    continue
                raise Refusal('pinned absent input appeared')
            if not re.fullmatch('[0-9a-f]{64}', digest) or sha(read_at(source, name)[0]) != digest:
                raise Refusal('installation input hash changed')
        metadata = strict(read_at(source, 'podman-domains.json')[0])
        manifest = strict(read_at(source, 'site/manifest.json')[0])
        ir = strict(read_at(source, 'stack.ir.json')[0])
    if (metadata.get('schemaVersion') != 1 or metadata.get('deploymentMode') != 'standalone'
            or manifest.get('deploymentMode') != 'standalone' or 'venue' in metadata):
        raise Refusal('standalone selected host metadata required')
    root = canonical(metadata.get('installerStateRoot'))
    if release.parent != root / 'releases':
        raise Refusal('release escapes installation receipt root')
    with directory(root) as root_fd:
        intent_bytes, _ = read_at(root_fd, '.install-intent.json', private=True)
    if sha(intent_bytes) != intent_sha or encoded(strict(intent_bytes)) != encoded(receipt):
        raise Refusal('installation intent/receipt CAS differs')
    scope_config = metadata.get('storageScope')
    if (not isinstance(scope_config, dict) or set(scope_config) != {'root', 'dataClass'}
            or scope_config != manifest.get('storageScope')
            or scope_config['dataClass'] not in ('synthetic', 'production')):
        raise Refusal('scope metadata differs')
    scope = canonical(scope_config['root'])
    if custody is None:
        trusted_chain(scope)
    rows, roots = [], []
    owned = {k: v for k, v in ir['services'].items()
             if v.get('placement') == 'rootless' and v.get('rootlessDomain') == domain}
    selected = None
    for row in metadata['domains']:
        if (not IDENT.fullmatch(row['name']) or not IDENT.fullmatch(row['user'])
                or type(row.get('uid')) is not int or row['uid'] <= 0):
            raise Refusal('invalid selected domain identity')
        entry = {key: row[key] for key in ('name', 'user', 'uid', 'stateRoot', 'graphRoot', 'volumeRoot')}
        for key in ('stateRoot', 'graphRoot', 'volumeRoot'):
            path = canonical(entry[key])
            if not path.is_relative_to(scope) or path == scope:
                raise Refusal('domain root escapes selected scope')
            roots.append(path)
        rows.append(entry)
        if row['name'] == domain:
            selected = row
    if (not rows or any(len({r[k] for r in rows}) != len(rows) for k in ('name', 'user', 'uid'))
            or any(a == b or a.is_relative_to(b) or b.is_relative_to(a)
                   for i, a in enumerate(roots) for b in roots[i + 1:])):
        raise Refusal('overlapping roots or duplicate domain identities')
    if (selected is None or selected['user'] != user or selected['uid'] != uid
            or selected['stateRoot'] != str(state_root) or sorted(selected['services']) != sorted(owned)
            or destination != state_root / 'releases' / release.name / 'runtime'):
        raise Refusal('domain/user/uid/root/service selection differs')
    if custody is None:
        controlled(destination.parent.lstat(), directory=True, private=True)
    expected = {'schemaVersion': 1, 'kind': 'standalone-stack-storage', 'site': manifest['site'],
                'scope': scope_config, 'domains': sorted(rows, key=lambda r: r['name']),
                'roots': sorted(str(p) for p in roots)}
    if custody is not None:
        controlled(release.lstat(), directory=True, private=True)
        custody.bind(receipt, scope, selected, expected, destination, marker_sha, sha(receipt_bytes), intent_sha)
    with directory(scope, custody) as scope_fd:
        marker_bytes, _ = read_at(scope_fd, '.stack-installation.json', private=True)
    if sha(marker_bytes) != marker_sha or strict(marker_bytes) != expected:
        raise Refusal('storage marker identity/hash differs')
    pins = {'intentSha256': intent_sha, 'receiptSha256': sha(receipt_bytes),
            'scopeMarkerSha256': marker_sha, 'inputs': inputs, 'release': str(release),
            'domain': domain, 'user': user, 'uid': uid, 'stateRoot': str(state_root)}
    return owned, pins


def write_file(root, name, body, executable=False):
    parts = relative(name).split('/')
    fd = os.dup(root)
    try:
        for part in parts[:-1]:
            try:
                os.mkdir(part, 0o700, dir_fd=fd)
            except FileExistsError:
                pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        out = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700 if executable else 0o600, dir_fd=fd)
        try:
            os.fchmod(out, 0o700 if executable else 0o600)
            view = memoryview(body)
            while view:
                count = os.write(out, view)
                if count <= 0:
                    raise Refusal('short projection write')
                view = view[count:]
            os.fsync(out)
        finally:
            os.close(out)
    finally:
        os.close(fd)


def publish(parent, stage, destination):
    # Linux renameat2(RENAME_NOREPLACE): never replace even an empty foreign dir.
    function = ctypes.CDLL(None, use_errno=True).renameat2
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    if function(parent, os.fsencode(stage), parent, os.fsencode(destination), 1) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    os.fsync(parent)


def project(release, destination, domain, user, uid, state_root,
            expected_install_intent_sha256, expected_scope_marker_sha256, root_only_env_keys=(),
            *, custody_lease=None):
    if os.geteuid() != 0:
        raise Refusal('root-only pre-chown projection')
    for digest in (expected_install_intent_sha256, expected_scope_marker_sha256):
        if not re.fullmatch('[a-f0-9]{64}', digest):
            raise Refusal('exact CAS hashes required')
    if any(not NAME.fullmatch(key) for key in root_only_env_keys):
        raise Refusal('invalid root-only key name')
    release, destination = canonical(str(release)), canonical(str(destination))
    args = (release, destination, domain, user, uid, state_root,
            expected_install_intent_sha256, expected_scope_marker_sha256)
    # Custody leases are an in-process installer integration only, never a CLI
    # owner-allowance switch. All permissions still come from the hashed receipt.
    with contextlib.ExitStack() as stack:
        custody = stack.enter_context(Custody(custody_lease)) if custody_lease is not None else None
        return project_bound(args, root_only_env_keys, custody)


def secret_forms(value):
    # Deny literal and normal JSON-escaped encodings; do not claim detection of
    # arbitrary transformations by a renderer (e.g. encryption/base64).
    return {value.encode(), json.dumps(value, ensure_ascii=True)[1:-1].encode(),
            json.dumps(value, ensure_ascii=False)[1:-1].encode()}


def owner_import_material(release):
    # Native provisioning takes its initial password on stdin, never aggregate
    # env. The exact realm import is its only legitimate projected destination.
    try:
        with subtree(release, 'runtime/configs') as configs:
            body, seen = read_at(configs, IDP_REALM)
    except FileNotFoundError:
        return None, ()
    realm = strict(body)
    values = []
    for user in realm.get('users', []):
        for credential in user.get('credentials', []):
            if credential.get('type') == 'password':
                value = credential.get('value')
                if not isinstance(value, str) or not value:
                    raise Refusal('ambiguous native realm password credential')
                values.extend(sorted(secret_forms(value)))
    return (body, seen), tuple(values)


def project_bound(args, root_only_env_keys, custody):
    release, destination = args[:2]
    services, pins = binding(*args, custody=custody)
    mounts = config_mounts(services)
    forbidden = lambda key: root_only(key, root_only_env_keys)
    # An empty selected domain still has full identity/marker/CAS custody but
    # has no secret authority: do not even open its source runtime/config tree.
    aggregate = aggregate_identity = None
    values = {}
    if services:
        with subtree(release, 'runtime') as runtime:
            aggregate, aggregate_identity = read_at(runtime, 'stack.env', private=True)
        values = env_values(aggregate)
    banned = [form for key, value in values.items() if forbidden(key) and value
              for form in secret_forms(value)]
    files, dirs, config_records = {}, set(), {}
    if mounts:
        with subtree(release, 'runtime/configs') as configs:
            files, dirs, config_records = read_tree(configs, mounts)
    owner_realm, owner_passwords = owner_import_material(release) if services else (None, ())
    if IDP_REALM in files and owner_passwords:
        idp = services.get('keycloak')
        if idp is None or not any(IDP_REALM == mount or IDP_REALM.startswith(mount + '/')
                                  for mount in config_mounts({'keycloak': idp})):
            raise Refusal('native password realm is not selected IdP configuration')
    payloads = {'configs/' + key: body for key, body in files.items()}
    used = set()
    for name, service in sorted(services.items()):
        if not IDENT.fullmatch(name):
            raise Refusal('invalid selected service name')
        lines = []
        for key, template in sorted(declarations(service).items()):
            if forbidden(key):
                raise Refusal('root-only environment output declaration')
            lines.append(key + '=' + expand(template, values, forbidden, used))
        if lines:
            payloads['service-env/' + name + '.env'] = ('\n'.join(lines) + '\n').encode()
    if any(secret in body for body in payloads.values() for secret in banned):
        raise Refusal('root-only material present in selected config/env')
    if any(secret in body for key, body in payloads.items() if key != 'configs/' + IDP_REALM
           for secret in owner_passwords):
        raise Refusal('native owner password outside exact IdP realm configuration')
    proof = dict(pins, schemaVersion=1, kind='domain-runtime-projection',
                 configMounts=mounts, services=sorted(services), environmentInputs=sorted(used),
                 files={key: sha(body) for key, body in sorted(payloads.items())},
                 directories=sorted({'configs', 'service-env'} | {'configs/' + key for key in dirs}),
                 aggregateSha256=sha(aggregate) if services else None, activationAuthorized=False)
    # The aggregate hash is proof to the root caller only, not actor material.
    payloads['projection.json'] = encoded({k: v for k, v in proof.items() if k != 'aggregateSha256'})
    with directory(destination.parent, custody) as parent:
        parent_identity = identity(os.fstat(parent))
        try:
            os.stat(destination.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise Refusal('destination already exists; previous projection retained')
        stage = '.domain-projection-' + secrets.token_hex(16)
        os.mkdir(stage, 0o700, dir_fd=parent)
        # A failed/interrupted private sibling is intentionally not recursively
        # deleted. The installer owns journalled disposition; never sweep temps.
        fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            os.fchmod(fd, 0o700)
            for rel in sorted({'configs', 'service-env'} | {'configs/' + p for p in dirs}, key=lambda x: (x.count('/'), x)):
                # Empty declared directories are part of the selected subtree.
                cursor = os.dup(fd)
                try:
                    for part in rel.split('/'):
                        try:
                            os.mkdir(part, 0o700, dir_fd=cursor)
                        except FileExistsError:
                            pass
                        child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=cursor)
                        os.close(cursor); cursor = child
                finally:
                    os.close(cursor)
            for name, body in sorted(payloads.items()):
                write_file(fd, name, body, name.startswith('configs/') and body.startswith(b'#!'))
            # Fsync all stage directories bottom-up before publication.
            def sync_tree(current):
                for item in os.listdir(current):
                    if stat.S_ISDIR(os.stat(item, dir_fd=current, follow_symlinks=False).st_mode):
                        child = os.open(item, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
                        try:
                            sync_tree(child)
                        finally:
                            os.close(child)
                os.fsync(current)
            sync_tree(fd)
            if binding(*args, custody=custody) != (services, pins):
                raise Refusal('selection CAS changed before publication')
            if services:
                with subtree(release, 'runtime') as runtime:
                    if read_at(runtime, 'stack.env', private=True) != (aggregate, aggregate_identity):
                        raise Refusal('rendered environment changed before publication')
            if mounts:
                with subtree(release, 'runtime/configs') as configs:
                    if read_tree(configs, mounts) != (files, dirs, config_records):
                        raise Refusal('selected config changed before publication')
            if services and owner_import_material(release) != (owner_realm, owner_passwords):
                raise Refusal('native owner realm changed before publication')
            # Creating our own stage changes parent timestamps, not its authority.
            actual = os.fstat(parent)
            if identity(actual)[:5] != parent_identity[:5]:
                raise Refusal('destination parent changed')
            with directory(destination.parent, custody) as current:
                if os.fstat(current).st_ino != actual.st_ino or os.fstat(current).st_dev != actual.st_dev:
                    raise Refusal('destination parent path changed')
            if custody is not None:
                custody.verify()
            publish(parent, stage, destination.name)
            if custody is not None:
                # The subtree remains root0700 and inert even if a parent is
                # moved at rename. Never authorize chown after this refusal.
                custody.verify()
        finally:
            os.close(fd)
    return dict(proof, destination=str(destination), projectionSha256=sha(payloads['projection.json']))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('release', 'destination', 'domain', 'user', 'state-root',
                 'expected-install-intent-sha256', 'expected-scope-marker-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--uid', type=int, required=True)
    parser.add_argument('--root-only-env-key', action='append', default=[])
    args = vars(parser.parse_args())
    args['root_only_env_keys'] = args.pop('root_only_env_key')
    try:
        print(json.dumps(project(**args), sort_keys=True))
    except (ValueError, OSError, KeyError, TypeError, AttributeError):
        # Never include config/secret values or parsed private input in errors.
        parser.exit(1, 'Domain runtime projection refused; previous runtime retained; inspect installer evidence\n')


if __name__ == '__main__':
    main()
