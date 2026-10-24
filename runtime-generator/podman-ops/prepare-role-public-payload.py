#!/usr/bin/env python3
"""Copy the exact positive public projection into an EMPTY pre-chown role leaf.

prepare(bundle, domain) -> metadata-only proof. The canonical installer must call
this BEFORE prepare_custody, retaining inherited exclusive FD9 throughout both.
No locks are acquired, receipts written, services changed, ownership transferred,
parents prepared, or failures cleaned up. A failed partial leaf is intentionally
left root:root0700 for the existing journal's disposition; retries never adopt it.

Authority is the existing native custody Session, not caller-supplied callbacks
or admission flags. This helper uses its real account, marker, preparing CAS,
full core-input pins, stopped manager/boot/API/linger/process and ancestry checks.
The sealed root build is the generator's reviewed-blob output, not a second
publisher: every emitted file is rechecked byte-for-byte against that source.
"""
import argparse
import fnmatch
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shlex
import stat
import time

# The owner's loader executes reviewed sibling source without creating bytecode.
import importlib.util
_spec = importlib.util.spec_from_file_location('_role_public_owner',
    Path(__file__).with_name('native-runtime-projection-owner.py'))
o = importlib.util.module_from_spec(_spec)
exec(compile(Path(_spec.origin).read_bytes(), _spec.origin, 'exec'), o.__dict__)
p = o.p
Refused = p.Refusal
MAX_NODES = 10000
MAX_FILE = 512 * 1024 * 1024
MAX_TOTAL = 8 * 1024**3
MAX_SECONDS = 120
# These names must never be carried even inside the positively selected build.
PRIVATE_NAMES = {'.git', '.hg', '.svn', '__pycache__', 'node_modules', '.cache',
                 'cache', 'caches', 'ops', 'runtime', 'runtimeRoot', 'secrets',
                 'site', 'siteprivate'}


def require(ok, message):
    if not ok:
        raise Refused(message)


def omitted(name):
    return (name in PRIVATE_NAMES or name == '.env' or
            name.endswith(('.env', '.env.template', '.pyc', '.pyo')) or
            'sops' in name.lower() or name == 'stack.env')


def tick(deadline):
    require(time.monotonic() < deadline, 'public payload lease expired')


def checked(fd, *, directory=False):
    info = os.fstat(fd)
    require(info.st_uid == info.st_gid == 0 and not info.st_mode & 0o7022
            and (stat.S_ISDIR(info.st_mode) if directory else
                 stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= MAX_FILE)
            and not p.acl_bytes(fd, 'system.posix_acl_access')
            and not p.acl_bytes(fd, 'system.posix_acl_default'),
            'public source/destination inode, root ownership, mode or ACL differs')
    return info


def open_node(root, relative, directory=False):
    p.relative(relative)
    return p.child_open(root, relative, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                        | (os.O_DIRECTORY if directory else 0))


def stream(fd, deadline, denied=(), output=None):
    """Bounded streaming hash/copy with cross-chunk root-material detection."""
    digest, size, tail = hashlib.sha256(), 0, b''
    overlap = max((len(value) - 1 for value in denied), default=0)
    while True:
        tick(deadline)
        body = os.read(fd, 128 * 1024)
        if not body:
            break
        size += len(body)
        require(size <= MAX_FILE, 'public file exceeds byte bound')
        window = tail + body
        require(not any(value in window for value in denied), 'root-only material in public payload')
        tail = window[-overlap:] if overlap else b''
        digest.update(body)
        if output is not None:
            pending = memoryview(body)
            while pending:
                tick(deadline)
                count = os.write(output, pending)
                require(count > 0, 'short public payload write')
                pending = pending[count:]
    return digest.hexdigest(), size


def snapshot(root, domain, build, deadline, denied=()):
    """Only build/, exact lockfile and selected Quadlet tree, never aggregate/site."""
    nodes, exclusions, total = {}, [], 0
    def visit(relative, *, force_directory=False):
        nonlocal total
        tick(deadline)
        require(len(nodes) + len(exclusions) < MAX_NODES, 'public payload exceeds node bound')
        fd = open_node(root, relative, force_directory)
        try:
            info = os.fstat(fd)
            isdir = stat.S_ISDIR(info.st_mode)
            checked(fd, directory=isdir)
            before = p.identity(info)
            name = PurePosixPath(relative).name
            if omitted(name):
                exclusions.append(relative)   # metadata only; never read the body
                return
            mode = 0o755 if isdir or info.st_mode & 0o111 else 0o644
            nodes[relative] = dict(identity=before, directory=isdir, mode=mode,
                                   sha256=None, size=0)
            if isdir:
                names = sorted(os.listdir(fd))
                for name in names:
                    p.relative(name)
                    require('/' not in name, 'ambiguous source child')
                    visit(relative + '/' + name)
                require(names == sorted(os.listdir(fd)), 'source child set changed')
            else:
                digest, size = stream(fd, deadline, denied)
                total += size
                require(total <= MAX_TOTAL, 'public payload exceeds total byte bound')
                nodes[relative].update(sha256=digest, size=size)
            require(before == p.identity(os.fstat(fd)), 'public source changed during snapshot')
            other = open_node(root, relative, isdir)
            try:
                require(p.identity(os.fstat(other)) == before, 'public source path CAS differs')
            finally:
                os.close(other)
        finally:
            os.close(fd)
    if build:
        visit('build', force_directory=True)
    # site/ is synthetic destination structure; source site siblings are NEVER enumerated.
    visit('site/components.lock.json')
    require(not nodes['site/components.lock.json']['directory'], 'component lock is not a file')
    visit('quadlet/rootless-' + domain, force_directory=True)
    return nodes, sorted(exclusions), total


def read_small(root, name, nodes):
    require(name in nodes and not nodes[name]['directory'] and nodes[name]['size'] <= p.MAX_FILE,
            'local build recipe is not in public projection')
    fd = open_node(root, name)
    try:
        require(p.identity(checked(fd)) == nodes[name]['identity'], 'build recipe identity differs')
        chunks, total = [], 0
        while True:
            body = os.read(fd, 65536)
            if not body:
                break
            chunks.append(body)
            total += len(body)
            require(total <= p.MAX_FILE, 'build recipe exceeds parse bound')
        body = b''.join(chunks)
        require(p.sha(body) == nodes[name]['sha256']
                and p.identity(os.fstat(fd)) == nodes[name]['identity'], 'build recipe changed')
        return body.decode('utf-8')
    finally:
        os.close(fd)


def closure(root, services, nodes, exclusions):
    """Conservative Docker COPY/ADD closure; unsupported dynamic syntax refuses.

    All selected IR local builds, including frozen recipes, are checked. Stage
    copies have no host-source dependency. Directory/glob copies which include
    ANY omitted path refuse, even if a .dockerignore might have hidden it.
    """
    checked_recipes = []
    for service, item in sorted(services.items()):
        recipe = item.get('build')
        if recipe is None:
            continue
        require(isinstance(recipe, dict), 'invalid selected local build')
        context = recipe.get('context', '.')
        require(isinstance(context, str), 'invalid local build context')
        context = context.removeprefix('./')
        context = '' if context in ('.', 'build', '') else p.relative(context)
        base = 'build' + ('/' + context if context else '')
        require(base in nodes and nodes[base]['directory'], 'local build context is absent')
        default_file = 'Containerfile' if base + '/Containerfile' in nodes else 'Dockerfile'
        containerfile = recipe.get('containerfile', default_file)
        require(isinstance(containerfile, str), 'invalid local containerfile path')
        containerfile = containerfile.removeprefix('./')
        p.relative(containerfile)
        path = base + '/' + containerfile
        text = read_small(root, path, nodes)
        # Fold Docker's ordinary backslash continuations; heredocs and alternate
        # escape directives are deliberately unsupported, never guessed.
        require(not any(line.lower().startswith('# escape=') for line in text.splitlines()),
                'unsupported build escape syntax')
        text = text.replace('\\\n', ' ')
        stages, stage_count = set(), 0
        for line in text.splitlines():
            fields = line.strip().split(None, 1)
            if not fields or fields[0].startswith('#'):
                continue
            instruction = fields[0].upper()
            rest = fields[1].strip() if len(fields) == 2 else ''
            require('<<' not in rest, 'unsupported build heredoc')
            if instruction == 'FROM':
                words = shlex.split(rest)
                if len(words) >= 3 and words[-2].upper() == 'AS':
                    stages.add(words[-1])
                stage_count += 1
                continue
            require(instruction != 'ONBUILD', 'unsupported deferred build input')
            if instruction not in ('COPY', 'ADD'):
                # Bind mounts are another route to host build inputs.
                require(not (instruction == 'RUN' and '--mount=' in rest),
                        'unsupported build input mount')
                continue
            flags = []
            while rest.startswith('--'):
                flag, sep, rest = rest.partition(' ')
                require(bool(sep) and '=' in flag, 'ambiguous build copy option')
                flags.append(flag)
                rest = rest.lstrip()
            froms = [flag[7:] for flag in flags if flag.startswith('--from=')]
            require(len(froms) <= 1 and all(flag.split('=', 1)[0] in
                    ('--from', '--chown', '--chmod', '--exclude') for flag in flags),
                    'unsupported build copy option')
            # Exclude semantics are not used to hide missing projected inputs.
            require(not any(flag.startswith('--exclude=') for flag in flags),
                    'unsupported build copy exclusion')
            words = json.loads(rest) if rest.startswith('[') else shlex.split(rest)
            require(isinstance(words, list) and len(words) >= 2
                    and all(isinstance(w, str) for w in words), 'ambiguous build copy sources')
            if froms:
                require(froms[0] in stages or (froms[0].isdigit() and int(froms[0]) < stage_count - 1),
                        'unproven external build copy')
                continue
            for source in words[:-1]:
                require('$' not in source and not source.startswith(('/', '~')) and
                        '://' not in source, 'dynamic/remote build input')
                source = source.removeprefix('./').rstrip('/')
                source = '' if source in ('.', '') else p.relative(source)
                pattern = base + ('/' + source if source else '')
                matches = [name for name in nodes if fnmatch.fnmatchcase(name, pattern)]
                require(matches, 'local build copy source is absent from public projection')
                require(not any(fnmatch.fnmatchcase(name, pattern)
                        or name.startswith(pattern + '/')
                        or any(nodes[m]['directory'] and name.startswith(m + '/') for m in matches)
                        for name in exclusions), 'local build copy requires omitted private-named input')
        checked_recipes.append(dict(service=service, path=path, sha256=nodes[path]['sha256']))
    return checked_recipes


def authority(session, deadline):
    """Revalidate existing authority during writes without blessing new public files."""
    tick(deadline)
    session.check_records()
    session.check_accounts()
    operator = o.pwd.getpwuid(1000)
    require(operator.pw_name == session.operator.pw_name and operator.pw_gid == 1000
            and o.pwd.getpwnam(operator.pw_name).pw_uid == 1000,
            'canonical operator primary group changed')
    for path, pins in ((session.scope.parent, session.external_pins),
                       (session.root, session.root_pins)):
        fd, current = o.open_absolute(path, session.operator if path == session.scope.parent else None)
        try:
            require(current == pins, 'public payload ancestor CAS differs')
            if path == session.scope.parent:
                child = p.child_open(fd, session.scope.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    require(p.custody_record(child) == session.records[session.scope], 'scope moved')
                finally:
                    os.close(child)
        finally:
            os.close(fd)
    for path, expected in session.records.items():
        require(p.custody_record(session.fds[path]) == expected, 'held selected directory changed')
        if path not in (session.scope, session.root):
            fd = p.child_open(session.fds[path.parent], path.name,
                              os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                require(p.custody_record(fd) == expected, 'selected path CAS differs')
            finally:
                os.close(fd)
    require(p.current_record(session.fds[session.root]) == session.root_current and
            p.current_record(session.fds[session.state]) == session.actor_current,
            'current pointer changed')
    body, seen = p.read_at(session.fds[session.scope], o.storage.MARKER, private=True)
    require(seen == session.marker_identity and p.sha(body) == session.marker_sha, 'scope marker changed')
    o.inactive(session.release, session.domain)
    tick(deadline)


def copy_payload(source, destination, nodes, deadline, denied, revalidate):
    """Only fresh destination nodes. No unlink, replacement, pruning or chown."""
    fds, pins, file_pins, emitted = {'': os.dup(destination)}, {}, {}, {}
    plan = dict(nodes)
    for path in ('site', 'quadlet'):
        plan[path] = dict(directory=True, mode=0o755)
    try:
        last_check = time.monotonic()
        for index, (name, row) in enumerate(sorted(plan.items(), key=lambda item: (item[0].count('/'), item[0]))):
            tick(deadline)
            if index % 64 == 0 or time.monotonic() - last_check > 1:
                revalidate(); last_check = time.monotonic()
            parent, _, leaf = name.rpartition('/')
            parentfd = fds[parent]
            if parent:
                require(p.custody_record(parentfd) == pins[parent], 'held public parent changed')
            if row['directory']:
                os.mkdir(leaf, mode=0o700, dir_fd=parentfd)
                fd = open_node(parentfd, leaf, True)
                fds[name] = fd
                checked(fd, directory=True)
                require(stat.S_IMODE(os.fstat(fd).st_mode) == 0o700, 'fresh directory mode differs')
                os.fchmod(fd, 0o755)
                pins[name] = p.custody_record(fd)
                emitted[name] = dict(directory=True, mode=0o755)
                continue
            src = open_node(source, name)
            out = None
            try:
                require(p.identity(checked(src)) == row['identity'], 'copy source identity differs')
                out = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                              0o600, dir_fd=parentfd)
                checked(out)
                digest, size = stream(src, deadline, denied, out)
                require(digest == row['sha256'] and size == row['size']
                        and p.identity(os.fstat(src)) == row['identity'], 'copied source hash/CAS differs')
                os.fchmod(out, row['mode'])
                os.fsync(out)
                seen = open_node(parentfd, leaf)
                try:
                    require(p.identity(checked(seen)) == p.identity(os.fstat(out)), 'copied destination path CAS differs')
                    check_hash, check_size = stream(seen, deadline, denied)
                    require((check_hash, check_size) == (digest, size), 'destination bytes differ')
                finally:
                    os.close(seen)
                file_pins[name] = p.identity(os.fstat(out))
                emitted[name] = dict(directory=False, mode=row['mode'], sha256=digest, size=size)
            finally:
                os.close(src)
                if out is not None:
                    os.close(out)
        for fd in fds.values():
            os.fsync(fd)
        revalidate()
        # Exact recursive inventory: an injected node is not accepted or deleted.
        def verify(fd, prefix=''):
            expected = {name[len(prefix):].split('/')[0] for name in emitted if name.startswith(prefix)}
            require(set(os.listdir(fd)) == expected, 'unknown destination payload member')
            for leaf in sorted(expected):
                name = prefix + leaf
                row = emitted[name]
                child = open_node(fd, leaf, row['directory'])
                try:
                    info = checked(child, directory=row['directory'])
                    require(stat.S_IMODE(info.st_mode) == row['mode'], 'destination mode differs')
                    if row['directory']:
                        require(p.custody_record(child) == pins[name], 'destination directory path CAS differs')
                        verify(child, name + '/')
                    else:
                        require(p.identity(info) == file_pins[name], 'destination file inode CAS differs')
                        require(stream(child, deadline, denied) == (row['sha256'], row['size'])
                                and p.identity(os.fstat(child)) == file_pins[name],
                                'destination final hash/CAS differs')
                finally:
                    os.close(child)
        verify(destination)
        return emitted
    finally:
        for fd in fds.values():
            os.close(fd)


def prepare(bundle, domain):
    deadline = time.monotonic() + MAX_SECONDS
    bundle = p.canonical(str(bundle))
    root = bundle.parent.parent
    require(bundle.parent == root / 'releases' and domain in o.native.IDENTITIES,
            'exact selected release/domain required')
    o.root_chain(bundle)
    o.lock_held(root)
    with p.directory(root) as fd:
        prior = p.strict(p.read_at(fd, '.install-intent.json', private=True)[0])
    session = o.Session(root, bundle, prior, domain)
    session.deadline = min(session.deadline, deadline)
    source = None
    try:
        require(not os.listdir(session.fds[session.slot]), 'selected root leaf must be EMPTY')
        # Existing Session validates primary group 1000 independently of group
        # spelling; no invented "stack" group is read or required here.
        authority(session, deadline)
        source, source_pins = o.open_absolute(bundle)
        denied = ()
        aggregate_pin = None
        if session.services:
            body, aggregate_pin = p.read_at(source, 'runtime/stack.env', private=True)
            denied = tuple({form for key, value in p.env_values(body).items()
                            if p.root_only(key, ()) and value for form in p.secret_forms(value)})
        nodes, exclusions, total = snapshot(source, domain, bool(session.services), deadline, denied)
        # The next canonical owner has tighter current inventory limits. Refuse
        # early rather than emit a payload that cannot enter its custody gate.
        require(len(nodes) + 2 <= o.MAX_NODES and total <= o.MAX_TOTAL
                and all(row['size'] <= p.MAX_FILE for row in nodes.values()),
                'public payload exceeds downstream custody bounds')
        recipes = closure(source, session.services, nodes, exclusions)
        if not session.services:
            base = 'quadlet/rootless-' + domain
            quadlets = {name for name in nodes if name.startswith(base + '/')}
            require(quadlets == {base + '/' + name for name in o.native.TARGETS}
                    and all(not nodes[name]['directory'] for name in quadlets),
                    'empty domain must have exactly four direct targets')
        def revalidate():
            authority(session, deadline)
            fd, current = o.open_absolute(bundle)
            try:
                require(current == source_pins, 'sealed source release moved')
            finally:
                os.close(fd)
            if aggregate_pin is not None:
                require(p.read_at(source, 'runtime/stack.env', private=True)[1] == aggregate_pin,
                        'root-only comparison authority changed')
        revalidate()
        # Closure and root-master scans finished BEFORE any payload creation.
        emitted = copy_payload(source, session.fds[session.slot], nodes, deadline, denied, revalidate)
        require(snapshot(source, domain, bool(session.services), deadline, denied)
                == (nodes, exclusions, total), 'public source snapshot changed')
        # Reuse the canonical public validator without rebinding its EMPTY
        # preparation pin, extending the deadline, or creating a new lease.
        # Main's subsequent prepare_custody captures its own populated pin.
        public = session.public_payload()
        require(set(public) == set(emitted) and all(public[name][1] == row.get('sha256')
                for name, row in emitted.items()), 'canonical public payload differs')
        revalidate()
        return dict(schemaVersion=1, status='public-payload-prepared', activationAuthorized=False,
                    ownershipTransferred=False, release=str(bundle), domain=domain,
                    destination=str(session.slot), intentSha256=session.cas,
                    scopeMarkerSha256=session.marker_sha, files=emitted,
                    omittedPaths=exclusions, totalBytes=total, localBuildCopyClosure=recipes)
    finally:
        if source is not None:
            os.close(source)
        session.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True)
    parser.add_argument('--domain', required=True)
    args = parser.parse_args()
    try:
        proof = prepare(args.bundle, args.domain)
    except (ValueError, OSError, KeyError, TypeError, UnicodeError):
        # No source bodies, environment values or filesystem exception payloads.
        parser.exit(1, 'public payload refused; retain inert leaf for canonical journal disposition\n')
    print(json.dumps(proof, sort_keys=True))


if __name__ == '__main__':
    main()
