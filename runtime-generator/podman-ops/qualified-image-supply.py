#!/usr/bin/env python3
"""Rebind immutable producer artifacts, never stores, permits or installed proof.

Internal artifact-only API for export-selected-images.py. A reviewed protected
producer record is transport evidence, not operation authority. Independently
check the entire original public tree, every selected recipe/effective COPY
closure, exact archive bytes and OCI config/ordered DiffIDs. All actor store,
journal, namespace, stopped and activation gates remain installer-owned.
"""
import contextlib
import fnmatch
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys
import time


def load_package():
    path = Path(__file__).with_name('package-release-images.py')
    spec = importlib.util.spec_from_file_location('_qualified_supply_package', path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


package = load_package()


def require(value):
    if not value:
        raise ValueError('qualified immutable artifact source/custody mismatch')


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


class ArchiveData:
    """Hash-bound DATA reader, not an authority for its mutable ancestors.

    Kernel-held no-follow descriptors keep source bytes separate from Root code
    and controls. An operator-owned mount parent cannot authenticate code; it
    can safely supply opaque bytes only after protected expected hashes and real
    OCI closure checks. No store, cache adoption, source writes or execution.
    """
    def __init__(self, root, manifest_name, manifest_sha):
        self.root = Path(root); self.files = {}
        require(self.root.is_absolute() and '..' not in self.root.parts
                and not any(word in str(self.root).lower() for word in ('lane', 'stack_lab', 'software_lab', 'obelisks')))
        self.fd = self.open_directory(self.root)
        try:
            self.directory_pin = self.signature(os.fstat(self.fd))
            try:
                os.stat('PENDING', dir_fd=self.fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError('source archive package is pending')
            manifest = self.add(manifest_name)
            require(manifest.stat().st_size <= package.MAX_METADATA
                    and package.digest_file(manifest) == manifest_sha)
        except BaseException:
            self.close()
            raise

    @staticmethod
    def signature(info):
        return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
                info.st_ctime_ns, info.st_nlink, info.st_mode, info.st_uid, info.st_gid)

    @staticmethod
    def open_directory(path):
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in path.parts[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd); fd = child
            return fd
        except BaseException:
            os.close(fd)
            raise

    def add(self, name):
        require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,199}', name)
                and name not in self.files)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.fd)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= package.MAX_ARCHIVE)
            self.files[name] = (fd, self.signature(info))
            return Path('/proc/self/fd/' + str(fd))
        except BaseException:
            os.close(fd)
            raise

    def recheck(self):
        named = self.open_directory(self.root)
        try:
            require(self.signature(os.fstat(named)) == self.directory_pin
                    and self.signature(os.fstat(self.fd)) == self.directory_pin)
        finally:
            os.close(named)
        for name, (fd, pin) in self.files.items():
            require(self.signature(os.fstat(fd)) == pin
                    and self.signature(os.stat(name, dir_fd=self.fd, follow_symlinks=False)) == pin)

    def close(self):
        for fd, _ in self.files.values(): os.close(fd)
        self.files.clear()
        if self.fd is not None:
            os.close(self.fd); self.fd = None


class QualifiedArtifacts:
    """Internal callback to the existing packager, never a CLI permit/token."""
    def __init__(self, binding, selected, rows, report, proof, roots, data, deadline, trees):
        self.binding, self.selected, self.rows, self.report = binding, selected, rows, report
        self.proof, self.roots, self.data, self.deadline = proof, roots, data, deadline
        self.trees = trees
        self.report_sha256 = hashlib.sha256((json.dumps(report, indent=2) + '\n').encode()).hexdigest()

    def guard(self):
        require(time.monotonic() < self.deadline)

    def verify(self, binding, selected):
        self.guard()
        require(binding == self.binding and selected == self.selected)
        package.assert_unchanged(self.proof)
        require(all(tree(root, {}) == expected for root, expected in self.trees))
        if self.data is not None: self.data.recheck()

    def copy(self, image, destination, guard):
        self.verify(self.binding, self.selected)
        row, source = self.rows[image]
        # FD paths here are constructed only from our own retained descriptors.
        with source.open('rb') as original, destination.open('xb') as target:
            copied = 0
            while block := original.read(8 * 1024**2):
                guard(); copied += len(block)
                require(copied <= row['archiveBytes'])
                target.write(block)
            target.flush(); os.fsync(target.fileno())
        require(copied == row['archiveBytes'] and package.digest_file(destination) == row['archiveSha256'])
        self.verify(self.binding, self.selected)


def protected_directory(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts)
    for node in (path, *path.parents):
        info = node.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)
    return path


def tree(root, proof):
    root = protected_directory(root)
    result = {}
    for directory, children, files in os.walk(root, followlinks=False):
        protected_directory(Path(directory))
        for name in children:
            protected_directory(Path(directory) / name)
        for name in files:
            path = Path(directory) / name
            require(len(result) < 10000)
            proof[path] = package.snapshot(package.plain_file(path))
            result[path.relative_to(root).as_posix()] = {
                'sha256': proof[path][-1], 'executable': bool(path.stat().st_mode & 0o111)}
    return result


def tree_hash(files):
    # The original producer's byte inventory intentionally has no newline.
    body = {name: row['sha256'] for name, row in files.items()}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def relative(value):
    require(isinstance(value, str) and value and not Path(value).is_absolute()
            and '..' not in Path(value).parts and '$' not in value and '\\' not in value)
    return Path(value).as_posix()


def copy_closure(recipe, files, context='.'):
    """Fail-closed selected Dockerfile subset; never evaluate shell instructions.

    Internal stage copies depend transitively on earlier unchanged stages.
    No ADD, ONBUILD, RUN mounts, external --from, dynamic source, JSON COPY,
    Dockerignore or path escapes. New syntax needs owning review/regressions.
    """
    context = relative(context)
    prefix = '' if context == '.' else context.rstrip('/') + '/'
    contextual = {name[len(prefix):]: name for name in files if name.startswith(prefix)}
    require('.dockerignore' not in contextual)
    stages = set(); closure = set(); pending = ''
    for raw in recipe.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        pending += line[:-1] + ' ' if line.endswith('\\') else line
        if line.endswith('\\'):
            continue
        words = shlex.split(pending); pending = ''
        require(bool(words))
        operation, *args = words
        operation = operation.upper()
        require(operation not in ('ADD', 'ONBUILD'))
        require(not (operation == 'RUN' and args and args[0].startswith('--mount')))
        if operation == 'FROM':
            require(bool(args) and not args[0].startswith('--'))
            if len(args) > 1:
                require(len(args) == 3 and args[1].upper() == 'AS' and args[2] not in stages)
                stages.add(args[2])
        if operation != 'COPY':
            continue
        stage = None
        while args and args[0].startswith('--'):
            option = args.pop(0)
            require('=' in option)
            key, value = option.split('=', 1)
            require(key in ('--from', '--chown', '--chmod') and bool(value))
            if key == '--from':
                require(stage is None); stage = value
        require(len(args) >= 2 and not args[0].startswith('['))
        if stage is not None:
            require(stage in stages)
            continue
        for source in args[:-1]:
            source = relative(source).rstrip('/') or '.'
            # Match path components, unlike fnmatch('*') across '/'.
            parts = Path(source).parts
            matches = []
            for name in contextual:
                candidate = Path(name).parts
                direct = (len(candidate) >= len(parts) and all(fnmatch.fnmatchcase(c, p)
                          for c, p in zip(candidate, parts)))
                if source == '.' or direct:
                    matches.append(name)
            require(bool(matches))
            closure.update(contextual[name] for name in matches)
    require(not pending)
    return {name: files[name] for name in sorted(closure)}


def recipe_paths(bundle, service):
    # Use the actual generated build unit: IR './build' and '.' can both mean
    # the materialized build root. Never infer host source paths from IR alone.
    units = list((bundle / 'quadlet').glob('*/webservices-' + service + '.build'))
    require(len(units) == 1 and not units[0].is_symlink())
    values = {}; build_options = []; section = ''
    for line in units[0].read_text().splitlines():
        if line.startswith('['):
            section = line
        elif section == '[Build]' and line and not line.startswith('#'):
            key = line.split('=', 1)[0]
            require(key in ('ImageTag', 'SetWorkingDirectory', 'File', 'Network', 'Pull'))
            if key not in ('SetWorkingDirectory', 'File'):
                build_options.append(line)
        if line.startswith(('SetWorkingDirectory=', 'File=')):
            key, value = line.split('=', 1)
            require(key not in values)
            tokens = shlex.split(value); require(len(tokens) == 1)
            values[key] = tokens[0]
    require(set(values) == {'SetWorkingDirectory', 'File'})
    parts = Path(values['SetWorkingDirectory']).parts
    require(parts.count('current') == 1)
    offset = parts.index('current') + 1
    require(parts[offset:offset + 1] == ('build',))
    context = relative(str(Path(*parts[offset + 1:])))
    recipe = relative(str(Path(context) / relative(values['File'])))
    return context, recipe, units[0], build_options


def rebind(bundle, source_bundle, public_build, producer_record, producer_sha,
           image_inputs, inputs_sha, output, *, archive_source=None, package_output=False):
    require(os.geteuid() == 0)
    with contextlib.ExitStack() as stack:
        data = None
        if archive_source is not None:
            package.pinned_document(Path(image_inputs), inputs_sha)
            data = ArchiveData(archive_source, Path(image_inputs).name, inputs_sha)
            stack.callback(data.close)
        return _rebind(bundle, source_bundle, public_build, producer_record, producer_sha,
                       image_inputs, inputs_sha, output, data=data, package_output=package_output)


def _rebind(bundle, source_bundle, public_build, producer_record, producer_sha,
            image_inputs, inputs_sha, output, *, data, package_output):
    require(os.geteuid() == 0)
    bundle, source_bundle, public_build, output = map(Path, (bundle, source_bundle, public_build, output))
    image_inputs, producer_record = Path(image_inputs), Path(producer_record)
    require(output.is_absolute() and '..' not in output.parts and not os.path.lexists(output))
    package.owned_directory(output.parent)
    deadline = time.monotonic() + 3600
    require(not os.path.lexists(image_inputs.parent / 'PENDING')
            and not os.path.lexists(producer_record.parent / 'PENDING'))
    binding, selected, proof = package.bundle_selection(bundle)
    producer, captured = package.pinned_document(producer_record, producer_sha); proof.update(captured)
    inputs, captured = package.pinned_document(image_inputs, inputs_sha); proof.update(captured)
    old_ir_path = source_bundle / 'stack.ir.json'
    proof[old_ir_path] = package.snapshot(package.plain_file(old_ir_path))
    old_ir = package.read_document(old_ir_path)
    ir = package.read_document(bundle / 'stack.ir.json')
    producers = {name: row for name, row in ir['services'].items() if 'build' in row}
    require(producer.get('allSelectedRecipesQualified') is True
            and producers and set(producer['outputs']) == set(producers)
            and producer['sourceBundleIrSha256'] == proof[old_ir_path][-1])
    old = tree(public_build, proof); new = tree(bundle / 'build', proof)
    require(producer['publicBuildTreeSha256'] == tree_hash(old)
            and producer['publicBuildFiles'] == len(old))
    closures = {}
    for name, service in producers.items():
        require('build' in old_ir['services'][name])
        context, recipe, unit, options = recipe_paths(bundle, name)
        old_context, old_recipe, old_unit, old_options = recipe_paths(source_bundle, name)
        proof[unit] = package.snapshot(package.plain_file(unit))
        proof[old_unit] = package.snapshot(package.plain_file(old_unit))
        require((context, recipe, options) == (old_context, old_recipe, old_options)
                and old[recipe] == new[recipe]
                and recipe + '.dockerignore' not in old and recipe + '.dockerignore' not in new)
        record = producer['outputs'][name]
        require(record['image'] == service['image'] and record['recipeSha256'] == old[recipe]['sha256']
                and relative(record['recipePath']) == recipe)
        before = copy_closure((public_build / recipe).read_text(), old, context)
        after = copy_closure((bundle / 'build' / recipe).read_text(), new, context)
        require(before == after)
        closures[name] = {'recipeSha256': old[recipe]['sha256'], 'copyFiles': len(before),
                          'copyClosureSha256': hashlib.sha256(encoded(before)).hexdigest()}
    require(set(inputs) == {'schemaVersion', 'images'} and type(inputs['schemaVersion']) is int
            and inputs['schemaVersion'] == 1 and isinstance(inputs['images'], list))
    rows = {}; oci = {}
    for row in inputs['images']:
        require(isinstance(row, dict) and set(row) == {'image', 'archiveFilename', 'archiveSha256', 'archiveBytes'})
        image, filename = row['image'], row['archiveFilename']
        require(image in selected and image not in rows and isinstance(filename, str)
                and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,199}\.tar', filename))
        if data is None:
            path = image_inputs.parent / filename
            proof[path] = package.snapshot(package.plain_file(path))
            observed_size, observed_sha = proof[path][2], proof[path][-1]
        else:
            path = data.add(filename)
            observed_size, observed_sha = path.stat().st_size, package.digest_file(path)
            data.recheck()
        require(observed_size == row['archiveBytes'] and type(row['archiveBytes']) is int
                and observed_sha == row['archiveSha256'])
        def guard():
            require(time.monotonic() < deadline)
            package.check_reserves(output.parent)
        guard()
        oci[image] = package.verify_oci(path, image, guard=guard)
        for name, service in producers.items():
            if service['image'] == image:
                record = producer['outputs'][name]
                require(record['archiveBytes'] == row['archiveBytes']
                        and record['archiveSha256'] == row['archiveSha256'] and record['ociProof'] == oci[image])
        # Non-producer immutable consumers must retain their exact source image.
        for name, service in ir['services'].items():
            if service.get('image') == image and 'build' not in service:
                require(old_ir['services'][name].get('image') == image)
        rows[image] = (row, path)
    require(set(rows) == set(selected))
    roots = (bundle, source_bundle, public_build, image_inputs.parent, producer_record.parent,
             *((data.root,) if data is not None else ()))
    require(output.is_absolute() and '..' not in output.parts
            and all(not (output == p or output in p.parents or p in output.parents) for p in roots))
    package.owned_directory(output.parent); package.check_reserves(output.parent)
    require(not os.path.lexists(output))
    filesystem = os.statvfs(output.parent)
    require(filesystem.f_bavail * filesystem.f_frsize - sum(row['archiveBytes'] for row, _ in rows.values()) >= 50 * package.GIB)
    package.assert_unchanged(proof)
    require(tree(public_build, {}) == old and tree(bundle / 'build', {}) == new)
    report = {'schemaVersion': 1, 'scope': 'immutable artifact/source rebind only; no store availability or operation authority',
              'qualifierSha256': package.digest_file(Path(__file__)),
              'producerRecordSha256': producer_sha, 'imageInputsSha256': inputs_sha,
              'originalPublicBuildTreeSha256': tree_hash(old), 'currentPublicBuildTreeSha256': tree_hash(new),
              'changedBuildPaths': sorted(name for name in set(old) | set(new) if old.get(name) != new.get(name)),
              'producerCopyClosures': closures, 'ociProofs': oci, 'binding': binding,
              'activationAuthorized': False, 'acceptedIntegratedInstalls': 0}
    if package_output:
        source_roots = set(roots[1:])
        source_roots = [path for path in source_roots if not any(other in path.parents for other in source_roots)]
        artifacts = QualifiedArtifacts(binding, selected, rows, report, proof, source_roots, data, deadline,
                                       [(public_build, old), (bundle / 'build', new)])
        with contextlib.redirect_stdout(sys.stderr):
            package.package(bundle, None, None, output, 600, qualified_artifacts=artifacts)
        return {'imageInputs': str(output / 'image-inputs.json'),
                'imageInputsSha256': package.digest_file(output / 'image-inputs.json'),
                'qualification': str(output / 'source-qualification.json'), 'acceptedIntegratedInstalls': 0}
    output.mkdir(mode=0o700)
    with (output / 'PENDING').open('xb') as marker:
        marker.write(b'qualified artifact copy incomplete\n'); marker.flush(); os.fsync(marker.fileno())
    for directory in (output, output.parent):
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)
    for row, source in rows.values():
        destination = output / row['archiveFilename']
        source_fd = os.open(source, os.O_RDONLY | (0 if data is not None else os.O_NOFOLLOW))
        with os.fdopen(source_fd, 'rb') as original, destination.open('xb') as target:
            info = os.fstat(original.fileno())
            if data is None:
                require(stat.S_ISREG(info.st_mode) and (info.st_dev, info.st_ino, info.st_size,
                        info.st_mtime_ns, info.st_ctime_ns) == proof[source][:-1])
            else:
                data.recheck()
            while block := original.read(8 * 1024**2):
                require(time.monotonic() < deadline)
                package.check_reserves(output)
                target.write(block)
            target.flush(); os.fsync(target.fileno())
        os.chmod(destination, 0o400)
        require(package.snapshot(destination)[-1] == row['archiveSha256'])
    package.assert_unchanged(proof)
    require(tree(public_build, {}) == old and tree(bundle / 'build', {}) == new)
    supply = {'schemaVersion': 1, 'purpose': 'release-image-supply', 'binding': binding,
              'imageAuthorities': selected, 'images': [rows[image][0] for image in sorted(rows)]}
    for name, document in [('supply.json', supply), ('source-qualification.json', report)]:
        with (output / name).open('xb') as target:
            target.write(encoded(document)); target.flush(); os.fsync(target.fileno())
        os.chmod(output / name, 0o400)
    package.assert_unchanged(proof)
    if data is not None: data.recheck()
    os.unlink(output / 'PENDING')
    fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)
    return {'supply': str(output / 'supply.json'), 'supplySha256': hashlib.sha256(encoded(supply)).hexdigest(),
            'qualification': str(output / 'source-qualification.json'), 'acceptedIntegratedInstalls': 0}
