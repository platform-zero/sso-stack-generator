"""Pure immutable-input-tree DATA format; not resource admission or materialization.

No filesystem, process, network, mount, credential or owner-policy operations.
A valid description/payload is not permission, physical custody, actual tree
completeness, a prepared volume, or a readiness receipt. Root never imports this
Core module. Future native materialization requires a separately reviewed,
standalone Root-owned implementation and the existing execution gates.

The v1 data profile represents regular files and explicit directories only.
Unsupported selected inputs must be reported, not dropped or normalized. Limits
below bound expanded bytes only; compressed+expanded supply closure and physical
allocation/reserves require separate validation. No operational caller exists yet.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re

from .model import ContractError, fields, identifier


METADATA_LIMIT = 8 * 1024**2
MEMBER_LIMIT = 128 * 1024**2
EXPANDED_LIMIT = 256 * 1024**2
ENTRY_LIMIT = 1000
PATH_LIMIT = 4096
_CHECKSUM = re.compile(r'[a-f0-9]{64}\Z')
_REFUSAL = 'invalid immutable input tree data'


def _need(condition):
    if not condition:
        raise ContractError(_REFUSAL)


def _pairs(items):
    result = {}
    for key, value in items:
        _need(key not in result)
        result[key] = value
    return result


def _constant(_):
    raise ContractError(_REFUSAL)


def _path(value):
    _need(type(value) is str and bool(value))
    try:
        encoded = value.encode('utf-8', errors='strict')
    except UnicodeError:
        raise ContractError(_REFUSAL) from None
    _need(len(encoded) <= PATH_LIMIT)
    _need('\\' not in value and not any(ord(c) < 32 or ord(c) == 127 for c in value))
    # Preserve exact spelling: never normalize traversal, separators or Unicode.
    _need(all(part not in ('', '.', '..') and len(part.encode('utf-8')) <= 255
              for part in value.split('/')))
    return value


@dataclass(frozen=True)
class TreeEntry:
    path: str
    kind: str
    size: int = 0
    sha256: str | None = None


@dataclass(frozen=True)
class TreeDescription:
    """Immutable data snapshot, deliberately without an admission/readiness flag."""
    resource: str
    entries: tuple[TreeEntry, ...]

    @property
    def expanded_bytes(self):
        return sum(entry.size for entry in self.entries)


def parse_manifest(raw: bytes) -> TreeDescription:
    """Check a bounded closed v1 description; do not inspect a live directory.

    Explicit empty input is representable, but the caller cannot infer that the
    selected assets are empty or authorized from an empty description. JSON keys
    are decoded keys, not a promise of canonical byte spelling.
    """
    _need(type(raw) is bytes and 0 < len(raw) <= METADATA_LIMIT)
    try:
        document = json.loads(raw.decode('utf-8', errors='strict'),
                              object_pairs_hook=_pairs, parse_constant=_constant)
        fields(document, {'schemaVersion', 'resource', 'entries'})
        _need(type(document['schemaVersion']) is int and document['schemaVersion'] == 1)
        resource = identifier(document['resource'])
        _need(len(resource) <= 48)  # Existing volume resource name bound, not authority.
        records = document['entries']
        _need(type(records) is list and len(records) <= ENTRY_LIMIT)
        entries = {}
        expanded = 0
        for record in records:
            _need(type(record) is dict)
            kind = record.get('kind')
            _need(type(kind) is str and kind in ('directory', 'file'))
            fields(record, {'path', 'kind'} if kind == 'directory'
                   else {'path', 'kind', 'size', 'sha256'})
            path = _path(record['path'])
            _need(path not in entries)
            if kind == 'directory':
                entry = TreeEntry(path, kind)
            else:
                size, checksum = record['size'], record['sha256']
                _need(type(size) is int and 0 <= size <= MEMBER_LIMIT)
                _need(type(checksum) is str and _CHECKSUM.fullmatch(checksum) is not None)
                expanded += size
                _need(expanded <= EXPANDED_LIMIT)
                entry = TreeEntry(path, kind, size, checksum)
            entries[path] = entry
        for path in entries:
            parts = path.split('/')
            for end in range(1, len(parts)):
                parent = entries.get('/'.join(parts[:end]))
                _need(parent is not None and parent.kind == 'directory')
        return TreeDescription(resource, tuple(entries[path] for path in sorted(entries)))
    except (ValueError, TypeError, UnicodeError, RecursionError):
        # Neither invalid paths, parser exceptions nor private content appear in diagnostics.
        raise ContractError(_REFUSAL) from None


def verify_payloads(raw: bytes, payloads: dict[str, bytes]) -> TreeDescription:
    """Verify exact immutable in-memory file bytes, not authority or kernel custody.

    Reparse rather than treating a caller-constructed TreeDescription as a grant.
    Directory content comes from explicit parent records; no implicit directories,
    link dereference, ignored/extra members, ambient scanning or normalization.
    Collection retains at most the declared file count of shallow references. This
    does not bound the caller's existing allocation or JSON parser peak memory.
    Concurrent mutation is unsupported: no atomic mapping-snapshot claim follows
    from iterator checks, and the caller must supply a stable mapping.
    """
    description = parse_manifest(raw)
    files = {entry.path: entry for entry in description.entries if entry.kind == 'file'}
    _need(type(payloads) is dict and len(payloads) == len(files))
    snapshot = {}
    try:
        for index, (path, data) in enumerate(payloads.items()):
            _need(index < len(files))
            _need(type(path) is str and type(data) is bytes)
            _need(path in files and path not in snapshot)
            snapshot[path] = data
    except RuntimeError:
        # A changing dictionary is refusal, not a diagnostic containing input data.
        raise ContractError(_REFUSAL) from None
    _need(snapshot.keys() == files.keys())
    for path, entry in files.items():
        data = snapshot[path]
        _need(len(data) == entry.size and hashlib.sha256(data).hexdigest() == entry.sha256)
    return description
