"""Pure SOURCE format fixtures; no filesystem, volume or native custody proof."""
import dataclasses
import hashlib
import json
import unittest

from p0core.inputtree import (ENTRY_LIMIT, EXPANDED_LIMIT, MEMBER_LIMIT,
                             METADATA_LIMIT, parse_manifest, verify_payloads)
from p0core.model import ContractError


def encoded(records, **changes):
    document = {'schemaVersion': 1, 'resource': 'fixture-assets', 'entries': records}
    document.update(changes)
    return json.dumps(document, separators=(',', ':')).encode()


def file_record(path='public/page.txt', data=b'fixture'):
    return {'path': path, 'kind': 'file', 'size': len(data),
            'sha256': hashlib.sha256(data).hexdigest()}


class InputTreeFormatTests(unittest.TestCase):
    def test_exact_payload_and_explicit_parents_produce_immutable_data_only(self):
        raw = encoded([file_record(), {'path': 'public', 'kind': 'directory'}])
        result = verify_payloads(raw, {'public/page.txt': b'fixture'})
        self.assertEqual(result.resource, 'fixture-assets')
        self.assertEqual([entry.path for entry in result.entries], ['public', 'public/page.txt'])
        self.assertEqual(result.expanded_bytes, 7)
        self.assertFalse(hasattr(result, 'admitted'))
        self.assertFalse(hasattr(result, 'ready'))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.resource = 'other'
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.entries[1].size = 8

    def test_explicit_empty_and_empty_file_are_data_not_selected_empty_assets(self):
        self.assertEqual(verify_payloads(encoded([]), {}).entries, ())
        result = verify_payloads(encoded([file_record('empty', b'')]), {'empty': b''})
        self.assertEqual(result.expanded_bytes, 0)

    def test_closed_top_level_duplicate_and_nonfinite_inputs_refuse(self):
        for raw in [b'', b'[]', b'null', b'{}', encoded([], ready=True),
                    encoded([], schemaVersion=True), encoded([], schemaVersion=1.0),
                    encoded([], resource='Not-A-Resource'), encoded([], resource='a' * 49),
                    encoded([], entries={}), encoded([]) + b'{}', b'\xff',
                    b'{"schemaVersion":1,"schemaVersion":1,"resource":"x","entries":[]}',
                    b'{"schemaVersion":1,"schemaVersion":NaN,"resource":"x","entries":[]}',
                    b'{"schemaVersion":1,"resource":"x","entries":[{"path":"a","kind":"file","size":0,"size":0,"sha256":"' + b'a' * 64 + b'"}]}']:
            with self.subTest(raw=raw[:80]), self.assertRaises(ContractError):
                parse_manifest(raw)

    def test_unrepresentable_link_unknown_and_duplicate_records_refuse(self):
        for entries in [
            [{'path': 'a', 'kind': 'symlink', 'target': 'b'}],
            [{'path': 'a', 'kind': 'hardlink', 'target': 'b'}],
            [{'path': 'a', 'kind': 'directory', 'owner': 0}],
            [{'path': 'a', 'kind': 'directory'}, {'path': 'a', 'kind': 'directory'}],
            [file_record('a'), {'path': 'a', 'kind': 'directory'}],
            [file_record('a'), file_record('a/b')],
            [file_record()],
            [None],
        ]:
            with self.subTest(entries=entries), self.assertRaises(ContractError):
                parse_manifest(encoded(entries))

    def test_paths_are_rejected_not_cleaned_or_followed(self):
        for path in ['', '/', '/absolute', '.', '..', 'a/../b', './a',
                     'a//b', 'a/', 'a\\b', 'a\x00b', 'a\nb', '\ud800', 'a' * 256, 'a' * 4097]:
            with self.subTest(path=repr(path)), self.assertRaises(ContractError):
                parse_manifest(encoded([file_record(path)]))
        # UTF8 spelling is preserved, not normalized to another member name.
        path = 'caf\u00e9.txt'
        self.assertEqual(parse_manifest(encoded([file_record(path)])).entries[0].path, path)

    def test_typed_file_size_and_checksum_bounds_refuse_without_large_payloads(self):
        for value in [True, -1, 1.0, '1', MEMBER_LIMIT + 1]:
            record = file_record('a')
            record['size'] = value
            with self.subTest(size=value), self.assertRaises(ContractError):
                parse_manifest(encoded([record]))
        for value in [None, 64, 'A' * 64, 'g' * 64, 'a' * 63]:
            record = file_record('a')
            record['sha256'] = value
            with self.subTest(checksum=value), self.assertRaises(ContractError):
                parse_manifest(encoded([record]))
        a, b, c = (file_record(name) for name in ('a', 'b', 'c'))
        a['size'] = b['size'] = MEMBER_LIMIT
        c['size'] = 1
        self.assertEqual(parse_manifest(encoded([a, b])).expanded_bytes, EXPANDED_LIMIT)
        with self.assertRaises(ContractError):
            parse_manifest(encoded([a, b, c]))

    def test_payload_members_immutable_bytes_size_and_hash_are_exact(self):
        raw = encoded([file_record('a')])
        for payloads in [{}, {'a': b'fixture', 'extra': b'x'}, {'a': b'wrong'},
                         {'a': bytearray(b'fixture')}, {'a': b'fixturE'}, {'b': b'fixture'}]:
            with self.subTest(keys=list(payloads)), self.assertRaises(ContractError):
                verify_payloads(raw, payloads)
        with self.assertRaises(ContractError):
            verify_payloads(raw, [('a', b'fixture')])

    def test_payload_collection_cardinality_and_exact_key_types_refuse(self):
        # Functional refusals, not an allocator measurement or concurrency proof.
        empty = encoded([])
        raw = encoded([file_record('a')])
        oversized = {'extra' + str(i): b'' for i in range(ENTRY_LIMIT + 1)}
        for manifest, payloads in [(empty, {'extra': b''}), (raw, oversized),
                                   (raw, {}), (raw, {1: b'fixture'}),
                                   (raw, {'wrong': b'fixture'}),
                                   (raw, {'a': memoryview(b'fixture')})]:
            with self.subTest(count=len(payloads)), self.assertRaises(ContractError):
                verify_payloads(manifest, payloads)
        entries = [file_record('f' + str(i), b'') for i in range(ENTRY_LIMIT)]
        payloads = {entry['path']: b'' for entry in entries}
        self.assertEqual(len(verify_payloads(encoded(entries), payloads).entries), ENTRY_LIMIT)

    def test_metadata_and_count_bounds_are_independent_of_payload_size(self):
        with self.assertRaises(ContractError):
            parse_manifest(b' ' * (METADATA_LIMIT + 1))
        entries = [{'path': 'd' + str(i), 'kind': 'directory'} for i in range(ENTRY_LIMIT)]
        self.assertEqual(len(parse_manifest(encoded(entries)).entries), ENTRY_LIMIT)
        entries.append({'path': 'extra', 'kind': 'directory'})
        with self.assertRaises(ContractError):
            parse_manifest(encoded(entries))

    def test_refusal_diagnostics_do_not_echo_private_input_values(self):
        sentinel = 'SYNTHETIC_PRIVATE_PATH_SENTINEL'
        raw = encoded([file_record('/' + sentinel)])
        with self.assertRaises(ContractError) as error:
            parse_manifest(raw)
        self.assertNotIn(sentinel, str(error.exception))
        self.assertEqual(str(error.exception), 'invalid immutable input tree data')


if __name__ == '__main__':
    unittest.main()
