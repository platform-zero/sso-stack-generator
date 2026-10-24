#!/usr/bin/env python3
"""Public dispatch/control-flow models, NOT host or installed recovery proof."""
import contextlib
import importlib.util
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

BASE = Path(__file__).absolute().parents[1]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module
c = load('public_recovery_cli', BASE / 'scripts/lib/stackctl-recovery.py')
a = load('public_recovery_fd9', BASE / 'scripts/lib/stackctl-operations.py')


class Public(unittest.TestCase):
    def setUp(self):
        self.events = []; self.root = Path('/model/root'); self.expected = dict(selectedRelease='r', intentSha256='a'*64, receiptSha256='a'*64, planSha256='b'*64)
        self.operation = dict(kind='backup', archive='/model/archive.age', recipient='age1'+'q'*58)
        @contextlib.contextmanager
        def lock(root):
            self.events.append('lock'); yield (1,2,8); self.events.append('unlock')
        @contextlib.contextmanager
        def fd9(fd):
            self.assertEqual(fd,8); self.events.append('actual-OFD-loan'); yield; self.events.append('end-loan')
        def dispatch(root, expected, operation, ops):
            self.assertEqual(self.events[-1], 'checked-CAS'); self.assertEqual(operation,self.operation)
            self.events.append('canonical-journal-dispatch'); return {'fixtureOnly':True,'installedAcceptance':False}
        self.journal = SimpleNamespace(native_recovery=dispatch)
        def expected(proof, wanted):
            self.assertEqual(proof,wanted); self.events.append('checked-CAS')
        self.ops = SimpleNamespace(installer_lock=lock, canonical_lock_fd=fd9, journal_module=lambda:self.journal,
            snapshot=lambda root,j:(Path('/model/root/releases/r'),{},self.expected,[],[]), check_expected=expected,
            stopped=lambda plans,seen:True, runtime_api=lambda release:SimpleNamespace(o=SimpleNamespace(journal=self.journal), verify_prepared_units=lambda *args:{'selectionSourceSha256':'c'*64}))
    def test_typed_execution_dispatches_under_same_canonical_lease(self):
        result=c.operate('backup',self.root,self.expected,self.operation,ops=self.ops)
        self.assertFalse(result['installedAcceptance']); self.assertEqual(self.events,['lock','actual-OFD-loan','checked-CAS','canonical-journal-dispatch','end-loan','unlock'])
    def test_interrupted_originals_recovery_uses_selected_not_public_journal(self):
        self.operation=dict(kind='recover-originals',recoveryJournalSha256='d'*64)
        selected=SimpleNamespace(native_recovery=self.journal.native_recovery)
        self.journal=SimpleNamespace(native_recovery=lambda *args:self.fail('Public-tree journal must not mutate selected release'))
        self.ops.runtime_api=lambda release:SimpleNamespace(o=SimpleNamespace(journal=selected))
        self.assertFalse(c.operate('restore',self.root,self.expected,self.operation,ops=self.ops)['installedAcceptance'])
        argv=['restore','--state-root','/model/root','--expected-release','r','--expected-intent-sha256','a'*64,
              '--expected-receipt-sha256','a'*64,'--expected-plan-sha256','b'*64,'--recover-originals','--recovery-journal-sha256','d'*64]
        with patch.object(c,'operate',return_value={'fixtureOnly':True}) as execute,patch('builtins.print'):
            self.assertEqual(c.main(argv),0)
        self.assertEqual(execute.call_args.args[3],self.operation)

    def test_plan_has_no_journal_publication_or_operation_permit(self):
        result=c.operate('backup',self.root,plan=True,ops=self.ops)
        self.assertFalse(result['operationAuthorized']); self.assertNotIn('canonical-journal-dispatch',self.events)
    def test_wrong_kind_and_missing_expected_cannot_dispatch(self):
        with self.assertRaises(ValueError):c.operate('backup',self.root,self.expected,dict(kind='restore'),ops=self.ops)
        self.assertNotIn('canonical-journal-dispatch',self.events)
    def test_cli_rejects_arbitrary_json_and_cross_kind_options(self):
        for args in (['backup','--state-root','/x','--proof-json','{}'],['restore','--state-root','/x'],
                     ['backup','--state-root','/x','--plan','--recipient','bad']):
            with self.subTest(args=args), self.assertRaises(SystemExit): c.main(args)
    def test_shell_only_adds_public_backup_restore_dispatch(self):
        source=(BASE/'scripts/stackctl.sh').read_text()
        self.assertIn('backup|restore) exec python3 -B "$SCRIPT_DIR/lib/stackctl-recovery.py" "$@"',source)
    def test_fd9_lends_actual_flock_open_description(self):
        import fcntl
        with tempfile.TemporaryFile() as stream:
            fcntl.flock(stream.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
            with a.canonical_lock_fd(stream.fileno()):
                self.assertEqual(os.fstat(9).st_ino,os.fstat(stream.fileno()).st_ino)
                text=Path('/proc/self/fdinfo/9').read_text();self.assertIn('FLOCK',text)
            self.assertEqual(os.fstat(stream.fileno()).st_nlink,0)
    def test_occupied_fd9_is_never_overwritten(self):
        import fcntl
        with tempfile.TemporaryFile() as stream, tempfile.TemporaryFile() as other:
            try: os.fstat(9)
            except OSError:
                os.dup2(other.fileno(),9)
                try:
                    before=os.fstat(9)
                    with self.assertRaises(ValueError):
                        with a.canonical_lock_fd(stream.fileno()):pass
                    self.assertEqual(before.st_ino,os.fstat(9).st_ino)
                finally:os.close(9)
            else:self.skipTest('Caller already owns FD9; no overwrite')

if __name__=='__main__':unittest.main(verbosity=2)
