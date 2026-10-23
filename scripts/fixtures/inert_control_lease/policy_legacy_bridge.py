import copy,pathlib
from unittest.mock import patch
import policy_fence as p
import test_complete_policy_fence as a
R=pathlib.Path(__file__).resolve().parent
ORIGINAL_SHA = p.sha
original_enter = a.World.__enter__
def entered(w):
    original_enter(w)
    w.plan['sourceCommit'] = p.TARGET_COMMIT
    state = w.read()
    state['plan'] = copy.deepcopy(w.plan)
    w.save(state)
    w.context.data = {'controlCommit': p.CONTROLLER['commit'], 'sourceProvenanceSha256': p.sha(w.provenance), 'siteVmSpecSha256': p.sha(b'{}')}

    def inputs(bundle, selector):
        state = w.read()
        prior = state.get(p.KEY)
        cfg = {'ledgerPath': str(w.ledger), 'initialReviewedLedgerSha256': prior['ledgerSha256Before'] if type(prior) is dict else p.sha(w.ledger.read_bytes()), 'planSha256': p.sha(p.canonical(w.plan)), 'provenanceSha256': p.sha(w.provenance)}
        return {'root': str(R), 'opsSha256': w.closure['ops'], 'pins': {'targetAuthority': {'inputConfiguration': cfg, 'namespace': w.ns}}}
    w.stack.enter_context(patch.object(p, '_policy_inputs', side_effect=inputs))
    return w
a.World.__enter__ = entered
legacy = a.World.sysd
def sysd(w, args):
    code, response = legacy(w, args)
    if args[0] == 'show' and args[1] in p.TMPFILES and ('MainPID' in args[-1]):
        row = dict((line.split('=', 1) for line in response.splitlines()))
        row.update(Type='oneshot', RemainAfterExit='yes', MainPID='0', ControlPID='0', Result='success', ExecMainStatus='0', ControlGroup='')
        if row['LoadState'] == 'loaded' and (not row['FragmentPath']):
            row['FragmentPath'] = '/usr/lib/systemd/system/' + args[1]
        response = '\n'.join((k + '=' + v for k, v in row.items())) + '\n'
    return (code, response)
a.World.sysd = sysd
class Legacy(a.CompleteTests):

    def test_actual_context_executes_closure_order_and_cache_refusal_branch(self):
        listing = p.os.listdir
        with patch.object(p, 'protected_input_tree', side_effect=lambda root: p.closed_code_tree(root)), patch.object(p, 'CONTROLLER', {**p.CONTROLLER, 'sha256': p.sha(b'closed')}), patch.object(p, '_slot_members', return_value={'p0_host_context.py': p.sha(b'closed'), 'manifest.json': 'f' * 64}), patch.object(p, 'sha', side_effect=lambda body: 'f' * 64 if body == p.encode({'p0_host_context.py': ORIGINAL_SHA(b'closed'), 'manifest.json': 'f' * 64}) else ORIGINAL_SHA(body)), patch.object(p.os, 'listdir', side_effect=lambda path: ['manifest.json', 'p0_host_context.py'] if str(path).endswith('host-fake') else listing(path)):
            a.CompleteTests.test_actual_context_executes_closure_order_and_cache_refusal_branch(self)
