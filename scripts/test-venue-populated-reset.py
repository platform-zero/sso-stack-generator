#!/usr/bin/env python3
"""Synthetic fd-safe owned-data reset; native commands never reach the host."""
import importlib.util,json,os,tempfile,unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch
source=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/venue-install-inert.py'
spec=importlib.util.spec_from_file_location('owned_reset',source);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
@unittest.skipUnless(os.geteuid()==0,'root-owned protected fixtures')
class Reset(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
    def row(self,path):
        info=path.lstat();return {'path':str(path),'dev':info.st_dev,'ino':info.st_ino,'restoreUid':0}
    def test_fd_deletion_never_follows_symlink_to_outside_data(self):
        outside=self.root/'preserved';outside.write_text('original')
        owned=self.root/'owned';owned.mkdir();(owned/'nested').mkdir();(owned/'nested/file').write_text('experiment')
        (owned/'link').symlink_to(outside);m.empty_owned_directory(self.row(owned))
        self.assertEqual(outside.read_text(),'original');self.assertEqual(list(owned.iterdir()),[])
        self.assertEqual(owned.stat().st_mode&0o777,0o700)
    def test_changed_top_inode_refuses_before_unlink(self):
        path=self.root/'owned';path.mkdir();(path/'data').write_text('retained');row=self.row(path);row['ino']+=1
        with self.assertRaises(m.Refusal):m.empty_owned_directory(row)
        self.assertEqual((path/'data').read_text(),'retained')
    def test_linked_top_is_never_reset(self):
        path=self.root/'owned';path.mkdir();(path/'data').write_text('retained');link=self.root/'alias';link.symlink_to(path)
        row=self.row(path);row['path']=str(link)
        with self.assertRaises(m.Refusal):m.empty_owned_directory(row)
        self.assertTrue((path/'data').exists())
    def test_whole_filesystem_is_not_a_reset_root(self):
        with self.assertRaises(m.Refusal):m.no_data_mounts([self.row(Path('/'))])
    def fixture(self,*,network_failure=False,guest_present=False):
        bundle=self.root/'bundle';(bundle/'site').mkdir(parents=True);(bundle/'site/agent-vm.json').write_text('{"name":"fresh-guest"}')
        log=self.root/'logs';log.mkdir();parent=self.root/'data';parent.mkdir();named=self.root/'named';named.mkdir()
        rows=[];sources={};huly=[]
        for i in range(61):
            p=parent/str(i);p.mkdir();(p/'data').write_text('experiment');row=self.row(p);row.pop('restoreUid');rows.append(row);sources[str(p)]={'owner':0}
        p=log/'caddy';p.mkdir();(p/'log').write_text('experiment');logrow=self.row(p);logrow.pop('restoreUid');logrow['consumers']=['caddy.container']
        names=['huly_'+str(i) for i in range(4)]
        for name in names:
            p=named/name;p.mkdir();(p/'data').write_text('experiment');row=self.row(p);huly.append({'name':name,'mountpoint':str(p),'dev':row['dev'],'ino':row['ino']})
        marker=self.root/'volume-ready-r1.txt';marker.write_text('p0test-r1-volume-ready-v1\n');marker.chmod(0o600)
        plan={'prefix':'p0test-r1','quadletTreeSha256':'tree','roots':{'rootful-state':str(self.root)},'accounts':[{'name':'p0test-r1-apps'}]}
        info=self.root.stat();ledger=self.root/'ledger';data={'plan':plan,'venueInstallerVersion':2,'venueStartPhase':'failed-quarantined',
            'activationAuthorized':False,'venueDataBindDirs':rows,'venueLogBindDirs':[logrow],'venueHulyVolumes':huly,
            'pathIdentities':{str(self.root):{'dev':info.st_dev,'ino':info.st_ino,'uid':0}}}
        ledger.write_text(json.dumps(data));ledger.chmod(0o600);events=[];identity='a'*64
        def probe(bundle,plan,data,images,**kwargs):
            if kwargs.get('recovering'):
                data['venueRecoveryContainers']={};data['venueRecoveryNetworks']={'root|p0test-r1_net':{'id':identity,'unit':'selected-network.service'}}
            return {'root':(self.root,['podman'])},{}
        registry=NS(authority=NS(authority=lambda *a:{'imageIds':{}}),probe=probe)
        lifecycle=NS(host_context=lambda *a:NS(digest='d'*64),lifecycle=lambda *a:nullcontext(),reviewed_retry=lambda *a,**k:None,
                     targets=lambda *a:None,units=NS(units_idle=lambda *a:None),selected_commands=lambda *a:[])
        def native(command,**kwargs):
            events.append(command)
            if command[0]=='virsh':return NS(returncode=0,stdout='fresh-guest\n' if guest_present else '')
            self.assertEqual(command,['podman','network','rm',identity]);self.assertEqual(json.loads(ledger.read_text())['venueOwnedResetPending'],{'network':identity})
            return NS(returncode=1 if network_failure else 0,stdout='')
        fake_binds=NS(inventory=lambda *a:sources,log_sources=lambda *a:{str(log/'caddy'):['caddy.container']})
        fake_huly=NS(NAMES=names,inventory=lambda *a:set(names),mountpoint=lambda apps,name:named/name)
        return bundle,ledger,plan,events,registry,lifecycle,native,fake_binds,fake_huly,rows,marker
    def run_fixture(self,*,network_failure=False,guest_present=False):
        b,p,plan,events,registry,lifecycle,native,binds,huly,rows,marker=self.fixture(network_failure=network_failure,guest_present=guest_present)
        with (patch.object(m,'context',return_value=(b,p,plan)),patch.object(m,'load',side_effect=lambda name,file:lifecycle if 'lifecycle' in name else registry),
              patch.object(m.graph,'run',side_effect=native),patch.object(m.composite,'binds',binds),patch.object(m.composite,'huly',huly),
              patch.object(m.composite.acl,'policy',return_value=[])):
            if network_failure or guest_present:
                with self.assertRaises(m.Refusal):m.reset_owned(b,'selector','inventory',p,m.stage.sha(p))
                self.assertTrue(all((Path(row['path'])/'data').exists() for row in rows));self.assertTrue(marker.exists())
            else:
                result=m.reset_owned(b,'selector','inventory',p,m.stage.sha(p))
                self.assertEqual(result['emptiedExactOwnedDirectories'],66);self.assertFalse(marker.exists())
                data=json.loads(p.read_text());self.assertEqual(data['venueInstallerVersion'],2);self.assertEqual(data['venueOwnedReset']['phase'],'empty-owned')
                self.assertEqual(len(data['venueOwnedReset']['emptied']),66);self.assertFalse(data['activationAuthorized'])
        return events
    def test_complete_owned_reset_retains_top_inodes_and_version_two_evidence(self):self.run_fixture()
    def test_network_failure_preserves_data_and_pending_exact_id(self):self.run_fixture(network_failure=True)
    def test_existing_guest_blocks_before_any_stack_or_data_mutation(self):
        events=self.run_fixture(guest_present=True);self.assertEqual(len(events),1)
if __name__=='__main__':unittest.main()
