import copy
import http.server
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

from p0core.model import Catalog, ContractError
from p0core.render import render
from p0core.socketrelay import PROXY

IMAGE = 'docker.io/library/alpine@sha256:' + 'a'*64


def declarations():
    return [
        {'id':'app', 'runtime':'rootless', 'image':IMAGE, 'requires':[],
         'endpoints':[{'bind':'127.0.0.1','hostPort':28080,'port':8080}],
         'probes':[{'kind':'tcp','host':'127.0.0.1','port':28080}]},
        {'id':'app-upstream','kind':'http-socket-relay','runtime':'rootful',
         'requires':[{'service':'app','kind':'ready'}], 'relay':{'service':'app','port':8080}},
        {'id':'edge','runtime':'rootful','image':IMAGE,
         'requires':[{'service':'app-upstream','kind':'order'}],
         'mounts':[{'kind':'upstream','source':'app-upstream','target':'/run/p0/upstreams/app-upstream'}]}]


def catalog(items):
    return Catalog([{'schemaVersion':1,'id':'fixture','services':items}])


class SocketRelayTests(unittest.TestCase):
    def test_one_graph_has_closed_native_units_and_fail_if_absent_directory_mount(self):
        plan, files = render(catalog(declarations()), ['edge'])
        self.assertEqual(plan['services'], ['app','app-upstream','edge'])
        self.assertIn('systemd/rootful/p0-app-upstream.socket', files)
        unit = files['systemd/rootful/p0-app-upstream.service']
        self.assertIn(PROXY+' --exit-idle-time=5min 127.0.0.1:28080', unit)
        self.assertIn('User=p0-runtime', unit)
        self.assertNotIn('DynamicUser=true', unit)
        self.assertNotIn('[Install]', unit)
        self.assertIn('SocketMode=0600', files['systemd/rootful/p0-app-upstream.socket'])
        edge = files['quadlet/rootful/p0-edge.container']
        self.assertIn('Mount=type=bind,source=/run/p0-v2-upstreams/app-upstream,destination=/run/p0/upstreams/app-upstream,ro', edge)
        self.assertNotIn('Volume=/run/', edge)
        self.assertNotIn('Network=host', edge)

    def test_no_extra_builtin_fields_or_arbitrary_executor(self):
        for extra in ({'command':['/bin/sh']},{'image':IMAGE},{'environment':{'PATH':'/tmp'}},
                      {'mounts':[]},{'kind':'arbitrary-host-command'},{'runtime':'rootless'},
                      {'resources':{'tasksMax':True}}):
            items = declarations(); items[1].update(extra)
            with self.subTest(extra=extra), self.assertRaises(ContractError):
                catalog(items)

    def test_nonloopback_udp_public_missing_or_ambiguous_upstreams_refuse(self):
        for change in ({'bind':'0.0.0.0'}, {'bind':'10.0.0.2'}, {'bind':'host.containers.internal'},
                       {'protocol':'udp'}, {'public':True}, {'hostPort':False}, {'port':9090}):
            items = declarations(); items[0]['endpoints'][0].update(change)
            with self.subTest(change=change), self.assertRaises(ContractError):
                catalog(items)
        items=declarations();items[0]['endpoints']*=2
        with self.assertRaises(ContractError):
            catalog(items)

    def test_requires_declared_rootless_provider_and_real_readiness(self):
        for change in ('missing', 'rootful', 'no-edge', 'no-probe'):
            items=declarations()
            if change=='missing': items[1]['relay']['service']='absent'
            if change=='rootful': items[0]['runtime']='rootful'
            if change=='no-edge': items[1]['requires'][0]['kind']='order'
            if change=='no-probe': items[0].pop('probes')
            with self.subTest(change=change),self.assertRaises(ContractError):
                render(catalog(items),['edge'])

    def test_no_general_host_binds_or_cross_class_upstream_mounts(self):
        for change in ('rootless-consumer','wrong-target','no-edge','writable','wrong-provider','host-bind'):
            items=declarations()
            if change=='rootless-consumer':items[2]['runtime']='rootless'
            if change=='wrong-target':items[2]['mounts'][0]['target']='/etc'
            if change=='no-edge':items[2]['requires']=[]
            if change=='writable':items[2]['mounts'][0]['readOnly']=False
            if change=='wrong-provider':items[2]['mounts'][0]['source']='app'
            if change=='host-bind':items[2]['mounts'][0]['kind']='bind'
            with self.subTest(change=change),self.assertRaises(ContractError):
                render(catalog(items),['edge'])

    def test_native_unix_path_bound_and_ipv6_target(self):
        items=declarations();items[0]['endpoints'][0]['bind']='::1'
        _,files=render(catalog(items),['edge'])
        self.assertIn('[::1]:28080',files['systemd/rootful/p0-app-upstream.service'])
        items=declarations();items[1]['id']='a'*80
        items[2]['requires'][0]['service']=items[1]['id']
        items[2]['mounts'][0]['source']=items[1]['id']
        items[2]['mounts'][0]['target']='/run/p0/upstreams/'+items[1]['id']
        with self.assertRaises(ContractError):catalog(items)

    def test_target_hash_binds_only_selected_native_provider(self):
        first=declarations();second=copy.deepcopy(first)
        second[0]['endpoints'][0]['hostPort']=28081
        self.assertNotEqual(catalog(first).plan(['edge'])['inputSha256'],catalog(second).plan(['edge'])['inputSha256'])

    @unittest.skipUnless(Path('/usr/libexec/podman/quadlet').is_file(),'native Quadlet generator unavailable')
    def test_actual_nonexecuting_generator_preserves_restricted_directory_mount(self):
        _,files=render(catalog(declarations()),['edge'])
        with tempfile.TemporaryDirectory(prefix='p0-upstream-quadlet-') as temporary:
            root=Path(temporary)
            (root/'p0-edge.container').write_text(files['quadlet/rootful/p0-edge.container'])
            result=subprocess.run(['/usr/libexec/podman/quadlet','-dryrun','-no-kmsg-log'],
                                  cwd=root,env={'PATH':'/usr/bin:/bin','QUADLET_UNIT_DIRS':str(root)},
                                  stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                  text=True,timeout=15)
            self.assertEqual(result.returncode,0,'native translator refused restricted mount')
            self.assertIn('--mount',result.stdout)
            self.assertIn('type=bind,source=/run/p0-v2-upstreams/app-upstream,destination=/run/p0/upstreams/app-upstream,ro',result.stdout)
            self.assertNotIn('--network=host',result.stdout)

    @unittest.skipUnless(Path(PROXY).is_file(),'installed native socket proxy unavailable')
    def test_actual_native_proxy_forwards_synthetic_http_without_systemd_or_privilege(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200);self.end_headers();self.wfile.write(b'fixture-ok')
            def log_message(self,*args):pass
        server=http.server.HTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        process=None
        try:
            with tempfile.TemporaryDirectory(prefix='p0-relay-source-') as temporary:
                path=str(Path(temporary)/'http.sock')
                listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                listener.bind(path);listener.listen()
                descriptor=listener.fileno()
                bootstrap=('import os,sys;fd=int(sys.argv[1]);os.dup2(fd,3);os.set_inheritable(3,True);'
                           'os.close(fd) if fd!=3 else None;'
                           'env={"PATH":"/usr/bin:/bin","LISTEN_PID":str(os.getpid()),"LISTEN_FDS":"1"};'
                           'os.execve(sys.argv[2],[sys.argv[2],"--exit-idle-time=1s",sys.argv[3]],env)')
                try:
                    process=subprocess.Popen([sys.executable,'-I','-c',bootstrap,str(descriptor),PROXY,
                                              f'127.0.0.1:{server.server_port}'],pass_fds=(descriptor,),
                                             stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                finally:listener.close()
                client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);client.settimeout(5)
                try:
                    client.connect(path);client.sendall(b'GET / HTTP/1.0\r\nHost: fixture.invalid\r\n\r\n')
                    response=b''
                    while True:
                        data=client.recv(4096)
                        if not data:break
                        response+=data
                        self.assertLess(len(response),16384)
                    self.assertIn(b'200 OK',response);self.assertTrue(response.endswith(b'fixture-ok'))
                finally:client.close()
                self.assertEqual(process.wait(timeout=5),0)
        finally:
            if process is not None and process.poll() is None:
                process.terminate();process.wait(timeout=3)
            server.shutdown();server.server_close();thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
