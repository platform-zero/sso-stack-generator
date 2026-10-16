#!/usr/bin/env python3
"""Real strict-TLS local sockets for the isolated Caddy transport checker."""
import importlib.util
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

src=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/verify-venue-caddy-live.py'
spec=importlib.util.spec_from_file_location('caddy_live',src)
ready=importlib.util.module_from_spec(spec);spec.loader.exec_module(ready)

class CaddyTransport(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.config=self.root/'Caddyfile';self.config.write_text('{\nadmin off\n}\n')
        self.cert=self.root/'local-ca.crt';self.key=self.root/'local-ca.key'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-sha256','-days','1',
            '-subj','/CN=portal.datamancy.net','-addext','subjectAltName=DNS:portal.datamancy.net',
            '-addext','basicConstraints=critical,CA:TRUE',
            '-keyout',str(self.key),'-out',str(self.cert)],check=True,capture_output=True,timeout=35)
        self.server=[]
    def start(self,tls=False,status=200,location=None):
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1)
        port=listener.getsockname()[1];self.addCleanup(listener.close)
        if tls:
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(str(self.cert),str(self.key))
        def serve():
            try:
                conn,_=listener.accept()
                with conn:
                    if tls:conn=ctx.wrap_socket(conn,server_side=True)
                    with conn:
                        conn.settimeout(5);conn.recv(4096)
                        body='HTTP/1.1 '+str(status)+' Example\r\nServer: Caddy\r\n'
                        if location:body+='Location: '+location+'\r\n'
                        conn.sendall((body+'Content-Length: 0\r\nConnection: close\r\n\r\n').encode())
            except (OSError,ssl.SSLError):pass
        thread=threading.Thread(target=serve,daemon=True);thread.start();self.server.append(thread)
        return port
    def test_strict_hostname_and_ca_redirect_scoped_success(self):
        uri='/__p0_venue_transport_probe?scope=caddy'
        http=self.start(status=308,location='https://portal.datamancy.net'+uri)
        https=self.start(tls=True)
        with patch.object(ready,'authority',return_value=('portal.datamancy.net',http,https,self.cert,self.config)):
            proof=ready.probe(None,None,None)
        self.assertTrue(proof['tlsHostnameAndCaVerified'])
        self.assertEqual(proof['httpStatus'],308)
        self.assertEqual(proof['httpsStatus'],200)
        self.assertFalse(proof['upstreamReady'] or proof['guestReachabilityProven'] or proof['activationAuthorized'])
        self.assertEqual(proof['acceptedIntegratedInstalls'],0)
    def test_redirect_to_nonstandard_port_is_not_accepted(self):
        http=self.start(status=308,location='https://portal.datamancy.net:56042/__p0_venue_transport_probe?scope=caddy')
        with patch.object(ready,'authority',return_value=('portal.datamancy.net',http,9,self.cert,self.config)):
            with self.assertRaises(ready.Refusal):ready.probe(None,None,None)
    def test_wrong_dns_name_fails_strict_certificate_validation(self):
        uri='/__p0_venue_transport_probe?scope=caddy'
        http=self.start(status=308,location='https://wrong.datamancy.net'+uri)
        https=self.start(tls=True)
        with patch.object(ready,'authority',return_value=('wrong.datamancy.net',http,https,self.cert,self.config)):
            with self.assertRaises(ssl.SSLCertVerificationError):ready.probe(None,None,None)

if __name__=='__main__':unittest.main()
