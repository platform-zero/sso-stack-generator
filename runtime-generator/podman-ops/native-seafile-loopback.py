#!/usr/bin/env python3
"""Finite loopback relay INSIDE the temporary networkless DB namespace.

No credentials, file access, receipt handling, host listener or admission API.
Main enters the exact held native network namespace and drops UID/GID/caps before
executing these public bytes. Parameters are two selected loopback port pairs.
"""
import json
import os
import select
import socket
import sys
import threading


def connection(client, target):
    upstream = None
    try:
        upstream = socket.create_connection(('127.0.0.1', target), timeout=5)
        client.setblocking(False); upstream.setblocking(False)
        peers = {client: upstream, upstream: client}
        while True:
            readable, _, _ = select.select(list(peers), [], [], 60)
            if not readable:
                return
            for source in readable:
                data = source.recv(65536)
                if not data:
                    return
                destination = peers[source]
                # Bounded blocking backpressure, never an unbounded queue.
                destination.settimeout(10)
                destination.sendall(data)
                destination.setblocking(False)
    except (OSError, ValueError):
        pass
    finally:
        client.close()
        if upstream is not None:
            upstream.close()


def main():
    # Only two finite service ports; no arbitrary address/destination support.
    assert len(sys.argv) == 2 and os.getuid() not in (0, 1000)
    pairs = json.loads(sys.argv[1])
    assert isinstance(pairs, list) and len(pairs) <= 2
    assert all(isinstance(pair, list) and len(pair) == 2 and
               all(type(port) is int and 1024 <= port <= 65535 for port in pair)
               and pair[1] in (3306, 6379) and pair[0] != pair[1] for pair in pairs)
    assert len({pair[0] for pair in pairs}) == len(pairs)
    sockets = {}
    for port, target in pairs:
        server = socket.socket()
        server.bind(('127.0.0.1', port)); server.listen(16)
        sockets[server] = target
    print('SEAFILE_PRIVATE_LOOPBACK_READY', flush=True)
    while True:
        readable, _, _ = select.select(list(sockets), [], [], 60)
        for server in readable:
            client, _ = server.accept()
            if threading.active_count() >= 33:
                client.close()
            else:
                threading.Thread(target=connection, args=(client, sockets[server]), daemon=True).start()


if __name__ == '__main__':
    main()
