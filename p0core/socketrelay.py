"""Closed Host builtin: private Unix socket -> declared loopback HTTP port.

No caller executable, host path, arbitrary URL or container-admin socket.
Rendering is not Root installation or authorization.
"""
from __future__ import annotations

import ipaddress

from .model import ContractError, fields, identifier

BASE = '/run/p0-v2-upstreams'
PROXY = '/usr/lib/systemd/systemd-socket-proxyd'
KIND = 'http-socket-relay'


def directory(name):
    identifier(name)
    result = BASE + '/' + name
    if len((result + '/http.sock').encode()) > 107:
        raise ContractError('relay identifier exceeds native Unix socket path bound')
    return result


def validate(catalog, service):
    declaration = service.declaration
    fields(declaration, {'id', 'runtime', 'requires', 'kind', 'relay'}, {'description', 'resources'})
    if declaration['kind'] != KIND or service.runtime != 'rootful' or service.image is not None:
        raise ContractError('Host socket relay requires its closed rootful builtin executor')
    directory(service.id)
    fields(declaration['relay'], {'service', 'port'})
    target = declaration['relay']['service']
    identifier(target)
    port = declaration['relay']['port']
    if type(port) is not int or not 1 <= port <= 65535:
        raise ContractError('invalid declared upstream container port')
    if target not in catalog.services or catalog.services[target].runtime != 'rootless':
        raise ContractError('relay upstream must be a declared rootless service')
    if not any(edge.service == target and edge.kind == 'ready' for edge in service.requires):
        raise ContractError('relay requires actual upstream readiness edge')
    endpoints = catalog.services[target].declaration.get('endpoints', [])
    if not isinstance(endpoints, list):
        raise ContractError('invalid upstream endpoints')
    selected = []
    for endpoint in endpoints:
        fields(endpoint, {'port', 'hostPort', 'bind'}, {'protocol', 'public'})
        if endpoint['port'] != port:
            continue
        if (type(endpoint['port']) is not int or type(endpoint['hostPort']) is not int
                or not 1 <= endpoint['hostPort'] <= 65535 or endpoint.get('protocol', 'tcp') != 'tcp'
                or endpoint.get('public', False) is not False):
            raise ContractError('relay needs an unambiguous private TCP endpoint')
        try:
            address = ipaddress.ip_address(endpoint['bind'])
        except (ValueError, TypeError) as error:
            raise ContractError('relay target must be a literal loopback address') from error
        if not address.is_loopback:
            raise ContractError('relay target must be a literal loopback address')
        selected.append((address, endpoint['hostPort']))
    if len(selected) != 1:
        raise ContractError('relay target endpoint missing or ambiguous')
    resources = declaration.get('resources', {})
    fields(resources, set(), {'memoryMax', 'tasksMax'})
    if any(type(value) is not int or value < 1 for value in resources.values()):
        raise ContractError('invalid relay resource limit')
    return selected[0]


def render(catalog, service):
    address, port = validate(catalog, service)
    provider = catalog.services[service.declaration['relay']['service']]
    # The graph's readiness runner must actually check this upstream before
    # Root activation. Systemd ordering cannot cross user/system managers.
    if not provider.declaration.get('probes'):
        raise ContractError('relay upstream lacks readiness probe')
    name = 'p0-' + service.id
    prefix = '# Generated closed P0 HTTP socket relay; no auto-start.\n'
    socket = (prefix + '[Unit]\nDescription=P0 private upstream listener\n\n[Socket]\n'
              + f'ListenStream={directory(service.id)}/http.sock\nService={name}.service\n'
              + 'SocketUser=p0-runtime\nSocketGroup=p0-runtime\nSocketMode=0600\n'
              + 'DirectoryMode=0710\nRemoveOnStop=true\n')
    host = f'[{address}]' if address.version == 6 else str(address)
    unit = (prefix + '[Unit]\nDescription=P0 fixed upstream forwarding\n\n[Service]\n'
            + f'ExecStart={PROXY} --exit-idle-time=5min {host}:{port}\n'
            + 'User=p0-runtime\nGroup=p0-runtime\nUMask=0077\nNoNewPrivileges=true\n'
            + 'CapabilityBoundingSet=\nAmbientCapabilities=\nPrivateTmp=true\nPrivateDevices=true\n'
            + 'ProtectSystem=strict\nProtectHome=true\nProtectKernelTunables=true\n'
            + 'ProtectKernelModules=true\nProtectControlGroups=true\n'
            + 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nRestrictSUIDSGID=true\n'
            + 'TimeoutStartSec=30\nTimeoutStopSec=30\nRestart=no\n')
    for key, directive in (('memoryMax', 'MemoryMax'), ('tasksMax', 'TasksMax')):
        if key in service.declaration.get('resources', {}):
            unit += f'{directive}={service.declaration["resources"][key]}\n'
    return {f'systemd/rootful/{name}.socket': socket, f'systemd/rootful/{name}.service': unit}
