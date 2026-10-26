"""Pure bounded new-network IPAM. No native commands or activation authority."""
from __future__ import annotations

import hashlib
import ipaddress
import re

from .model import ContractError, canonical, fields, identifier

POOLS = tuple(ipaddress.IPv4Network(value) for value in ('172.16.0.0/12', '10.0.0.0/8', '192.168.0.0/16'))


def _prefix(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 80 or '%' in value:
        raise ContractError('network inventory needs literal prefixes')
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError as error:
        raise ContractError('invalid network inventory prefix') from error


def _strings(values, limit):
    if not isinstance(values, list) or len(values) > limit:
        raise ContractError('network inventory bound exceeded')
    return values


def _snapshot(snapshot):
    fields(snapshot, {'schemaVersion', 'interfaces', 'routes', 'reservedPrefixes'}, set())
    if type(snapshot['schemaVersion']) is not int or snapshot['schemaVersion'] != 1:
        raise ContractError('unsupported network inventory schema')
    if len(canonical(snapshot)) > 1024 * 1024:
        raise ContractError('network inventory byte bound exceeded')
    names, occupied = set(), []
    for interface in _strings(snapshot['interfaces'], 256):
        fields(interface, {'name', 'prefixes'}, set())
        name = interface['name']
        if not isinstance(name, str) or not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}', name) or name in names:
            raise ContractError('invalid or duplicate host interface')
        names.add(name)
        occupied.extend(_prefix(value) for value in _strings(interface['prefixes'], 64))
    # A default route does not allocate all addresses. Interface and explicit
    # exclusion /0 prefixes DO reserve everything; never discard those.
    for value in _strings(snapshot['routes'], 4096):
        prefix = _prefix(value)
        if prefix.prefixlen:
            occupied.append(prefix)
    occupied.extend(_prefix(value) for value in _strings(snapshot['reservedPrefixes'], 4096))
    intervals = sorted((int(item.network_address), int(item.broadcast_address))
                       for item in occupied if item.version == 4)
    merged = []
    for low, high in intervals:
        if merged and low <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(high, merged[-1][1]))
        else:
            merged.append((low, high))
    return names, merged


def plan_new(snapshot, network='identity', interface='p0v2edge0'):
    """Select a fresh /24 from observed/excluded space, never adopt a link."""
    identifier(network)
    if not isinstance(interface, str) or not re.fullmatch(r'p0v2[a-z0-9]{1,11}', interface):
        raise ContractError('network interface must use dedicated bounded namespace')
    names, occupied = _snapshot(snapshot)
    if interface in names:
        raise ContractError('requested interface exists; ownership/adoption not inferred')
    size = 256
    chosen = None
    for pool in POOLS:
        candidate, end = int(pool.network_address), int(pool.broadcast_address)
        for low, high in occupied:
            if high < candidate:
                continue
            if candidate + size - 1 < low:
                break
            candidate = ((high + 1 + size - 1) // size) * size
            if candidate + size - 1 > end:
                break
        if candidate + size - 1 <= end:
            chosen = ipaddress.IPv4Network((candidate, 24))
            break
    if chosen is None:
        raise ContractError('no nonoverlapping private network remains in approved pools')
    desired = {'networkName': 'p0-' + network, 'interfaceName': interface, 'subnet': str(chosen),
               'gateway': str(chosen.network_address + 1), 'ingressAddress': str(chosen.network_address + 2)}
    return {'schemaVersion': 1, 'scope': 'new-network-plan-only', 'desired': desired,
            'desiredSha256': hashlib.sha256(canonical(desired)).hexdigest(),
            'inventorySha256': hashlib.sha256(canonical(snapshot)).hexdigest(),
            'nativeRecheckRequired': True, 'installationCertified': False}


def snapshot_from_ip_json(addresses, routes, reserved=()):
    """Normalize public `ip -j address/route` metadata supplied explicitly.

    The caller must gather all required route tables and separately supply
    known inactive/network-namespace allocations. This does not claim that
    host-visible routes enumerate every existing engine or private namespace.
    """
    if not isinstance(reserved, (tuple, list)):
        raise ContractError('explicit network exclusions must be an array')
    interfaces = []
    for item in _strings(addresses, 256):
        if not isinstance(item, dict) or not isinstance(item.get('addr_info'), list):
            raise ContractError('invalid native address inventory')
        prefixes = []
        for address in _strings(item['addr_info'], 64):
            if not isinstance(address, dict) or address.get('family') not in ('inet', 'inet6'):
                raise ContractError('unsupported native address entry')
            value, length = address.get('local'), address.get('prefixlen')
            if type(length) is not int or not isinstance(value, str):
                raise ContractError('invalid native address prefix')
            try:
                parsed = ipaddress.ip_interface(f'{value}/{length}')
            except ValueError as error:
                raise ContractError('invalid native address prefix') from error
            if (parsed.version == 4) != (address['family'] == 'inet'):
                raise ContractError('native address family mismatch')
            prefixes.append(str(parsed.network))
        interfaces.append({'name': item.get('ifname'), 'prefixes': prefixes})
    prefixes = []
    for item in _strings(routes, 4096):
        if not isinstance(item, dict):
            raise ContractError('invalid native route inventory')
        destination = item.get('dst')
        if not isinstance(destination, str):
            raise ContractError('native route destination missing')
        if destination == 'default':
            continue
        prefixes.append(str(_prefix(destination)))
    snapshot = {'schemaVersion': 1, 'interfaces': interfaces, 'routes': prefixes,
                'reservedPrefixes': list(reserved)}
    _snapshot(snapshot)
    return snapshot
