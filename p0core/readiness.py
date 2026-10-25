"""Bounded host-side observations; never executes application supplied commands."""
from __future__ import annotations

import http.client
import socket
import time
from typing import Callable

from .model import ContractError


class ReadinessError(RuntimeError):
    pass


def observe(probe: dict, timeout: float) -> bool:
    if timeout <= 0:
        return False
    if probe['kind'] == 'tcp':
        try:
            # Callers validate numeric addresses; getaddrinfo for arbitrary DNS
            # has no reliable stdlib deadline. Reject rather than hang setup.
            with socket.create_connection((probe['host'], probe['port']), timeout=timeout):
                return True
        except OSError:
            return False
    if probe['kind'] == 'http':
        connection = http.client.HTTPConnection(probe['host'], probe['port'], timeout=timeout)
        try:
            connection.request('GET', probe.get('path', '/'), headers={'Connection': 'close'})
            response = connection.getresponse()
            # No redirects, response bodies or potentially secret headers logged.
            return response.status == probe.get('status', 200)
        except (OSError, http.client.HTTPException):
            return False
        finally:
            connection.close()
    raise ContractError('unsupported readiness probe')


def wait(probes: list[dict], budget: float = 60, *,
         check: Callable = observe, clock: Callable = time.monotonic,
         sleep: Callable = time.sleep, cancelled: Callable = lambda: False) -> dict:
    import ipaddress
    if not probes or not 0 < budget <= 300:
        raise ContractError('readiness requires probes and bounded budget')
    for probe in probes:
        try:
            ipaddress.ip_address(probe['host'])
        except (ValueError, KeyError, TypeError) as error:
            raise ContractError('bounded host probes require numeric IP addresses') from error
        if probe.get('kind') not in ('tcp', 'http'):
            raise ContractError('unsupported readiness probe')
        if type(probe.get('port')) is not int or not 1 <= probe['port'] <= 65535:
            raise ContractError('invalid readiness port')
    started = clock()
    deadline = started + budget
    attempts = 0
    for probe in probes:
        probe_budget = probe.get('timeoutSeconds', 30)
        if type(probe_budget) is not int or not 1 <= probe_budget <= 300:
            raise ContractError('invalid readiness deadline')
        probe_deadline = min(deadline, clock() + probe_budget)
        while True:
            if cancelled():
                raise ReadinessError('readiness cancelled; service lifetime unchanged')
            remaining = probe_deadline - clock()
            if remaining <= 0:
                raise ReadinessError('readiness deadline exceeded')
            attempts += 1
            if check(probe, min(remaining, 1.0)):
                if clock() >= probe_deadline:
                    raise ReadinessError('readiness result exceeded deadline')
                break
            sleep(min(0.1, max(0, probe_deadline - clock())))
    return {'schemaVersion': 1, 'scope': 'readiness-observation-only',
            'ready': True, 'attempts': attempts, 'elapsedSeconds': clock() - started,
            'installationCertified': False}
