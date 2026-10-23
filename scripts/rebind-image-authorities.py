#!/usr/bin/env python3
"""Rebind immutable image pin authority labels by explicit old/new domain policy.

Changes only store-user labels, never image identities/registry references. Writes
one NEW file; operator review and a site-source commit are separate steps. Does
not invoke a runtime, read credentials, pull images or change any Linux account.
"""
import argparse
import json
import os
from pathlib import Path
import re
import sys
import yaml


def users(policy):
    domains = policy['podman']['domains']
    if not isinstance(domains, dict) or not domains:
        raise ValueError('explicit domain policies required')
    result = {}
    for name, row in domains.items():
        user = row['user']
        if not isinstance(user, str) or not re.fullmatch(r'[a-z_][a-z0-9_-]*', user) or user == 'root':
            raise ValueError('invalid domain user')
        result[name] = user
    if len(set(result.values())) != len(result):
        raise ValueError('duplicate domain account')
    return result


def rebind(pins, old, new):
    before, after = users(old), users(new)
    if set(before) != set(after):
        raise ValueError('domain membership changed; store-label-only rebinding refused')
    mapping = {before[name]: after[name] for name in before}
    mapping['root'] = 'root'
    base = isinstance(pins, dict) and 'baseImages' in pins
    rows = pins['baseImages'] if base else pins
    if not isinstance(rows, dict) or not rows:
        raise ValueError('image pin object required')
    output = {}
    for key, value in rows.items():
        user, separator, reference = key.partition('|')
        if not separator or not reference or '|' in reference or user not in mapping:
            raise ValueError('unknown image authority/reference')
        if base:
            if not isinstance(value, dict) or not re.fullmatch(r'sha256:[a-f0-9]{64}', value.get('configId', '')):
                raise ValueError('invalid immutable base image identity')
        elif not isinstance(value, str) or not re.fullmatch(r'sha256:[a-f0-9]{64}', value):
            raise ValueError('invalid immutable registry image identity')
        rebound = mapping[user] + '|' + reference
        if rebound in output:
            raise ValueError('image authority collision')
        output[rebound] = value
    if base:
        return {**pins, 'baseImages': output}
    return output


def read_plain(path):
    path = Path(path).absolute()
    for component in (path, *path.parents):
        if component.is_symlink():
            raise ValueError('linked pin/policy paths refused')
    return path.read_text()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('from-policy', 'to-policy', 'pins', 'output'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    try:
        output = rebind(json.loads(read_plain(args.pins)),
                        yaml.safe_load(read_plain(args.from_policy)), yaml.safe_load(read_plain(args.to_policy)))
        path = Path(args.output).absolute()
        if any(parent.is_symlink() for parent in path.parents):
            raise ValueError('linked output parents refused')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as target:
            json.dump(output, target, indent=2, sort_keys=True); target.write('\n')
            target.flush(); os.fsync(target.fileno())
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError):
        print('image authority rebind refused; verify policy membership and immutable pin structure', file=sys.stderr)
        return 1
    print('Wrote new immutable pins with explicit domain-user rebinding; no runtime/account mutations')
    return 0


if __name__ == '__main__': raise SystemExit(main())
