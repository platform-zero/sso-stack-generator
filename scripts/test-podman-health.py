#!/usr/bin/env python3
"""Check real generated probes and native readiness argv without starting containers."""
import json
import importlib.util
import re
import shlex
import sys
from pathlib import Path

INPUT = re.compile(r"(?<!\$)\$(?:\{([A-Z_][A-Z0-9_]*)|([A-Z_][A-Z0-9_]*))")


def values(text, key):
    return [line.partition("=")[2] for line in text.splitlines() if line.startswith(key + "=")]


def decode(value):
    # Quadlet -> systemd command escaping; no shell/environment evaluation.
    return value.replace("$$", "$").replace("%%", "%")


def check(bundle, generated):
    services = json.loads((bundle / "stack.ir.json").read_text())["services"]
    files = {p.stem: p for p in (bundle / "quadlet").glob("*/*.container")}
    prefixes = [name.removesuffix("-huly-kvs") for name in files if name.endswith("-huly-kvs")]
    assert len(prefixes) == 1, "expected exact selected Huly KVS unit"
    prefix = prefixes[0]
    probes = gated = 0
    for name, service in services.items():
        unit_name = prefix + "-" + name
        if unit_name not in files:
            assert service["lifecycle"] == "on-demand" and not service.get("quadletManaged", False), name
            assert not any(s.get("dependencies", {}).get(name) == "healthy" for s in services.values()), name
            continue
        unit = files[unit_name]
        text = unit.read_text()
        if prefix != "webservices":
            assert values(text, "DNS") == ["192.168.140.1"], (name, "private DNS without public fallback")
            native = generated / unit.parent.name / (unit_name + ".service")
            native_argv = shlex.split(values(native.read_text(), "ExecStart")[0])
            assert native_argv[native_argv.index("--dns") + 1] == "192.168.140.1", name
            assert native_argv.count("--dns") == 1, name
        isolated_root = prefix != "webservices" and unit.parent.name == "rootful"
        assert ("Environment=DISABLE_HC_SYSTEMD=true" in text) == isolated_root, name
        config = service.get("health", {})
        test = config.get("test", [])
        enabled = bool(test) and test != ["NONE"] and not config.get("disable", False)
        needs_ready = any(s.get("dependencies", {}).get(name) == "healthy" for s in services.values())
        assert ("--sdnotify=healthy" in text) == needs_ready, name
        if not enabled:
            assert not values(text, "HealthCmd"), name
            assert not needs_ready, name
            continue
        aliases = {}
        if test[0] == "CMD-SHELL":
            def replace(match):
                key = match[1] or match[2]
                alias = "P0_HEALTH_INPUT_" + key
                aliases[alias] = "${" + key + "}"
                return "${" + alias if match[1] else "$" + alias
            expected = ["/bin/sh", "-c", INPUT.sub(replace, test[1]).replace("$$", "$")]
        else:
            assert test[0] == "CMD", name
            expected = [part.replace("$$", "$") for part in test[1:]]
        assert json.loads(decode(values(text, "HealthCmd")[0])) == expected, name
        for key, option in (("interval", "HealthInterval"), ("timeout", "HealthTimeout"),
                            ("start_period", "HealthStartPeriod"), ("retries", "HealthRetries")):
            if key in config:
                assert values(text, option) == [str(config[key])], (name, key)
        if aliases:
            env = (bundle / "runtime-env" / (name + ".env.template")).read_text()
            assert values(text, "EnvironmentFile"), name
            for key, expression in aliases.items():
                assert values(env, key) == [expression], (name, key)
        native = generated / unit.parent.name / (unit_name + ".service")
        native_text = native.read_text()
        argv = shlex.split(values(native_text, "ExecStart")[0])
        command = argv[argv.index("--health-cmd") + 1].replace("$$", "$").replace("%%", "%")
        assert json.loads(command) == expected, (name, "native health argv")
        notify = [arg.partition("=")[2] for arg in argv if arg.startswith("--sdnotify=")]
        assert notify[-1] == ("healthy" if needs_ready else "conmon"), (name, notify)
        assert values(native_text, "Type") == ["notify"], name
        if needs_ready:
            assert service["lifecycle"] == "daemon", name
            assert values(native_text, "TimeoutStartSec") == ["900"], name
            gated += 1
        probes += 1
    # Critical regression: KVS must be ordered after a health-notifying Cockroach.
    kvs = files[prefix + "-huly-kvs"].read_text()
    assert values(kvs, "After") and prefix + "-huly-cockroach.service" in values(kvs, "After")
    assert "--sdnotify=healthy" in files[prefix + "-huly-cockroach"].read_text()
    spec = importlib.util.spec_from_file_location('bundle_health_batches', bundle / 'ops/venue-start-quarantine.py')
    dispatcher = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dispatcher)
    directories = sorted(p for p in (bundle / 'quadlet').iterdir() if p.name.startswith('rootless-'))
    plan = {'prefix': prefix, 'accounts': [{'name': prefix + '-' + p.name.removeprefix('rootless-'),
            'uid': 3200 + i, 'home': '/nonexistent-fixture'} for i, p in enumerate(directories)]}
    batches = dispatcher.activation_batches(bundle, plan)
    order = {account['name'] if account else None: i for i, (account, _, _) in enumerate(batches)}
    barriers = {account['name'] if account else None: required for account, _, required in batches}
    owners = {name.removeprefix(prefix + '-'): (None if path.parent.name == 'rootful' else
              prefix + '-' + path.parent.name.removeprefix('rootless-')) for name, path in files.items()}
    cross_edges = 0
    for consumer, service in services.items():
        for producer, condition in service.get('dependencies', {}).items():
            if condition != 'healthy' or owners[consumer] == owners[producer]:
                continue
            owner, upstream = owners[consumer], owners[producer]
            assert order[upstream] < order[owner], (consumer, producer)
            assert (upstream, prefix + '-' + producer + '.service') in barriers[owner], (consumer, producer)
            cross_edges += 1
    print(f"[health-contract] {probes} probes / {gated} health-ready producers; native argv verified; {cross_edges} cross-manager healthy edges gated")


if __name__ == "__main__":
    check(Path(sys.argv[1]), Path(sys.argv[2]))
