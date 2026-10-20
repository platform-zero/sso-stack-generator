#!/usr/bin/env python3
"""Actual Kotlin resource helper and native systemd parse; no runtime services."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    os.umask(0o077)
    source = (ROOT / 'runtime-generator/stack-generator.main.kts').read_text()
    helper = source[source.index('fun resourceLimit('):source.index('fun renderQuadletService(')]
    assert 'resourceLimit(limits.path("memory"), "memory")' in source
    cases = [
        ({}, 'memory', False, None),
        ({'value': None}, 'memory', False, None),
        ({'value': ''}, 'memory', False, None),
    ]
    for value, expected in [
        ('512m', '512M'), ('256m', '256M'), ('2g', '2G'),
        ('1024k', '1024K'), ('1t', '1T'), ('2p', '2P'), ('1e', '1E'),
        ('512M', '512M'), ('2G', '2G'), ('536870912', '536870912'),
        ('2.5g', '2.5G'), ('512MiB', '512MiB'),
        ('${MEMORY_LIMIT:-512m}', '512M'), ('${MEMORY_LIMIT:-2G}', '2G'),
    ]:
        cases.append(({'value': value}, 'memory', False, expected))
    for value in ['0m', '-1m', '512mm', '512m;Other=x', '${MEMORY_LIMIT}',
                  '${MEMORY_LIMIT:-}', '${MEMORY_LIMIT:-512m};Other=x',
                  'infinity', 'NaN', '1e2', '512m\nOther=x', True]:
        cases.append(({'value': value}, 'memory', True, None))
    for kind, value, expected in [('cpus', '0.5', '0.5'), ('cpus', '${CPUS:-2}', '2'),
                                  ('pids', '128', '128'), ('pids', '${PIDS:-64}', '64')]:
        cases.append(({'value': value}, kind, False, expected))
    for kind, value in [('cpus', '2m'), ('cpus', '0'), ('cpus', '-1'),
                        ('pids', '128m'), ('pids', '0'), ('pids', '1.5')]:
        cases.append(({'value': value}, kind, True, None))
    header = '''import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
val json=ObjectMapper()
fun fail(message:String):Nothing=error(message)
'''
    tail = '''
for (case in json.readTree(java.io.File(args[0]))) {
 val result=runCatching { resourceLimit(case[0].path("value"), case[1].asText()) }
 check(result.isFailure==case[2].asBoolean()) { "unexpected resource result: $case => $result" }
 if(result.isSuccess) check(result.getOrThrow()==if(case[3].isNull) null else case[3].asText())
}
println("actual Kotlin concrete resource cases passed")
'''
    cp = (ROOT / 'runtime-generator/build/generator-classpath.txt').read_text().strip()
    with tempfile.TemporaryDirectory(prefix='podman-resource-limits-') as directory:
        p = Path(directory)
        script = p / 'resource.main.kts'
        script.write_text(header + helper + tail)
        fixtures = p / 'cases.json'
        fixtures.write_text(json.dumps(cases))
        subprocess.run(['java', '-Xmx512m', '-cp', cp,
                        'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler', '-script', str(script),
                        '-no-stdlib', '-no-reflect', '-classpath', cp, '--', str(fixtures)], check=True)
        unit = p / 'resource-case.service'
        unit.write_text('[Unit]\nDescription=Resource parser check only\n'
                        '[Service]\nType=oneshot\nExecStart=/usr/bin/true\nMemoryMax=512M\n')
        subprocess.run(['systemd-analyze', 'verify', '--man=no', str(unit)], check=True)
    print(f'[podman-resource-limits] {len(cases)} actual Kotlin cases and native '
          'canonical MemoryMax parse passed; SOURCE/PARSER ONLY, no application execution')


if __name__ == '__main__':
    main()
