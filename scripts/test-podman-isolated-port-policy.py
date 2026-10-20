#!/usr/bin/env python3
"""Exercise the actual Kotlin isolated-port guard; no listeners or services."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    os.umask(0o077)
    source = (ROOT / 'runtime-generator/stack-generator.main.kts').read_text()
    start = source.index('    if (unitPrefix != "webservices" && (portMap.size')
    guard = source[start:source.index('    return PodmanPolicy(', start)]
    originals = [80, 443, 9100, 7880, 7881, 7882] + list(range(18001, 18045))
    valid = {str(port): 56000 + i for i, port in enumerate(originals)}
    cases = []

    def case(label, mapping, ip='192.168.140.1', refusal=True):
        cases.append({'label': label, 'ports': mapping, 'nodeIp': ip, 'refusal': refusal})

    case('measured-fifty', valid, refusal=False)
    case('order-independent', dict(reversed(list(valid.items()))), refusal=False)
    missing = dict(valid); missing.pop('18001')
    case('missing-one', missing)
    retired = dict(valid); retired['18110'] = 56999
    case('retired-fifty-one', retired)
    duplicate = dict(valid); duplicate['443'] = duplicate['80']
    case('duplicate-destination', duplicate)
    overlap = dict(valid); overlap['443'] = 18002
    case('old-new-identity-overlap', overlap)
    for mandatory in ('80', '443', '9100', '7880', '7881', '7882'):
        changed = dict(valid); changed['19000'] = changed.pop(mandatory)
        case('missing-mandatory-' + mandatory, changed)
    case('wrong-ice-node', valid, ip='192.168.0.11')
    case('missing-ice-node', valid, ip='')
    header = '''import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
val json=ObjectMapper()
fun fail(message:String):Nothing=error(message)
fun validate(unitPrefix:String, portMap:Map<Int,Int>, siteConfig:JsonNode) {
'''
    tail = '''
}
for (case in json.readTree(java.io.File(args[0]))) {
 val ports=case.path("ports").fields().asSequence().associate { it.key.toInt() to it.value.asInt() }
 val site=json.createObjectNode()
 site.putObject("runtime").put("livekit_node_ip",case.path("nodeIp").asText())
 val result=runCatching { validate("p0test-r1", ports, site) }
 check(result.isFailure==case.path("refusal").asBoolean()) { "unexpected port policy result: ${case.path("label")} => $result" }
}
println("actual Kotlin isolated port guard cases passed")
'''
    cp = (ROOT / 'runtime-generator/build/generator-classpath.txt').read_text().strip()
    with tempfile.TemporaryDirectory(prefix='podman-isolated-ports-') as directory:
        p = Path(directory)
        script = p / 'ports.main.kts'; script.write_text(header + guard + tail)
        fixtures = p / 'cases.json'; fixtures.write_text(json.dumps(cases))
        subprocess.run(['java', '-Xmx512m', '-cp', cp,
                        'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler', '-script', str(script),
                        '-no-stdlib', '-no-reflect', '-classpath', cp, '--', str(fixtures)], check=True)
    print(f'[podman-isolated-ports] {len(cases)} actual Kotlin cases passed; SOURCE ONLY, no listener')


if __name__ == '__main__':
    main()
