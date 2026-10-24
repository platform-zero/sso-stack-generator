#!/usr/bin/env python3
"""Execute the owning Kotlin CIDR function, isolated from generator/live actions.

Uses the already prepared public generator classpath; never downloads toolchains,
changes source/index, generates a bundle or inspects host network/private data.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

BASE = Path(__file__).resolve().parents[1]
source = BASE / 'runtime-generator/stack-generator.main.kts'
before = source.read_bytes()
text = before.decode()
start = text.index('fun standaloneIngressDirectPeers(')
end = text.index('\nfun applyStandaloneHostProfile(', start)
function = text[start:end]
classpath = (BASE / 'runtime-generator/build/generator-classpath.txt').read_text().strip()
assert classpath and all(Path(p).is_file() for p in classpath.split(os.pathsep))
positives = [
    {}, {'ingressDirectNonClientCidrs': []},
    {'ingressDirectNonClientCidrs': ['127.0.0.0/8', '::1/128', '192.168.0.0/24']},
    {'ingressDirectNonClientCidrs': ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7', 'fd12:3456::/32']},
    {'ingressDirectNonClientCidrs': ['127.0.0.1/32', '10.1.2.3/32']},
]
negative_values = [None, '127.0.0.0/8', 1, {}, [None], [True],
    ['0.0.0.0/0'], ['10.0.0.0/7'], ['172.16.0.0/11'], ['192.168.0.1/24'],
    ['127.000.0.0/8'], ['127.0.0.0/08'], ['127.0.0.0/-1'], ['127.0.0.0/33'],
    ['127.0.0.0/8', '127.0.0.0/8'], ['8.8.8.8/32'], ['localhost/32'],
    ['127.0.0.0/8\nunsafe'], ['127.0.0.0/8;unsafe'], ['127.0.0.0/8 #unsafe'],
    ['::/0'], ['fc00::/6'], ['FC00::/7'], ['fc00:0:0:0:0:0:0:0/7'],
    ['2001:db8::/32'], ['::1%lo/128'], ['::ffff:127.0.0.1/128'], ['fc00::1/7'],
    ['127.0.0.0/8'] * 65,
]
negatives = [{'ingressDirectNonClientCidrs': value} for value in negative_values]
# JSON is passed as a normal escaped Kotlin string, never interpolated script.
def literal(value):
    return json.dumps(json.dumps(value, separators=(',', ':'))).replace('$', '${\'$\'}')
body = '''import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
fun fail(message: String): Nothing = error(message)
val mapper = ObjectMapper()
'''+function+'\n'
for index, value in enumerate(positives):
    expected = json.dumps(value.get('ingressDirectNonClientCidrs', []))
    body += f'check(standaloneIngressDirectPeers(mapper.readTree({literal(value)})) == mapper.readTree({json.dumps(expected)}).map {{ it.asText() }}) {{ "positive {index}" }}\n'
for index, value in enumerate(negatives):
    body += f'run {{ var refused = false; try {{ standaloneIngressDirectPeers(mapper.readTree({literal(value)})) }} catch (_: IllegalStateException) {{ refused = true }}; check(refused) {{ "negative {index} unexpectedly accepted" }} }}\n'
body += f'println("PASS {len(positives) + len(negatives)} actual Kotlin ingress CIDR cases; source only")\n'
java = str(Path(os.environ['JAVA_HOME']) / 'bin/java') if os.environ.get('JAVA_HOME') else 'java'
with tempfile.TemporaryDirectory(prefix='standalone-ingress-source-') as temporary:
    script = Path(temporary) / 'ingress.main.kts'
    script.write_text(body)
    result = subprocess.run([java, '-Xmx1024m', '-XX:ActiveProcessorCount=2', '-cp', classpath,
        'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler', '-script', str(script),
        '-no-stdlib', '-no-reflect', '-classpath', classpath], timeout=105)
    if result.returncode:
        raise SystemExit(result.returncode)
assert source.read_bytes() == before, 'owning Kotlin source changed during proof'
print('Owning generator source SHA256:', hashlib.sha256(before).hexdigest())
