#!/usr/bin/env python3
"""Execute actual standalone compiler functions and their results consumer.

Public source + disposable JSON/temp filesystem only. No generator command,
Git, downloads, engine, private inputs, activation or claimed installed proof.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import yaml

BASE = Path(__file__).resolve().parents[1]
MODULE = BASE.parent / 'module-delivery/test-runners'
SOURCE = BASE / 'runtime-generator/stack-generator.main.kts'
before = SOURCE.read_bytes()
text = before.decode()

def function(start, end):
    return text[text.index(start):text.index(end, text.index(start))]

functions = '\n'.join([
    function('fun standaloneHost(', '\nfun standaloneCaddyLogRoot('),
    function('fun standaloneResultsMount(', '\nfun standaloneIngressDirectPeers('),
    function('fun standaloneIngressDirectPeers(', '\nfun applyStandaloneHostProfile('),
    function('fun applyStandaloneHostProfile(', '\nfun materializeStandaloneHostInputs('),
])
metadata = yaml.safe_load((MODULE / 'stack.runtime.yaml').read_text())
scope = '/mnt/stack/synthetic-results'
volume = scope + '/volumes/test-runners'
domain = dict(name='test-runners', user='webservices-lab-test-runners', uid=786,
              modules=['test-runners'], stateRoot=scope + '/podman/test-runners/state',
              graphRoot=scope + '/podman/test-runners/storage', volumeRoot=volume)
ir = dict(services=metadata['services'], volumes={'caddy_ca': {'hostPath': scope + '/volumes/platform/caddy_ca'}})
for service in ir['services'].values():
    service.update(module='test-runners', rootlessDomain='test-runners', rootlessUser=domain['user'], rootlessVolumeRoot=volume)
manifest = dict(deploymentMode='standalone', storageScope=dict(root=scope, dataClass='synthetic'))
positives = [(ir, domain, manifest)]
legacy = copy.deepcopy(ir)
positives.append((legacy, domain, {}))
negatives = []
for name in ('test-runner', 'test-runner-managed'):
    for key, value in [('module', 'other'), ('placement', 'rootful'), ('lifecycle', 'daemon'),
                       ('rootlessDomain', 'apps'), ('rootlessUser', 'operator'), ('rootlessVolumeRoot', '/unscoped'),
                       ('userns', 'host'), ('user', '1000:1000'),
                       ('x-standalone-results-mount', {'version': True, 'target': '/app/test-results'}),
                       ('x-standalone-results-mount', {'version': 1, 'target': '/wrong'}),
                       ('x-standalone-results-mount', None),
                       ('volumes', [{'type': 'bind', 'source': '${OTHER_DIR}', 'target': '/app/test-results'}]),
                       ('volumes', [{'type': 'bind', 'source': '/mnt/stack/podman/test-runners/state/test-runner/results', 'target': '/app/test-results'}]),
                       ('volumes', [{'type': 'bind', 'source': volume + '/test-results', 'target': '/app/test-results'}]),
                       ('volumes', ['${TEST_RESULTS_HOST_DIR:?TEST_RESULTS_HOST_DIR must be set by run-tests.sh}:/app/test-results:U'])]:
        changed = copy.deepcopy(ir)
        changed['services'][name][key] = value
        negatives.append((changed, domain, manifest))
    changed = copy.deepcopy(ir)
    del changed['services'][name]['x-standalone-results-mount']
    negatives.append((changed, domain, manifest))
    for field, value in [('target', '/wrong'), ('type', 'volume'), ('read_only', True), ('bind', {'create_host_path': True})]:
        changed = copy.deepcopy(ir)
        mounts = changed['services'][name]['volumes']
        mount = next(m for m in mounts if isinstance(m, dict) and m.get('target') == '/app/test-results')
        mount[field] = value
        negatives.append((changed, domain, manifest))
    changed = copy.deepcopy(ir)
    changed['services'][name]['environment']['TEST_RUNNER_STANDALONE_RESULTS'] = 'v1'
    negatives.append((changed, domain, manifest))
    changed = copy.deepcopy(ir)
    original = next(m for m in changed['services'][name]['volumes'] if isinstance(m, dict) and m.get('target') == '/app/test-results')
    changed['services'][name]['volumes'].append(copy.deepcopy(original))
    negatives.append((changed, domain, manifest))
for key, value in [('uid', 1000), ('user', 'operator'), ('modules', []), ('name', 'apps'),
                   ('volumeRoot', '/mnt/stack/unscoped/test-runners'),
                   ('volumeRoot', volume + '/'), ('volumeRoot', volume + '/../other'),
                   ('volumeRoot', volume + '/${OVERRIDE}')]:
    changed = dict(domain)
    changed[key] = value
    changed_ir = copy.deepcopy(ir)
    for service in changed_ir['services'].values():
        service['rootlessVolumeRoot'] = changed['volumeRoot']
    negatives.append((changed_ir, changed, manifest))
foreign = copy.deepcopy(ir)
foreign['services']['unrelated'] = foreign['services'].pop('test-runner')
negatives.append((foreign, domain, manifest))

# Kotlin strings never interpolate test JSON; no shell or generated DSL input.
def literal(value):
    return json.dumps(json.dumps(value, separators=(',', ':'))).replace('$', "${'$'}")

body = '''import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
import com.fasterxml.jackson.databind.node.ArrayNode
import kotlin.io.path.Path
import java.nio.file.Path
val mapper = ObjectMapper()
fun fail(message: String): Nothing = error(message)
fun JsonNode.fieldsMap(): List<Pair<String, JsonNode>> = fields().asSequence().map { it.key to it.value }.toList()
fun JsonNode.textOrNull(): String? = if (isTextual) asText() else null
fun obj(): ObjectNode = mapper.createObjectNode()
fun arr(): ArrayNode = mapper.createArrayNode()
data class FixtureDomain(val name: String, val user: String, val stateRoot: String, val graphRoot: String,
    val volumeRoot: String, val modules: Set<String>, val uid: Int?)
data class FixturePolicy(val domains: List<FixtureDomain>, val unitPrefix: String = "webservices")
lateinit var activePodmanPolicy: FixturePolicy
fun fixturePolicy(node: JsonNode) = FixturePolicy(listOf(FixtureDomain(node.path("name").asText(), node.path("user").asText(),
    node.path("stateRoot").asText(), node.path("graphRoot").asText(), node.path("volumeRoot").asText(),
    node.path("modules").map { it.asText() }.toSet(), node.path("uid").asInt())))
// Unselected Caddy/volume-init branches are fixture dependencies, not tested implementations.
fun standaloneCaddyLogRoot(): String = error("unselected Caddy branch")
fun standaloneStorageMarkerSha(manifest: JsonNode): String = error("unselected storage-check branch")
'''+functions+'\n'
with tempfile.TemporaryDirectory(prefix='standalone-results-kotlin-') as temporary:
    output = Path(temporary) / 'compiled-ir.json'
    for index, (fixture, policy, selected_manifest) in enumerate(positives):
        body += f'''run {{
activePodmanPolicy = fixturePolicy(mapper.readTree({literal(policy)}))
val ir = mapper.readTree({literal(fixture)}) as ObjectNode
val original = ir.deepCopy()
applyStandaloneHostProfile(ir, mapper.readTree({literal(selected_manifest)}))
'''
        if selected_manifest:
            body += f'''for (name in listOf("test-runner", "test-runner-managed")) {{
val service = ir.path("services").path(name)
val mounts = service.path("volumes").filter {{ it.path("target").asText() == "/app/test-results" }}
check(mounts.size == 1 && mounts.single().path("source").asText() == "{volume}/test-results")
check(service.path("userns").asText() == "keep-id:uid=1000,gid=1000")
check(service.path("user").asText() == "0:0")
check(service.path("environment").path("TEST_RUNNER_STANDALONE_RESULTS").asText() == "v1")
}}
java.nio.file.Files.writeString(Path({json.dumps(str(output))}), mapper.writeValueAsString(ir))
'''
        else:
            body += 'check(ir == original) { "non-standalone dynamic contract changed" }\n'
        body += '}\n'
    for index, (fixture, policy, selected_manifest) in enumerate(negatives):
        body += f'''run {{
activePodmanPolicy = fixturePolicy(mapper.readTree({literal(policy)}))
var refused = false
try {{ applyStandaloneHostProfile(mapper.readTree({literal(fixture)}) as ObjectNode, mapper.readTree({literal(selected_manifest)})) }}
catch (_: IllegalStateException) {{ refused = true }}
check(refused) {{ "negative {index} unexpectedly accepted" }}
}}
'''
    body += f'println("PASS {len(positives) + len(negatives)} actual Kotlin results cases; source only")\n'
    script = Path(temporary) / 'results.main.kts'
    script.write_text(body)
    classpath = (BASE / 'runtime-generator/build/generator-classpath.txt').read_text().strip()
    assert classpath and all(Path(p).is_file() for p in classpath.split(os.pathsep))
    java = str(Path(os.environ['JAVA_HOME']) / 'bin/java') if os.environ.get('JAVA_HOME') else 'java'
    subprocess.run([java, '-Xmx1024m', '-XX:ActiveProcessorCount=2', '-cp', classpath,
                    'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler', '-script', str(script),
                    '-no-stdlib', '-no-reflect', '-classpath', classpath], timeout=105, check=True)
    # Feed actual compiled IR to the actual consumer (no mounted/native state).
    helper = MODULE / 'stack.containers/test-runner/retained-workflows/standalone_results.py'
    spec = importlib.util.spec_from_file_location('compiled_results_consumer', helper)
    consumer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(consumer)
    compiled = output.read_bytes()
    (Path(temporary) / 'stack.ir.json').write_bytes(compiled)
    (Path(temporary) / 'bundle.json').write_text(json.dumps(dict(deploymentMode='standalone', irSha256=hashlib.sha256(compiled).hexdigest())))
    (Path(temporary) / 'podman-domains.json').write_text(json.dumps(dict(deploymentMode='standalone', storageScope=manifest['storageScope'], domains=[domain])))
    assert consumer.contract(Path(temporary) / 'bundle.json') == volume + '/test-results'
    print('PASS actual Kotlin emitted IR -> actual native results consumer; no engine')
assert SOURCE.read_bytes() == before, 'owning generator source changed during proof'
print('Owning generator source SHA256:', hashlib.sha256(before).hexdigest())
