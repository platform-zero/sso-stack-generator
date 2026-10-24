#!/usr/bin/env python3
"""Actual Kotlin standalone Caddy materialization, on temporary public source.

No generator command, source archive, Git, Go, image/engine, host/private inputs
or installed proof. Needs only the already prepared generator JVM classpath.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--caddy-module', required=True, type=Path)
args = parser.parse_args()
base = Path(__file__).resolve().parents[1]
source = base / 'runtime-generator/stack-generator.main.kts'
before = source.read_bytes()
text = before.decode()
module = args.caddy_module.resolve(strict=True)
caddy = module / 'stack.config/caddy/Caddyfile'
plugin = module / 'stack.containers/caddy-ingress'


def take(name):
    start = text.index('fun ' + name + '(')
    end = text.index('\nfun ', start)
    return text[start:end]


functions = '\n'.join(take(name) for name in (
    'excludedIds', 'selectedModuleIds', 'sha256', 'standaloneHost',
    'requireStandaloneCaddyPrivacy', 'materializeStandaloneHostInputs'))


def literal(value):
    return json.dumps(value).replace('$', "${'$'}")


classpath = (base / 'runtime-generator/build/generator-classpath.txt').read_text().strip()
assert classpath and all(Path(p).is_file() for p in classpath.split(os.pathsep))
java = str(Path(os.environ['JAVA_HOME']) / 'bin/java') if os.environ.get('JAVA_HOME') else 'java'
with tempfile.TemporaryDirectory(prefix='standalone-caddy-source-') as temporary:
    root = Path(temporary)
    fixture = root / 'public-fixture'
    fixture.mkdir()
    shutil.copyfile(caddy, fixture / 'Caddyfile')
    native = fixture / 'plugin'
    native.mkdir()
    inventory = {}
    for line in (plugin / 'SOURCES.sha256').read_text().splitlines():
        digest, relative = line.split('  ./', 1)
        assert relative not in inventory and not Path(relative).is_absolute() and '..' not in Path(relative).parts
        inventory[relative] = digest
    names = [*inventory, 'SOURCES.sha256', 'build-recipe.json']
    observed = {'Caddyfile': hashlib.sha256(caddy.read_bytes()).hexdigest()}
    for name in names:
        path = plugin / name
        assert path.is_file() and not path.is_symlink()
        destination = native / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)
        observed[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        if name in inventory:
            assert observed[name] == inventory[name], 'public source differs from its owning inventory'
    body = '''import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import kotlin.io.path.*
val mapper = ObjectMapper()
fun fail(message: String): Nothing = error(message)
'''+functions+'\n'
    body += f'''val fixture = Path({literal(str(fixture))})
val work = Path({literal(str(root / 'cases'))})
val original = fixture.resolve("Caddyfile").readText()
val caddyPaths = listOf("build/stack.config/caddy/Caddyfile", "runtime/configs/caddy/Caddyfile")
val alloyPaths = listOf("build/stack.config/alloy/alloy.hcl", "runtime/configs/alloy/alloy.hcl")
val nativeNames = mapper.readTree({literal(json.dumps(names))}).map {{ it.asText() }}
val start = "# webservices-component-start caddy"
val end = "# webservices-component-end caddy"
val standalone = mapper.readTree("""{{"deploymentMode":"standalone","storageScope":{{"root":"/mnt/stack/source-fixture","dataClass":"synthetic"}},"modules":["caddy","alloy"]}}""") as ObjectNode
val caddyOnly = standalone.deepCopy().also {{ it.set<JsonNode>("modules", mapper.readTree("[\\"caddy\\"]")) }}
fun setup(name: String): Path {{
    val output = work.resolve(name)
    for (relative in caddyPaths) {{
        val path = output.resolve(relative)
        path.parent.createDirectories(); path.writeText(original)
    }}
    for (name in nativeNames) {{
        val target = output.resolve("build/stack.containers/caddy-ingress").resolve(name)
        target.parent.createDirectories()
        Files.copy(fixture.resolve("plugin").resolve(name), target)
    }}
    for (relative in alloyPaths) {{
        val path = output.resolve(relative)
        path.parent.createDirectories()
        path.writeText("uid = sys.env(\\"STACK_LOG_UID_REGEX\\")\\nunit = sys.env(\\"STACK_LOG_UNIT_REGEX\\")\\n")
    }}
    return output
}}
var passed = 0
fun refusal(name: String, change: (Path) -> Unit) {{
    val output = setup(name)
    change(output)
    var refused = false
    try {{ materializeStandaloneHostInputs(standalone, output) }}
    catch (_: IllegalStateException) {{ refused = true }}
    check(refused) {{ "unknown/unsafe source accepted: $name" }}
    passed++
}}
run {{
    val output = setup("approved-native")
    materializeStandaloneHostInputs(standalone, output)
    val expected = original.substringBefore(start) + original.substringAfter(end)
    for (relative in caddyPaths) {{
        val emitted = output.resolve(relative).readText()
        check(emitted == expected) {{ "non-control source changed" }}
        check(emitted.contains("log default {{\\n\\t\\tformat p0_metadata\\n\\t}}"))
        check(!emitted.contains("unix//run/p0-control/http.sock"))
        check(!emitted.contains(start) && !emitted.contains(end))
    }}
    passed++
}}
run {{
    val output = setup("optional-alloy-not-selected")
    alloyPaths.forEach {{ Files.delete(output.resolve(it)) }}
    materializeStandaloneHostInputs(caddyOnly, output)
    passed++
}}
run {{
    val output = work.resolve("managed-untouched")
    check(!output.exists())
    materializeStandaloneHostInputs(mapper.readTree("{{}}") as ObjectNode, output)
    check(!output.exists())
    passed++
}}
'''
    mutations = {
        'unfiltered-format': ('replace', 'format p0_metadata', 'format json'),
        'filter-format-waiver': ('replace', 'format p0_metadata', 'format filter {\n wrap json\n}'),
        'default-with-options': ('replace', 'format p0_metadata', 'format p0_metadata extra'),
        'encoder-with-fields': ('replace', 'format p0_metadata', 'format p0_metadata {\n message_key message\n}'),
        'extra-operational-logger': ('append', '\n{\n log other {\n format p0_metadata\n }\n}\n'),
        'extra-unfiltered-logger': ('append', '\n{\n log leak {\n output stdout\n format json\n }\n}\n'),
        'site-access-logging': ('replace', 'import access_observability', 'import access_observability\n log {\n format p0_metadata\n }'),
        'site-named-access-logging': ('replace', 'import access_observability', 'import access_observability\n log named {\n output stdout\n }'),
        'identity-log-append': ('append', '\n(unsafe) {\n log_append user {http.request.header.Remote-User}\n}\n'),
        'extra-external-import': ('append', '\nimport /tmp/unreviewed-logging.caddy\n'),
        'quoted-logging': ('append', '\n"log" "other" {\n "format" "json"\n}\n'),
        'inline-logging': ('append', '\nextra.invalid { log { format json } }\n'),
        'log-comment-bait': ('replace', 'format p0_metadata', '# format p0_metadata\n format json'),
        'old-redaction-counter-bait': ('replace', 'format p0_metadata', 'format json\n # request>uri replace\n # request>uri replace'),
        'extra-global-debug': ('replace', '{{CADDY_GLOBAL_OPTIONS}}', '{{CADDY_GLOBAL_OPTIONS}}\n debug'),
        'unknown-global-slot': ('replace', '{{CADDY_GLOBAL_OPTIONS}}', '{{UNREVIEWED_OPTIONS}}'),
        'guard-removed': ('replace', '\timport ingress_guard', '\t# no ingress guard'),
        'guard-redefined': ('append', '\n(ingress_guard) {\n respond ok\n}\n'),
        'duplicate-start': ('append', '\n# webservices-component-start caddy\n'),
        'duplicate-end': ('append', '\n# webservices-component-end caddy\n'),
        'missing-start': ('replace', '# webservices-component-start caddy', '# missing start'),
        'missing-end': ('replace', '# webservices-component-end caddy', '# missing end'),
        'wrong-control-socket': ('replace', 'unix//run/p0-control/http.sock', 'unix//tmp/other.sock'),
        'wrong-control-host': ('replace', 'control.{$DOMAIN}', 'unreviewed.{$DOMAIN}'),
        'extra-managed-route': ('replace', '# webservices-component-end caddy', 'extra.invalid {\n log\n}\n# webservices-component-end caddy'),
    }
    for name, mutation in mutations.items():
        if mutation[0] == 'append':
            expression = 'original + ' + literal(mutation[1])
        else:
            expression = 'original.replace(' + literal(mutation[1]) + ', ' + literal(mutation[2]) + ')'
        body += f'refusal({literal(name)}) {{ output -> output.resolve(caddyPaths[0]).writeText({expression}) }}\n'
    body += '''refusal("reversed-markers") { output ->
    val changed = original.replace(start, "# temporary-marker").replace(end, start).replace("# temporary-marker", end)
    output.resolve(caddyPaths[0]).writeText(changed)
}
refusal("second-copy-unsafe") { output -> output.resolve(caddyPaths[1]).appendText("\\nlog { format json }\\n") }
refusal("legacy-counter-only") { output ->
    val old = "{\\n# request>uri replace\\n# request>uri replace\\n}\\n" + start + "\\ncontrol.{$DOMAIN} {\\n reverse_proxy unix//run/p0-control/http.sock\\n}\\n" + end
    output.resolve(caddyPaths[0]).writeText(old)
}
'''.replace('{$DOMAIN}', "{${'$'}DOMAIN}")
    plugin_mutations = {
        'encoder-mutated': 'output.resolve("build/stack.containers/caddy-ingress/encoder.go").appendText("\\n// unreviewed encoder\\n")',
        'builder-mutated': 'output.resolve("build/stack.containers/caddy-ingress/Containerfile").appendText("\\nRUN echo unreviewed\\n")',
        'inventory-mutated': 'output.resolve("build/stack.containers/caddy-ingress/SOURCES.sha256").appendText("\\n")',
        'ingress-mutated': 'output.resolve("build/stack.containers/caddy-ingress/ingress.go").appendText("\\n// unreviewed logging\\n")',
        'policy-mutated': 'output.resolve("build/stack.containers/caddy-ingress/policy/policy.go").appendText("\\n// unreviewed fields\\n")',
        'dependency-mutated': 'output.resolve("build/stack.containers/caddy-ingress/go.mod").appendText("\\n// unreviewed source graph\\n")',
        'additional-go-source': 'output.resolve("build/stack.containers/caddy-ingress/unsafe.go").writeText("package ingress\\n")',
        'additional-config-source': 'output.resolve("build/stack.containers/caddy-ingress/unsafe.caddy").writeText("log { format json }\\n")',
        'missing-policy': 'Files.delete(output.resolve("build/stack.containers/caddy-ingress/policy/policy.go"))',
        'missing-encoder': 'Files.delete(output.resolve("build/stack.containers/caddy-ingress/encoder.go"))',
        'linked-encoder': 'val path = output.resolve("build/stack.containers/caddy-ingress/encoder.go"); Files.delete(path); Files.createSymbolicLink(path, fixture.resolve("plugin/encoder.go"))',
        'linked-native-directory': 'val path = output.resolve("build/stack.containers/caddy-ingress"); Files.move(path, path.resolveSibling("parked")); Files.createSymbolicLink(path, fixture.resolve("plugin"))',
        'linked-caddy': 'val path = output.resolve(caddyPaths[0]); Files.delete(path); Files.createSymbolicLink(path, fixture.resolve("Caddyfile"))',
        'missing-caddy': 'Files.delete(output.resolve(caddyPaths[0]))',
        'linked-nested-source': 'val path = output.resolve("build/stack.containers/caddy-ingress/policy/policy.go"); Files.delete(path); Files.createSymbolicLink(path, fixture.resolve("plugin/policy/policy.go"))',
    }
    for name, change in plugin_mutations.items():
        body += f'refusal({literal(name)}) {{ output -> {change} }}\n'
    for index in range(2):
        for key in ('STACK_LOG_UID_REGEX', 'STACK_LOG_UNIT_REGEX'):
            body += f'refusal({literal(f"alloy-{index}-{key}")}) {{ output -> val path = output.resolve(alloyPaths[{index}]); path.writeText(path.readText().replace({literal(key)}, "UNSCOPED")) }}\n'
        body += f'refusal({literal(f"alloy-{index}-missing")}) {{ output -> Files.delete(output.resolve(alloyPaths[{index}])) }}\n'
        body += f'refusal({literal(f"alloy-{index}-linked")}) {{ output -> val path = output.resolve(alloyPaths[{index}]); val target = output.resolve("other-alloy.hcl"); Files.move(path, target); Files.createSymbolicLink(path, target) }}\n'
    body += 'println("PASS $passed actual Kotlin native privacy/materialization cases; source/temp fixtures only")\n'
    body += 'println("JVM version: " + System.getProperty("java.version"))\n'
    script = root / 'privacy.main.kts'
    script.write_text(body)
    subprocess.run([java, '-Xmx1024m', '-XX:ActiveProcessorCount=2', '-cp', classpath,
                    'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler', '-script', str(script),
                    '-no-stdlib', '-no-reflect', '-classpath', classpath], check=True, timeout=105)
assert source.read_bytes() == before, 'generator source changed during source proof'
assert hashlib.sha256(caddy.read_bytes()).hexdigest() == observed['Caddyfile']
for name in names:
    assert hashlib.sha256((plugin / name).read_bytes()).hexdigest() == observed[name], 'owning Caddy source changed'
print('Generator source SHA256:', hashlib.sha256(before).hexdigest())
print('Approved actual Caddyfile SHA256:', observed['Caddyfile'])
print('Read-only owning source hashes preserved; no Go/build/native/installed claim')
