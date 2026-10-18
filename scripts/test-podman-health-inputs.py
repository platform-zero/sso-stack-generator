#!/usr/bin/env python3
"""Execute the actual Kotlin probe translator against positive/hostile inputs."""
import json
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run():
    source = (ROOT / 'runtime-generator/stack-generator.main.kts').read_text()
    body = source[source.index('val healthInput ='):source.index('fun renderEnvironmentTemplate(')]
    cases = []

    def good(name, service, command=None, inputs=None):
        cases.append(dict(name=name, service=service, command=command, inputs=inputs or {}))

    def bad(name, test, error, environment=None):
        cases.append(dict(name=name, service=dict(health=dict(test=test), environment=environment or {}), error=error))

    good('absent', {})
    good('disabled', dict(health=dict(disable=True)))
    good('none', dict(health=dict(test=['NONE'])))
    good('shell', dict(health=dict(test=['CMD-SHELL', 'echo literal'])), ['/bin/sh', '-c', 'echo literal'])
    good('container dollars and quoting', dict(health=dict(test=['CMD-SHELL', 'printf \'%s\\n\' "$${LOCAL:-x}"\necho "a b"'])),
         ['/bin/sh', '-c', 'printf \'%s\\n\' "$${LOCAL:-x}"\necho "a b"'])
    good('private input not argv value', dict(environment=dict(GLOBAL='synthetic-value-not-in-argv'), health=dict(test=['CMD-SHELL', 'echo "${GLOBAL}" $GLOBAL'])),
         ['/bin/sh', '-c', 'echo "${P0_HEALTH_INPUT_GLOBAL}" $P0_HEALTH_INPUT_GLOBAL'], {'P0_HEALTH_INPUT_GLOBAL': '${GLOBAL}'})
    good('nested defaults', dict(health=dict(test=['CMD-SHELL', 'echo "${SITE:-app.${DOMAIN}}"'])),
         ['/bin/sh', '-c', 'echo "${P0_HEALTH_INPUT_SITE:-app.${P0_HEALTH_INPUT_DOMAIN}}"'],
         {'P0_HEALTH_INPUT_SITE': '${SITE}', 'P0_HEALTH_INPUT_DOMAIN': '${DOMAIN}'})
    good('exec preserves argv without shell', dict(health=dict(test=['CMD', 'probe', 'a b', '"quoted"', '%s\\n', '$$LOCAL'])),
         ['probe', 'a b', '"quoted"', '%s\\n', '$$LOCAL'])
    bad('exec interpolation refuses', ['CMD', 'probe', '${GLOBAL}'], 'rendered argv contract')
    bad('reserved input collision', ['CMD-SHELL', 'echo ${GLOBAL}'], 'reserved health input collision', {'P0_HEALTH_INPUT_GLOBAL': 'foreign'})
    bad('unknown mode', ['OTHER', 'probe'], 'unsupported health.test mode')
    bad('multiple shell fragments', ['CMD-SHELL', 'true', 'false'], 'exactly one shell fragment')
    bad('empty test', [], 'nonempty string array')
    bad('nonstring test', ['CMD', 42], 'nonempty string array')
    bad('missing command', ['CMD'], 'requires a command')
    bad('none with extra command', ['NONE', 'true'], 'unsupported health.test mode')
    bad('nonarray test', 'true', 'nonempty string array')
    harness = '''import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import java.io.File
val json = ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT)
fun fail(message: String): Nothing = error("stack generator: $message")
''' + body + '''
val cases = json.readTree(File(args[0]))
for (case in cases) {
    val result = runCatching { podmanHealth(case.path("service")) }
    if (case.has("error")) {
        check(result.isFailure) { "expected refusal: ${case.path("name")}" }
        check(result.exceptionOrNull()!!.message!!.contains(case.path("error").asText())) { result.exceptionOrNull()!!.toString() }
    } else {
        val actual = result.getOrThrow()
        val command = actual.command?.let { json.readTree(it) }
        check(command == case.get("command").takeUnless { it.isNull }) { "argv mismatch: ${case.path("name")}" }
        check(json.valueToTree<JsonNode>(actual.inputs) == case.path("inputs")) { "input mismatch: ${case.path("name")}" }
        check(!(actual.command ?: "").contains("synthetic-value-not-in-argv"))
    }
}
println("[health-input-test] ${cases.size()} actual-translator cases passed")
'''
    cp = (ROOT / 'runtime-generator/build/generator-classpath.txt').read_text().strip()
    with tempfile.TemporaryDirectory(prefix='p0-health-input-test-') as directory:
        root = Path(directory)
        script = root / 'health.main.kts'
        fixtures = root / 'fixtures.json'
        script.write_text(harness)
        fixtures.write_text(json.dumps(cases))
        subprocess.run(['java', '-Xmx512m', '-cp', cp, 'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler',
                        '-script', str(script), '-no-stdlib', '-no-reflect', '-classpath', cp, '--', str(fixtures)], check=True)


if __name__ == '__main__':
    run()
