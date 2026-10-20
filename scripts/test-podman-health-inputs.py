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
val dnsGood = listOf(
    Triple("{}", false, emptyList<String>()),
    Triple("""{"dns":null}""", false, emptyList<String>()),
    Triple("""{"dns":"9.9.9.9"}""", false, listOf("9.9.9.9")),
    Triple("""{"dns":["9.9.9.9","1.1.1.1"]}""", false, listOf("9.9.9.9", "1.1.1.1")),
    Triple("{}", true, listOf("192.168.140.1")),
    Triple("""{"dns":[]}""", true, listOf("192.168.140.1")),
    Triple("""{"dns":"192.168.140.1"}""", true, listOf("192.168.140.1")),
    Triple("""{"dns":["192.168.140.1"]}""", true, listOf("192.168.140.1")))
for ((raw, isolated, expected) in dnsGood) check(podmanDns(json.readTree(raw), isolated) == expected)
val dnsBad = listOf("""{"dns":"1.1.1.1"}""", """{"dns":["192.168.140.1","1.1.1.1"]}""",
    """{"dns":[42]}""", """{"dns":42}""")
for (raw in dnsBad) check(runCatching { podmanDns(json.readTree(raw), true) }.isFailure)
val mailDns = json.readTree("""{"dns":["8.8.8.8","8.8.4.4"]}""")
check(podmanDns(mailDns, false, "mailserver") == listOf("8.8.8.8", "8.8.4.4"))
check(podmanDns(mailDns, true, "mailserver") == listOf("192.168.140.1"))
for (name in listOf("", "caddy")) check(runCatching { podmanDns(mailDns, true, name) }.isFailure)
check(runCatching { podmanDns(json.readTree("""{"dns":["8.8.8.8","1.1.1.1"]}"""), true, "mailserver") }.isFailure)
println("[scope-dns-test] ${dnsGood.size + dnsBad.size + 5} actual-translator cases passed; exact mail defaults scoped without fallback")
val aliasGood = listOf(
    Triple("{}", true, emptyList<String>()),
    Triple("""{"extraHosts":["keycloak.datamancy.net:host-gateway"]}""", false, listOf("keycloak.datamancy.net:host-gateway")),
    Triple("""{"extraHosts":["keycloak.datamancy.net:host-gateway"]}""", true, listOf("keycloak.datamancy.net:192.168.140.1")),
    Triple("""{"extraHosts":["datamancy.net:host-gateway","api.bookstack.datamancy.net:host-gateway"]}""", true, listOf("datamancy.net:192.168.140.1", "api.bookstack.datamancy.net:192.168.140.1")),
    Triple("""{"extraHosts":["mail.datamancy.net:192.168.140.1"]}""", true, listOf("mail.datamancy.net:192.168.140.1")),
    Triple("""{"extraHosts":["host.docker.internal:host-gateway","host.containers.internal:host-gateway"]}""", true, listOf("host.docker.internal:host-gateway", "host.containers.internal:host-gateway")),
    Triple("""{"extraHosts":["example.net:127.0.0.1","notdatamancy.net:host-gateway"]}""", true, listOf("example.net:127.0.0.1", "notdatamancy.net:host-gateway")),
    Triple("""{"extraHosts":["keycloak.datamancy.net:127.0.0.1"]}""", false, listOf("keycloak.datamancy.net:127.0.0.1")))
for ((raw, isolated, expected) in aliasGood) check(podmanExtraHosts(json.readTree(raw), isolated) == expected)
for (target in listOf("127.0.0.1", "169.254.1.2", "1.1.1.1"))
    check(runCatching { podmanExtraHosts(json.readTree("""{"extraHosts":["keycloak.datamancy.net:$target"]}"""), true) }.isFailure)
println("[scope-host-alias-test] ${aliasGood.size + 3} actual-translator cases passed; canonical issuer names preserved, no pasta-gateway/public fallback")
val caddySource = "prefix && test -s /ca/caddy-ca.crt && wget --quiet --tries=1 --spider --timeout=5 http://127.0.0.1:2019/config/ && wget --quiet --tries=1 --spider --timeout=5 http://127.0.0.1:2019/reverse_proxy/upstreams && caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile | grep Valid"
val caddyScoped = isolatedCaddyProbe(caddySource)
check(!caddyScoped.contains(":2019") && caddyScoped.startsWith("prefix && test -s /ca/caddy-ca.crt"))
check(caddyScoped.contains("test -s /certs/pki/authorities/local/root.crt && pidof caddy"))
check(caddyScoped.contains("caddy validate --config"))
for (badSource in listOf("true", caddySource.replace("2019/config/", "2018/config/"),
    caddySource.replace("test -s /ca/caddy-ca.crt", "true"), caddySource + " http://127.0.0.1:2019/config/"))
    check(runCatching { isolatedCaddyProbe(badSource) }.isFailure)
println("[scope-caddy-health-test] 5 actual-translator cases passed; admin API remains off")
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
