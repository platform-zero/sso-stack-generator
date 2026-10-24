#!/usr/bin/env python3
"""Execute the owning Kotlin resolver against public fixtures; no runtime authority."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

parser=argparse.ArgumentParser();parser.add_argument('--gateway-runtime',type=Path,required=True)
args=parser.parse_args()
import yaml
root=Path(__file__).parents[1]
text=(root/'runtime-generator/stack-generator.main.kts').read_text()
resolver='fun resolveModuleIntegrations('+text.split('fun resolveModuleIntegrations(',1)[1].split('fun buildIr(',1)[0]
service=yaml.safe_load(args.gateway_runtime.read_bytes())['services']['keycloak-configure']
assert set(service['moduleIntegrations'])=={'firefly-iii'}
body=json.dumps(service).replace('$',"${'$'}")
fixture='''
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
import com.fasterxml.jackson.databind.node.ArrayNode
fun fail(message: String): Nothing = throw IllegalArgumentException(message)
'''+resolver+'''\n
val mapper=ObjectMapper()
val original=mapper.readTree("""'''+body+'''""") as ObjectNode
val absent=original.deepCopy()
resolveModuleIntegrations(absent,setOf("keycloak","keycloak-auth-gateway"))
check(!absent.has("moduleIntegrations"))
check(absent.path("environment").fieldNames().asSequence().none { it.startsWith("FIREFLY_") })
check(absent.path("volumes").none { it.asText().contains("finance") })
val present=original.deepCopy()
resolveModuleIntegrations(present,setOf("firefly-iii","keycloak-auth-gateway"))
check(!present.has("moduleIntegrations"))
check(present.path("environment").path("FIREFLY_NATIVE_OWNERSHIP_FILE").asText()=="/run/p0-finance/input.json")
check(present.path("volumes").count { it.asText()=="/var/lib/webservices-native-finance:/run/p0-finance:ro" }==1)
check(present.path("volumes").count { it.asText()=="./configs/keycloak/configure-finance.sh:/configure-finance.sh:ro" }==1)
check(present.path("user")==original.path("user") && present.path("dependencies")==original.path("dependencies"))
fun refused(change: (ObjectNode)->Unit) {
 val value=original.deepCopy();change(value)
 var failed=false
 try { resolveModuleIntegrations(value,setOf("firefly-iii")) } catch(e:IllegalArgumentException) { failed=true }
 check(failed)
}
refused { (it.path("moduleIntegrations").path("firefly-iii") as ObjectNode).put("user","0") }
refused { (it.path("environment") as ObjectNode).put("FIREFLY_NATIVE_OWNERSHIP_FILE","foreign") }
refused { (it.path("volumes") as ArrayNode).add("/var/lib/webservices-native-finance:/run/p0-finance:ro") }
refused { (it.path("moduleIntegrations") as ObjectNode).put("firefly-iii","bad") }
refused { (it.path("moduleIntegrations").path("firefly-iii").path("environment") as ObjectNode).put("FOREIGN",true) }
refused { (it.path("moduleIntegrations").path("firefly-iii").path("volumes") as ArrayNode).add(42) }
refused { (it.path("moduleIntegrations") as ObjectNode).set<JsonNode>("../foreign",it.path("moduleIntegrations").path("firefly-iii").deepCopy()) }
val plain=absent.deepCopy();resolveModuleIntegrations(plain,emptySet());check(plain==absent)
check(original.has("moduleIntegrations"))
println("Actual Kotlin module integration resolver: selected/unselected source cohort and7 negative mutations passed; NOT installation")
'''
classpath=(root/'runtime-generator/build/generator-classpath.txt').read_text().strip()
env=dict(os.environ,JAVA_HOME='/usr/lib/jvm/java-21-openjdk-amd64',JAVA_TOOL_OPTIONS='-XX:ActiveProcessorCount=2 -Xmx2g')
with tempfile.TemporaryDirectory(prefix='module-integrations-') as temp:
 p=Path(temp)/'fixture.main.kts';p.write_text(fixture)
 subprocess.run([env['JAVA_HOME']+'/bin/java','-cp',classpath,'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-script',str(p),'-no-stdlib','-no-reflect','-classpath',classpath],env=env,check=True)
