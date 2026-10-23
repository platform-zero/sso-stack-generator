#!/usr/bin/env python3
"""Execute owning Kotlin freeze policy for unmanaged standalone clients."""
import json,subprocess,tempfile,unittest
from pathlib import Path
R=Path(__file__).resolve().parents[1];CP=R/'runtime-generator/build/generator-classpath.txt'
@unittest.skipUnless(CP.is_file(),'requires delivery generator compiler classpath')
class Closure(unittest.TestCase):
 def test_standalone_freezes_every_emitted_producer_legacy_unchanged(self):
  body=(R/'runtime-generator/stack-generator.main.kts').read_text();functions='fun quadletManaged'+body.split('fun quadletManaged',1)[1].split('fun immutableOverlayFiles',1)[0]
  fixture={'services':{'daemon':{'build':{},'image':'discovery','lifecycle':'daemon'},'managed':{'build':{},'image':'discovery','lifecycle':'on-demand','quadletManaged':True},'client':{'build':{},'image':'discovery','lifecycle':'on-demand','quadletManaged':False}}}
  script='''import java.nio.file.Path
import kotlin.io.path.*
import com.fasterxml.jackson.databind.*
import com.fasterxml.jackson.databind.node.*
val json=ObjectMapper()
fun JsonNode.fieldsMap():List<Pair<String,JsonNode>> = fields().asSequence().map { it.key to it.value }.toList()
fun fail(message:String):Nothing=throw IllegalArgumentException(message)
fun readTree(path:Path):JsonNode=json.readTree(path.toFile())
data class Policy(val standalone:Boolean)
var activePodmanPolicy=Policy(true)
'''+functions+'\nfun fixture():ObjectNode=json.readTree('+json.dumps(json.dumps(fixture))+') as ObjectNode\n'+'''
val root=Path.of(args[0]);root.resolve("global.settings").createDirectories()
val manifest=root.resolve("manifest.json");manifest.writeText("""{"localBuildImagePinsPath":"global.settings/local-build-image-ids.json"}""")
fun checkCase(standalone:Boolean, includeClient:Boolean, success:Boolean) {
 activePodmanPolicy=Policy(standalone)
 val imageMap=json.createObjectNode().put("daemon","sha256:"+"a".repeat(64)).put("managed","sha256:"+"b".repeat(64))
 if(includeClient)imageMap.put("client","sha256:"+"c".repeat(64))
 val pins=json.createObjectNode().put("schemaVersion",1);pins.set<ObjectNode>("images",imageMap)
 root.resolve("global.settings/local-build-image-ids.json").writeText(json.writeValueAsString(pins))
 val ir=fixture();val before=ir.deepCopy<ObjectNode>()
 try {
  freezeLocalBuildImages(ir,manifest)
  check(success)
  check(ir.path("quadletBuildImagesFrozen").asBoolean())
  check(ir.path("services").path("client").has("frozenBuildImage")==standalone)
  check(quadletEmitted(ir.path("services").path("client"))==standalone)
  check(ir.path("services").path("client").path("lifecycle").asText()=="on-demand")
 } catch(e:IllegalArgumentException) {
  check(!success);check(ir==before)
 }
}
checkCase(true,true,true)
checkCase(true,false,false)
checkCase(false,false,true)
checkCase(false,true,false)
println("4 owning Kotlin closure cases passed")
'''
  with tempfile.TemporaryDirectory()as t:
   p=Path(t)/'closure.kts';p.write_text(script);cp=CP.read_text().strip();result=subprocess.run(['/usr/lib/jvm/java-21-openjdk-amd64/bin/java','-Xmx1g','-cp',cp,'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-script',str(p),'-no-stdlib','-no-reflect','-classpath',cp,'--',t],capture_output=True,text=True,timeout=120,cwd=R)
   self.assertEqual(result.returncode,0,result.stderr);self.assertIn('4 owning Kotlin closure cases passed',result.stdout)
if __name__=='__main__':unittest.main()
