#!/usr/bin/env python3
"""Real owning Kotlin/Python marker serialization agreement; no host mutation."""
import hashlib,json,subprocess,tempfile,unittest
from pathlib import Path
R=Path(__file__).resolve().parents[1];CP=R/'runtime-generator/build/generator-classpath.txt'
@unittest.skipUnless(CP.is_file(),'requires delivery generator compiler classpath')
class StorageMarker(unittest.TestCase):
 def test_python_storage_authority_matches_owning_generator_hash(self):
  manifest={'site':'fixture','deploymentMode':'standalone','storageScope':{'root':'/fixture-scope','dataClass':'synthetic'}}
  rows=[{'name':n,'user':'fixture-'+n,'uid':uid,'stateRoot':'/fixture-scope/state/'+n,'graphRoot':'/fixture-scope/graphs/'+n,'volumeRoot':'/fixture-scope/volumes/'+n}for n,uid in [('platform',1801),('finance',1802)]]
  expected={'schemaVersion':1,'kind':'standalone-stack-storage','site':'fixture','scope':manifest['storageScope'],'domains':sorted(rows,key=lambda r:r['name']),'roots':sorted(r[k]for r in rows for k in ('stateRoot','graphRoot','volumeRoot'))};digest=hashlib.sha256((json.dumps(expected,sort_keys=True)+'\n').encode()).hexdigest()
  body=(R/'runtime-generator/stack-generator.main.kts').read_text();functions='fun storageMarkerPythonJson'+body.split('fun storageMarkerPythonJson',1)[1].split('fun applyStandaloneHostProfile',1)[0]
  script='''import java.nio.file.Path
import java.security.MessageDigest
import com.fasterxml.jackson.databind.*
import com.fasterxml.jackson.databind.node.*
val json=ObjectMapper()
val nodes=JsonNodeFactory.instance
fun obj():ObjectNode=nodes.objectNode()
fun arr():ArrayNode=nodes.arrayNode()
fun JsonNode.fieldsMap():List<Pair<String,JsonNode>> = fields().asSequence().map { it.key to it.value }.toList()
fun fail(message:String):Nothing=error(message)
data class Domain(val name:String,val user:String,val uid:Int?,val stateRoot:String,val graphRoot:String,val volumeRoot:String)
data class Policy(val domains:List<Domain>)
'''
  script+='val activePodmanPolicy=Policy(listOf('+','.join('Domain('+','.join([json.dumps(r[k])for k in ('name','user')])+','+str(r['uid'])+','+','.join(json.dumps(r[k])for k in ('stateRoot','graphRoot','volumeRoot'))+')'for r in rows)+'))\n'+functions+'\nval manifest=json.readTree('+json.dumps(json.dumps(manifest))+')\nprintln(standaloneStorageMarkerSha(manifest))\n'
  with tempfile.TemporaryDirectory()as t:
   path=Path(t)/'check.kts';path.write_text(script);cp=CP.read_text().strip();r=subprocess.run(['/usr/lib/jvm/java-21-openjdk-amd64/bin/java','-Xmx1g','-cp',cp,'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-script',str(path),'-no-stdlib','-no-reflect','-classpath',cp],capture_output=True,text=True,timeout=120,cwd=R)
   self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stdout.strip(),digest)
 def test_owning_readonly_contract_and_exact_unit_scope(self):
  body=(R/'runtime-generator/stack-generator.main.kts').read_text();self.assertIn('"$scopeRoot/.stack-installation.json:/scope-marker.json:ro"',body);self.assertIn('"storageProvisioningOwner", "native-installer"',body);self.assertIn('"STACK_LOG_UNIT_REGEX", alternatives.joinToString',body)
  module=(R.parent/'module-delivery/stack-foundation/stack.runtime.yaml').read_text();self.assertIn('x-standalone-storage-check:',module);self.assertIn('sha256sum -c -',module)
if __name__=='__main__':unittest.main()
