#!/usr/bin/env python3
"""Exercise actual Kotlin and shell selectors; fixtures are not deployed proof."""
import json,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def run():
 source=(ROOT/'runtime-generator/stack-generator.main.kts').read_text()
 module=source[source.index('fun excludedIds('):source.index('fun validateDependencies(')]
 component=source[source.index('fun resolveComponentSelection('):source.index('fun materializeComponentLock(')]
 cuts=['vaultwarden','librechat','workload-spawner','n8n']
 retained=['core','jupyterhub','jupyter-notebook','forgejo-runner']
 catalog={'schemaVersion':1,'defaultComponents':['full'],'components':{n:{'dependencies':[]} for n in retained+cuts}}
 catalog['components'].update({'full':{'dependencies':['apps','forgejo-runner']},'apps':{'dependencies':['jupyterhub','vaultwarden']}})
 cases=[]
 def case(mode,manifest,error=False):cases.append(dict(mode=mode,manifest=manifest,error=error))
 case('module',{'modules':retained,'excludedModules':cuts})
 case('module',{'modules':retained})
 for cut in cuts:case('module',{'modules':retained+[cut],'excludedModules':cuts},True)
 for bad in (None,True,'vaultwarden',[''],['vaultwarden','vaultwarden'],[42],['../vaultwarden']):case('module',{'modules':retained,'excludedModules':bad},True)
 case('component',{'components':retained,'excludedComponents':cuts})
 for cut in cuts:case('component',{'components':[cut],'excludedComponents':cuts},True)
 for roots in (['full'],['apps']):case('component',{'components':roots,'excludedComponents':cuts},True)
 # A catalog default is just as constrained as an explicit full request.
 case('component',{'excludedComponents':cuts},True)
 for bad in (None,True,'n8n',['n8n','n8n'],[42]):case('component',{'components':retained,'excludedComponents':bad},True)
 header='''import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
import java.nio.file.Path
import java.nio.file.Files
val json=ObjectMapper()
fun fail(message:String):Nothing=error(message)
fun readTree(path:Path):ObjectNode=json.readTree(path.toFile()) as ObjectNode
'''
 tail='''
val cases=json.readTree(java.io.File(args[0]))
val catalog=readTree(Path.of(args[1]))
val manifest=Path.of(args[2])
for (case in cases) {
 val data=case.path("manifest") as ObjectNode
 Files.writeString(manifest,data.toString())
 val result=runCatching { if(case.path("mode").asText()=="module") selectedModuleIds(data) else resolveComponentSelection(manifest,catalog) }
 check(result.isFailure==case.path("error").asBoolean()) { "unexpected selector result: $case => $result" }
 if (result.isSuccess) check(result.getOrThrow().containsAll(listOf("jupyterhub","jupyter-notebook","forgejo-runner")))
}
println("[selection-exclusion-test] ${cases.size()} actual Kotlin selector cases passed")
'''
 cp=(ROOT/'runtime-generator/build/generator-classpath.txt').read_text().strip()
 with tempfile.TemporaryDirectory(prefix='p0-selection-exclusion-') as directory:
  root=Path(directory);script=root/'test.main.kts';fixtures=root/'cases.json';cat=root/'catalog.json';manifest=root/'manifest.json'
  script.write_text(header+module+component+tail);fixtures.write_text(json.dumps(cases));cat.write_text(json.dumps(catalog))
  subprocess.run(['java','-Xmx512m','-cp',cp,'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-script',str(script),'-no-stdlib','-no-reflect','-classpath',cp,'--',str(fixtures),str(cat),str(manifest)],check=True)
  shell=0
  for row in cases:
   if row['mode']!='component':continue
   manifest.write_text(json.dumps(row['manifest']))
   p=subprocess.run(['bash','-c','source "$1/scripts/lib/components.sh"; component_selection_resolve "$2" "$3"','_',str(ROOT),str(manifest),str(cat)],capture_output=True,text=True)
   assert (p.returncode!=0)==row['error'],(row,p.stdout,p.stderr)
   if not row['error']:assert set(retained)<=set(p.stdout.splitlines())
   shell+=1
  print(f'[selection-exclusion-test] {shell} actual shell selector cases passed; retained Jupyter/CI positive, full/default/direct/dependency reintroduction refuses')
if __name__=='__main__':run()
