#!/usr/bin/env python3
"""Actual Kotlin option helper + native Quadlet dry-run; no running services."""
import json,os,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
 source=(ROOT/'runtime-generator/stack-generator.main.kts').read_text()
 helper=source[source.index('fun podmanSecurityOptions('):source.index('data class PodmanHealth(')]
 assert 'lines += podmanSecurityOptions(service)' in source
 cases=[({},False,[]),({'securityOpt':[]},False,[])]
 for value in ('no-new-privileges','no-new-privileges:true','no-new-privileges=true'):
  cases.append(({'securityOpt':[value]},False,['NoNewPrivileges=true']))
 for bad in (None,True,'no-new-privileges',[True],['no-new-privileges:false'],['seccomp:unconfined'],['no-new-privileges:true','no-new-privileges:true']):
  cases.append(({'securityOpt':bad},True,[]))
 header='''import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
val json=ObjectMapper()
fun fail(message:String):Nothing=error(message)
'''
 tail='''
for (case in json.readTree(java.io.File(args[0]))) {
 val result=runCatching { podmanSecurityOptions(case[0]) }
 check(result.isFailure==case[1].asBoolean()) { "unexpected security option result: $case => $result" }
 if(result.isSuccess) check(result.getOrThrow()==case[2].map { it.asText() })
}
println("actual Kotlin security option cases passed")
'''
 cp=(ROOT/'runtime-generator/build/generator-classpath.txt').read_text().strip()
 with tempfile.TemporaryDirectory(prefix='p0-security-options-') as directory:
  p=Path(directory);script=p/'security.main.kts';fixtures=p/'cases.json';script.write_text(header+helper+tail);fixtures.write_text(json.dumps(cases))
  subprocess.run(['java','-Xmx512m','-cp',cp,'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-script',str(script),'-no-stdlib','-no-reflect','-classpath',cp,'--',str(fixtures)],check=True)
  (p/'security.container').write_text('[Container]\nImage=docker.io/library/busybox:1.37\nPull=never\nNoNewPrivileges=true\nDropCapability=ALL\nReadOnly=true\nUser=65532:0\n[Service]\nRestart=no\n')
  env=dict(os.environ,QUADLET_UNIT_DIRS=str(p))
  result=subprocess.run(['/usr/lib/systemd/system-generators/podman-system-generator','--dryrun'],env=env,capture_output=True,text=True,check=True)
  assert '--security-opt no-new-privileges' in result.stdout or '--security-opt=no-new-privileges' in result.stdout,result.stdout+result.stderr
  service=result.stdout.split('[Service]',1)[1].split('[Unit]',1)[0]
  assert not any(line.startswith('NoNewPrivileges=') for line in service.splitlines()) # X-Container metadata is inert; no host/user-manager sandbox
 print(f'[podman-security-options] {len(cases)} actual Kotlin cases + native Quadlet no-new-privileges translation passed; SOURCE/PARSER ONLY')
if __name__=='__main__':main()
