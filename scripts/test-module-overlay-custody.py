#!/usr/bin/env python3
"""Execute owning Kotlin Git-overlay functions against disposable Git fixtures."""
import json,os,subprocess,tempfile,unittest
from pathlib import Path
R=Path(__file__).resolve().parents[1];CP=R/'runtime-generator/build/generator-classpath.txt'
@unittest.skipUnless(CP.is_file(),'requires delivery generator compiler classpath')
class ImmutableOverlays(unittest.TestCase):
 def test_real_owning_functions_ignore_untracked_and_reject_links(self):
  with tempfile.TemporaryDirectory()as t:
   root=Path(t);repo=root/'repo';repo.mkdir();cfg=repo/'stack.config';cfg.mkdir();(cfg/'public.bin').write_bytes(b'\0\xffapproved\n');(cfg/'run.sh').write_text('#!/bin/sh\nexit 0\n');(cfg/'run.sh').chmod(0o755)
   def git(*args):return subprocess.check_output(['git','-c','core.hooksPath=/dev/null','-c','user.name=Synthetic','-c','user.email=fixture@example.invalid','-c','commit.gpgsign=false',*args],cwd=repo,stderr=subprocess.DEVNULL).decode().strip()
   git('init','-q');git('add','stack.config');git('commit','-qm','fixture');clean=git('rev-parse','HEAD')
   # These bodies must never enter an immutable overlay, even if the workspace
   # changes after initial source admission or ignored interpreter caches exist.
   (cfg/'ignored-secret').write_text('NOT_A_RELEASE_INPUT');secret=root/'external';secret.write_text('EXTERNAL_SYNTHETIC_SENTINEL');(cfg/'ignored-link').symlink_to(secret)
   (cfg/'private-cache').mkdir();(cfg/'private-cache'/'private').write_text('NOT_READ');(cfg/'private-cache').chmod(0)
   (cfg/'tracked-link').symlink_to(secret);git('add','stack.config/tracked-link');git('commit','-qm','tracked link');linked=git('rev-parse','HEAD')
   body=(R/'runtime-generator/stack-generator.main.kts').read_text();functions=body.split('fun immutableOverlayFiles(',1)[1].split('fun materializeModules(',1)[0]
   script=root/'check.kts';script.write_text('''import java.nio.file.Path
import kotlin.io.path.*
data class ModuleCheckout(val id:String,val dir:Path,val commit:String)
fun fail(message:String):Nothing=error(message)
fun commandOutput(command:List<String>,cwd:Path):String { val p=ProcessBuilder(command).directory(cwd.toFile()).start(); val s=p.inputStream.bufferedReader().readText(); check(p.waitFor()==0); return s }
fun immutableOverlayFiles('''+functions+f'''
val module=ModuleCheckout("fixture",Path({json.dumps(str(repo))}),{json.dumps(clean)})
val rows=immutableOverlayFiles(module,Path("stack.config"))
check(rows.map{{it.first.toString()}}.toSet()==setOf("stack.config/public.bin","stack.config/run.sh"))
check(overlayBlob(module,rows.first{{it.first.fileName.toString()=="public.bin"}}.second).contentEquals(byteArrayOf(0,-1)+"approved\\n".toByteArray()))
check(rows.first{{it.first.fileName.toString()=="run.sh"}}.third)
check(runCatching{{immutableOverlayFiles(module.copy(commit={json.dumps(linked)}),Path("stack.config"))}}.isFailure)
check(runCatching{{immutableOverlayFiles(module,Path("../external"))}}.isFailure)
check(runCatching{{immutableOverlayFiles(module,Path("missing"))}}.isFailure)
println("immutable overlay owning Kotlin checks: 6 passed")
''')
   try:
    cp=CP.read_text().strip();result=subprocess.run(['/usr/lib/jvm/java-21-openjdk-amd64/bin/java','-Xmx1g','-cp',cp,'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-script',str(script),'-no-stdlib','-no-reflect','-classpath',cp],capture_output=True,text=True,timeout=120,cwd=R)
    self.assertEqual(result.returncode,0,result.stderr);self.assertIn('checks: 6 passed',result.stdout)
   finally:(cfg/'private-cache').chmod(0o700)
if __name__=='__main__':unittest.main()
