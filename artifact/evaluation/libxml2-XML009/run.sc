#!/usr/bin/env -S scala-cli shebang --power
//> using python
//> using toolkit latest
//> using dep org.scala-lang.modules::scala-parallel-collections:1.0.4
//> using file ../../taint_tracking/taint_tracking.scala
//> using file ../common.scala

import me.shadaj.scalapy.py
import scala.collection.parallel.CollectionConverters._

def scriptDir = scriptPath.startsWith("/") match {
  case true  => os.Path(scriptPath) / os.up
  case false => os.pwd / os.RelPath(scriptPath) / os.up
}
def artifactDir = scriptDir / "result"
def projectDir = scriptDir / os.up / os.up

def target = projectDir / os.RelPath(
  "magma-v1.2/targets/libxml2/libxml2_xml_read_memory_fuzzer"
)
def instrumentedTarget = projectDir / os.RelPath(
  "magma-v1.2/targets/libxml2/repo/libxml2_xml_read_memory_fuzzer.instrumented"
)
def inputDir = projectDir / os.RelPath(
  "evaluation/input-file/e889da585fc8fe7a3622e34cb6fe6f80541064e0"
)
def nonCrashInput1 = inputDir / "000042" // encoding が UTF-8
def nonCrashInput2 = inputDir / "002485" // encoding が UTF-7
def crashInput = inputDir / "crash-000927" // encoding が UTF-7

class Task extends PolyTracker(artifactDir, projectDir) {
  def command(target: os.Path, inputFile: os.Path) = {
    val command = Seq(
      target.toString,
      inputFile.toString
    )
    println(s"[*] Running: ${command.mkString(" ")}")
    command
  }

  def run(inputFile: os.Path) = {
    execute(
      LogFile.stdout(this.artifactDir)(inputFile),
      LogFile.stderr(this.artifactDir)(inputFile)
    )(inputFile)(
      command(instrumentedTarget, inputFile)
    )

    unexpectOutput(
      LogFile.stderr(this.artifactDir)(inputFile),
      "[error] "
    )

    val G = analyzeTaint(inputFile)()

    renderAncestors(G)(
      G.matches("XML009"),
      graphFile("subgraph.XML009.")(inputFile)("dot")
    )
    renderAncestors(G)(
      G.contains("= xmlCharEncFirstLineInput"),
      graphFile("subgraph.xmlCharEncFirstLineInput.")(inputFile)("dot")
    )
  }
}

cleanup(artifactDir)
build(artifactDir, projectDir)(instrumentedTarget)

val task = new Task()

os.proc(
  task.command(target, crashInput)
).call(
  check = false,
  stdout = LogFile.stdout(artifactDir)(target),
  stderr = LogFile.stderr(artifactDir)(target)
)
expectOutput(
  LogFile.stderr(artifactDir)(target),
  "[!] Canary triggered by XML009"
)

Seq(
  nonCrashInput1,
  nonCrashInput2,
  crashInput
).par.foreach(task.run(_))

expectOutput(
  LogFile.stderr(artifactDir)(crashInput),
  "[!] Canary triggered by XML009"
)

task.diff(nonCrashInput2, crashInput)(Seq("XML009"))
