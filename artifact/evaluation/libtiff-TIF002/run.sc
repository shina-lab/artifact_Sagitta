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
  "magma-v1.2/targets/libtiff/tiff_read_rgba_fuzzer"
)
def instrumentedTarget = projectDir / os.RelPath(
  "magma-v1.2/targets/libtiff/repo/tiff_read_rgba_fuzzer.instrumented"
)
def inputDir = projectDir / os.RelPath(
  "evaluation/input-file/29367f9cdba0e770c3b6a2f081c07db679b18009"
)

// def nonCrashInput = inputDir / "005435" // 局所化グラフが空
// def nonCrashInput = inputDir / "005444" // 局所化グラフが空
// def nonCrashInput = inputDir / "005450" // 局所化グラフが空
// def nonCrashInput = inputDir / "005458" // 局所化グラフが空
// def nonCrashInput = inputDir / "005469" // 局所化グラフが空
def nonCrashInput = inputDir / "006022" // 局所化グラフが空
def crashInput = inputDir / "crash-000295"
def pocInput = projectDir / os.RelPath(
  "evaluation/input-file/PoC/TIF002/CVE-2016-5314.tif"
)

class Task extends PolyTracker(artifactDir, projectDir) {
  def command(target: os.Path, inputFile: os.Path) = {
    assert(os.exists(inputFile), s"${inputFile} does not exist")
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

    val G = analyzeTaint(inputFile)(ignoreDominator = true)

    renderAncestors(G)(
      G.matches("TIF002"),
      graphFile("subgraph.TIF002.")(inputFile)("dot"),
      ignoreWeak = true
    )
  }
}

// cleanup(artifactDir)
build(artifactDir, projectDir)(instrumentedTarget)

val task = new Task()

// os.proc(
//   task.command(target, pocInput)
// ).call(
//   check = false,
//   stdout = LogFile.stdout(artifactDir)(target),
//   stderr = LogFile.stderr(artifactDir)(target)
// )
// expectOutput(
//   LogFile.stderr(artifactDir)(target),
//   "[!] Canary triggered by TIF002"
// )

Seq(
  nonCrashInput,
  crashInput
).par.foreach(task.run(_))

expectOutput(
  LogFile.stderr(artifactDir)(crashInput),
  "[!] Canary triggered by TIF002"
)

task.diff(nonCrashInput, crashInput)(Seq("TIF002"))
