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
  "magma-v1.2/targets/libtiff/repo/build/tools/tiffcp"
)
def instrumentedTarget = projectDir / os.RelPath(
  "magma-v1.2/targets/libtiff/repo/tiffcp.instrumented"
)
def inputDir = projectDir / os.RelPath(
  "evaluation/input-file/c7aba08c1ec309b1229e9ae38075e09d44483e06"
)
/* 📝
- 000000: カナリア通過
- 000114: カナリア通過
- 000792: カナリア通過せず
 */
def nonCrashInput = inputDir / "000114"
def crashInput = inputDir / "crash-000044"

class Task extends PolyTracker(artifactDir, projectDir) {
  def command(target: os.Path, inputFile: os.Path) = {
    val command = Seq(
      target.toString,
      "-M",
      inputFile.toString,
      (this.artifactDir / s"${inputFile.baseName}.tmp.out").toString
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
      G.matches("TIF012-2"),
      graphFile("subgraph.TIF012-2.")(inputFile)("dot"),
      ignoreWeak = true
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
  "[!] Canary triggered by TIF012"
)

Seq(
  inputDir / "000000",
  nonCrashInput,
  inputDir / "000792",
  crashInput
).par.foreach(task.run(_))

expectOutput(
  LogFile.stderr(artifactDir)(crashInput),
  "[!] Canary triggered by TIF012"
)

task.diff(nonCrashInput, crashInput)(Seq("TIF012-2"))
