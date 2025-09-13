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
  "evaluation/input-file/a4e5131f88891c8fc828284b4cc3da4a3ecaf69b"
)
def nonCrashInput = inputDir / "001608"
def crashInput = inputDir / "crash-000085"

class Task extends PolyTracker(artifactDir, projectDir) {
  def command(target: os.Path, inputFile: os.Path) = {
    assert(os.exists(inputFile), s"${inputFile} does not exist")
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
      G.matches("TIF007"),
      graphFile("subgraph.TIF007.")(inputFile)("dot")
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
  "[!] Canary triggered by TIF007"
)

Seq(
  nonCrashInput,
  crashInput
).par.foreach(task.run(_))

expectOutput(
  LogFile.stderr(artifactDir)(crashInput),
  "[!] Canary triggered by TIF007"
)

task.diff(nonCrashInput, crashInput)(Seq("TIF007"))
