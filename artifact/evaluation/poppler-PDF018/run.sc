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
  "magma-v1.2/targets/poppler/work/poppler/utils/pdfimages"
)
def instrumentedTarget = projectDir / os.RelPath(
  "magma-v1.2/targets/poppler/work/poppler/pdfimages.instrumented"
)
def inputDir = projectDir / os.RelPath(
  "evaluation/input-file/f5fda30683d10174b212f95b5519c45441c889c2"
)
def nonCrashInput = inputDir / "000025"
def crashInput = inputDir / "crash-000312"

class Task extends PolyTracker(artifactDir, projectDir) {
  def command(target: os.Path, inputFile: os.Path) = {
    val command = Seq(
      target.toString,
      inputFile.toString,
      "/tmp/out"
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
      G.matches("PDF018"),
      graphFile("subgraph.PDF018.")(inputFile)("dot"),
      ignoreWeak = true,
      n = 2000
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
  "[!] Canary triggered by PDF018"
)

Seq(
  nonCrashInput,
  crashInput
).par.foreach(task.run(_))

expectOutput(
  LogFile.stderr(artifactDir)(crashInput),
  "[!] Canary triggered by PDF018"
)

task.diff(nonCrashInput, crashInput)(Seq("PDF018"))
