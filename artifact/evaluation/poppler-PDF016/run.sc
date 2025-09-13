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

def instrumentedTarget = projectDir / os.RelPath(
  "magma-v1.2/targets/poppler/work/poppler/pdfimages.instrumented"
)
def inputDir = projectDir / os.RelPath(
  "evaluation/input-file/66fa547598c420d7bf2f8043f8a9986c488e7a0f"
)
def nonCrashInput = inputDir / "000024"
def crashInput = inputDir / "crash-000225"

class Task extends PolyTracker(artifactDir, projectDir) {
  def command(target: os.Path, inputFile: os.Path) = {
    val command = Seq(
      target.toString,
      inputFile.toString,
      "/dev/null"
    )
    println(s"[*] Running: ${command.mkString(" ")}")
    command
  }

  def run(inputFile: os.Path) = {
    val startTime = System.currentTimeMillis()

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
      G.matches("\"PDF016\""),
      graphFile("subgraph.PDF016.")(inputFile)("dot")
    )

    renderAncestors(G)(
      G.matches("\"PDF011\""),
      graphFile("subgraph.PDF011.")(inputFile)("dot")
    )

    // DEBUG:
    if inputFile == nonCrashInput then {
      renderDescendants(G)(
        G.startsWith("000024[0x13"),
        graphFile("subgraph.non-crash-offset-0x130.")(inputFile)("dot")
      )
    }

    val endTime = System.currentTimeMillis()
    println(
      s"[*|${inputFile.last}] run: Total execution time ${(endTime - startTime) / 1000.0} sec"
    )
  }
}

cleanup(artifactDir)
build(artifactDir, projectDir)(instrumentedTarget)

val task = new Task()
Seq(
  nonCrashInput,
  crashInput
).par.foreach(task.run(_))

expectOutput(
  LogFile.stderr(artifactDir)(crashInput),
  "[!] Canary triggered by PDF016"
)

task.diff(nonCrashInput, crashInput)(Seq("PDF016", "PDF011"))
