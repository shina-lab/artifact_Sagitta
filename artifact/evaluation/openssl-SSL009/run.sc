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
  "magma-v1.2/targets/openssl/repo/x509.instrumented"
)

def inputDir = projectDir / os.RelPath(
  "evaluation/input-file/5800206d864adc35552c7d33552721c15baa37e6"
)
def nonCrashInput = inputDir / "000169"
def crashInput = inputDir / "crash-000004"

class Task extends PolyTracker(artifactDir, projectDir) {
  def run(inputFile: os.Path) = {
    execute(
      LogFile.stdout(this.artifactDir)(inputFile),
      LogFile.stderr(this.artifactDir)(inputFile)
      // Map("POLY_LOG_UNTAINTED_LABELS" -> "On")
    )(inputFile)(
      Seq(
        instrumentedTarget.toString,
        inputFile.toString
      )
    )

    val G = analyzeTaint(inputFile)()

    renderAncestors(G)(
      G.matches("SSL009"),
      graphFile("subgraph.SSL009.")(inputFile)("dot")
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
  "[!] Canary triggered by SSL009"
)

task.diff(nonCrashInput, crashInput)(Seq("SSL009"))
