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
  "magma-v1.2/targets/sqlite3/sqlite3_fuzz"
)
def instrumentedTarget = projectDir / os.RelPath(
  "magma-v1.2/targets/sqlite3/work/sqlite3_fuzz.instrumented"
)
def inputDir = projectDir / os.RelPath(
  "evaluation/input-file/79577211db355239822497abb588b009ff65e648"
)
def nonCrashInput = inputDir / "003184"
def crashInput = inputDir / "crash-000015"

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

    expectOutput(
      LogFile.stdout(this.artifactDir)(inputFile),
      "[*] Saving output file"
    )
    unexpectOutput(
      LogFile.stderr(this.artifactDir)(inputFile),
      "[error] "
    )

    val G = analyzeTaint(inputFile)()

    renderAncestors(G)(
      G.matches("SSL002"),
      graphFile("subgraph.SSL002.")(inputFile)("dot")
    )
  }
}

cleanup(artifactDir)
build(artifactDir, projectDir)(instrumentedTarget)

val task = new Task()

os.proc(task.command(target, crashInput))
  .call(
    stdout = LogFile.stdout(artifactDir)(target),
    stderr = LogFile.stderr(artifactDir)(target)
  )

Seq(
  nonCrashInput,
  crashInput
).par.foreach(task.run(_))

expectOutput(
  LogFile.stderr(artifactDir)(crashInput),
  "[!] Canary triggered by SQL002"
)

task.diff(nonCrashInput, crashInput)(Seq("SQL002"))
