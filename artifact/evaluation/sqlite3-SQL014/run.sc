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
  "evaluation/input-file/e2908402b3f4ef349b07e1eb9429eeae99e58669"
)
def nonCrashInput = inputDir / "003220"
def crashInput = inputDir / "crash-000054"
def origCrashInput = projectDir / os.RelPath(
  "magma-artifact/afl/afl_sqlite3_sqlite3_fuzz_JCH228.0d4"
)

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
      G.matches("SQL014"),
      graphFile("subgraph.SQL014.")(inputFile)("dot")
    )
  }
}

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
  "[!] Canary triggered by SQL014"
)

Seq(
  nonCrashInput,
  crashInput
).par.foreach(task.run(_))

expectOutput(
  LogFile.stderr(artifactDir)(crashInput),
  "[!] Canary triggered by SQL014"
)

task.diff(nonCrashInput, crashInput)(Seq("SQL014"))
