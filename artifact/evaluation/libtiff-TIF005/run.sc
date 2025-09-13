#!/usr/bin/env -S scala-cli shebang --power
//> using python
//> using toolkit latest
//> using dep org.scala-lang.modules::scala-parallel-collections:1.0.4
//> using file ../../taint_tracking/taint_tracking.scala
//> using file ../common.scala
//> using file ../metrics_itrace.scala

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
  "evaluation/input-file/6256014af6e239bcd904b49d6f2ad37ca6818ea7"
)
def nonCrashInput = inputDir / "000707"
def crashInput = inputDir / "crash-000034"

object Task extends PolyTracker(artifactDir, projectDir) {
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

    renderLastAncestors(G)(
      G.matches("\"TIF005\""),
      graphFile("subgraph.TIF005.")(inputFile)("dot"),
      lastN = 2
    )
    renderLastAncestors(G)(
      G.matches("TIF005-actual"),
      graphFile("subgraph.TIF005-actual.")(inputFile)("dot"),
      ignoreWeak = true,
      lastN = 5
    )
  }
}

val command = args.length match
  case 0 => None
  case _ => Some(args(0))
command match
  case None =>
    cleanup(artifactDir)
    build(artifactDir, projectDir)(instrumentedTarget)

    os.proc(
      Task.command(target, crashInput)
    ).call(
      check = false,
      stdout = LogFile.stdout(artifactDir)(target),
      stderr = LogFile.stderr(artifactDir)(target)
    )
    expectOutput(
      LogFile.stderr(artifactDir)(target),
      "[!] Canary triggered by TIF005"
    )

    Seq(
      nonCrashInput,
      crashInput
    ).par.foreach(Task.run(_))

    expectOutput(
      LogFile.stderr(artifactDir)(crashInput),
      "[!] Canary triggered by TIF005"
    )

    Task.diff(nonCrashInput, crashInput)(Seq("TIF005", "TIF005-actual"))

  case Some("metrics") =>
    // ❸LogLuvClose関数でoutをbitspersample=16に書き換え
    // td->td_bitspersample •= 16; <LogLuvClose>
    reportItraceMetrics(artifactDir, projectDir)(
      Task.command(target, crashInput),
      rootCauseLocation = SourceCodeLocation("tif_luv.c", 1577),
      crashLocation =
        SourceCodeLocation("tif_dirwrite.c", 2065) // TIF005-actual
    )

  case Some(_) =>
    println(s"[*] Unknown command: ${args(0)}")
