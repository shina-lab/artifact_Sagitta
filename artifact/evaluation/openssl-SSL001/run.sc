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
  "magma-v1.2/targets/openssl/repo/fuzz/asn1"
)
def instrumentedTarget = projectDir / os.RelPath(
  "magma-v1.2/targets/openssl/repo/asn1.instrumented"
)
def inputDir = projectDir / os.RelPath(
  "evaluation/input-file/a5b412c7572ca8c613d74c8eeb1021b5fd213d40"
)
def nonCrashInput = inputDir / "001179"
def crashInput = inputDir / "crash-000002"

object Task extends PolyTracker(artifactDir, projectDir) {
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
      // Map("POLY_LOG_UNTAINTED_LABELS" -> "On")
    )(inputFile)(
      command(instrumentedTarget, inputFile)
    )

    // カナリアがパッチが当たったwhile文に支配されている
    val G = analyzeTaint(inputFile)(ignoreDominator = false)

    renderAncestors(G)(
      G.matches("SSL001"),
      graphFile("subgraph.SSL001.")(inputFile)("dot"),
      n = 2000,
      ignoreWeak = true
    )
  }
}

val command = args.length match
  case 0 => None
  case _ => Some(args(0))
command match
  case None =>
    // cleanup(artifactDir)
    build(artifactDir, projectDir)(instrumentedTarget)

    Seq(
      nonCrashInput,
      crashInput
    ).par.foreach(Task.run(_))

    expectOutput(
      LogFile.stderr(artifactDir)(crashInput),
      "[!] Canary triggered by SSL001"
    )

    Task.diff(nonCrashInput, crashInput)(Seq("SSL001"))

  case Some("diff") =>
    Task.diff(nonCrashInput, crashInput)(Seq("SSL001"))

  case Some("metrics") =>
    reportItraceMetrics(
      artifactDir,
      projectDir,
      Map("MAGMA_TERM_ID" -> "SSL001")
    )(
      Task.command(target, crashInput),
      rootCauseLocation = SourceCodeLocation("a_int.c", 164), // while (!*n) {
      crashLocation = SourceCodeLocation("a_int.c", 175)
    )

  case Some(_) =>
    println(s"[*] Unknown command: ${args(0)}")
