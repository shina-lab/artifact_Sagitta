#!/usr/bin/env -S scala-cli shebang --power
//> using python
//> using toolkit default
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

def target =
  projectDir / os.RelPath("magma-v1.2/targets/libpng/libpng_read_fuzzer")
def instrumentedTarget = projectDir / os.RelPath(
  "magma-v1.2/targets/libpng/repo/libpng_read_fuzzer.instrumented"
)
def inputDir = projectDir / os.RelPath(
  "evaluation/input-file/eb347440f0702b05b849995f2cb2b77148f82c45"
)
def nonCrashInput = inputDir / "000974"
def crashInput = inputDir / "crash-000073"

object Task extends PolyTracker(artifactDir, projectDir) {
  def command(instrumentedTarget: os.Path, inputFile: os.Path) = {
    assert(os.exists(inputFile), s"${inputFile} does not exist")
    val command = Seq(
      instrumentedTarget.toString,
      inputFile.toString
    )
    println(s"[*] Running: ${command.mkString(" ")}")
    command
  }

  def run(inputFile: os.Path) = {
    execute(
      this.artifactDir / s"stdout.${inputFile.baseName}.log",
      this.artifactDir / s"stderr.${inputFile.baseName}.log"
      // env=Map("POLY_LOG_UNTAINTED_LABELS" -> "On")
    )(inputFile)(
      Seq(instrumentedTarget.toString, inputFile.toString)
    )

    unexpectOutput(
      LogFile.stderr(this.artifactDir)(inputFile),
      "[error] "
    )

    val G = analyzeTaint(inputFile)()

    renderAncestors(G)(
      G.matches("PNG001"),
      graphFile("subgraph.PNG001.")(inputFile)("dot")
      // G.matches("row_factor_l :(size_t) <png_check_chunk_length>"),
      // graphFile("subgraph.row_factor_l.")(inputFile)("dot")
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

    Seq(
      nonCrashInput,
      crashInput
    ).par.foreach(Task.run(_))

    Task.diff(nonCrashInput, crashInput)(Seq("PNG001"))

  case Some("metrics") =>
    // ❶IHDRセククションのフィールド値がユーザーにより操作可能（これはPNGの仕様）
    // interlace_type = •buf[12]; <png_handle_IHDR>
    reportItraceMetrics(artifactDir, projectDir)(
      Task.command(target, crashInput),
      rootCauseLocation = SourceCodeLocation("pngrutil.c", 865),
      crashLocation = SourceCodeLocation("pngrutil.c", 3189)
    )

  case Some(_) =>
    println(s"[*] Unknown command: ${args(0)}")
