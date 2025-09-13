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
  "magma-v1.2/targets/libtiff/tiff_read_rgba_fuzzer"
)
def instrumentedTarget = projectDir / os.RelPath(
  "magma-v1.2/targets/libtiff/repo/tiff_read_rgba_fuzzer.instrumented"
)
def inputDir = projectDir / os.RelPath(
  "evaluation/input-file/7fcf1f3ea2333be518eac93dc8bcfc276272db21"
)
def nonCrashInput = inputDir / "004839"
def crashInput = inputDir / "crash-000117"

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
      LogFile.stderr(this.artifactDir)(inputFile),
      Map("MAGMA_TERM_ID" -> "TIF008")
    )(inputFile)(
      command(instrumentedTarget, inputFile)
    )

    val G = analyzeTaint(inputFile)()

    renderAncestors(G)(
      G.contains("TIF008"),
      graphFile("subgraph.TIF008.")(inputFile)("dot"),
      ignoreWeak = true,
      n = 2000
    )

    // DEBUG:
    if inputFile == crashInput then
      renderDescendants(G)(
        G.contains(s"${inputFile.last}[0x7a2]"),
        graphFile("subgraph.offset-7a2.")(inputFile)("dot"),
        n = 1000
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

    expectOutput(
      LogFile.stderr(artifactDir)(crashInput),
      "[!] Canary triggered by TIF008"
    )

    Task.diff(nonCrashInput, crashInput)(Seq("TIF008"))

  case Some("metrics") =>
    // ❶メモリ読み出しを伴うループが、入力ファイルの入力のTileWidthフィールドに支配されている
    // td->td_imagewidth = (uint32_t) •va_arg(ap, uint32_t); <_TIFFVSetField> (11856#39533)
    reportItraceMetrics(artifactDir, projectDir)(
      Task.command(target, crashInput),
      rootCauseLocation = SourceCodeLocation("tif_dir.c", 360), // より根本と言えるコード
      // rootCauseLocation = SourceCodeLocation("tif_next.c", 108), // 根本原因の説明の文章に近いコード（クラッシュの直前すぎる）
      crashLocation = SourceCodeLocation("tif_next.c", 132)
    )

  case Some(_) =>
    println(s"[*] Unknown command: ${args(0)}")
