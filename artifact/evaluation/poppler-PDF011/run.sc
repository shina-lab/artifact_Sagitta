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
  "magma-v1.2/targets/poppler/work/poppler/utils/pdfimages"
)
def instrumentedTarget = projectDir / os.RelPath(
  "magma-v1.2/targets/poppler/work/poppler/pdfimages.instrumented"
)
def inputDir = projectDir / os.RelPath(
  "evaluation/input-file/44ca73120eb7678d9cf7e690843f10a7a4bba463"
)
def nonCrashInput = inputDir / "000017"
def crashInput = inputDir / "crash-000159"

object Task extends PolyTracker(artifactDir, projectDir) {
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
      LogFile.stderr(this.artifactDir)(inputFile),
      Map("MAGMA_TERM_ID" -> "PDF011")
    )(inputFile)(
      command(instrumentedTarget, inputFile)
    )

    unexpectOutput(
      LogFile.stderr(this.artifactDir)(inputFile),
      "[error] "
    )

    val G = analyzeTaint(inputFile)(ignoreDominator = true)

    renderLastAncestors(G)(
      G.matches("\"PDF011\""),
      graphFile("subgraph.PDF011.")(inputFile)("dot"),
      ignoreWeak = true,
      n = 2000
    )

    // renderDescendants(G)(
    //   G.contains(s"${inputFile.last}[0x1e9]"),
    //   graphFile("subgraph.offset-1e9.")(inputFile)("dot"),
    //   ignoreWeak = true
    // )

    val endTime = System.currentTimeMillis()
    println(
      s"[*|${inputFile.last}] run: Total execution time ${(endTime - startTime) / 1000.0} sec"
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
      "[!] Canary triggered by PDF011"
    )

    Task.diff(nonCrashInput, crashInput)(Seq("PDF011"))

  case Some("metrics") =>
    // ❶入力ファイルから読み出したXRef (indirect reference object) が負値である
    // 対応するソースコードが無いため厳密な計測不能。PDFのIntegerオブジェクトの読み出しが共通化されている
    // const int gen = buf1.getInt(); ←あえてソースコードに一番近い根本原因を選ぶとここ
    reportItraceMetrics(
      artifactDir,
      projectDir,
      Map("MAGMA_TERM_ID" -> "PDF011")
    )(
      Task.command(target, crashInput),
      rootCauseLocation = SourceCodeLocation("Parser.cc", 181),
      crashLocation = SourceCodeLocation("XRef.cc", 1679)
    )

  case Some(_) =>
    println(s"[*] Unknown command: ${args(0)}")
