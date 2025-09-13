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

def target = projectDir / os.RelPath(
  "magma-v1.2/targets/poppler/work/poppler/utils/pdfdetach"
)
def instrumentedTarget = projectDir / os.RelPath(
  "magma-v1.2/targets/poppler/work/poppler/pdfdetach.instrumented"
)
def inputDir = projectDir / os.RelPath(
  "evaluation/input-file/6325ac3c300544dd539425e72d29ae772740be44"
)
def nonCrashInput = inputDir / "000000"
def crashInput = inputDir / "crash-000025"

object Task extends PolyTracker(artifactDir, projectDir) {
  def command(target: os.Path, inputFile: os.Path) = {
    val command = Seq(
      target.toString,
      "-o",
      "/dev/null",
      "-save",
      "1",
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

    unexpectOutput(
      LogFile.stderr(this.artifactDir)(inputFile),
      "[error] "
    )

    val G = analyzeTaint(inputFile)()
    G.render(
      G.subgraph(
        G.ancestors(
          G.labels(
            G.contains("PDF015")
          ),
          n = 500
        )
      ).write(graphFile("subgraph.PDF015.")(inputFile)("dot"))
    )
    // G.render(
    //   G.subgraph(
    //     G.ancestors(
    //       G.labels(
    //         G.contains("embFile = ")
    //       )
    //     )
    //   ).write(graphFile("subgraph.embFile.")(inputFile)("dot"))
    // )
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
      target.toString,
      "-o",
      "/dev/null",
      "-save",
      "1",
      crashInput.toString
    ).call(
      check = false,
      stdout = LogFile.stdout(artifactDir)(target),
      stderr = LogFile.stderr(artifactDir)(target)
    )
    expectOutput(
      LogFile.stderr(artifactDir)(target),
      "[!] Canary triggered by PDF015"
    )

    Seq(
      nonCrashInput,
      crashInput
    ).par.foreach(Task.run(_))

    expectOutput(
      LogFile.stderr(artifactDir)(crashInput),
      "[!] Canary triggered by PDF015"
    )

    Task.diff(nonCrashInput, crashInput)(Seq("PDF015"))

  case Some("metrics") =>
    // ❶Stream型と思ってオブジェクトをパースしたが、文法エラーでDict型にフォールバック
    // if (allowStreams && (str = makeStream(std::move(obj), fileKey, encAlgorithm, keyLength, objNum, objGen, recursion + 1, strict))) {
    // •return obj; <_ZN6Parser6getObjEbPKh14CryptAlgorithmiiiibb> (1330415)
    reportItraceMetrics(
      artifactDir,
      projectDir,
      Map("MAGMA_TERM_ID" -> "PDF015")
    )(
      Task.command(target, crashInput),
      rootCauseLocation = SourceCodeLocation("Parser.cc", 167, 40),
      crashLocation = SourceCodeLocation("FileSpec.cc", 107)
    )

  case Some(_) =>
    println(s"[*] Unknown command: ${args(0)}")
