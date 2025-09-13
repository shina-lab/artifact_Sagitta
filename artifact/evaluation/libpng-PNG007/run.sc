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

def target =
  projectDir / os.RelPath("magma-v1.2/targets/libpng/libpng_read_fuzzer")
def instrumentedTarget = projectDir / os.RelPath(
  "magma-v1.2/targets/libpng/repo/libpng_read_fuzzer.instrumented"
)

def inputDir =
  projectDir / os.RelPath(
    "evaluation/input-file/3a54435a70b7390ac4edfba3c274f36f9afb8d61"
  )
def nonCrashInput = inputDir / "000003"
def crashInput = inputDir / "crash-000066"

object Task extends PolyTracker(artifactDir, projectDir) {
  def command(target: os.Path, inputFile: os.Path) = {
    assert(os.exists(inputFile), s"${inputFile} does not exist")
    val command = Seq(
      target.toString,
      inputFile.toString
    )
    println(s"[*] Running: ${command.mkString(" ")}")
    command
  }

  def run(inputFile: os.Path) = {
    execute(
      this.artifactDir / s"stdout.${inputFile.baseName}.log",
      this.artifactDir / s"stderr.${inputFile.baseName}.log"
    )(inputFile)(
      command(instrumentedTarget, inputFile)
    )

    unexpectOutput(
      LogFile.stderr(this.artifactDir)(inputFile),
      "[error] "
    )

    val G = analyzeTaint(inputFile)()
    renderAncestors(G)(
      G.contains("\"PNG007\""),
      graphFile("subgraph.PNG007.")(inputFile)("dot"),
      ignoreWeak = true
    )
    renderAncestors(G)(
      G.contains("PNG007-actual"),
      graphFile("subgraph.PNG007-actual.")(inputFile)("dot"),
      ignoreWeak = true
    )
    // renderDescendants(G)(
    //   G.contains("png_ptr->palette = &bull;png_voidcast("),
    //   graphFile("subgraph.palette-calloc.")(inputFile)("dot"),
    //   ignoreWeak = true,
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

    Seq(
      nonCrashInput,
      crashInput
    ).par.foreach(Task.run(_))
    expectOutput(
      LogFile.stderr(artifactDir)(crashInput),
      "[!] Canary triggered by PNG007-actual"
    )

    Task.diff(nonCrashInput, crashInput)(Seq("PNG007", "PNG007-actual"))

  case Some("metrics") =>
    // ❶paletteのメモリ確保をせずに関数をExit（処理続行）
    // png_chunk_report(png_ptr, "Invalid palette", PNG_CHUNK_ERROR);
    reportItraceMetrics(artifactDir, projectDir)(
      Task.command(target, crashInput),
      rootCauseLocation = SourceCodeLocation("pngset.c", 613),
      crashLocation =
        SourceCodeLocation("pngrtran.c", 4367) // *dp-- = palette[*sp].blue;
    )

  case Some(_) =>
    println(s"[*] Unknown command: ${args(0)}")
