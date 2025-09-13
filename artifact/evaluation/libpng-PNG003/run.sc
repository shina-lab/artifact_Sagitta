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

def inputDir = projectDir / os.RelPath(
  "evaluation/input-file/481e0952be03728a70a99d9ad68f6c4f90748820"
)
def nonCrashInput = inputDir / "000342"
def crashInput = inputDir / "crash-000005"

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
    )(inputFile)(
      command(instrumentedTarget, inputFile)
    )

    unexpectOutput(
      LogFile.stderr(this.artifactDir)(inputFile),
      "[error] "
    )

    val G = analyzeTaint(inputFile)()

    // renderAncestors(G)(
    //   G.matches("num .* <png_handle_PLTE>"),
    //   graphFile("subgraph.num.")(inputFile)("dot")
    // )
    // renderAncestors(G)(
    //   G.matches("max_palette_length .* <png_handle_PLTE>"),
    //   graphFile("subgraph.max_palette_length.")(inputFile)("dot")
    // )
    renderAncestors(G)(
      G.matches("PNG003"),
      graphFile("subgraph.PNG003.")(inputFile)("dot")
    )
  }
}

val command = args.length match
  case 0 => None
  case _ => Some(args(0))
command match
  case None =>
    build(artifactDir, projectDir)(instrumentedTarget)

    Seq(
      nonCrashInput,
      crashInput
    ).par.foreach(Task.run(_))
    expectOutput(
      LogFile.stderr(artifactDir)(crashInput),
      "[!] Canary triggered by PNG003"
    )

    Task.diff(nonCrashInput, crashInput)(Seq("PNG003"))

  case Some("metrics") =>
    // ❶IHDRセクションの bits フィールドの値が小さくなった
    // bit_depth = •buf[8]; <png_handle_IHDR>
    reportItraceMetrics(artifactDir, projectDir)(
      Task.command(target, crashInput),
      SourceCodeLocation("pngrutil.c", 861),
      crashLocation = SourceCodeLocation("pngrutil.c", 992)
    )

  case Some(_) =>
    println(s"[*] Unknown command: ${args(0)}")
