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
  "magma-v1.2/targets/libpng/libpng_read_fuzzer"
)
def instrumentedTarget = projectDir / os.RelPath(
  "magma-v1.2/targets/libpng/repo/libpng_read_fuzzer.instrumented"
)
def inputDir = projectDir / os.RelPath(
  "evaluation/input-file/a2e7b0db62bc61145d305d537acd61c5879cb208"
)
def nonCrashInput = inputDir / "003731"
def crashInput = inputDir / "crash-000108"

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
      LogFile.stdout(this.artifactDir)(inputFile),
      LogFile.stderr(this.artifactDir)(inputFile)
    )(inputFile)(
      command(instrumentedTarget, inputFile)
    )

    val G = analyzeTaint(inputFile)()

    renderAncestors(G)(
      G.matches("PNG006"),
      graphFile("subgraph.PNG006.")(inputFile)("dot"),
      n = 2000
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
      "[!] Canary triggered by PNG006"
    )

    Task.diff(nonCrashInput, crashInput)(Seq("PNG006"))

  case Some("metrics") =>
    // ❶このバグを発生させるには、fuzzerが有効な入力とeXIFチャンクを作れば十分です（オブジェクトの破壊時にマーク（free_me）が解除されないため、ダングリングポインタが発生します）（※Magma論文ママ）
    // info_ptr->eXIf_buf = png_voidcast(png_bytep, png_malloc_warn(png_ptr, length)); ※行を追加するパッチだったので、最も近い行を選んだ
    reportItraceMetrics(artifactDir, projectDir)(
      Task.command(target, crashInput),
      rootCauseLocation = ("pngrutil.c", 2071),
      crashLocation = ("png.c", 620)
    )

  case Some(_) =>
    println(s"[*] Unknown command: ${args(0)}")
