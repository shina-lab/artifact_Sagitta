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

class InputSeries(
    val instrumentedTarget: os.Path,
    val inputDir: os.Path,
    nonCrashInputName: String,
    crashInputName: String
) {
  def nonCrashInput = inputDir / nonCrashInputName
  def crashInput = inputDir / crashInputName
}
val pdftoppm = new InputSeries(
  projectDir / os.RelPath(
    "magma-v1.2/targets/poppler/work/poppler/pdftoppm.instrumented"
  ),
  projectDir / os.RelPath(
    "evaluation/input-file/a8a3a0b29088a6afe16befa80417595571609db9"
  ),
  "000003",
  "crash-000119"
) // 6分くらいかかる
val pdf_fuzzer = new InputSeries(
  projectDir / os.RelPath(
    "magma-v1.2/targets/poppler/work/poppler/pdf_fuzzer.instrumented"
  ),
  projectDir / os.RelPath(
    "evaluation/input-file/815e510582dbf848322e526467347407e6320aed"
  ),
  "000000",
  "crash-000015"
) // 20分くらいかかる
val triple = pdftoppm

class Task extends PolyTracker(artifactDir, projectDir) {
  def command(target: os.Path, inputFile: os.Path) = {
    val command = target match
      case pdftoppm.instrumentedTarget =>
        Seq(
          target.toString,
          "-mono",
          "-cropbox",
          inputFile.toString
        )
      case pdf_fuzzer.instrumentedTarget =>
        Seq(
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
      command(triple.instrumentedTarget, inputFile)
    )

    unexpectOutput(
      LogFile.stderr(this.artifactDir)(inputFile),
      "[error] "
    )

    val G = analyzeTaint(inputFile)()

    renderAncestors(G)(
      G.matches("PDF010"),
      graphFile("subgraph.PDF010.")(inputFile)("dot")
    )
  }
}

cleanup(artifactDir)
build(artifactDir, projectDir)(triple.instrumentedTarget)

val task = new Task()
Seq(
  triple.nonCrashInput,
  triple.crashInput
).par.foreach(task.run(_))

expectOutput(
  LogFile.stderr(artifactDir)(triple.crashInput),
  "[!] Canary triggered by PDF010"
)

task.diff(triple.nonCrashInput, triple.crashInput)(Seq("PDF010"))
