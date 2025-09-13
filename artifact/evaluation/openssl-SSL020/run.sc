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
  "magma-v1.2/targets/openssl/repo/fuzz/server"
)
def instrumentedTarget = projectDir / os.RelPath(
  "magma-v1.2/targets/openssl/repo/server.instrumented"
)
def inputDir = projectDir / os.RelPath(
  "evaluation/input-file/34c773c1bffb7389c434899395211077dcebf8c9"
)
def nonCrashInput = inputDir / "000130"
def crashInput = inputDir / "crash-000005"

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
      LogFile.stdout(this.artifactDir)(inputFile),
      LogFile.stderr(this.artifactDir)(inputFile),
      Map("POLY_LOG_UNTAINTED_LABELS" -> "On")
    )(inputFile)(
      command(instrumentedTarget, inputFile)
    )

    val G = analyzeTaint(inputFile)()

    renderAncestors(G)(
      G.matches("SSL020"),
      graphFile("subgraph.SSL020.")(inputFile)("dot")
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
      "[!] Canary triggered by SSL020"
    )

    Task.diff(nonCrashInput, crashInput)(Seq("SSL020"))

  case Some("metrics") =>
    // パケットから対応するpayloadを読み出すコードは、他のフィールドの読み出しでも使われているため根本原因のコードとするのは不適当
    // *data = pkt->•curr; <PACKET_peek_bytes.1182>
    // よって、読み出そうとした箇所を根本原因とみなす
    // ❶入力された値（PACKET_remaining関数で読み出した値）をそのまま eticklen（関数tls_decrypt_ticketの引数）に代入
    //    ret = tls_decrypt_ticket(s, PACKET_data(&identity),
    //             PACKET_remaining(&identity), NULL, 0,
    //             &sess);
    reportItraceMetrics(
      artifactDir,
      projectDir,
      Map("MAGMA_TERM_ID" -> "SSL020")
    )(
      Task.command(target, crashInput),
      rootCauseLocation =
        SourceCodeLocation("ssl/statem/extensions_srvr.c", 1122),
      crashLocation = SourceCodeLocation("ssl/t1_lib.c", 1905)
    )

  case Some(_) =>
    println(s"[*] Unknown command: ${args(0)}")
