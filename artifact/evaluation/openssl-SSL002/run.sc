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

def instrumentedTarget = projectDir / os.RelPath(
  "magma-v1.2/targets/openssl/repo/client.instrumented"
)
def inputDir = projectDir / os.RelPath(
  "evaluation/input-file/8ce65c0633e35d7a16a5c750fd764c4a6368c397"
)
def nonCrashInput = inputDir / "000086"
def crashInput = inputDir / "crash-000017"

class Task extends PolyTracker(artifactDir, projectDir) {
  def run(inputFile: os.Path) = {
    execute(
      LogFile.stdout(this.artifactDir)(inputFile),
      LogFile.stderr(this.artifactDir)(inputFile)
      // Map("POLY_LOG_UNTAINTED_LABELS" -> "On")
    )(inputFile)(
      Seq(
        instrumentedTarget.toString,
        inputFile.toString
      )
    )

    val G = analyzeTaint(inputFile)(ignoreDominator = true)

    renderAncestors(G)(
      // echo "render(write_dot(G.subgraph(ancestors(ids(matches('s->init_msg :.* <grow_init_buf>'))[-1])), 'subgraph.init_msg.$(basename $1).dot'))"; \
      // echo "render(write_dot(G.subgraph(ancestors(ids(matches('s->init_buf->data :.* <grow_init_buf>'))[-1])), 'subgraph.init_buf.data.$(basename $1).dot'))"; \
      // echo "render(write_dot(G.subgraph(ancestors(ids(matches('msg_offset :.* <grow_init_buf>'))[-1])), 'subgraph.msg_offset.$(basename $1).dot'))"; \
      G.matches("SSL002"),
      graphFile("subgraph.SSL002.")(inputFile)("dot")
    )
  }
}

// TODO:
// metrics_itrace() {
//     cd ${run_dir}/result/
//     ASAN_OPTIONS=exitcode=0 ${PIN} -t ${PINTOOL} -- ${TARGET}.orig $1
//     python3 ${run_dir}/../metrics_itrace.py iaddr2line.log > executed_lines.log
//     cd -
// }

// cleanup(artifactDir)
build(artifactDir, projectDir)(instrumentedTarget)

val task = new Task()
Seq(
  nonCrashInput,
  crashInput
).par.foreach(task.run(_))

expectOutput(
  LogFile.stderr(artifactDir)(crashInput),
  "[!] Canary triggered by SSL002"
)

task.diff(nonCrashInput, crashInput)(Seq("SSL002"))
