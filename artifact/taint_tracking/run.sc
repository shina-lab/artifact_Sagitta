#!/usr/bin/env -S scala-cli shebang --power
//> using file project.scala
//> using file taint_tracking.scala

import me.shadaj.scalapy.py

def scriptDir = scriptPath.startsWith("/") match {
  case true  => os.Path(scriptPath) / os.up
  case false => os.pwd / os.RelPath(scriptPath) / os.up
}
def buildDir = scriptDir / "build"
def projectDir = scriptDir / os.up

def target =
  projectDir / os.RelPath(
    "magma-v1.2/targets/libpng/repo/libpng_read_fuzzer.instrumented"
  )

def inputDir =
  projectDir / os.RelPath(
    "evaluation/input-file/3a54435a70b7390ac4edfba3c274f36f9afb8d61"
  )
def nonCrash = inputDir / "000003"

def clean() = {
  println("[*] == Clean")

  os.remove.all(buildDir)
}

def build() = {
  clean()

  println("[*] = Build")
  os.makeDir(buildDir)
  println("[*] == Build target")
  os.proc(
    "polytracker",
    "build",
    "clang++",
    "-g",
    "-O0",
    "-fno-discard-value-names",
    "-std=c++17",
    // "-fno-elide-constructors", // Avoid Return Value Optimization (RVO)
    "../test.cpp",
    "-o",
    "test"
  ).call(cwd = buildDir, stdout = os.Inherit, stderr = os.Inherit)
  println("[*] == Instrument target")
  os.proc("polytracker", "instrument-targets", "--taint", "test")
    .call(cwd = buildDir, stdout = os.Inherit, stderr = os.Inherit)
  // .call(cwd = buildDir, stdout = os.Inherit, stderr = os.Inherit, env = Map("POLY_DEBUG" -> "1"))
  println("[*] == Disassemble target")
  val llFile = buildDir / "test.instrumented.ll"
  os.proc("llvm-dis", "test.instrumented.bc")
    .call(cwd = buildDir, stdout = llFile, stderr = os.Inherit)
  os.proc("llvm-dis", "test.bc", "-o", "test.ll")
    .call(cwd = buildDir, stdout = os.Inherit, stderr = os.Inherit)
}

def testRun() = {
  println("[*] = Test run")

  build()

  println("[*] == Run test")
  val runTarget = buildDir / "test.instrumented"
  val poly = PolyTracker(buildDir, projectDir)
  poly.execute(
    buildDir / "test.stdout.log",
    buildDir / "test.stderr.log",
    // env = Map("POLY_LOG_UNTAINTED_LABELS" -> "On")
  )(runTarget)(
    Seq(runTarget.toString, nonCrash.toString)
  )

  os.proc("./tokenize.sc", poly.labelLog(runTarget).toString)
    .call(
      cwd = scriptDir,
      stdout = os.Path(s"${poly.labelLog(runTarget).toString}.tokens")
    )

  println("[*] == Analyze taint")
  val G = poly.analyzeTaint(runTarget)()

  println("[*] === Load graph")
  G.render(
    G.subgraph(
      G.ancestors(
        G.labels(
          G.contains("Test: x")
        )
      )
    ).writeDot(poly.graphFile("subgraph.x.")(runTarget)("dot"))
  )
  G.render(
    G.subgraph(
      G.ancestors(
        G.labels(
          G.contains("objs")
        )
      )
    ).writeDot(poly.graphFile("subgraph.objs.")(runTarget)("dot"))
  )
  G.render(
    G.subgraph(
      G.ancestors(
        G.labels(
          G.contains("memcpy")
        )
      )
    ).writeDot(poly.graphFile("subgraph.memcpy.")(runTarget)("dot"))
  )
  G.render(
    G.subgraph(
      G.ancestors(
        G.labels(
          G.contains("heap_taint_test2.c")
        )
      )
    ).writeDot(poly.graphFile("subgraph.heap_taint_test2.")(runTarget)("dot"))
  )
  G.render(
    G.subgraph(
      G.ancestors(
        G.labels(
          G.contains("dominator_test")
        )
      )
    ).writeDot(poly.graphFile("subgraph.dominator_test.")(runTarget)("dot"))
  )
  G.render(
    G.subgraph(
      G.ancestors(
        G.labels(
          G.contains("stack_test")
        )
      )
    ).writeDot(poly.graphFile("subgraph.stack_test.")(runTarget)("dot"))
  )
  G.render(
    G.subgraph(
      G.ancestors(
        G.labels(
          G.contains("stack_taint_test")
        )
      )
    ).writeDot(poly.graphFile("subgraph.stack_taint_test.")(runTarget)("dot"))
  )

  // val G = poly.loadGraph()(gmlFile)
  // G.render(
  //   G.write_dot(
  //     G.subgraph(
  //       G.ancestors(
  //         G.labels(
  //           G.contains("Test: x")
  //         )
  //       )
  //     ),
  //     poly.graphFile("subgraph.x.")(runTarget)("dot").toString
  //   )
  // )
  // G.render(
  //   G.write_dot(
  //     G.subgraph(
  //       G.descendants(
  //         G.labels(
  //           G.contains("input-file")
  //         )
  //       )
  //     ),
  //     poly.graphFile("subgraph.input-file.")(runTarget)("dot").toString
  //   )
  // )
}

// def targetRun() = {
//   println("[*] = Target run")

//   val poly = PolyTracker(buildDir, projectDir)
//   poly.execute()(target)(Seq(target.toString, nonCrash.toString))

//   targetAnalyzeTaint()
// }

// def targetAnalyzeTaint() = {
//   println("[*] == Target analyze taint")
//   val poly = PolyTracker(buildDir, projectDir)
//   val taintGraphFile = poly.analyzeTaint(target)()

//   println("[*] === Render subgraph")
//   py.local {
//     val G = poly.loadGraph()(taintGraphFile)
//     G.render(
//       G.write_dot(
//         G.subgraph(
//           G.ancestors(
//             G.ids(
//               G.matches(".*png_ptr->palette.*png_read_transform_info.*")
//             )
//           )
//         ),
//         (buildDir / s"subgraph.png_ptr.palette.${nonCrash.last}.dot").toString
//       )
//     )
//   }
// }

def diffRun() = {
  println("[*] = Diff run")

  /*
    A   B
     \ /
      C
       \
        D
   */
  var G1 = new Graph()
  val n1 = G1.addNodeLabel(G1.addWriteNode(TaintLabelId(1)), Label("A"))
  val n2 = G1.addNodeLabel(G1.addWriteNode(TaintLabelId(1)), Label("B"))
  val n3 = G1.addNodeLabel(G1.addWriteNode(TaintLabelId(1)), Label("C"))
  val n4 = G1.addNodeLabel(G1.addWriteNode(TaintLabelId(1)), Label("D"))
  G1.addEdge(n1, n3)
  G1.addEdge(n2, n3)
  G1.addEdge(n3, n4)

  /*
    E
     \
      C
       \
        D
   */
  var G2 = new Graph()
  val n5 = G2.addNodeLabel(G2.addWriteNode(TaintLabelId(1)), Label("E"))
  val n6 = G2.addNodeLabel(G2.addWriteNode(TaintLabelId(1)), Label("C"))
  val n7 = G2.addNodeLabel(G2.addWriteNode(TaintLabelId(1)), Label("D"))
  G2.addEdge(n5, n6)
  G2.addEdge(n6, n7)

  val G = Graph.diff(G1, G2)
  G._1.render(G._1.writeDot(buildDir / "G1.dot"))
  G._2.render(G._2.writeDot(buildDir / "G2.dot"))
}

def all() = {
  println("[*] = All")
  testRun()
  // targetRun()
  diffRun()
}

// def docker() = {
//   println("[*] = Docker")

//   // NOTE: -l -c は引数１つまでしか受け付けない
//   dockerRun("polytracker", Seq("bash", "-l", "-c", "./run.sc"), os.pwd / os.up)
//   // FIXME: => "PermissionError: [Errno 13] Permission denied: 'gclang++'"
// }

var command = args.length match {
  case 0 => "all" // Default command
  case _ => args(0)
}

command match {
  case "clean" => clean()
  case "test"  => testRun()
  // case "target"  => targetRun()
  // case "analyze" => targetAnalyzeTaint()
  case "all" => all()
  // case "docker" => docker()
  case "diff" => diffRun()
  case _      => println(s"[!] Invalid command: ${command}")
}
