//> using toolkit default
import me.shadaj.scalapy.py

def dataflowAnalyzerDir = os.RelPath("data-flow-analyzer")
def dataflowAnalyzer =
  dataflowAnalyzerDir / os.RelPath("target/debug/data-flow-analyzer")

object LogFile {
  def stdout(artifactDir: os.Path)(inputFile: os.Path): os.Path = {
    artifactDir / s"stdout.${inputFile.baseName}.log"
  }
  def stderr(artifactDir: os.Path)(inputFile: os.Path): os.Path = {
    artifactDir / s"stderr.${inputFile.baseName}.log"
  }
}

def build(artifactDir: os.Path, projectDir: os.Path)(target: os.Path) = {
  println(s"[*] == Build")

  // Check if the target is instrumented by polytracker
  assert(os.exists(target), s"Program does not exist: ${target}")
  val nm = os
    .proc("nm", target)
    .call(cwd = projectDir, stdout = os.Pipe, stderr = os.Inherit)
  assert(
    nm.toString().contains("polytracker_tdag"),
    s"Program is not instrumented by polytracker: ${target}"
  )

  os.makeDir.all(artifactDir)
}

def cleanup(path: os.Path) = {
  println(s"[*] == Cleaning up: ${path}")
  if os.exists(path) then {
    assert(path.last == "result", s"Path is not a artifact directory: ${path}")
    os.remove.all(path)
  }
}

def expectOutput(path: os.Path, text: String) = {
  val output = os.read(path)
  val result = output.contains(text)
  assert(result, s"Expected output not found: text=${text} in path=${path}")
  result
}

def unexpectOutput(path: os.Path, text: String) = {
  val output = os.read(path)
  val result = !output.contains(text)
  assert(result, s"Expected output found: text=${text} in path=${path}")
  result
}

def renderAncestors(
    G: Graph
)(
    matcher: Label => Boolean,
    exportTo: os.Path,
    n: Int = 0,
    ignoreWeak: Boolean = false
) = {
  println(s"[*] == Render ancestors: exportTo=${exportTo}")
  val startTime = System.currentTimeMillis()
  G.render(
    G.subgraph(
      G.ancestors(
        G.labels(matcher),
        n = n,
        ignoreWeak = ignoreWeak
      )
    ).write(exportTo)
  )
  println(
    s"[*|${exportTo.last}] Rendered ancestors: took ${(System.currentTimeMillis() - startTime) / 1000.0} seconds"
  )
}

def renderLastAncestors(
    G: Graph
)(
    matcher: Label => Boolean,
    exportTo: os.Path,
    n: Int = 0,
    ignoreWeak: Boolean = false,
    lastN: Int = 1
) = {
  println(s"[*] == Render last ancestors: exportTo=${exportTo}")
  val startTime = System.currentTimeMillis()
  G.render(
    G.subgraph(
      G.ancestors(
        G.last(
          G.labels(matcher),
          n = lastN
        ),
        n = n,
        ignoreWeak = ignoreWeak
      )
    ).write(exportTo)
  )
  println(
    s"[*] Rendered last ancestors: took ${(System.currentTimeMillis() - startTime) / 1000.0} seconds"
  )
}

def renderDescendants(
    G: Graph
)(
    matcher: Label => Boolean,
    exportTo: os.Path,
    n: Int = 0,
    ignoreWeak: Boolean = false
) = {
  G.render(
    G.subgraph(
      G.descendants(
        G.labels(matcher),
        n = n,
        ignoreWeak = ignoreWeak
      )
    ).write(exportTo)
  )
}

// def renderAncestors(G: py.Dynamic)(matcher: py.Dynamic, exportTo: os.Path) = {
//   G.render(
//     G.write_dot(
//       G.subgraph(
//         G.ancestors(
//           G.labels(
//             matcher
//           )
//         )
//       ),
//       exportTo.toString
//     )
//   )
// }

// def renderLastAncestors(
//     G: py.Dynamic
// )(matcher: py.Dynamic, n: Int, exportTo: os.Path) = {
//   G.render(
//     G.write_dot(
//       G.subgraph(
//         G.ancestors(
//           G.last(
//             G.ids(
//               matcher
//             ),
//             n
//           )
//         )
//       ),
//       exportTo.toString
//     )
//   )
// }

// def renderDescendants(G: py.Dynamic)(matcher: py.Dynamic, exportTo: os.Path) = {
//   G.render(
//     G.write_dot(
//       G.subgraph(
//         G.descendants(
//           G.labels(
//             matcher
//           )
//         )
//       ),
//       exportTo.toString
//     )
//   )
// }
