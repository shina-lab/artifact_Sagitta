//> using file project.scala
//> using dep io.circe::circe-yaml-v12:1.15.0
//> using dep org.scala-lang.modules::scala-parallel-collections:1.0.4

import scala.collection.mutable
import scala.collection.parallel.CollectionConverters.seqIsParallelizable
import scala.io.Source
import scala.math.Ordering.Implicits._
import scala.util.matching.Regex

import io.circe.yaml.v12 as yaml
import java.io._
import java.nio.file.attribute.FileTime
import java.nio.file.attribute.PosixFilePermission
import java.text.NumberFormat
import java.time.format.DateTimeFormatter
import java.time.ZoneId
import me.shadaj.scalapy.py

class PolyTracker(
    val artifactDir: os.Path,
    val projectDir: os.Path,
    val polydbDir: os.Path = os.Path("/dev/shm")
) {
  def moduleDir = projectDir / "taint_tracking"
  def polydb(inputFile: os.Path) =
    polydbDir / s"${inputFile.last}.polytracker.tdag"
  def labelLog(inputFile: os.Path) =
    artifactDir / s"${inputFile.last}.label.log"
  def graphFile(prefix: String = "")(inputFile: os.Path)(ext: String) =
    artifactDir / s"${prefix}${inputFile.last}.taint.${ext}"

  def removePolydb() = {
    println("[*] == Remove polydb")
    for (tdag <- os.list(polydbDir).filter(_.ext == "tdag")) {
      if os.perms(tdag).contains(PosixFilePermission.OWNER_WRITE) then
        println(s"[*] Remove: ${tdag}")
        os.remove(tdag)
    }
  }
  removePolydb() // NOTE: 1回のみ実行。PolytTracker のインスタンス生成時が適当な契機

  def inJST(fileTime: FileTime): String = {
    val jst = ZoneId.systemDefault()
    val jstDateTime = fileTime.toInstant.atZone(jst)
    val formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
    jstDateTime.format(formatter)
  }

  def execute(
      stdout: os.ProcessOutput = os.Inherit,
      stderr: os.ProcessOutput = os.Inherit,
      env: Map[String, String] = Map()
  )(inputFile: os.Path)(args: Seq[String]) = {
    println(s"[*|${inputFile.last}] == Execute")
    val program = os.Path(args.head)
    assert(os.exists(program), s"Program not found: ${program}")
    println(
      s"[*] Modified time of ${program.last}: ${inJST(os.stat(program).mtime)}"
    )
    assert(os.exists(inputFile), s"Input file not found: ${inputFile}")

    val polyEnv = Map(
      "POLYDB" -> polydb(inputFile).toString,
      "POLYPATH_LOG_FILE" -> labelLog(inputFile).toString
    )

    val beforeTime = System.currentTimeMillis
    println(s"[*|${inputFile.last}] Execute: ${args.mkString(" ")}")
    os.proc(args)
      .call(
        cwd = projectDir,
        stdout = stdout,
        stderr = stderr,
        env = polyEnv ++ env,
        check = false
      )
    val afterTime = System.currentTimeMillis
    println(
      s"[*|${inputFile.last}] Execution time: ${afterTime - beforeTime} ms"
    )
    assert(
      os.exists(polydb(inputFile)),
      s"Polytracker DB not found: ${polydb(inputFile)}"
    )
  }

  /// @return taint graph in GML format
  def analyzeTaint(
      inputFile: os.Path
  )(ignoreDominator: Boolean = false): Graph = {
    println(s"[*|${inputFile.last}] === Load taint forest from polytracker")
    val startTime = System.currentTimeMillis

    var graph = new Graph(inputFile.last)

    py.local {
      val sys = py.module("sys")
      sys.path.append(moduleDir.toString)
      val polyanalyze = py.module("polyanalyze")

      val inputSourceLabels =
        polyanalyze
          .input_source_labels(polydb(inputFile).toString())
          .as[Seq[py.Dynamic]]
      var label2offset = Map[TaintLabelId, Int]()
      for (v <- inputSourceLabels) {
        val label = v.bracketAccess("label").as[Int]
        val offset = v.bracketAccess("offset").as[Int]
        label2offset += TaintLabelId(label) -> offset
      }

      val startAnalyzeTime = System.currentTimeMillis
      val pydag =
        polyanalyze
          .taint_forest(polydb(inputFile).toString())
          .as[Seq[py.Dynamic]]
      println(
        s"[*|${inputFile.last}] pydag: ${pydag.size} nodes"
      )
      println(
        s"[*|${inputFile.last}] Taint DAG extraction: took ${(System.currentTimeMillis - startAnalyzeTime) / 1000.0} seconds"
      )

      println(s"[*|${inputFile.last}] Converting taint DAG nodes...")
      val startDagNodesConversionTime = System.currentTimeMillis
      // NOTE: pydag.toSeq.par.map だと、存在しないノードが生成されるのでNG。原因は不明
      val dag = pydag
        .map(n =>
          TaintForestNode(
            TaintLabelId(n.bracketAccess("label").as[Int]),
            n.bracketAccess("parent_labels").as[Seq[Int]].map(TaintLabelId(_)),
            n.bracketAccess("source").as[String]
          )
        )
        .sorted
      println(s"[*|${inputFile.last}] dag: ${dag.size} nodes")
      assert(dag.size == pydag.size, "Number of DAG nodes mismatched")
      println(
        s"[*|${inputFile.last}] Converted taint DAG nodes: took ${(System.currentTimeMillis - startDagNodesConversionTime) / 1000.0} seconds"
      )

      // Add taint source node
      var startIterTime = System.currentTimeMillis
      for ((taint, i) <- dag.zipWithIndex) {
        if i > 0 && i % 500000 == 0 then
          val elapsed = (System.currentTimeMillis - startIterTime) / 1000.0
          println(
            s"[*|${inputFile.last}] Processing taint source: ${String
                .format("%.1f", i.toFloat / dag.size * 100)}% (${String
                .format("%.1f", i.toFloat / elapsed)} iter/s)"
          )

        taint.source match
          case "ナン" => ()
          case _ => {
            val node = graph.addWriteNode(taint.label)
            graph.taintSource += node

            val name = taint.source match
              case source if source.startsWith("/") => {
                val path = os.Path(source)
                path.last
              }
              case _ => taint.source
            val label = label2offset.get(taint.label) match {
              case Some(offset) =>
                Label(s"${name}[0x${offset.toHexString}]")
              case None => Label(name)
            }

            assert(graph.containsNode(node), s"Node not exists: ${node}")
            graph.addNodeLabel(node, label)
          }
      }
      println(
        s"[*|${inputFile.last}] Finished processing taint source: took ${(System.currentTimeMillis - startIterTime) / 1000.0} seconds"
      )

      var fileReader = new FileReader()
      var getElementPtr = Map[Location, TaintLabelId]()
      var callParam = Map[Location, Seq[TaintLabelId]]()
      var locationOf = Map[NodeId, Location]()
      val startLoadingLabelLogTime = System.currentTimeMillis
      for (
        (logLine, i) <- Source
          .fromFile(labelLog(inputFile).toString)
          .getLines
          .zipWithIndex
      ) {
        if i > 0 && i % 500000 == 0 then
          val elapsed =
            (System.currentTimeMillis - startLoadingLabelLogTime) / 1000.0
          println(
            s"[*|${inputFile.last}] Loading label log: ${String.format("%.1f", i.toFloat / elapsed)} lines/sec"
          )

        // - { kind: label, label: 1, opcode: ctor, path: /path/to/magma-v1.2/targets/openssl/repo/fuzz/driver.c, line: 23, column: 12, function: LLVMFuzzerInitialize }
        val kind = """kind: (\w+)""".r.findFirstMatchIn(logLine).get.group(1)
        {
          kind match
            case "label" => {
              val lineFormat =
                """- \{ kind: label, label: (\d+), opcode: (\w+), path: (.+), line: (\d+), column: (\d+), function: (.+) \}""".r
              val v = lineFormat.findFirstMatchIn(logLine).get

              val taintLabel =
                TaintLabelId(v.group(1).toInt)
              val opcode = v.group(2)
              val location = Location(
                os.Path(v.group(3)),
                v.group(4).toInt,
                v.group(5).toInt
              )
              val function = v.group(6)

              // TODO: ノードを削減するための苦肉の策
              def blockedFunctions(function: String): Boolean = {
                for (
                  block <- Seq(
                    // poppler
                    "FlateStream",
                    "getChar",
                    "GetChar",
                    "_ZN6ObjectD2Ev", // Object::~Object()
                    "_ZN5Lexer6getObjEi", // Lexer::getObj(int)
                    "_ZN6Object4freeEv", // Object::free()
                    "_ZN6ObjectC2EOS_", // Object::Object(Object&&)
                    "_ZN6ObjectaSEOS_", // Object::operator=(Object&&)

                    // libtiff
                    "makebwmap", // TIF008ではノイズ
                    "TIFFCleanup", // TIF008ではノイズ
                    // "TIFFFindField",
                    // "TIFFReadDirectoryFindFieldInfo",
                    // "TIFFReverseBits",
                    "tagCompare", // TIF005で大量発生
                    "TIFFComputeTile",
                    "TIFFReadDirectoryFindFieldInfo", // TIF005で大量発生
                    "_TIFFMultiplySSize",
                    "TIFFReadDirEntryData",
                    "TIFFReadDirEntryArrayWithLimit",
                    // "TIFFFillTile",
                    // "TIFFRGBAImageBegin",
                    // "_TIFFReadEncodedTileAndAllocBuffer",
                    // "TIFFTileRowSize64",
                    // "TIFFReadDirectoryFindEntry",
                    // "gtTileContig",
                    // "TIFFStartTile",
                    // "TIFFCheckTile",
                  )
                ) {
                  if function.contains(block) then return true
                }
                false
              }

              if TaintLabelId.isTainted(taintLabel) && !blockedFunctions(
                  function
                )
              then
                val useLastNode = graph.getTaintFlowLastNode(taintLabel) match
                  case Some(lastNode) => {
                    val isSameLocation = locationOf.get(lastNode) match
                      case Some(lastLocation) =>
                        lastLocation == location
                      case None => true
                    isSameLocation && !graph.taintSource.contains(lastNode)
                  }
                  case None => false

                val noTaintNode =
                  graph.getTaintFlowFirstNode(taintLabel) match
                    case Some(firstNode) =>
                      !graph.taintSource.contains(firstNode)
                      && graph.getTaintFlowFirstNode(
                        taintLabel
                      ) == graph.getTaintFlowLastNode(taintLabel)
                    case None => false
                if noTaintNode then
                  graph.replaceTaintFlowFirstNode(
                    taintLabel,
                    graph.addWriteNode(taintLabel)
                  )
                val node = opcode match
                  case "load" | "load_ptr" | "getelementptr" |
                      "getelementptr_ptr" | "call_param" | "call_param_ptr" =>
                    useLastNode match
                      case true  => graph.getOrAddReadNode(taintLabel)
                      case false => graph.addReadNode(taintLabel)
                  case _ => // store, call_ptr
                    useLastNode match
                      case true  => graph.getOrAddWriteNode(taintLabel)
                      case false => graph.addWriteNode(taintLabel)

                locationOf += node -> location

                // [Stage 1]
                opcode match
                  case "getelementptr_ptr" | "load_ptr" =>
                    getElementPtr += location -> taintLabel
                  case "call_param_ptr" | "call_param" =>
                    callParam.get(location) match
                      case Some(taintLabels) =>
                        callParam += location -> (taintLabels :+ taintLabel)
                      case None => callParam += location -> Seq(taintLabel)
                  case "ctor" => {
                    callParam.get(location) match
                      case Some(parentTaintLabels) =>
                        for (parentTaintLabel <- parentTaintLabels) {
                          if taintLabel != parentTaintLabel then {
                            val parent =
                              graph.getOrAddWriteNode(parentTaintLabel)
                            val isWeakEdge = locationOf.get(parent) match
                              case Some(parentLocation) => {
                                parentLocation != location || graph
                                  .inEdges(node)
                                  .size > 1
                              }
                              case None => {
                                true
                              }
                            val label = Some(Label("call param of"))
                            isWeakEdge match
                              case true =>
                                ()
                              case false =>
                                graph.addWeakEdge(
                                  parent,
                                  node,
                                  label
                                )
                          }
                        }
                      case None => ()
                  }
                  case "load" => {
                    getElementPtr.get(location) match
                      case Some(parentTaintLabel) =>
                        val parent = graph.getOrAddReadNode(parentTaintLabel)
                        val edge = graph.addWeakEdge(
                          parent,
                          node,
                          Some(Label("parent of"))
                        )
                      case None => ()
                  }
                  case _ => ()

                // [Stage 2]
                // val continue = opcode match
                //   case "load" | "load_ptr" =>
                //     !graph.taintFlowIsLabeled(taintLabel)
                //   case _ => true
                val continue = location.isValid()
                if continue then {
                  fileReader.addFile(location.path)
                  val foundToken = fileReader.readAt(location) match
                    case Some(token) => Label(s"${token} <${function}>")
                    case None =>
                      Label(
                        s"${location.path.last}:${location.line}:${location.column}"
                      )
                  if !graph.taintSource.contains(node) then
                    assert(
                      graph.containsNode(node),
                      s"Node not exists: ${node}"
                    )
                    graph.addNodeLabel(node, foundToken)
                }
            }
            case "update" => {
              if logLine.contains("cause") then {
                val _v =
                  """- \{ kind: update, cause: (\w+), old_label: (\d+), new_label: (\d+), path: (.+), line: (\d+), column: (\d+), function: (.+) \}""".r
                    .findFirstMatchIn(logLine)
                if _v.isEmpty then
                  println(
                    s"[!|${inputFile.last}] Invalid update log: ${logLine}"
                  )
                else
                  val v = _v.get
                  val cause = v.group(1)
                  val old_label = v.group(2).toInt
                  val new_label = v.group(3).toInt

                  cause match
                    case "store" =>
                      graph.addEdge(
                        graph.getOrAddReadNode(TaintLabelId(old_label)),
                        graph.getOrAddWriteNode(TaintLabelId(new_label)),
                        Some(Label(s"Updated by ${cause}"))
                      )
                    case _ => ()
              }
            }
            case "dominator" =>
              if !ignoreDominator then
                val v =
                  """- \{ kind: dominator, dominator: (\d+), dominates: (\d+) \}""".r
                    .findFirstMatchIn(logLine)
                    .get
                val dominator = v.group(1).toInt
                val dominates = v.group(2).toInt
                graph.addEdge(
                  graph.getOrAddWriteNode(TaintLabelId(dominator)),
                  graph.getOrAddWriteNode(TaintLabelId(dominates)),
                  Some(Label("dominates"))
                )
        }
      }
      println(
        s"[*|${inputFile.last}] Loaded label log: took ${(System.currentTimeMillis - startLoadingLabelLogTime) / 1000.0} seconds"
      )

      // Union taint flows
      graph.setupAnalysis()
      val formatter = NumberFormat.getIntegerInstance
      println(
        s"[*|${inputFile.last}] Union taint flows (${formatter.format(dag.size)} entries)"
      )
      val startUnionTime = System.currentTimeMillis
      for ((taint, i) <- dag.zipWithIndex) {
        if !taint.parent_labels.isEmpty then
          val child = graph.getTaintFlowFirstNode(taint.label) match
            case Some(child) => child
            case None        => graph.getOrAddWriteNode(taint.label)
          graph.unionNode += child

          for (parentLabel <- taint.parent_labels) {
            val parent =
              if TaintLabelId.extract(parentLabel) < 0 then
                graph.getOrAddWriteNode(parentLabel)
              else
                // 子のノードよりも古い（idが小さい）ノードを探す
                val parentCandidates = graph
                  .getNodesTainted(parentLabel)
                  .map(_.filter(_ < child))
                  .getOrElse(Seq.empty)
                if parentCandidates.isEmpty then
                  graph.getOrAddWriteNode(parentLabel)
                else parentCandidates.max

            // FIXME: PNG001で存在しないparentを返す模様。そうはならんやろ
            if (!graph.containsNode(parent)) {
              println(s"[!|${inputFile.last}] Parent node not found: ${parent}")
            }

            graph.addEdge(parent, child)
          }

        if i > 0 && i % 100000 == 0 then
          val elapsed = (System.currentTimeMillis - startUnionTime) / 1000.0
          println(
            s"[*|${inputFile.last}] Union taint flows: ${String
                .format("%.1f", i.toFloat / dag.size * 100)}% (${String
                .format("%.1f", i.toFloat / elapsed)} iter/s)"
          )
      }
    }

    println(s"[*|${inputFile.last}] === Export taint forest")
    val exportTo = graphFile()(inputFile)
    val gmlFile = exportTo("gml")
    graph.writeGml(gmlFile)
    println(s"[*|${inputFile.last}] Exported: ${gmlFile.last}")

    println(
      s"[*|${inputFile.last}] Built taint DAG: took ${(System.currentTimeMillis - startTime.toFloat) / 1000} seconds"
    )

    graph
  }

  def diff(inputFile1: os.Path, inputFile2: os.Path)(
      prefixes: Seq[String],
      prefix_subgraph: String = "subgraph",
      prefix_diff: String = "diff"
  ) = {
    for (prefix <- prefixes) {
      val G1 = graphFile(s"${prefix_subgraph}.${prefix}.")(inputFile1)("gml")
      val G2 = graphFile(s"${prefix_subgraph}.${prefix}.")(inputFile2)("gml")

      val sys = py.module("sys")
      sys.path.append(moduleDir.toString)
      val graph_analyzer = py.module("graph_analyzer_gt")
      graph_analyzer.render(
        graph_analyzer.write_dot(
          graph_analyzer.diff_gml(G1.toString, G2.toString),
          (
            graphFile(s"${prefix_diff}.${prefix}.")(inputFile1)("dot").toString,
            graphFile(s"${prefix_diff}.${prefix}.")(inputFile2)("dot").toString
          )
        )
      )
    }
  }

  def loadGraph()(gmlFile: os.Path): py.Dynamic = {
    val sys = py.module("sys")
    sys.path.append(moduleDir.toString)
    val graph_analyzer = py.module("graph_analyzer_gt")
    graph_analyzer.entrypoint(gmlFile.toString)
    return graph_analyzer
  }

  // def diffGraph(beforeInputFile: os.Path, afterInputFile: os.Path)() = {
  //   def render(before: os.Path, after: os.Path) = {
  //     py.local {
  //       val G = loadGraph()(before)
  //       G.render(
  //         G.write_dot(
  //           G.diff(
  //             G.load(after.toString)
  //           ),
  //           py.None
  //         )
  //       )
  //     }
  //   }

  //   def changes(
  //       beforeGmlFile: os.Path,
  //       afterGmlFile: os.Path
  //   ): Seq[(os.Path, os.Path)] = {
  //     var result = mutable.Set[(os.Path, os.Path)]()
  //     val beforeSuffix = beforeGmlFile.last
  //     val afterSuffix = afterGmlFile.last
  //     println((beforeSuffix, afterSuffix)) // DEBUG:

  //     val keys = mutable.Set[String]()
  //     for (file <- os.list(artifactDir)) {
  //       if file.baseName.startsWith("subgraph.") && file.ext == "gml" then
  //         keys += file.last
  //           .replace("subgraph.", "")
  //           .replace(beforeSuffix, "")
  //           .replace(afterSuffix, "")
  //     }
  //     println("[*] keys: " + keys) // DEBUG:

  //     for (key <- keys) {
  //       val subgraphBefore = artifactDir / s"subgraph.${key}${beforeSuffix}"
  //       val subgraphAfter = artifactDir / s"subgraph.${key}${afterSuffix}"
  //       assert(
  //         os.exists(subgraphBefore),
  //         s"Subgraph file not found: ${subgraphBefore}}"
  //       )
  //       assert(
  //         os.exists(subgraphAfter),
  //         s"Subgraph file not found: ${subgraphAfter}}"
  //       )
  //       result += ((subgraphBefore, subgraphAfter))
  //     }
  //     println("[*] result: " + result) // DEBUG:
  //     result.toSet.toSeq
  //   }

  //   println("[*] == Diff taint forest")

  //   for (
  //     set <- changes(
  //       graphFile()(beforeInputFile)("gml"),
  //       graphFile()(afterInputFile)("gml")
  //     )
  //   ) {
  //     render(set._1, set._2)
  //   }
  // }
}

class TaintForestNode(
    val label: TaintLabelId,
    val parent_labels: Seq[TaintLabelId],
    val source: String
) extends Ordered[TaintForestNode] {
  override def toString(): String = {
    s"TaintForestNode(label=${label}, parent_labels=${parent_labels}, source=${source})"
  }

  def compare(that: TaintForestNode): Int = {
    TaintLabelId.extract(this.label).compare(TaintLabelId.extract(that.label))
  }
}

class Location(
    val path: os.Path,
    val line: Int,
    val column: Int
) {
  def isValid(): Boolean = {
    line > 0 && column > 0
  }

  override def toString(): String = {
    s"Location(${path.last}:${line}:${column})"
  }

  override def equals(that: Any): Boolean = {
    that match
      case that: Location =>
        this.path == that.path &&
        this.line == that.line &&
        this.column == that.column
      case _ => false
  }

  override def hashCode(): Int = {
    (path, line, column).hashCode
  }
}

class FileReader {
  var files = Map[os.Path, Seq[String]]()
  var filesNotFound = Set[os.Path]()

  def marker(): String = "&bull;"

  def addFile(path: os.Path): Unit = {
    if files contains path then return
    if !os.exists(path) then
      if !filesNotFound.contains(path) then
        println(s"[!] File not found: ${path}")
        filesNotFound += path
      return
    files += path -> Source.fromFile(path.toString, "UTF-8").getLines.toSeq
  }

  def readAt(location: Location): Option[String] = {
    files.get(location.path) match {
      case Some(lines) => {
        location.line match
          case 0 => None
          case _ => {
            assert(
              lines.size > location.line - 1,
              s"Line not found: ${location.path}:${location.line}"
            )
            var line_text = lines(location.line - 1)
            if line_text.trim.endsWith(",") then
              line_text += " " + lines(location.line).trim
            location.column match
              case 0 => Some(line_text.trim)
              case _ =>
                val marker_position =
                  Seq(location.column - 1, line_text.size).min
                Some(
                  line_text
                    .substring(0, marker_position) + marker() + line_text
                    .substring(marker_position)
                )
          }
      }
      case None => None
    }
  }
}

opaque type TaintLabelId = Int
object TaintLabelId {
  def apply(id: Int): TaintLabelId = id
  def extract(id: TaintLabelId): Int = id
  def isTainted(id: TaintLabelId): Boolean = extract(id) > 0
}
opaque type NodeId = Int
object NodeId {
  def apply(id: Int): NodeId = id
  implicit val nodeIdOrdering: Ordering[NodeId] = Ordering.Int
}
opaque type ClusterId = Int
object ClusterId {
  def apply(id: Int): ClusterId = id
}

opaque type Label = String
object Label {
  def apply(label: String): Label = label
  def unapply(label: Label): Option[String] = Some(label)
  def extract(label: Label): String = label
  def contains(label: Label, condition: String): Boolean = {
    Label.extract(label).contains(condition)
  }
}

class Graph(val graphName: String = "Graph") {
  // General graph structure
  private var nodes = Map[NodeId, TaintLabelId]()
  private var edges = Set[(NodeId, NodeId)]()
  private var weakEdges = Set[(NodeId, NodeId)]()
  private var nextNodeId = 0
  // Graph metadata
  private var nodeLabels = Map[NodeId, Label]()
  private var edgeLabels = Map[(NodeId, NodeId), Label]()
  private var nodeProps = Map[(NodeId, String), String]()
  // Taint tracking specific data
  var taintSource = Set[NodeId]()
  var unionNode = Set[NodeId]()
  private var taintFlowFirstNodes = Map[TaintLabelId, NodeId]()
  private var taintFlowLastNodes = Map[TaintLabelId, NodeId]()
  private var taintFlowLastWriteNodes = Map[TaintLabelId, NodeId]()
  private var taintLabel2Nodes = Map[TaintLabelId, mutable.Set[NodeId]]()
  // Graph analysis workspace
  private var analysisResultIsValid = false
  private var parentOf = Map[NodeId, Set[NodeId]]()
  private var childOf = Map[NodeId, Set[NodeId]]()

  // Member accessor
  def connectedNodes: Set[NodeId] = edges.map(_._1) ++ edges.map(_._2)
  def containsNode(node: NodeId): Boolean = nodes.contains(node)
  def getTaintFlowFirstNode(taint: TaintLabelId): Option[NodeId] =
    taintFlowFirstNodes.get(taint)
  def getTaintFlowLastNode(taint: TaintLabelId): Option[NodeId] =
    taintFlowLastNodes.get(taint)
  def getNodesTainted(taint: TaintLabelId): Option[Set[NodeId]] =
    taintLabel2Nodes.get(taint) match
      case Some(nodes) => Some(nodes.toSet)
      case None        => None

  def addReadNode(taint: TaintLabelId): NodeId = {
    val node = NodeId(nextNodeId)
    nextNodeId += 1

    taintFlowLastWriteNodes.get(taint) match
      case Some(parent) => addEdge(parent, node)
      case None         => ()
    taintFlowFirstNodes.contains(taint) match
      case true  => ()
      case false => taintFlowFirstNodes += taint -> node

    taintFlowLastNodes += taint -> node
    this.nodes += node -> taint
    analysisResultIsValid = false

    node
  }

  def addWriteNode(taint: TaintLabelId): NodeId = {
    val node = NodeId(nextNodeId)
    nextNodeId += 1

    taintFlowLastNodes.get(taint) match
      case Some(parent) => addEdge(parent, node)
      case None         => ()
    taintFlowFirstNodes.contains(taint) match
      case true  => ()
      case false => taintFlowFirstNodes += taint -> node

    taintFlowLastNodes += taint -> node
    taintFlowLastWriteNodes += taint -> node
    this.nodes += node -> taint
    analysisResultIsValid = false

    node
  }

  def getOrAddReadNode(taint: TaintLabelId): NodeId = {
    taintFlowLastNodes.get(taint) match
      case Some(node) => node
      case None       => addReadNode(taint)
  }

  def getOrAddWriteNode(taint: TaintLabelId): NodeId = {
    taintFlowLastNodes.get(taint) match
      case Some(node) => node
      case None       => addWriteNode(taint)
  }

  def addNodeLabel(node: NodeId, label: Label): NodeId = {
    assert(
      this.nodes.contains(node),
      s"Node not found in addNodeLabel: ${node}"
    )
    nodeLabels += node -> label
    node
  }

  def replaceTaintFlowFirstNode(taint: TaintLabelId, node: NodeId): NodeId = {
    assert(
      this.nodes.contains(node),
      s"Node not found in replaceTaintFlowFirstNode: ${node}"
    )
    taintFlowFirstNodes += taint -> node
    node
  }

  def taintFlowIsLabeled(taint: TaintLabelId): Boolean = {
    taintFlowLastNodes.get(taint) match
      case Some(node) =>
        nodeLabels.get(node) match
          case Some(_) => true
          case None    => false
      case None => false
  }

  def addEdge(
      parent: NodeId,
      child: NodeId,
      label: Option[Label] = None
  ): (NodeId, NodeId) = {
    if this.edges.contains((parent, child)) then return (parent, child)

    if parent != child then this.edges += (parent, child)

    label match
      case Some(label) => edgeLabels += (parent, child) -> label
      case None        => ()

    // _memorizeEdge(parent, child)
    analysisResultIsValid = false

    (parent, child)
  }

  def addWeakEdge(
      parent: NodeId,
      child: NodeId,
      label: Option[Label] = None
  ): Unit = {
    if this.edges.contains((parent, child)) then return
    if this.weakEdges.contains((parent, child)) then return

    if parent != child then this.weakEdges += (parent, child)
    label match
      case Some(label) => edgeLabels += (parent, child) -> label
      case None        => ()

    // _memorizeEdge(parent, child)
  }

  def updateNodeProp(node: NodeId, key: String, value: String): Unit = {
    nodeProps += (node, key) -> value
  }

  def getNodeProp(node: NodeId, key: String): Option[String] = {
    nodeProps.get((node, key))
  }

  def inEdges(node: NodeId): Set[NodeId] = {
    parentOf.get(node) match
      case Some(parents) => parents
      case None          => Set()
  }

  def labels(matcher: Label => Boolean): Set[NodeId] = {
    nodeLabels.filter { case (_, label) => matcher(label) }.keys.toSet
  }

  def taintLabels(matcher: TaintLabelId => Boolean): Set[NodeId] = {
    nodes.filter { case (_, taint) => matcher(taint) }.keys.toSet
  }

  def head(nodes: Set[NodeId]): Set[NodeId] = {
    nodes.size match
      case 0 => Set()
      case _ => Set(nodes.toSeq.sorted.head)
  }

  def last(nodes: Set[NodeId], n: Int = 1): Set[NodeId] = {
    nodes.size match
      case 0 => Set()
      case _ => nodes.toSeq.sorted.takeRight(n).toSet
  }

  // matcher
  def startsWith(condition: String)(label: Label): Boolean = {
    Label.extract(label).startsWith(condition)
  }

  // matcher
  def contains(condition: String)(label: Label): Boolean = {
    Label.extract(label).contains(condition)
  }

  // matcher
  def matches(condition: String)(label: Label): Boolean = {
    val pattern: Regex = new Regex(condition)
    pattern.findFirstIn(Label.extract(label)) match
      case Some(_) => true
      case None    => false
  }

  // matcher
  def eq(condition: TaintLabelId): TaintLabelId => Boolean = { taint =>
    taint == condition
  }

  private def _memorizeEdge(parent: NodeId, child: NodeId) = {
    parentOf.get(child) match
      case Some(parents) => parentOf += child -> (parents + parent)
      case None          => parentOf += child -> Set(parent)
    childOf.get(parent) match
      case Some(children) => childOf += parent -> (children + child)
      case None           => childOf += parent -> Set(child)
  }

  def setupAnalysis(): Unit = {
    if analysisResultIsValid then return
    analysisResultIsValid = true

    parentOf = Map[NodeId, Set[NodeId]]()
    childOf = Map[NodeId, Set[NodeId]]()
    for (parent, child) <- this.edges do _memorizeEdge(parent, child)
    for (parent, child) <- this.weakEdges do _memorizeEdge(parent, child)

    taintLabel2Nodes = Map[TaintLabelId, mutable.Set[NodeId]]()
    for (node, taintLabel) <- this.nodes do
      taintLabel2Nodes.get(taintLabel) match
        case None        => taintLabel2Nodes += taintLabel -> mutable.Set(node)
        case Some(nodes) => nodes += node

    val formatter = NumberFormat.getIntegerInstance
    println(s"[*|${graphName}] setupAnalysis()")
    println(
      s"[*|${graphName}]   Number of node: ${formatter.format(this.nodes.size)}"
    )
    println(
      s"[*|${graphName}]   Number of edge: ${formatter.format(this.edges.size)}"
    )
    println(
      s"[*|${graphName}]   Number of weak-edge: ${formatter.format(this.weakEdges.size)}"
    )
  }

  class Visitor(
      val next: NodeId,
      val ignoreWeak: Boolean,
      val countDominator: Int
  )

  def ancestors(
      nodes: Set[NodeId],
      n: Int = 0,
      ignoreWeak: Boolean = false
  ): Set[NodeId] = {
    setupAnalysis()

    var result = Set[NodeId]()
    var visited = Set[NodeId]()
    var willVisit = mutable.ArrayDeque[Visitor]() // FIFO Queue
    val bottomNode = nodes.size match
      case 0 => NodeId(0)
      case _ => nodes.max

    // 幅優先探索
    willVisit.appendAll(nodes.map(Visitor(_, ignoreWeak, 0))) // 昇順で追加
    while willVisit.nonEmpty && (n == 0 || result.size < n) do
      val visitor = willVisit.removeLast() // 逆順で取り出し
      // TODO: bottom ノードに対して無効なデータフローが出てこないようにしたい
      if visitor.next <= bottomNode || this.unionNode.contains(
          visitor.next
        ) || true
      then
        result += visitor.next
        visited += visitor.next
        parentOf.get(visitor.next) match
          case Some(parents) => {
            for parent <- parents.filterNot(visited.contains).toSeq.reverse do
              val countDominator = edgeLabels.get((parent, visitor.next)) match
                case Some(Label("dominates")) => visitor.countDominator + 1
                case _                        => visitor.countDominator
              if countDominator <= 1 then
                // 部分グラフの肥大化を防ぐため、二度目の　weak edge の親ノードはこれ以上探索しない
                weakEdges.contains((parent, visitor.next)) match
                  case true =>
                    // weak-edgeと通常の辺が合流した場合、通常辺側から探索を再開するのが難しい
                    if !visitor.ignoreWeak then
                      // ignoreWeak が true でも、1回目の weak-edge は探索する
                      willVisit.prepend(Visitor(parent, true, countDominator))
                  case false =>
                    willVisit.prepend(
                      Visitor(parent, visitor.ignoreWeak, countDominator)
                    )
          }
          case None => ()

    result
  }

  def descendants(
      nodes: Set[NodeId],
      n: Int = 0,
      ignoreWeak: Boolean = false
  ): Set[NodeId] = {
    setupAnalysis()

    var result = Set[NodeId]()
    var visited = Set[NodeId]()
    var willVisit = mutable.ArrayDeque[Visitor]() // FIFO Queue
    var stoppedAt = Set[NodeId]()
    val bottomNode = nodes.size match
      case 0 => 0
      case _ => nodes.max

    // 幅優先探索
    // TODO: bottomより古いノードは含めたくない
    willVisit.appendAll(nodes.map(Visitor(_, ignoreWeak, 0))) // 昇順で追加
    while willVisit.nonEmpty && (n == 0 || result.size < n) do
      val visitor = willVisit.removeLast() // 逆順で取り出し
      result += visitor.next
      visited += visitor.next
      childOf.get(visitor.next) match
        case Some(children) => {
          for child <- children.filterNot(visited.contains).toSeq.reverse do
            // 部分グラフの肥大化を防ぐため、二度目の　weak edge の親ノードはこれ以上探索しない
            weakEdges.contains((child, visitor.next)) match
              case true =>
                if !visitor.ignoreWeak then
                  stoppedAt += child
                  willVisit.prepend(
                    Visitor(child, true, visitor.countDominator)
                  )
              case false =>
                if stoppedAt.contains(child) then visited -= child
                willVisit.prepend(
                  Visitor(child, visitor.ignoreWeak, visitor.countDominator)
                )
        }
        case None => ()

    result
  }

  def subgraph(subgraphNodes: Set[NodeId]): Graph = {
    val result = new Graph(s"${graphName}.subgraph")
    for node <- subgraphNodes do
      assert(
        this.nodes.contains(node),
        s"Node not found in graph ${this.graphName}: NodeId=${node}"
      )
      result.nodes += node -> this.nodes.get(node).get
    for (parent, child) <- edges.filterNot(weakEdges.contains) do
      if subgraphNodes.contains(parent) && subgraphNodes.contains(child) then
        result.addEdge(parent, child, edgeLabels.get((parent, child)))
    for (parent, child) <- weakEdges do
      if subgraphNodes.contains(parent) && subgraphNodes.contains(child) then
        result.addWeakEdge(parent, child, edgeLabels.get((parent, child)))
    for (node, label) <- nodeLabels do
      if subgraphNodes.contains(node) then result.nodeLabels += node -> label
    println(s"[*|${result.graphName}] Number of node: ${result.nodes.size}")
    println(s"[*|${result.graphName}] Number of edge: ${result.edges.size}")
    println(
      s"[*|${result.graphName}] Number of weak-edge: ${result.weakEdges.size}"
    )
    result
  }

  private def escape(s: String): String = s.trim.replace("\"", "&quot;")

  def writeDot(dotFile: os.Path): os.Path = {
    val file = new BufferedWriter(new FileWriter(new File(dotFile.toString)))

    file.write("digraph {\n")

    // Write default settings
    file.write(
      "  node [fontsize=12, fontname=\"Inter, Arial\", shape=oval, penwidth=1, margin=0.05];\n"
    )
    file.write("  nodesep = 0.2; ranksep = 0.3;\n")
    file.write("  edge [fontsize=12, fontname=\"Inter, Arial\", penwidth=1];\n")

    // Write nodes
    for ((node, taintLabel) <- this.nodes) {
      val label = nodeLabels.get(node) match
        case Some(label) =>
          s"${label} (${taintLabel}#${node})"
        case None =>
          s"(${taintLabel}#${node})"
      val props = nodeProps
        .filter { case ((n, _), _) => n == node }
        .map { case ((_, key), value) =>
          s"${key}=\"${value}\""
        }
        .mkString(", ")
      file.write(s"  ${node} [label=\"${escape(label)}\"] [${props}];\n")
    }

    // Write edges
    for ((parent, child) <- edges) {
      val label = edgeLabels.get((parent, child)) match
        case Some(label) => s"[label=\"${escape(label.toString)}\"]"
        case None        => ""
      file.write(s"  ${parent} -> ${child} ${label};\n")
    }
    for ((parent, child) <- weakEdges) {
      val label = edgeLabels.get((parent, child)) match
        case Some(label) => s"[label=\"${escape(label.toString)}\"]"
        case None        => ""
      file.write(s"  ${parent} -> ${child} ${label} [style=dashed];\n")
    }

    file.write("}\n")

    file.close()
    dotFile
  }

  def writeGml(gmlFile: os.Path): os.Path = {
    // Ref: GML format https://web.archive.org/web/20190207140002/http://www.fim.uni-passau.de/index.php?id=17297&L=1

    val file = new BufferedWriter(new FileWriter(new File(gmlFile.toString)))

    file.write(s"graph [\n")
    file.write(s"  directed 1\n")
    file.write(s"  name \"${gmlFile.last}\"\n")

    for ((node, taintLabel) <- nodes) {
      val label = nodeLabels.get(node) match
        case Some(label) => s"${label} (${taintLabel}#${node})"
        case None        => s"(${taintLabel}#${node})"

      file.write(s"  node [\n")
      file.write(s"    id ${node}\n")
      file.write(s"    label \"${escape(label)}\"\n")
      file.write(s"    taintedLabel ${taintLabel}\n")
      file.write(s"    _id ${node}\n")
      file.write(s"  ]\n")
    }

    for ((parent, child) <- edges) {
      val label = edgeLabels.get((parent, child)) match
        case Some(label) => label.toString
        case None        => ""
      file.write(s"  edge [\n")
      file.write(s"    source ${parent}\n")
      file.write(s"    target ${child}\n")
      file.write(s"    label \"${escape(label)}\"\n")
      file.write(s"    weak 0\n")
      file.write(s"  ]\n")
    }
    for ((parent, child) <- weakEdges) {
      val label = edgeLabels.get((parent, child)) match
        case Some(label) => label.toString
        case None        => ""
      file.write(s"  edge [\n")
      file.write(s"    source ${parent}\n")
      file.write(s"    target ${child}\n")
      file.write(s"    label \"${escape(label)}\"\n")
      file.write(s"    weak 1\n")
      file.write(s"  ]\n")
    }

    file.write("]\n")
    file.close()

    gmlFile
  }

  def write(dotFile: os.Path): os.Path = {
    def exportTo(ext: String): os.Path =
      os.Path(dotFile.toString.replace(".dot", s".${ext}"))
    writeGml(exportTo("gml"))
    writeDot(dotFile)
  }

  def render(dotFile: os.Path): os.Path = {
    println(s"[*] Rendering graph: ${dotFile.last}")

    if !os.exists(dotFile) then
      println(s"[!] dot file not found: ${dotFile}")
      return dotFile

    val renderer = os.stat(dotFile).size < 1 * 1024 * 1024 match
      case true  => "dot"
      case false => "sfdp"

    def exportTo(ext: String): os.Path =
      os.Path(dotFile.toString.replace(".dot", s".${ext}"))

    val svgFile = exportTo("svg")
    os.proc(renderer, "-Goverlap=prism", "-Tsvg", dotFile, "-o", svgFile)
      .call(
        stdout = os.Inherit,
        stderr = os.Inherit,
        check = true
      )
    println(s"\tExported to: ${svgFile.last}")

    val pdfFile = exportTo("pdf")
    os.proc(
      Seq("cairosvg", svgFile.toString, "-o", pdfFile.toString)
    ).call(
      stdout = os.Inherit,
      stderr = os.Inherit,
      check = true
    )
    println(s"\tExported to: ${pdfFile.last}")

    // NOTE: PNGファイルはファイルサイズが大きいので描画しない
    // if os.proc("which", "cairosvg").call(check = false).exitCode != 0 then
    //   println("[!] cairosvg not found. Skip exporting to PNG")
    //   return svgFile
    // val (actualWidth, actualHeight) = canvasSizeOfSvg(svgFile)
    // println(s"\tCanvas size: ${actualWidth} x ${actualHeight}")
    // val cairosvgSizeLimit = 20000
    // val resizeOptions =
    //   (actualWidth > cairosvgSizeLimit, actualHeight > cairosvgSizeLimit) match
    //     case (true, true) =>
    //       Seq(
    //         "--output-width",
    //         cairosvgSizeLimit.toString,
    //         "--output-height",
    //         cairosvgSizeLimit.toString
    //       )
    //     case (true, false) => Seq("--output-width", cairosvgSizeLimit.toString)
    //     case (false, true) => Seq("--output-height", cairosvgSizeLimit.toString)
    //     case (false, false) => Seq()

    // // val pngFile = exportTo("png")
    // os.proc(
    //   Seq("cairosvg", svgFile.toString, "-o", pngFile.toString) ++ resizeOptions
    // ).call(
    //   stdout = os.Inherit,
    //   stderr = os.Inherit,
    //   check = true
    // )
    // println(s"\tExported to: ${pngFile.last}")

    svgFile
  }
}

object Graph {
  def diff(G_before: Graph, G_after: Graph): (Graph, Graph) = {
    val COLOR_GREEN = "#008000"

    def normalizeLabel(label: Label): String = {
      val pattern: Regex = """(.+) \(\S+\)""".r
      val sLabel = Label.extract(label)

      pattern.findFirstIn(sLabel) match
        case Some(matched) => matched
        case None          => sLabel
    }

    G_before.setupAnalysis()
    G_after.setupAnalysis()

    val beforeNodes = G_before.nodeLabels.values.map(normalizeLabel).toSet
    val afterNodes = G_after.nodeLabels.values.map(normalizeLabel).toSet
    val deletedNodes = beforeNodes -- afterNodes
    val newNodes = afterNodes -- beforeNodes
    val commonNodes = beforeNodes & afterNodes

    println(s"[NEW] ${newNodes}")
    println(s"[DEL] ${deletedNodes}")

    G_before.nodeLabels.foreach { (node, label) =>
      if (deletedNodes.contains(normalizeLabel(label))) {
        G_before.updateNodeProp(node, "color", "red")
        G_before.updateNodeProp(node, "penwidth", "2")
        G_before.updateNodeProp(node, "style", "dashed")
      }
    }

    G_after.nodeLabels.foreach { (node, label) =>
      if (newNodes.contains(normalizeLabel(label))) {
        G_after.updateNodeProp(node, "color", COLOR_GREEN)
        G_after.updateNodeProp(node, "penwidth", "2")
        G_after.updateNodeProp(node, "style", "dashed")
      }
    }

    // 注目しているノードより、時系列で後のノードをハイライト
    def bottomNode(graph: Graph): NodeId = {
      if (graph.childOf.nonEmpty) {
        val candidates = graph.childOf
          .filter((k, v) => v.isEmpty)
          .map((k, v) => k)
        candidates.nonEmpty match
          case true  => candidates.max
          case false => NodeId(graph.nodes.size - 1)
      } else {
        NodeId(graph.nodes.size - 1)
      }
    }
    val beforeBottom = bottomNode(G_before)
    val afterBottom = bottomNode(G_after)
    println(s"[BOTTOM] before=${beforeBottom}, after=${afterBottom}")

    G_before.nodes.keys.foreach { node =>
      if (node > beforeBottom) {
        G_before.updateNodeProp(node, "color", "red")
      }
    }

    G_after.nodes.keys.foreach { node =>
      if (node > afterBottom) {
        G_after.updateNodeProp(node, "color", COLOR_GREEN)
      }
    }

    (G_before, G_after)
  }
}

def canvasSizeOfSvg(svgFile: os.Path): (Int, Int) = {
  val fileContent = os.read(svgFile)

  val widthRegex: Regex = """width="(\d+)(?:pt)?"""".r
  val heightRegex: Regex = """height="(\d+)(?:pt)?"""".r

  val width = widthRegex.findFirstMatchIn(fileContent).get.group(1).toInt
  val height = heightRegex.findFirstMatchIn(fileContent).get.group(1).toInt

  (width, height)
}
