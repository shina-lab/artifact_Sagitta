//> using toolkit default
import scala.io.Source
import scala.util.matching.Regex
import scala.util.Using
import java.io.{File, FileWriter, BufferedWriter}

def naodbi(projectDir: os.Path) = projectDir / os.RelPath("naodbi-rs")
def pin(naodbi: os.Path) =
  naodbi / os.RelPath("external/pin-3.18-98332-gaebd7b1e6-gcc-linux/pin")
def pintool(naodbi: os.Path) =
  naodbi / os.RelPath("target/debug/examples/libintelpin_iaddr2line.so")

def obtainInstructionTrace(artifactDir: os.Path, projectDir: os.Path)(
    traceeArgs: Seq[String]
): os.Path = {
  assert(
    os.exists(pin(naodbi(projectDir))),
    s"Error: Pin does not exist: ${pin(naodbi(projectDir))}"
  )
  assert(
    os.exists(pintool(naodbi(projectDir))),
    s"Error: Pintool does not exist: ${pintool(naodbi(projectDir))}"
  )
  os.proc(
    Seq(
      pin(naodbi(projectDir)).toString,
      "-t",
      pintool(naodbi(projectDir)).toString,
      "--"
    ) ++ traceeArgs
  ).call(
    check = false,
    cwd = artifactDir,
    env = Map("ASAN_OPTIONS" -> "exitcode=0")
  )

  val outFilePath = artifactDir / "iaddr2line.log"
  assert(
    os.exists(outFilePath),
    s"Error: Instruction trace file does not exist: ${outFilePath}"
  )
  println(s"[*] Obtained instruction trace: ${outFilePath}")
  return outFilePath
}

def retrieveExecutedSourceCodeLineFromInstructionTrace(artifactDir: os.Path)(
    itraceFile: os.Path
): os.Path = {
  assert(
    os.exists(itraceFile),
    s"Error: Instruction trace file does not exist: ${itraceFile}"
  )

  val outFilePath = artifactDir / "executed_lines.log"
  val outFile = new BufferedWriter(
    new FileWriter(new File((outFilePath.toString)))
  )

  val reExpect: Regex =
    """- \{ event: Instruction, count: (\d+), kind: DebugInfo, address: \S+, line: (\d+), column: (\d+), file: ".*\/repo\/(.*)" \}""".r

  var lastLocation: Option[(String, String)] = None

  val itraceLines = Source.fromFile(itraceFile.toString).getLines()
  itraceLines.foreach { itraceLine =>
    reExpect.findFirstMatchIn(itraceLine) match {
      case Some(m) =>
        val count = m.group(1)
        val line = m.group(2)
        val column = m.group(3)
        val file = m.group(4)

        // トレースで得た実行された命令とソースコードの位置を対応させる。
        // ただし、前後で同じファイルの同じ行が実行されていれば数に入れない。
        if (lastLocation != Some((line, file))) {
          outFile.write(
            s"- { event: Instruction, count: $count, line: $line, column: $column, file: \"$file }\n"
          )
          lastLocation = Some((line, file))
        }

      case None => // 無視
    }
  }
  outFile.close()

  println(
    s"[*] Retrieved executed source code lines from instruction trace: ${outFilePath}"
  )
  return outFilePath
}

class SourceCodeLocation(
    val file: String,
    val line: Int,
    val column: Int = 0
) {
  override def toString: String = {
    column match
      case 0 => s"$file:$line"
      case _ => s"$file:$line:$column"
  }

  def locatesAt(text: String): Boolean = {
    text.contains(file) && text.contains(s"line: $line") && (column match {
      case 0 => true
      case _ => text.contains(s"column: $column")
    })
  }
}

class DistanceMetricsItrace(
    val distance: Option[Int],
    val countRootCauseLocation: Option[Int],
    val countCrashLocation: Option[Int]
) {
  override def toString: String = {
    s"{ distance: ${distance}, countRootCauseLocation: ${countRootCauseLocation}, countCrashLocation: ${countCrashLocation} }"
  }
}

def calculateDistance(
    traceFilePath: os.Path
)(from: SourceCodeLocation, to: SourceCodeLocation): DistanceMetricsItrace = {
  val traceLines =
    Source.fromFile(traceFilePath.toString).getLines().zipWithIndex
  var fromPos: Option[Int] = None
  var fromCount: Option[Int] = None
  var toPos: Option[Int] = None
  var toCount: Option[Int] = None
  var currentPos: Int = 0
  val reExpect: Regex = """- \{ event: Instruction, count: (\d+), """.r
  for ((line, lineNo) <- traceLines) {
    reExpect.findFirstMatchIn(line) match
      case Some(m) =>
        currentPos += 1
        val count = m.group(1)
        if (fromPos.isEmpty && from.locatesAt(line)) {
          // NOTE: Memorize the first executed root cause
          fromPos = Some(currentPos)
          fromCount = Some(count.toInt)

          println(
            s"[*] Found from=${from.file}:${from.line} at count=${count}, line=${lineNo + 1}"
          )
          println(s"\t$line") // DEBUG:
        } else if (to.locatesAt(line)) {
          // NOTE: Memorize the last executed crash point
          toPos = Some(currentPos)
          toCount = Some(count.toInt)

          println(
            s"[*] Found to=${to.file}:${to.line} at count=${count}, line=${lineNo + 1}"
          )
          println(s"\t$line") // DEBUG:
        }
      case None => ()
  }
  (fromCount, toCount) match
    case (Some(_), Some(_)) =>
      return DistanceMetricsItrace(
        Some(toPos.get - fromPos.get),
        fromCount,
        toCount
      )
    case _ =>
      return DistanceMetricsItrace(
        None,
        fromCount,
        toCount
      )
}

def reportItraceMetrics(
    artifactDir: os.Path,
    projectDir: os.Path,
    traceeEnv: Map[String, String] = Map()
)(
    traceeArgs: Seq[String],
    rootCauseLocation: SourceCodeLocation,
    crashLocation: SourceCodeLocation
): os.Path = {
  var reportFilePath = artifactDir / "report-metrics_itrace.yml"
  var reportFile = new BufferedWriter(
    new FileWriter(new File((reportFilePath.toString)))
  )

  reportFile.write(s"config: {\n")
  reportFile.write(
    s"\t# traceeArgs: run command line arguments to calculate metrics\n"
  )
  reportFile.write(s"\ttraceeArgs: ${traceeArgs}\n")
  reportFile.write(
    s"\trootCauseLocation: \"${rootCauseLocation}\"\n"
  )
  reportFile.write(
    s"\tcrashLocation: \"${crashLocation}\"\n"
  )
  reportFile.write("}\n")

  val itraceFile = obtainInstructionTrace(artifactDir, projectDir)(traceeArgs)
  val executedLinesFile =
    retrieveExecutedSourceCodeLineFromInstructionTrace(artifactDir)(itraceFile)

  val itraceDistance =
    calculateDistance(itraceFile)(rootCauseLocation, crashLocation)
  val executedLinesDistance =
    calculateDistance(executedLinesFile)(rootCauseLocation, crashLocation)

  reportFile.write(s"metrics_itrace: {\n")
  reportFile.write(
    s"\tassembly: ${itraceDistance} # Unit is [instructions]\n"
  )
  reportFile.write(
    s"\tsourceCode: ${executedLinesDistance} # Unit is [lines]\n"
  )
  reportFile.write("}\n")

  reportFile.close()

  Using.resource(Source.fromFile(reportFilePath.toString)) { source =>
    source.getLines().foreach(println)
  }

  return reportFilePath
}
