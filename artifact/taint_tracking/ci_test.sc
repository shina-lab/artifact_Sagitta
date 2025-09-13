#!/usr/bin/env -S scala-cli shebang
//> using file project.scala
//> using file taint_tracking.scala

import scala.concurrent.Future
import scala.concurrent.ExecutionContext.Implicits.global
import scala.util.{Success, Failure}

def scriptDir = scriptPath.startsWith("/") match {
  case true  => os.Path(scriptPath) / os.up
  case false => os.pwd / os.RelPath(scriptPath) / os.up
}

val artifactDir = scriptDir / "artifacts"
val projectDir = scriptDir / os.up
val testDir = scriptDir / "test"

def polydb(caseName: String, prefix: String)(baseDir: os.Path)(
    suffix: String
) =
  baseDir / caseName / s"${prefix}.polytracker.tdag${suffix}"
def labelLog(caseName: String, prefix: String)(
    baseDir: os.Path,
    middle: os.RelPath = os.RelPath(".")
)(suffix: String) =
  baseDir / caseName / middle / s"${prefix}.label.log${suffix}"
def taintGml(caseName: String, prefix: String)(
    baseDir: os.Path,
    middle: os.RelPath = os.RelPath(".")
)(suffix: String) =
  baseDir / caseName / middle / s"${prefix}.taint.gml${suffix}"

def addTestCase(
    caseName: String,
    inputFile: String,
    srcPolydb: os.Path
) = {
  println(s"[*] == Add test case: ${caseName}")
  val evaluationDir = projectDir / "evaluation"
  {
    println(s"[*] === Cleanup test dir: ${testDir / caseName}")
    os.remove.all(testDir / caseName)
    os.makeDir.all(testDir / caseName)
  }
  {
    val source =
      labelLog(caseName, inputFile)(evaluationDir, os.RelPath("result"))("")
    val target = labelLog(caseName, inputFile)(testDir)(".zst")
    println(s"[*] === Copy: ${source} -> ${target}")
    os.proc("zstd", source, "-o", target).call(check = true)
  }
  {
    val source = srcPolydb
    val target = polydb(caseName, inputFile)(testDir)(".zst")
    println(s"[*] === Copy: ${source} -> ${target}")
    os.proc("zstd", "-k", source, "-o", target).call(check = true)
  }
  {
    val source =
      taintGml(caseName, inputFile)(evaluationDir, os.RelPath("result"))("")
    val target = taintGml(caseName, inputFile)(testDir)(".gz")
    println(s"[*] === Copy: ${source} -> ${target}")
    os.proc("gzip", "-c", source).call(check = true, stdout = target)
  }
}

def runTestCase(caseName: String, inputFile: String) = {
  println(s"[*] == Test: ${caseName}")
  os.makeDir.all(artifactDir / caseName)

  println(s"[*] === Extract requirements: ${caseName}")
  {
    val path = polydb(caseName, inputFile)
    os.proc(
      "zstd",
      "-d",
      path(testDir)(".zst"),
      "-o",
      path(artifactDir)("")
    ).call(check = true)
    os.perms.set(path(artifactDir)(""), "r--r--r--")
  }
  {
    def path(baseDir: os.Path) = labelLog(caseName, inputFile)(baseDir)
    os.proc(
      "zstd",
      "-d",
      path(testDir)(".zst"),
      "-o",
      path(artifactDir)("")
    ).call(check = true)
  }
  {
    val pt =
      PolyTracker(artifactDir / caseName, projectDir, artifactDir / caseName)
    pt.analyzeTaint(os.Path("/") / inputFile)()
  }
  {
    println(s"[*] === Diff: ${caseName}")
    def path(baseDir: os.Path) = taintGml(caseName, inputFile)(baseDir)
    os.proc("gzip", path(artifactDir)("")).call(check = true)
    os.proc("zdiff", path(testDir)(".gz"), path(artifactDir)(".gz"))
      .call(check = true)
  }
}

def all() = {
  println("[*] = All")
  clean()

  runTestCase("libpng-PNG001", "crash-000073")
  runTestCase("libtiff-TIF005", "crash-000034")
}

def add(caseName: String) = {
  caseName match {
    case "PNG001" => addTestCasePNG001()
    case "TIF005" => addTestCaseTIF005()
    case _        => println(s"[!] Invalid case: ${caseName}")
  }
}

def addTestCasePNG001() = {
  println("[*] == Add test case: PNG001")
  addTestCase(
    "libpng-PNG001",
    "crash-000073",
    os.Path("/dev/shm/crash-000073.polytracker.tdag"),
  )
}

def addTestCaseTIF005() = {
  println("[*] == Add test case: TIF005")
  addTestCase(
    "libtiff-TIF005",
    "crash-000034",
    os.Path("/dev/shm/crash-000034.polytracker.tdag"),
  )
}

def clean() = {
  println("[*] == Clean")
  os.remove.all(artifactDir)
}

def diff() = {}

var command = args.length match {
  case 0 => "all" // Default command
  case _ => args(0)
}

command match {
  case "add"   => add(args(1))
  case "clean" => clean()
  case "all"   => all()
  case _       => println(s"[!] Invalid command: ${command}")
}
