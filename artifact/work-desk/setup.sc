#!/usr/bin/env -S scala-cli shebang --quiet
//> using toolkit default
//> using file config.scala

def buildDir = scriptPath.startsWith("/") match {
  case true  => os.Path(scriptPath) / os.up
  case false => os.pwd / os.RelPath(scriptPath) / os.up
}

def dockerfile(name: String) = buildDir / s"Dockerfile.${name}"

def dockerBuild(name: String, args: Seq[String]): os.CommandResult = {
  println(s"[*] Building ${name}")

  var cmd = Seq(
    "docker",
    "build"
  ) ++ args ++ Seq(
    "-t",
    dockerImage(name),
    "-f",
    dockerfile(name).toString(),
    "--build-arg",
    s"USER=${user}",
    "--build-arg",
    s"UID=${uid}",
    "--build-arg",
    s"GID=${gid}",
    buildDir.toString()
  )
  println(cmd)
  return os.proc(cmd).call(stdout = os.Inherit, stderr = os.Inherit, check = true)
}

def prehook(name: String) = {
  println(s"[*] Running prehook for ${name}")
  
  name match {
    case "polytracker" | "polytracker.slim" =>
      os.proc("polytracker", "docker", "rebuild").call(stdout = os.Inherit, stderr = os.Inherit, check = true)
    case _ => ()
  }
}

def posthook(name: String) = {
  println(s"[*] Running posthook for ${name}")
  
  name match {
    case "llvm-13" =>
      os.proc("docker", "tag", dockerImage(name), name).call(stdout = os.Inherit, stderr = os.Inherit, check = true)
    case _ => ()
  }
}

def main(name: String, additional: Seq[String]) = {
  if !os.exists(dockerfile(name)) then
    println(s"[!] Dockerfile for ${name} does not exist: ${dockerfile(name)}")
    sys.exit(1)
  prehook(name)
  dockerBuild(name, additional)
  posthook(name)
}

main(args(0), args.drop(1))
