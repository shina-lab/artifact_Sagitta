#!/usr/bin/env -S scala-cli shebang --quiet
//> using toolkit default
//> using file config.scala

def dockerRun(name: String, args: Seq[String], cwd: os.Path): os.CommandResult = {
  // NOTE: Dockerがデフォルトで用意する /dev/shm は 64MB しかない
  var cmd = Seq(
    "docker",
    "run",
    "--cap-add",
    "SYS_ADMIN", // perf を使えるようにする
    "--rm",
    "-it",
    "-v",
    s"${realpathHome}:${home}",
    "-v",
    s"/mnt/${user}:/mnt/${user}",
    "-v",
    "/dev/shm:/dev/shm",
    "-u",
    s"${uid}:${gid}",
    "-w",
    s"${os.pwd}",
    // NOTE: ホスト側の scala-cli との干渉を防止する
    "-e",
    s"SCALA_CLI_HOME=/tmp",
    dockerImage(name)
  ) ++ args
  println(cmd)
  return os
    .proc(cmd)
    .call(
      stdin = os.Inherit,
      stdout = os.Inherit,
      stderr = os.Inherit,
      cwd = cwd
    )
}

@main def main(name: String, args: String*) = {
  args match {
    case Seq() => dockerRun(name, Seq("bash"), os.pwd)
    case _     => dockerRun(name, args, os.pwd)
  }
}
