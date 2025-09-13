#!/usr/bin/env -S scala-cli shebang --quiet
//> using toolkit default
//> using file config.scala

def dockerExec(name: String): os.CommandResult = {
  var cmd = Seq(
    "docker",
    "run",
    "--rm",
    "-i",
    "-v",
    s"${realpathHome}:${home}",
    "-v",
    "/dev/shm:/dev/shm",
    "-u",
    s"${uid}:${gid}",
    "-w",
    s"${os.pwd}",
    dockerImage(name),
    "bash",
    "-i"
  )
  println(cmd)
  return os
    .proc(cmd)
    .call(
      stdin = os.Inherit,
      stdout = os.Inherit,
      stderr = os.Inherit
    )
}

@main def main(name: String) = {
  dockerExec(name)
}
