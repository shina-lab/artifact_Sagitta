var home = os.Path(System.getenv("HOME"))
var realpathHome = os.proc("realpath", home.toString).call().out.text().trim()
var user = System.getenv("USER")
var uid = os.proc("id", "-u").call().out.text().trim()
var gid = os.proc("id", "-g").call().out.text().trim()
def dockerImage(name: String) = s"${System.getenv("USER")}/work-desk/${name}"
