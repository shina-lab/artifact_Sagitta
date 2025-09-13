//> using python
import me.shadaj.scalapy.py

class Graph(val graph: py.Dynamic) {
  var name = graph.name.as[String]
  var labels: Map[Int, String] = Map()
  for (v: py.Dynamic <- graph.nodes().__iter__().as[Seq[py.Dynamic]]) {
    println(v)
    addNodeLabel(v(0).as[Int], v(1).as[String])
  }

  def addNodeLabel(id: Int, label: String) = {
    labels += id -> label
  }
}

def read_gml(gml_file: String) = {
  var nx = py.module("networkx")
  var gml = nx.readwrite.gml.read_gml(gml_file)
  println(s"[*|${gml.name}] Number of node: ${gml.nodes}")
  println(s"[*|${gml.name}] Number of edge: ${gml.edges}")
  var G = new Graph(gml)
}

def main(gml_file: String) = {
  var G = read_gml(gml_file);
}

// main(args(0))
main("test.gml")
