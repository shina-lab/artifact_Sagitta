#!/usr/bin/env -S scala-cli shebang -q --power
//> using file project.scala
//> using file taint_tracking.scala

import scala.io.Source
import io.circe.yaml.v12 as yaml

def tokenize(labelLog: String) = {
  var fileReader = new FileReader()
  for (line <- Source.fromFile(labelLog).getLines) {
    val result = yaml.parser.parse(line)
    assert(
      result.isRight,
      s"Failed to parse YAML: ${result.left}\n\t${line}"
    )
    val v = result.right.get.asArray.get(0).asObject
    {
      val kind = v.get("kind").get.asString.get
      kind match
        case "label" => {
          val location = Location(
            os.Path(v.get("path").get.asString.get),
            v.get("line").get.asNumber.get.toInt.get,
            v.get("column").get.asNumber.get.toInt.get
          )
          val function = v.get("function").get.asString.get
          val opcode = v.get("opcode").get.asString.get
          val label = v.get("label").get.asNumber.get.toInt.get

          fileReader.addFile(location.path)
          fileReader.readAt(location) match
            case Some(token) =>
              println(
                s"${token.replaceAll("^\\s+", "").replaceAll(fileReader.marker(), "👉")} opcode=${opcode} label=${label} function=${function} line=${location.line}"
              )
            case None => ()
        }
        case "update" => {
          val location = Location(
            os.Path(v.get("path").get.asString.get),
            v.get("line").get.asNumber.get.toInt.get,
            v.get("column").get.asNumber.get.toInt.get
          )
          val function = v.get("function").get.asString.get
          val old_label = v.get("old_label").get.asNumber.get.toInt.get
          val new_label = v.get("new_label").get.asNumber.get.toInt.get

          fileReader.addFile(location.path)
          fileReader.readAt(location) match
            case Some(token) =>
              println(
                s"${token.replaceAll("^\\s+", "").replaceAll(fileReader.marker(), "👉")} old_label=${old_label} new_label=${new_label} function=${function}"
              )
            case None => ()
        }
        case _ => ()
    }
  }
}

tokenize(args(0))
