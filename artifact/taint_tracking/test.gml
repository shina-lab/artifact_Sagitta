graph [
  directed 1
  name "Test"
  node [
    id 0
    label "x = a + b;"
  ]
  node [
    id 1
    label "x"
  ]
  node [
    id 2
    label "a + b"
  ]
  node [
    id 3
    label "a"
  ]
  node [
    id 4
    label "b"
  ]
  edge [
    source 0
    target 1
    label "="
  ]
  edge [
    source 0
    target 2
    label "="
  ]
  edge [
    source 2
    target 3
  ]
  edge [
    source 2
    target 4
  ]
]
