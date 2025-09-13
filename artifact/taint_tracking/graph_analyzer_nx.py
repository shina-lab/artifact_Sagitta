"""shell
python3 -m pip install -r requirements.txt
python3 -i graph_analyzer.py DOT_FILE
"""
import networkx as nx
import argparse
import re
import os
import subprocess
import time
import sys
import queue
from pathlib import Path

# sys.setrecursionlimit(5000) # => segv

class NodeList(list):
    def __getitem__(self, idx):
        try:
            return super().__getitem__(idx)
        except IndexError:
            return None

def lookup_id(label):
    global label2id
    return label2id[label]

def lookup_label(_id):
    if "label" in G.nodes[_id]:
        return G.nodes[_id]["label"].strip("\"")
    else:
        return _id

def labels(filter_func=lambda _: True):
    return NodeList(map(lambda kv: kv[0], filter(filter_func, label2id.items())))

def ids(filter_func):
    return NodeList(map(lambda kv: kv[1], filter(filter_func, label2id.items())))

def startswith(condition):
    return lambda kv: kv[0].startswith(condition)

def contains(condition):
    return lambda kv: condition in kv[0]

def matches(condition):
    pattern = re.compile(condition)
    return lambda kv: bool(pattern.search(kv[0]))

def last(iterable, n):
    result = list(iterable)
    if result:
        return [result[-n:]]
    else:
        return []

def subgraph(nodes):
    global G
    return G.subgraph(nodes)

def is_root(_id):
    global G
    return G.out_degree(_id) == 0

# def has_edge(label):
#     def __has_edge(child):
#         for parent in G.predecessors(child):
#             assert(G.has_edge(child, parent))
#             if G.edges[parent, child, 0]["label"].strip("\"") == label:
#                 return True
#         return False
#     return __has_edge

# def drop_if_ancestor_does_not_have_edge(label, nodes):
#     def __drop_if_ancestor_does_not_have_edge(child):
#         for parent in G.predecessors(child):
#             if parent in nodes:
#                 if G.edges[parent, child, 0]["label"].strip("\"") == label:
#                     return True
#                 else:
#                     return __drop_if_ancestor_does_not_have_edge(parent)
#         return False
#     res = set()
#     for node in nodes:
#         if __drop_if_ancestor_does_not_have_edge(node):
#             res.add(node)
#     return res

def normalize_label(_input):
    def __normalize_label(label):
        try:
            return re.findall("(.+) \(\S+\)", label.strip("\""))[0]
        except IndexError as e:
            print(f"[!] Invalid label format: {label}")
            if label.startswith("("):
                # No label
                return label
            raise e
    if isinstance(_input, str):
        return __normalize_label(_input)
    else:
        return set(map(lambda label: __normalize_label(label), _input))

def ssa_id(label):
    m = re.findall("\((\d+)\)$", label)
    if m:
        return int(m[0])
    else:
        return -1

def sort(items):
    global G
    return sorted(items, key=ssa_id)

def dump(items, func=lambda x: x):
    for x in items:
        print(func(x))

def load(path):
    global label2id
    
    print(f"[*] Start loading graph: {path}")
    start_time = time.time_ns()
    if path.endswith(".dot"):
        G = nx.drawing.nx_pydot.read_dot(path)
    else:
        ### gml mode
        G = nx.readwrite.gml.read_gml(path)
    G.path = path
    if not G.name or G.name == "G":
        G.name = os.path.basename(path)
    print("[*|{}] Graph loading time: {:.2f} sec".format(G.name, (time.time_ns() - start_time) / (1000 * 1000 * 1000)))

    label2id = {}
    for _id, label in G.nodes(data="label"):
        if label:
            label = label.strip("\"")
            assert not label in label2id
            label2id[label] = _id
        else:
            ### NOTE: use label as _id in gml mode
            label2id[_id] = _id

    print(f"[*|{G.name}] Number of node: {len(G.nodes)}")
    print(f"[*|{G.name}] Number of edge: {len(G.edges)}")
    print(f"[*|{G.name}] G.path={G.path}")

    return G

def successors(label):
    global G
    for node in G.successors(lookup_id(label)):
        print(lookup_label(node))

def predecessors(label):
    global G
    for node in G.predecessors(lookup_id(label)):
        print(lookup_label(node))

# AttributeError: 'MultiDiGraph' object has no attribute 'ancestors'
def ancestors(_id):
    def __ancestors(bot):
        global G
        res = [bot]
        visited = set(bot) # Clone passed value
        waiting = queue.Queue()
        waiting.put(bot)
        
        while not waiting.empty():
            _id = waiting.get()
            visited.add(_id)
            for node in list(G.predecessors(_id)):
                if not node in visited: ### NOTE: 巡回グラフ対策
                    waiting.put(node)
                    res.append(node)
        return res

    if _id == None:
        return []
    elif isinstance(_id, list) or isinstance(_id, set):
        res = set()
        for v in _id:
            res |= set(__ancestors(v))
        return list(res)
    else:
        return __ancestors(_id)
    

def descendants(_id, visited=set()):
    global G
    res = [_id]
    visited = set(visited) # Clone passed value
    visited.add(_id)
    for node in list(G.successors(_id)):
        if not node in visited: ### NOTE: 巡回グラフ対策
            res.extend(descendants(node, visited))
    return res

def root_of(_id):
    global G
    res = []
    if is_root(_id):
        res.append(_id)
    for parent in G.predecessors(_id):
        res.extend(root_of(parent))
    return res

def edges(func):
    return list(map(lambda t: (t[0], t[1]), filter(func, G.edges(data=True))))

def label_is(label):
    return lambda edge: edge[-1]["label"].strip("\"") == label

def label_is_any_of(labels):
    def __label_is_any_of(edge):
        child_label = edge[-1]["label"].strip("\"")
        for label in labels:
            if child_label == label:
                return True
        return False
    return __label_is_any_of

def unique_parent():
    global G
    return lambda edge: len(list(G.predecessors(edge[1]))) == 1

def flatten(data):
    res = []
    for x in data:
        res.extend(list(x))
    return res

def apply(func, nodes):
    res = []
    assert(not isinstance(nodes, str))
    for node in nodes:
        res.extend(func(node))
    return res

def diff(G_before, G_after=None, debug=False):
    global G
    if not G_after:
        G_after = G
    
    COLOR_GREEN = "#008000"
    
    before_nodes = set(map(lambda label: normalize_label(label), G_before.nodes))
    after_nodes = set(map(lambda label: normalize_label(label), G_after.nodes))
    deleted_nodes = before_nodes - after_nodes
    new_nodes = after_nodes - before_nodes
    common_nodes = before_nodes & after_nodes

    if debug:
        print(f"[NEW] {repr(new_nodes).encode('utf-8')}")
        print(f"[DEL] {repr(deleted_nodes).encode('utf-8')}")
    for node in G_before.nodes:
        label = normalize_label(node)
        if label in deleted_nodes:
            G_before.nodes[node]["color"] = "red"
            G_before.nodes[node]["penwidth"] = 2
            G_before.nodes[node]["style"] = "dashed"
    for node in G_after.nodes:
        label = normalize_label(node)
        if label in new_nodes:
            G_after.nodes[node]["color"] = COLOR_GREEN
            G_after.nodes[node]["penwidth"] = 2
            G_after.nodes[node]["style"] = "dashed"
    
    ### 注目しているノードより、時系列で後のノードをハイライト
    
    if len(G_before.nodes) > 0:
        before_bottom = max(map(ssa_id, filter(lambda label: len(list(G_before.successors(label))) == 0, G_before.nodes)))
    else:
        before_bottom = 0
    if len(G_after.nodes) > 0:
        after_bottom = max(map(ssa_id, filter(lambda label: len(list(G_after.successors(label))) == 0, G_after.nodes)))
    else:
        after_bottom = 0
    print(f"[BOTTOM] before={before_bottom}, after={after_bottom}")
    for node in G_before.nodes:
        if ssa_id(node) > before_bottom:
            G_before.nodes[node]["color"] = "red"
    for node in G_after.nodes:
        if ssa_id(node) > after_bottom:
            G_after.nodes[node]["color"] = COLOR_GREEN
    
    return (G_before, G_after)

def write_dot(G, path):
    def __write_dot(G, path):
        basename = os.path.basename(path)
        print(f"[*|{basename}] Number of node: {len(G.nodes)}")
        print(f"[*|{basename}] Number of edge: {len(G.edges)}")
        
        ### Dump graph
        nx.drawing.nx_agraph.write_dot(G, path)
        nx.readwrite.gml.write_gml(G, path.replace(".dot", ".gml"))

        ### Add header to dumped graph
        with open(path, "r", encoding='utf-8') as f:
            dot_file = f.readlines()
        with open(path, "w", encoding='utf-8') as f:
            for i, line in enumerate(dot_file):
                print(line, file=f, end="")
                if i < 5 and line.strip().startswith("graph"):
                    print('\tnode [fontsize=12, fontname="Arial", shape=oval, penwidth=1, margin=0];', file=f)
                    print('\tnodesep = 0.2; ranksep = 0.3;', file=f)
                    print('\tedge [fontsize=12, fontname="Arial", penwidth=1];', file=f)
        
        print(f"[*|{basename}] Dot file written to {path}")
        return path

    if isinstance(G, tuple):
        dirname0 = os.path.dirname(os.path.abspath(G[0].path))
        dirname1 = os.path.dirname(os.path.abspath(G[1].path))
        basename0 = os.path.basename(G[0].path).replace(".gml", ".dot")
        basename1 = os.path.basename(G[1].path).replace(".gml", ".dot")
        return ( __write_dot(G[0], f"{dirname0}/diff.{basename0}"), __write_dot(G[1], f"{dirname1}/diff.{basename1}"))
    else:
        return __write_dot(G, path)

def render(path):
    def __render(path):
        if os.path.getsize(path) > 2 * 1024 * 1024:
            print(f"[*|{G.name}] Graph is too large to render. Skip")
            return
        
        path = Path(path)
        export_to = lambda ext: os.path.join(Path(path).parent, path.stem + ext)
        
        subprocess.run(["dot", "-Tsvg", path, "-o", export_to(".svg")], check=True)
        subprocess.run(["dot", "-Tpng", "-Gdpi=300", path, "-o", export_to(".png")], check=True, capture_output=True)

    if isinstance(path, tuple):
        for x in list(path):
            __render(x)
    else:
        __render(path)

def entrypoint(file):
    global G
    G = load(file)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Graph (dot file) analyzer')
    parser.add_argument("DOT_FILE")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    try:
        entrypoint(args.DOT_FILE)
    except Exception as e:
        print(e)
        exit(1)

    ### command alias
    succ = successors
    pred = predecessors
    ance = ancestors
