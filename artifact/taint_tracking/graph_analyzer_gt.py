"""shell
conda create --name gt -c conda-forge graph-tool
conda activate gt
python3 -i graph_analyzer_gt.py GML_FILE
"""
import graph_tool.all as gt
import argparse
import re
import os
import subprocess
import time
import sys
import queue
from pathlib import Path

def normalize_label(_input):
    def __normalize_label(label):
        try:
            return re.findall("(.+) \(\S+\)", label.strip("\""))[0]
        except IndexError as e:
            # print(f"[!] Invalid label format: {label}")
            if label.startswith("("):
                # No label
                return ""
            raise e
    if isinstance(_input, str):
        return __normalize_label(_input)
    else:
        return set(map(lambda label: __normalize_label(label), _input))

def load(path):
    global label2id
    
    print(f"[*] Start loading graph: {path}")
    start_time = time.time_ns()
    G = gt.load_graph(path)
    G.path = path
    G.name = os.path.basename(path)
    print("[*|{}] Graph loading time: {:.2f} sec".format(G.name, (time.time_ns() - start_time) / (1000 * 1000 * 1000)))

    ### Add NetworkX like interface
    G.nodes = lambda : G.vertices()
    G.predecessors = lambda v: [int(e.source()) for e in G.vertex(v).in_edges()]
    G.successors = lambda v: [int(e.target()) for e in G.vertex(v).out_edges()]

    label2id = {}
    for _id in G.iter_vertices():
        label = G.vp.label[_id]
        if label:
            label = label.strip("\"")
            label2id[label] = _id
        else:
            ### NOTE: use label as _id in gml mode
            label2id[_id] = _id

    print(f"[*|{G.name}] Number of node: {G.num_vertices()}")
    print(f"[*|{G.name}] Number of edge: {G.num_edges()}")
    print(f"[*|{G.name}] G.path={G.path}")

    return G

def diff(G_before, G_after, debug=False):
    COLOR_LIGHTGREY = "#D1D5DB" # Gray/300
    COLOR_GREY = "#6B7280" # Gray/500
    COLOR_BLACK = "black"
    COLOR_GREEN = "#15803D" # Green/700
    COLOR_RED = "#B91C1C" # Red/700
    COLOR_INDIGO = "#4338CA" # Indigo/700
    
    if G_before.num_vertices() > 0:
        before_nodes = set(map(lambda label: normalize_label(label), G_before.vp.label))
    else:
        before_nodes = set()
    if G_after.num_vertices() > 0:
        after_nodes = set(map(lambda label: normalize_label(label), G_after.vp.label))
    else:
        after_nodes = set()
    deleted_nodes = before_nodes - after_nodes
    new_nodes = after_nodes - before_nodes
    common_nodes = before_nodes & after_nodes

    G_before.vp["color"] = G_before.new_vertex_property("string", val=COLOR_BLACK)
    G_before.vp["fontcolor"] = G_before.new_vertex_property("string", val=COLOR_BLACK)
    G_before.vp["penwidth"] = G_before.new_vertex_property("int", val=1)
    G_before.vp["style"] = G_before.new_vertex_property("string", val="solid")
    G_before.ep["color"] = G_before.new_edge_property("string", val="black")
    G_before.ep["penwidth"] = G_before.new_edge_property("int", val=1)
    G_before.ep["style"] = G_before.new_edge_property("string", val="solid")
    G_before.ep["tooltip"] = G_before.new_edge_property("string", val="")

    G_after.vp["color"] = G_after.new_vertex_property("string", val=COLOR_BLACK)
    G_after.vp["fontcolor"] = G_after.new_vertex_property("string", val=COLOR_BLACK)
    G_after.vp["penwidth"] = G_after.new_vertex_property("int", val=1)
    G_after.vp["style"] = G_after.new_vertex_property("string", val="solid")
    G_after.ep["color"] = G_after.new_edge_property("string", val="black")
    G_after.ep["penwidth"] = G_after.new_edge_property("int", val=1)
    G_after.ep["style"] = G_after.new_edge_property("string", val="solid")
    G_after.ep["tooltip"] = G_after.new_edge_property("string", val="")

    if debug:
        print(f"[NEW] {repr(new_nodes).encode('utf-8')}")
        print(f"[DEL] {repr(deleted_nodes).encode('utf-8')}")
    for node in G_before.iter_vertices():
        label = normalize_label(G_before.vp.label[node])
        if label in deleted_nodes:
            G_before.vp.color[node] = COLOR_RED
            G_before.vp.penwidth[node] = 2
            G_before.vp.style[node] = "dashed"
    for node in G_after.iter_vertices():
        label = normalize_label(G_after.vp.label[node])
        if label in new_nodes:
            G_after.vp.color[node] = COLOR_GREEN
            G_after.vp.penwidth[node] = 2
            G_after.vp.style[node] = "dashed"
    
    ### weak edge の装飾
    for edge in G_before.iter_edges():
        if G_before.ep.weak[edge] == 1:
            G_before.ep.style[edge] = "dashed"
    for edge in G_after.iter_edges():
        if G_after.ep.weak[edge] == 1:
            G_after.ep.style[edge] = "dashed"
    
    ### 辺の装飾
    for edge in G_before.iter_edges():
        G_before.ep.tooltip[edge] = f"{G_before.vp.label[edge[0]]} -> {G_before.vp.label[edge[1]]}"
        if G_before.ep.label[edge] == "dominates":
            G_before.ep.color[edge] = COLOR_INDIGO
            G_before.ep.penwidth[edge] = 2
    for edge in G_after.iter_edges():
        G_after.ep.tooltip[edge] = f"{G_after.vp.label[edge[0]]} -> {G_after.vp.label[edge[1]]}"
        if G_after.ep.label[edge] == "dominates":
            G_after.ep.color[edge] = COLOR_INDIGO
            G_after.ep.penwidth[edge] = 2

    ### 注目しているノードより、時系列で後のノードをハイライト
    ### （注）テイントの union がいつされたのかを記録されていないので、unionの前後にテイントがあったのかは判定不能
    def node_id(G):
        def _node_id(node):
            if "_id" in G.vp:
                return G.vp._id[node]
            else:
                return node
        return _node_id
    def bottom_node(G):
        if G.num_vertices() > 0:
            return int(max(
                map(
                    node_id(G), 
                    filter(
                        lambda node: len(G.get_out_edges(node)) == 0, 
                        G.iter_vertices()
                    )
                )
            ))
        else:
            return 0
    before_bottom = bottom_node(G_before)
    after_bottom = bottom_node(G_after)
    print(f"[BOTTOM] before={before_bottom}, after={after_bottom}")
    for node in G_before.iter_vertices():
        if node_id(G_before)(node) > before_bottom:
            G_before.vp.color[node] = COLOR_LIGHTGREY
            G_before.vp.fontcolor[node] = COLOR_GREY
            G_before.vp.penwidth[node] = 1
            G_before.vp.style[node] = "solid"
    for node in G_after.iter_vertices():
        if node_id(G_after)(node) > after_bottom:
            G_after.vp.color[node] = COLOR_LIGHTGREY
            G_after.vp.fontcolor[node] = COLOR_GREY
            G_after.vp.penwidth[node] = 1
            G_after.vp.style[node] = "solid"
    
    return (G_before, G_after)

def write_dot(G, path):
    def __write_dot(G, path):
        basename = os.path.basename(path)
        print(f"[*|{basename}] write_dot: Number of node: {G.num_vertices()}")
        print(f"[*|{basename}] write_dot: Number of edge: {G.num_edges()}")
        
        ### Dump graph
        path = Path(path)
        export_to = lambda ext: os.path.join(Path(path).parent, path.stem + ext)
        G.save(export_to(".gml"))
        G.save(export_to(".dot"))

        ### Remove gomi
        with open(path, "rb") as f:
            dot_file = f.read().replace(b"\"\x00\"", b"\"\"").replace(b"\"\x01\"", b"\"\"")
        with open(path, "wb") as f:
            f.write(dot_file)

        ### Add header to dumped graph
        with open(export_to(".dot"), "r", encoding='utf-8') as f:
            dot_file = f.readlines()
        with open(export_to(".dot"), "w", encoding='utf-8') as f:
            for i, line in enumerate(dot_file):
                print(line, file=f, end="")
                if i < 5 and (line.startswith("graph") or line.startswith("digraph")):
                    print('  node [fontsize=12, fontname="Inter, Arial", shape=oval, penwidth=1, margin=0];', file=f)
                    print('  nodesep = 0.2; ranksep = 0.3;', file=f)
                    print('  edge [fontsize=12, fontname="Inter, Arial", penwidth=1];', file=f)
        
        print(f"[*|{basename}] Dot file written to {path}")
        return path

    if isinstance(G, tuple) and isinstance(path, tuple):
        return ( 
            __write_dot(G[0], path[0]), 
            __write_dot(G[1], path[1])
        )
    else:
        return __write_dot(G, path)

def render(path):
    def canvas_size_of_svg(svg_file: Path) -> (int, int):
        with open(svg_file, 'r', encoding='utf-8') as file:
            file_content = file.read()
        
        width_regex = re.compile(r'width="(\d+)(?:pt)?"')
        height_regex = re.compile(r'height="(\d+)(?:pt)?"')
        
        width_match = width_regex.search(file_content)
        height_match = height_regex.search(file_content)
        
        if width_match and height_match:
            width = int(width_match.group(1))
            height = int(height_match.group(1))
        else:
            width, height = 0, 0  # Or you could raise an exception if necessary
        
        return width, height

    def __render(path):
        path = Path(path)
        export_to = lambda ext: os.path.join(Path(path).parent, path.stem + ext)

        if os.path.getsize(path) > 3 * 1024 * 1024:
            print(f"[!] Too large graph file. Skip plotting: {path.name} size={os.path.getsize(path)}")
            return
        
        if os.path.getsize(path) < 2 * 1024 * 1024:
            renderer = "dot"
        else:
            renderer = "sfdp"
        subprocess.run([renderer, "-Goverlap=prism", "-Tsvg", path, "-o", export_to(".svg")], check=True)
        if subprocess.run(["which", "cairosvg"], stdout=subprocess.PIPE, check=True).returncode == 0:
            (actual_width, actual_height) = canvas_size_of_svg(export_to(".svg"))
            print(f"[*] Canvas size of {path.name}: {actual_width} x {actual_height}")

            ### Adjust SVG size to cairosvg size limit
            cairosvg_size_limit = 20000
            resize_options = []
            if actual_width > cairosvg_size_limit and actual_height > cairosvg_size_limit:
                resize_options.extend(["--output-width", str(cairosvg_size_limit), "--output-height", str(cairosvg_size_limit)])
            elif actual_width > cairosvg_size_limit:
                resize_options.extend(["--output-width", str(cairosvg_size_limit)])
            elif actual_height > cairosvg_size_limit:
                resize_options.extend(["--output-height", str(cairosvg_size_limit)])
            
            # subprocess.run(["cairosvg", export_to(".svg"), "-o", export_to(".png")] + resize_options, check=True)
            subprocess.run(["cairosvg", export_to(".svg"), "-o", export_to(".pdf")], check=True)

    if isinstance(path, tuple):
        for x in list(path):
            __render(x)
    else:
        __render(path)

def entrypoint(file):
    global G
    G = load(file)

def diff_gml(file0, file1):
    G0 = load(file0)
    G1 = load(file1)
    return diff(G0, G1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Graph (gml file) analyzer')
    parser.add_argument("GML_FILE")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--diff")
    args = parser.parse_args()

    if args.diff:
        render(
            write_dot(
                diff_gml(args.GML_FILE, args.diff),
                (
                    args.GML_FILE.replace("subgraph.", "diff.").replace(".gml", ".dot"),
                    args.diff.replace("subgraph.", "diff.").replace(".gml", ".dot")
                )
            )
        )
        exit(0)

    try:
        entrypoint(args.GML_FILE)
    except Exception as e:
        print(e)
        # exit(1)

    # ### command alias
    # succ = successors
    # pred = predecessors
    # ance = ancestors
