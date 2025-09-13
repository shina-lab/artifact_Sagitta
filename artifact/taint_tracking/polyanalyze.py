#!/usr/bin/env python3
from polytracker import PolyTrackerTrace, taint_dag
import os
import time

def taint_forest(tdag_file):
    trace = PolyTrackerTrace.load(tdag_file)

    ### Preview taint forest
    # if (len(list(trace.taint_forest.to_graph().edges())) < 10):
    #     print(trace.taint_forest.to_graph().to_dot())

    ### Access taint forest
    print(f"[*|{os.path.basename(tdag_file)}] Number of taint label: {trace.taint_forest.node_count}")
    dag = []
    for n in trace.taint_forest.nodes():
        dag.append({
            "label": n.label,
            "parent_labels": n.parent_labels if n.parent_labels is not None else (),
            "source": f"{n.source.path}" if n.source is not None else "ナン",
        })
    return dag

def input_sources(tdag_file):
    trace = PolyTrackerTrace.load(tdag_file)
    inputs = []
    try:
        for i in trace.inputs:
                inputs.append({
                    "uid": i.uid,
                    "path": i.path,
                    "size": i.size,
                    "track_start": i.track_start,
                    "track_end": i.track_end,
                    # "content": i.content, # Requires POLYSAVEINPUT=1
                })
    except ValueError:
        pass
    return inputs

def input_source_labels(tdag_file):
    trace = PolyTrackerTrace.load(tdag_file)
    inputs = []
    for label in trace.tdfile.input_labels():
        try:
            node = trace.tdfile.decode_node(label)
            inputs.append({
                "label": label,
                "idx": node.idx,
                "offset": node.offset,
            })
        except ValueError:
            """
              File "polytracker/taint_dag.py", line 127, in read_raw
                return c_uint64.from_buffer_copy(self.section, label * sizeof(c_uint64)).value
            <class 'ValueError'> Buffer size too small (108336 instead of at least 108384 bytes)
            """
            print(f"[!] ValueError: label={label}")
            pass
    return inputs

def stats(tdag_file):
    trace = PolyTrackerTrace.load(tdag_file)
    print(f"[*] Number of taint label: {trace.taint_forest.node_count}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='About this program')
    parser.add_argument("tdag_file", help="Path to tdag file")
    parser.add_argument("--stats", action="store_true", help="Preview statistics of given tdag file")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.stats:
        stats(args.tdag_file)
        exit(0)

    print("[*] Input sources")
    for v in input_sources(args.tdag_file):
        print(v)

    # print("[*] Input source labels")
    # for v in input_source_labels(args.tdag_file)[:100]:
    #     print(v)

    print("[*] Taint DAG")
    for v in taint_forest(args.tdag_file):
        print(v)