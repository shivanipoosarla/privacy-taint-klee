# klee_leaklens_postprocessor.py
import os
import json
import argparse
import graphviz
from pathlib import Path

def parse_info_log(info_path):
    leaks = []
    with open(info_path, 'r') as f:
        for line in f:
            if "TAINTED" in line or "sink" in line:
                leaks.append(line.strip())
    return leaks

def parse_ktest(ktest_path):
    from ktest import KTest  # Requires ktest.py from KLEE repo
    test = KTest(ktest_path)
    inputs = {entry.name: entry.bytes for entry in test.objects}
    return inputs

def generate_graph(leaks, output_path):
    dot = graphviz.Digraph(comment='Taint Flow')
    
    for i, leak in enumerate(leaks):
        parts = leak.split(' -> ')
        for j in range(len(parts) - 1):
            dot.edge(parts[j], parts[j + 1])

    dot.render(output_path, format='pdf', cleanup=True)
    print(f"Graph written to {output_path}.pdf")

def summarize_leaks(leaks, inputs, output_file):
    with open(output_file, 'w') as f:
        f.write("# Leak Summary\n\n")
        f.write("## Inputs:\n")
        for name, val in inputs.items():
            f.write(f"- {name}: {val.hex()}\n")

        f.write("\n## Leaks Detected:\n")
        for leak in leaks:
            f.write(f"- {leak}\n")
    print(f"Textual report written to {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Post-process klee-taint outputs")
    parser.add_argument("--ktest", required=True, help="Path to .ktest file")
    parser.add_argument("--info", required=True, help="Path to .info log")
    parser.add_argument("--outdir", required=True, help="Directory to save reports")
    args = parser.parse_args()

    Path(args.outdir).mkdir(parents=True, exist_ok=True)
    
    leaks = parse_info_log(args.info)
    inputs = parse_ktest(args.ktest)

    generate_graph(leaks, os.path.join(args.outdir, "leak_graph"))
    summarize_leaks(leaks, inputs, os.path.join(args.outdir, "summary.txt"))

if __name__ == "__main__":
    main()
