#!/usr/bin/env python3
"""Generate nodeX_Y.txt input files:  python3 gen_data.py --stars 3 --nodes 4 --lines 6"""
import argparse, os, random

ap = argparse.ArgumentParser()
ap.add_argument("--stars", type=int, default=3)
ap.add_argument("--nodes", default="4")
ap.add_argument("--lines", type=int, default=6)
ap.add_argument("--dir", default="data")
a = ap.parse_args()
counts = [int(x) for x in a.nodes.split(",")]
counts = counts * a.stars if len(counts) == 1 else counts
os.makedirs(a.dir, exist_ok=True)
everyone = [(n + 1, i) for n, c in enumerate(counts) for i in range(1, c + 1)]
words = "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima".split()
for (x, y) in everyone:
    with open(os.path.join(a.dir, "node%d_%d.txt" % (x, y)), "w") as f:
        for _ in range(a.lines):
            dx, dy = random.choice([e for e in everyone if e != (x, y)])
            f.write("%d_%d: %s\n" % (dx, dy, " ".join(random.choices(words, k=random.randint(1, 8)))))
