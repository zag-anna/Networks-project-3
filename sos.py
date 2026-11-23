#!/usr/bin/env python3
"""Main class: builds the whole Star-of-Stars, runs it, shuts it down cleanly.

  python3 sos.py --stars 3 --nodes 4 [--kill-ccs-after 1.0]
"""
import argparse
import os
import sys
import threading
import time

from protocol import *
from ccs import CCS
from cas import CAS
from node import Node


def main():
    ap = argparse.ArgumentParser(description="Star of Stars with bridge and firewall")
    ap.add_argument("--stars", type=int, default=3, help="number of arm-end stars (1-15)")
    ap.add_argument("--nodes", default="4", help="nodes per star: one number or a comma list (1-16 each)")
    ap.add_argument("--data-dir", default="data")
    ap.add_argument("--out-dir", default="output")
    ap.add_argument("--firewall", default="firewall.txt")
    ap.add_argument("--base-port", type=int, default=9000)
    ap.add_argument("--send-delay", type=float, default=0.02, help="pause between frames")
    ap.add_argument("--kill-ccs-after", type=float, default=None,
                    help="crash the main CCS after N seconds to demo the shadow")
    ap.add_argument("--block-outbound", action="store_true",
                    help="'local' rules also stop the node/star from sending global traffic")
    a = ap.parse_args()

    counts = [int(x) for x in a.nodes.split(",")]
    if len(counts) == 1:
        counts *= a.stars
    if len(counts) != a.stars or not 1 <= a.stars <= 15 or not all(1 <= c <= 16 for c in counts):
        sys.exit("need 1-15 stars and 1-16 nodes per star (and one count per star)")
    topology = {i + 1: c for i, c in enumerate(counts)}
    rules = open(a.firewall).read() if os.path.exists(a.firewall) else ""

    p = a.base_port
    main_ccs = CCS("CCS-main", p, topology, rules)
    shadow = CCS("CCS-shadow", p + 1, None, "", main_port=p)
    main_ccs.start(); shadow.start()
    time.sleep(0.5)                                   # let the shadow attach

    cass = [CAS(n, c, p + 10 + n, [p, p + 1], a.block_outbound) for n, c in topology.items()]
    for c in cass:
        c.start()
    start_evt = threading.Event()
    nodes = [Node(n, i, p + 10 + n, a.data_dir, a.out_dir, start_evt, a.send_delay)
             for n, c in topology.items() for i in range(1, c + 1)]
    for nd in nodes:
        nd.start()
    deadline = time.time() + 10
    while not all(c.ready for c in cass) and time.time() < deadline:
        time.sleep(0.05)
    log("MAIN", "network up: %d stars, %d nodes - start sending" % (len(cass), len(nodes)))
    start_evt.set()
    if a.kill_ccs_after is not None:
        threading.Timer(a.kill_ccs_after, main_ccs.fail).start()

    for nd in nodes:                                  # wait until every node finished sending
        nd.sender.join()
    time.sleep(0.7)                                   # let last ACKs / output flush

    log("MAIN", "shutting down: nodes, CAS switches, CCS shadow, CCS main")
    for nd in nodes:
        nd.stop()
    for c in cass:
        c.stop()
    shadow.stop(); main_ccs.stop()
    tot = {k: sum(n.stats[k] for n in nodes) for k in nodes[0].stats}
    log("MAIN", "totals: %s" % tot)


if __name__ == "__main__":
    main()
