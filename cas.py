"""Core switch of an Arm-end Star (CAS): local switching + bridge to the CCS.

* Learns node ports from source addresses (HELLO + every frame), floods when a
  destination port is unknown.
* Local = destination is in the preloaded local forwarding table; otherwise the
  frame is bridged to the CCS (main, or the shadow if the main is dead).
* Enforces the firewall rules received from the CCS at start-up.
* Sends AC=00 / 01 / 10 back as described in the flowchart.
"""
import socket
import threading
import time

from protocol import *


class CAS:
    def __init__(self, net, node_count, port, ccs_ports, block_outbound=False):
        self.net, self.port, self.ccs_ports = net, port, ccs_ports
        self.local = {addr(net, i) for i in range(1, node_count + 1)}   # forwarding table
        self.ports = {}                      # learned: node address -> Conn
        self.firewall = Firewall()
        self.block_outbound = block_outbound
        self.rules_ready = threading.Event()
        self.ccs = [None, None]              # [main, shadow]
        self.pending = Pending()
        self.running = False
        self.label = "CAS%d" % net

    @property
    def ready(self):
        return self.rules_ready.is_set() and len(self.ports) >= len(self.local)

    def start(self):
        self.running = True
        self.listener = listen(self.port)
        threading.Thread(target=self._accept, daemon=True).start()
        for i, p in enumerate(self.ccs_ports):
            c = connect(p)
            self.ccs[i] = c
            if c:
                c.send_frame(ctrl_frame("CAS %d" % self.net))
                threading.Thread(target=self._from_ccs_loop, args=(c, i), daemon=True).start()
        watch(self.pending, self._timeout, lambda: self.running)

    def stop(self):
        self.running = False
        try:
            self.listener.close()
        except OSError:
            pass
        for c in self.ccs + list(self.ports.values()):
            if c:
                c.close()

    # ------------------------------------------------------------ plumbing
    def _accept(self):
        while self.running:
            try:
                s, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._node_loop, args=(Conn(s),), daemon=True).start()

    def _send_ccs(self, f):
        """Main CCS preferred; transparently fail over to the shadow."""
        for i in (0, 1):
            c = self.ccs[i]
            if c and c.alive and c.send_frame(f):
                if i == 1 and not getattr(self, "_failed_over", False):
                    self._failed_over = True
                    log(self.label, "main CCS unreachable -> using SHADOW CCS")
                return True
        return False

    def _to_node(self, f):
        c = self.ports.get(f.dst)
        if c and c.alive:
            c.send_frame(f)
        else:                                # unknown port -> flood
            log(self.label, "flooding frame for %s" % name(f.dst))
            for conn in set(self.ports.values()):
                conn.send_frame(f)

    def _route_ack(self, a):
        if a.dst in self.local:
            self._to_node(a)
        elif not self._send_ccs(a):
            pass                             # nothing reachable; sender's own timer recovers

    def _timeout(self, key):
        src, dst = key
        log(self.label, "no ACK for %s -> %s, sending AC=00" % (name(src), name(dst)))
        self._route_ack(Frame(src, dst, ACK_TIMEOUT))

    # -------------------------------------------------- frames from nodes
    def _node_loop(self, conn):
        while self.running:
            r = conn.read_frame()
            if r is None:
                break
            self._from_node(r[0], r[1], conn)
        for a, c in list(self.ports.items()):
            if c is conn:
                del self.ports[a]

    def _from_node(self, f, ok, conn):
        if f.is_ctrl:
            if f.data == b"HELLO":
                self.ports[f.src] = conn
            return
        self.ports[f.src] = conn             # source address learning
        if f.is_ack:
            if ok:
                self.pending.clear((f.dst, f.src))
                self._route_ack(f)
            return
        if not ok:
            log(self.label, "CRC error from %s, sending AC=01" % name(f.src))
            self._route_ack(ack_for(f, ACK_CRC))
            return
        if f.dst in self.local:              # local traffic (always allowed)
            self._to_node(f)
            self.pending.add((f.src, f.dst), T_CAS_DST)
        else:                                # global traffic -> bridge to CCS
            if self.block_outbound and self.firewall.blocks(f.src):
                log(self.label, "FIREWALL blocked outbound %s" % name(f.src))
                self._route_ack(ack_for(f, ACK_FIREWALL))
            elif self._send_ccs(f):
                self.pending.add((f.src, f.dst), T_CAS_SRC)
            else:
                self._route_ack(ack_for(f, ACK_TIMEOUT))

    # --------------------------------------------------- frames from CCS
    def _from_ccs_loop(self, conn, idx):
        while self.running:
            r = conn.read_frame()
            if r is None:
                break
            self._from_ccs(r[0], r[1])

    def _from_ccs(self, f, ok):
        if f.is_ctrl:
            t = f.data.decode()
            if t.startswith("RULE "):
                self.firewall.add_line(t[5:])
            elif t == "RULES_DONE":
                log(self.label, "received %d firewall rule(s) from CCS" % len(self.firewall.rules))
                self.rules_ready.set()
            return
        if f.is_ack:                         # ACK for a frame one of our nodes sent
            self.pending.clear((f.dst, f.src))
            self._route_ack(f)
            return
        if f.dst not in self.local or self.firewall.blocks(f.dst):
            log(self.label, "LOCAL FIREWALL blocked %s -> %s" % (name(f.src), name(f.dst)))
            self._send_ccs(ack_for(f, ACK_FIREWALL))
        elif not ok:
            self._send_ccs(ack_for(f, ACK_CRC))
        else:
            self._to_node(f)
            self.pending.add((f.src, f.dst), T_CAS_DST)
