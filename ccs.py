"""Core switch of the Central Star (CCS) and its shadow.

* Reads the firewall file, enforces it on inter-star traffic and forwards the
  rules to every CAS at start-up.
* Forwards global frames by network number only (Global Firewall Table, GFT).
* The shadow runs the same code with `main_port` set: it syncs rules/GFT from
  the main CCS over a link with heartbeats, stays passive, and takes over when
  that link dies.
"""
import threading
import time

from protocol import *


class CCS:
    def __init__(self, label, port, topology=None, rules_text="", main_port=None):
        self.label, self.port, self.main_port = label, port, main_port
        self.is_shadow = main_port is not None
        self.active = not self.is_shadow
        self.running = False
        self.firewall, self.rule_lines = Firewall(), []
        for line in rules_text.splitlines():
            if self.firewall.add_line(line):
                self.rule_lines.append(line.strip())
        self.gft = {}                       # node address -> star (CAS) number
        for net, n in (topology or {}).items():
            self._add_net(net, n)
        self.cas, self.conns = {}, []       # star number -> Conn ; every open Conn
        self.pending = Pending()

    def _add_net(self, net, count):
        for i in range(1, count + 1):
            self.gft[addr(net, i)] = net

    # ------------------------------------------------------------ lifecycle
    def start(self):
        self.running = True
        self.listener = listen(self.port)
        threading.Thread(target=self._accept, daemon=True).start()
        watch(self.pending, self._timeout, lambda: self.running)
        if self.is_shadow:
            threading.Thread(target=self._follow_main, daemon=True).start()
        log(self.label, "up on port %d (%s)" % (self.port, "SHADOW/standby" if self.is_shadow else "ACTIVE"))

    def stop(self):
        self.running = False
        try:
            self.listener.close()
        except OSError:
            pass
        for c in list(self.conns):
            c.close()

    def fail(self):
        """Simulate a crash (power / link failure)."""
        log(self.label, "!!! SIMULATED FAILURE - going dark")
        self.stop()

    def _accept(self):
        import socket
        while self.running:
            try:
                s, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            c = Conn(s)
            self.conns.append(c)
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, conn):
        while self.running:
            r = conn.read_frame()
            if r is None:
                break
            self._handle(r[0], r[1], conn)
        for net, c in list(self.cas.items()):
            if c is conn:
                del self.cas[net]

    # ------------------------------------------------------------- handlers
    def _handle(self, f, ok, conn):
        if f.is_ctrl:
            self._control(f.data.decode(), conn)
            return
        if not self.active:                 # standby shadow never forwards
            return
        if f.is_ack:                        # pass ACK back as is
            self.pending.clear((f.dst, f.src))
            self._send_cas(split_addr(f.dst)[0], f)
            return
        if not ok:
            self._reply(f, ACK_CRC)
            return
        dnet = self.gft.get(f.dst)
        if dnet is None or self.firewall.blocks(f.dst):
            log(self.label, "FIREWALL blocked %s -> %s" % (name(f.src), name(f.dst)))
            self._reply(f, ACK_FIREWALL)
            return
        if self._send_cas(dnet, f):
            self.pending.add((f.src, f.dst), T_CCS)
        else:
            self._reply(f, ACK_TIMEOUT)

    def _control(self, text, conn):
        if text.startswith("CAS "):
            net = int(text.split()[1])
            self.cas[net] = conn
            log(self.label, "CAS %d registered" % net)
            if not self.is_shadow:          # push local firewall rules to the CAS
                for line in self.rule_lines:
                    conn.send_frame(ctrl_frame("RULE " + line))
                conn.send_frame(ctrl_frame("RULES_DONE"))
        elif text == "SHADOW" and not self.is_shadow:
            log(self.label, "shadow attached, syncing state")
            threading.Thread(target=self._sync_to, args=(conn,), daemon=True).start()

    def _reply(self, f, kind):
        self._send_cas(split_addr(f.src)[0], ack_for(f, kind))

    def _send_cas(self, net, f):
        c = self.cas.get(net)
        return bool(c and c.alive and c.send_frame(f))

    def _timeout(self, key):
        src, dst = key
        log(self.label, "no ACK for %s -> %s, sending AC=00" % (name(src), name(dst)))
        self._send_cas(split_addr(src)[0], Frame(src, dst, ACK_TIMEOUT))

    # ------------------------------------------------------- shadow syncing
    def _sync_to(self, conn):                # runs on the MAIN CCS
        for line in self.rule_lines:
            conn.send_frame(ctrl_frame("RULE " + line))
        for net in sorted(set(self.gft.values())):
            cnt = sum(1 for v in self.gft.values() if v == net)
            conn.send_frame(ctrl_frame("NET %d %d" % (net, cnt)))
        ok = conn.send_frame(ctrl_frame("SYNC_DONE"))
        while self.running and ok:           # heartbeat
            time.sleep(0.3)
            ok = conn.send_frame(ctrl_frame("PING"))

    def _follow_main(self):                  # runs on the SHADOW CCS
        link = connect(self.main_port)
        if link is None:
            return
        self.conns.append(link)
        link.send_frame(ctrl_frame("SHADOW"))
        link.sock.settimeout(1.5)            # heartbeat time-out
        while self.running:
            r = link.read_frame()
            if r is None:
                break
            t = r[0].data.decode()
            if t.startswith("RULE "):
                if self.firewall.add_line(t[5:]):
                    self.rule_lines.append(t[5:])
            elif t.startswith("NET "):
                _, n, c = t.split()
                self._add_net(int(n), int(c))
        if self.running:
            self.active = True
            log(self.label, "main CCS lost -> SHADOW TAKES OVER (rules=%d, nodes=%d)"
                % (len(self.rule_lines), len(self.gft)))
