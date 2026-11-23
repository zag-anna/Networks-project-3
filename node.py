"""End node (x, y): reads nodeX_Y.txt, sends stop-and-wait frames with a sent
buffer + retransmission, writes received data to nodeX_Youtput.txt."""
import os
import queue
import random
import threading
import time

from protocol import *


class Node:
    def __init__(self, net, num, cas_port, data_dir, out_dir, start_evt, delay=0.02):
        self.net, self.num, self.addr = net, num, addr(net, num)
        self.cas_port, self.data_dir, self.out_dir = cas_port, data_dir, out_dir
        self.start_evt, self.delay = start_evt, delay
        self.label = "node%d_%d" % (net, num)
        self.acks = queue.Queue()
        self.running = False
        self.stats = dict(sent=0, delivered=0, firewalled=0, retries=0, failed=0, received=0)

    def start(self):
        self.running = True
        self.conn = connect(self.cas_port)
        self.conn.send_frame(Frame(CTRL_DST, self.addr, 0, b"HELLO"))
        os.makedirs(self.out_dir, exist_ok=True)
        self.out = open(os.path.join(self.out_dir, "%soutput.txt" % self.label), "w")
        threading.Thread(target=self._recv_loop, daemon=True).start()
        self.sender = threading.Thread(target=self._send_all, daemon=True)
        self.sender.start()

    def stop(self):
        self.running = False
        self.conn.close()
        self.out.close()

    # ------------------------------------------------------------ receiving
    def _recv_loop(self):
        while self.running:
            r = self.conn.read_frame()
            if r is None:
                break
            f, ok = r
            if f.is_ctrl or f.dst != self.addr:      # ignore flooded frames
                continue
            if f.is_ack:
                self.acks.put(f)
            elif not ok:
                log(self.label, "CRC error in frame from %s -> AC=01" % name(f.src))
                self.conn.send_frame(ack_for(f, ACK_CRC))
            elif random.random() < ERROR_RATE:       # 5%: fail to acknowledge
                log(self.label, "(simulated) dropping frame from %s, no ACK" % name(f.src))
            else:
                self.out.write("%s: %s\n" % (name(f.src), f.data.decode(errors="replace")))
                self.out.flush()
                self.stats["received"] += 1
                self.conn.send_frame(ack_for(f, ACK_OK))

    # -------------------------------------------------------------- sending
    def _send_all(self):
        self.start_evt.wait()
        path = os.path.join(self.data_dir, "%s.txt" % self.label)
        if not os.path.exists(path):
            log(self.label, "no input file %s" % path)
            return
        for line in open(path):
            if ":" not in line:
                continue
            target, text = line.rstrip("\n").split(":", 1)
            x, y = target.strip().split("_")
            text = text[1:] if text.startswith(" ") else text
            payload = text.encode()
            for i in range(0, len(payload), MAX_DATA):       # <=255 bytes per frame
                self._send_reliable(addr(int(x), int(y)), payload[i:i + MAX_DATA])
                time.sleep(self.delay)
        log(self.label, "done sending %s" % self.stats)

    def _send_reliable(self, dst, chunk):
        frame = Frame(dst, self.addr, 0, chunk)      # kept in buffer until ACKed
        fails = 0
        self.stats["sent"] += 1
        while fails < MAX_RETRIES and self.running:
            while not self.acks.empty():             # drop stale ACKs
                self.acks.get_nowait()
            raw = frame.encode()
            if random.random() < ERROR_RATE:         # 5%: erroneous frame
                raw = corrupt(raw)
                log(self.label, "(simulated) corrupting frame to %s" % name(dst))
            self.conn.send(raw)
            ack, deadline = None, time.time() + T_NODE
            while ack is None and time.time() < deadline:
                try:
                    a = self.acks.get(timeout=max(0.01, deadline - time.time()))
                except queue.Empty:
                    break
                if a.src == dst:
                    ack = a
            kind = ack.ack if ack else ACK_TIMEOUT
            if kind == ACK_OK:
                self.stats["delivered"] += 1
                return True
            if kind == ACK_FIREWALL:                 # NACK: no resend
                log(self.label, "frame to %s FIREWALLED, discarded" % name(dst))
                self.stats["firewalled"] += 1
                return False
            fails += 1
            self.stats["retries"] += 1
            log(self.label, "to %s: %s, retry %d/%d" % (name(dst), ACK_NAMES[kind], fails, MAX_RETRIES))
        admin_error("%s: frame to %s dropped after %d failures" % (self.label, name(dst), MAX_RETRIES))
        self.stats["failed"] += 1
        return False
