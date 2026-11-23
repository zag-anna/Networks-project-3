"""Shared pieces of the Star-of-Stars (SoSs) protocol.

Wire format (binary, NOT serialized objects) -- see README for the full spec:
    [DST:1][SRC:1][CRC:1][SIZE/ACK:1][ACK type:1][data: SIZE bytes]
"""
import random
import socket
import sys
import threading
import time

HOST = "127.0.0.1"

# ACK types (value of the "ACK type" byte; the 2-bit codes 00,01,10,11)
ACK_TIMEOUT, ACK_CRC, ACK_FIREWALL, ACK_OK = 0, 1, 2, 3
ACK_NAMES = {0: "NO-RESPONSE(00)", 1: "CRC-ERROR(01)", 2: "FIREWALLED(10)", 3: "ACK(11)"}

CTRL_DST = 0xFF        # reserved destination: switch-to-switch / hello control frames
HEADER_LEN = 5
MAX_DATA = 255
NODES_PER_NET = 16     # address = (net-1)*16 + node  (net 1..15, node 1..16 -> 1..240)

# Layered time-outs (seconds). The hop closest to the destination fires first,
# so the nearest switch reports AC=00 upstream before the sender gives up.
T_CAS_DST = 0.5        # dest CAS waiting for the destination node's ACK
T_CCS = 1.0            # CCS waiting for the destination CAS's ACK
T_CAS_SRC = 1.5        # source CAS waiting for the CCS's ACK
T_NODE = 2.5           # source node last-resort time-out
MAX_RETRIES = 5
ERROR_RATE = 0.05      # 5% corrupt frames / 5% dropped ACKs at nodes

_log_lock = threading.Lock()


def log(who, msg):
    with _log_lock:
        print("[%s] %-9s %s" % (time.strftime("%H:%M:%S"), who, msg), flush=True)


def admin_error(msg):
    with _log_lock:
        print("*** ADMIN ERROR: %s" % msg, file=sys.stderr, flush=True)


# ---------------------------------------------------------------- addressing
def addr(net, node):
    return (net - 1) * NODES_PER_NET + node


def split_addr(a):
    return (a - 1) // NODES_PER_NET + 1, (a - 1) % NODES_PER_NET + 1


def name(a):
    if a == CTRL_DST:
        return "ctrl"
    if a == 0:
        return "switch"
    n, y = split_addr(a)
    return "%d_%d" % (n, y)


# -------------------------------------------------------------------- frames
class Frame:
    """One frame. `raw` keeps the original bytes so switches forward frames
    untouched ("pass as is"), including any injected corruption."""

    def __init__(self, dst, src, ack=0, data=b"", raw=None):
        assert len(data) <= MAX_DATA
        self.dst, self.src, self.ack, self.data, self.raw = dst, src, ack, data, raw

    @property
    def is_ctrl(self):
        return self.dst == CTRL_DST

    @property
    def is_ack(self):          # SIZE == 0  -> ACK frame
        return len(self.data) == 0 and not self.is_ctrl

    def encode(self):
        if self.raw is not None:
            return self.raw
        b = bytearray([self.dst, self.src, 0, len(self.data), self.ack]) + self.data
        b[2] = sum(b) & 0xFF   # CRC computed with CRC byte = 0
        return bytes(b)


def ctrl_frame(text):
    return Frame(CTRL_DST, 0, 0, text.encode())


def ack_for(frame, kind):
    """ACK/NACK travelling back to the sender of `frame`."""
    return Frame(frame.src, frame.dst, kind)


def corrupt(raw):
    """Flip one bit in the data area (a single-bit flip always breaks the sum)."""
    b = bytearray(raw)
    b[random.randrange(HEADER_LEN, len(b))] ^= 1 << random.randrange(8)
    return bytes(b)


# --------------------------------------------------------------- connections
class Conn:
    """Socket wrapper: thread-safe sends, exact reads, frame parsing."""

    def __init__(self, sock):
        sock.settimeout(None)
        self.sock, self.alive, self.lock = sock, True, threading.Lock()

    def send(self, data):
        try:
            with self.lock:
                self.sock.sendall(data)
            return True
        except OSError:
            self.alive = False
            return False

    def send_frame(self, f):
        return self.send(f.encode())

    def recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            try:
                chunk = self.sock.recv(n - len(buf))
            except OSError:
                chunk = b""
            if not chunk:
                self.alive = False
                return None
            buf += chunk
        return buf

    def read_frame(self):
        """Returns (Frame, crc_ok) or None when the link is closed."""
        hdr = self.recv_exact(HEADER_LEN)
        if hdr is None:
            return None
        body = self.recv_exact(hdr[3]) if hdr[3] else b""
        if body is None:
            return None
        raw = hdr + body
        crc_ok = ((sum(raw) - raw[2]) & 0xFF) == raw[2]
        return Frame(hdr[0], hdr[1], hdr[4], body, raw), crc_ok

    def close(self):
        self.alive = False
        for fn in (lambda: self.sock.shutdown(socket.SHUT_RDWR), self.sock.close):
            try:
                fn()
            except OSError:
                pass


def connect(port, tries=100, delay=0.1):
    for _ in range(tries):
        try:
            return Conn(socket.create_connection((HOST, port), timeout=2))
        except OSError:
            time.sleep(delay)
    return None


def listen(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, port))
    s.listen(64)
    s.settimeout(0.2)
    return s


# ------------------------------------------------------------------ pending
class Pending:
    """Frames forwarded downstream that still await an ACK. key=(src,dst)."""

    def __init__(self):
        self.d, self.lock = {}, threading.Lock()

    def add(self, key, ttl):
        with self.lock:
            self.d[key] = time.time() + ttl

    def clear(self, key):
        with self.lock:
            self.d.pop(key, None)

    def expired(self):
        now = time.time()
        with self.lock:
            dead = [k for k, t in self.d.items() if t < now]
            for k in dead:
                del self.d[k]
        return dead


def watch(pending, callback, running):
    def loop():
        while running():
            for k in pending.expired():
                callback(k)
            time.sleep(0.05)
    threading.Thread(target=loop, daemon=True).start()


# ----------------------------------------------------------------- firewall
class Firewall:
    """Rules such as `3_5: local` or `2_#: local` ('#', 'X' or '*' = wildcard).
    A 'local' rule means: only local traffic is accepted, so GLOBAL frames
    destined to the matching node / star are blocked."""

    def __init__(self):
        self.rules = []

    @staticmethod
    def parse(line):
        line = line.strip()
        if ":" not in line or line.startswith("//"):
            return None
        left, right = line.split(":", 1)
        if right.strip().lower() != "local" or "_" not in left:
            return None
        conv = lambda s: None if s.strip() in ("#", "X", "x", "*") else int(s)
        n, y = left.split("_")
        return conv(n), conv(y)

    def add_line(self, line):
        r = self.parse(line)
        if r:
            self.rules.append(r)
        return r

    def blocks(self, a):
        n, y = split_addr(a)
        return any((rn is None or rn == n) and (ry is None or ry == y) for rn, ry in self.rules)
