# CSCI/IT 3053 – Project 3: Star of Stars (SoSs) with Bridge and Firewall

1. **Group members:** Anna Zagrai
2. **Git repository:** https://github.com/zag-anna/Networks-project-3.git
(I only pushed the code to the Git once it was errorless)

## Compile / run (Python 3.8+, no third-party packages)
```
make build                 # byte-compiles everything
make run                   # generates data + runs 3 stars x 4 nodes
make run STARS=4 NODES=6   # other sizes (NODES may be 1-16)
make failover              # crashes the main CCS after 1s to show the shadow taking over
make clean
python3 sos.py --stars 3 --nodes 4,3,5 --firewall firewall.txt --data-dir data --out-dir output
```
Options: `--block-outbound` (also stops a "local" node/star sending global traffic), `--send-delay`, `--base-port`, `--kill-ccs-after N`.
Output files appear in `output/nodeX_Youtput.txt` (`2_1: ABCDEFG`). Admin errors go to stderr.

## Files
| File | Purpose |
|---|---|
| `sos.py` | Main class: parses args, builds CCS + shadow, CASs, nodes; waits for senders; clean shutdown |
| `ccs.py` | CCS (global switch): firewall file, global firewalling, bridging by network number, pushes rules to CASs, shadow sync/heartbeat/takeover |
| `cas.py` | CAS (star core switch): learning/flooding switch, local/global decision, local firewall, bridge to CCS with failover to shadow, AC=00/01/10 |
| `node.py` | Node: input file, sent-frame buffer, retransmission, output file, 5% corrupt / 5% drop-ACK |
| `protocol.py` | Frame encode/decode, CRC, sockets wrapper, pending-ACK timers, firewall rules, logging |
| `gen_data.py` | Generates `nodeX_Y.txt` test input |
| `firewall.txt` | Sample firewall rules |
| `Makefile` | Build automation |

## Frame format (binary on the wire)
| Field | Bytes | Range | Meaning |
|---|---|---|---|
| DST | 1 | 1-240 (255 = control) | Destination address |
| SRC | 1 | 1-240 | Source address |
| CRC | 1 | 0-255 | Sum of all frame bytes (CRC byte = 0 during calculation) mod 256 |
| SIZE/ACK | 1 | 0-255 | Data length; 0 = ACK frame (no data) |
| ACK type | 1 | 0-3 | Always present (0 in data frames). 0 = no response, 1 = CRC error, 2 = firewalled, 3 = positive ACK |
| data | SIZE | 1-255 | Payload |

Address of node (x,y) = `(x-1)*16 + y` (x 1-15, y 1-16); star = `(addr-1)//16 + 1`.
**Deviations (documented):** no explicit end-of-frame byte (SIZE delimits the frame); ACK-type codes are the 2-bit values 00,01,10,11 stored as 0..3; `DST=0xFF` frames are switch control frames (`HELLO`, `CAS n`, `RULE ...`, `RULES_DONE`, `SHADOW`, `NET n c`, `PING`) with ASCII payload.

## Design notes
* Stop-and-wait per node; frame stays buffered until positive ACK; max 5 failures then admin error. AC=10 -> discard, no resend; AC=00/01 -> resend.
* Layered time-outs (dest CAS 0.5s < CCS 1.0s < source CAS 1.5s < node 2.5s) so the switch nearest the destination reports AC=00 first.
* "local" rule: global frames *to* that node/star are blocked (CCS and the owning CAS both check). `X_#`/`#_Y`/`X_Y` wildcards supported.
* Shadow CCS: syncs rules + GFT from main, every CAS connects to both, heartbeat 0.3s / timeout 1.5s, CASs fail over automatically.

## Feature checklist
| Feature | Status |
|---|---|
| Compiles/builds without warnings or errors | complete |
| Switch classes (CAS, CCS) | complete |
| Switches read/write frames with threads | complete (per-connection threads; no single global queue) |
| Multiple connections | complete |
| Flood when destination unknown | complete (nodes ignore flooded frames) |
| Learn destinations / no needless forwarding | complete |
| CAS connects to CCS; receives local firewall rules | complete |
| CAS sends AC=00/01/10; forwards traffic and ACKs | complete |
| CCS reads firewall file, global firewalling, passes global traffic, sends AC=00 | complete |
| CCS shadow runs and takes over | complete |
| Nodes: connect, read input, write output, 5% bad frame, 5% dropped ACK, reject traffic | complete |

## Known bugs / limits
* Duplicate delivery is possible if an ACK is delayed beyond a time-out (no sequence numbers in the frame format).
* Frames in flight at the instant of CCS failure are lost and recovered by retransmission.
* Everything runs in one process on localhost (threads + real TCP sockets).
