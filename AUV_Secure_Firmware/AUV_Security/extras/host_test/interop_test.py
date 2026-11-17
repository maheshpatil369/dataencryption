#!/usr/bin/env python3
"""C++ (STM32 library, built for host) <-> Python (Jetson) interoperability test. Run: make check CRYPTO=<path to arduinolibs>"""
import hashlib, os, subprocess, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "jetson"))
import auv_secure_link as A

def demo_key(src, dst):
    return hashlib.sha256(b"AUV-DEMO-KEY-NOT-SECRET-v1" + bytes([src, dst])).digest()

peer = subprocess.Popen([os.path.join(os.path.dirname(__file__), "interop_peer")],
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
def cmd(c):
    peer.stdin.write(c + "\n"); peer.stdin.flush()
    return peer.stdout.readline().strip()

passed = failed = 0
def check(ok, name, exp):
    global passed, failed
    passed += ok; failed += (not ok)
    print("[%s] %s  (expected: %s)" % ("PASS" if ok else "FAIL", name, exp))

peer.stdout.readline()  # EPOCH line
jet = A.SecureLink(A.ID_JETSON, A.ID_MASTER, demo_key(A.ID_JETSON, A.ID_MASTER),
                   demo_key(A.ID_MASTER, A.ID_JETSON), my_epoch=77)
t = 1.0
# handshake: Jetson HB -> C++, C++ HB -> Python, Python HB -> C++
r = cmd("RX " + jet.build_frame(A.TYPE_HEARTBEAT).hex())
check(r.startswith("NONE STALE_ECHO"), "C++ learns Jetson epoch from first heartbeat", "STALE_ECHO (not delivered)")
fr = bytes.fromhex(cmd("HB").split()[1])
got = jet.feed(fr, t)
check(len(got) == 1 and got[0][0] == A.TYPE_HEARTBEAT, "Python accepts C++ heartbeat echoing epoch 77", "delivered")
r = cmd("RX " + jet.build_frame(A.TYPE_HEARTBEAT).hex())
check(r.startswith("DELIVERED 01"), "C++ accepts Python heartbeat after handshake", "DELIVERED")

ok_up = ok_down = 0
for i in range(1000):
    t += 0.01
    cmd("T %d" % int(t * 1000))
    payload = bytes([0x10]) + bytes((i + k) & 0xFF for k in range(i % 60))
    fr = bytes.fromhex(cmd("TX " + payload.hex()).split()[1])
    got = jet.feed(fr, t)
    ok_up += len(got) == 1 and got[0][1] == payload
    pl = bytes([0x10]) + bytes([i & 0xFF]) * 8
    r = cmd("RX " + jet.build_frame(A.TYPE_COMMAND, pl).hex())
    ok_down += r == "DELIVERED 20 " + pl.hex()
check(ok_up == 1000, "1000 C++ -> Python frames, payload 1..60 B", "1000 delivered, identical")
check(ok_down == 1000, "1000 Python -> C++ command frames", "1000 delivered, identical")

fr = bytearray.fromhex(cmd("TX 1011223344").split()[1]); fr[20] ^= 1
check(jet.feed(bytes(fr), t) == [] and jet.stats["auth_fail"] == 1, "Python rejects tampered C++ frame", "auth_fail")
good = jet.build_frame(A.TYPE_COMMAND, b"\x10\x01")
bad = bytearray(good); bad[-1] ^= 0x80
check(cmd("RX " + bad.hex()) == "NONE AUTH_FAILED", "C++ rejects tampered Python frame", "AUTH_FAILED")
check(cmd("RX " + good.hex()).startswith("DELIVERED"), "untampered original still accepted", "DELIVERED")
check(cmd("RX " + good.hex()) == "NONE REPLAY", "C++ rejects Python replay", "REPLAY")
fr = bytes.fromhex(cmd("TX 10aa").split()[1])
jet.feed(fr, t); check(jet.feed(fr, t) == [] and jet.stats["replay"] >= 1, "Python rejects C++ replay", "replay")

# C++ (master) reboots: old captured C++ frame must be refused by Python
old = bytes.fromhex(cmd("TX 10bb").split()[1])
cmd("REBOOT")  # prints EPOCH (consumed by cmd())
r = cmd("RX " + jet.build_frame(A.TYPE_HEARTBEAT).hex())          # C++ learns jetson epoch again
fr = bytes.fromhex(cmd("HB").split()[1]); jet.feed(fr, t)           # python learns new C++ epoch
check(jet.feed(old, t) == [] and jet.stats["old_epoch"] >= 1, "Python rejects frame from C++'s previous boot", "old_epoch")
# Python (Jetson) reboots with new epoch: old Jetson commands must not be delivered by C++
captured = jet.build_frame(A.TYPE_COMMAND, b"\x10\x99")
jet2 = A.SecureLink(A.ID_JETSON, A.ID_MASTER, demo_key(A.ID_JETSON, A.ID_MASTER),
                    demo_key(A.ID_MASTER, A.ID_JETSON), my_epoch=78)
cmd("RX " + jet2.build_frame(A.TYPE_HEARTBEAT).hex())
check(cmd("RX " + captured.hex()) == "NONE OLD_EPOCH", "C++ rejects command captured before Jetson reboot", "OLD_EPOCH")

# epoch store
import tempfile
d = tempfile.mkdtemp()
st = A.EpochStore(os.path.join(d, "ep"))
try:
    st.next_epoch(); check(False, "Python epoch store refuses empty store", "SecurityError")
except A.SecurityError:
    check(True, "Python epoch store refuses empty store", "SecurityError")
e1 = st.next_epoch(allow_provision=True); e2 = st.next_epoch(); e3 = st.next_epoch()
check((e1, e2, e3) == (1, 2, 3), "Python epoch store +1 per start", "1,2,3")
open(st.paths[0], "wb").write(b"garbage"); e4 = st.next_epoch()
check(e4 > e3, "one epoch file corrupted after use", "next epoch > %d (got %d)" % (e3, e4))

cmd("QUIT")
print("RESULT: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
