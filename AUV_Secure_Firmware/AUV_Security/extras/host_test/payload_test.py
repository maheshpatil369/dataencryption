#!/usr/bin/env python3
"""Checks Jetson decoders/encoders against the C++ payload layouts, and NodeFreshness."""
import os, subprocess, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "jetson"))
import auv_secure_link as A
out = dict(l.split() for l in subprocess.check_output([os.path.join(os.path.dirname(__file__), "payload_gen")], text=True).splitlines())
ok = fail = 0
def check(c, n):
    global ok, fail
    ok += c; fail += not c
    print("[%s] %s" % ("PASS" if c else "FAIL", n))
s = A.decode_sensor(bytes.fromhex(out["SENSOR"]))
check(s and s["voltage"] == 12.5 and s["power"] == 15.625 and s["leak_mask"] == 5 and s["leak"] == 1, "sensor payload decodes identically")
i = A.decode_imu(bytes.fromhex(out["IMU"]))
check(i and i["quat"][3] == 1.0 and i["accel"][2] == 9.75 and i["mag"][1] == -20.0 and i["connected"] == 1, "IMU payload decodes identically")
t = A.decode_thruster(bytes.fromhex(out["THRUSTER"]))
check(t and t["servo"] == [10, 20, 30, 40] and t["thruster_us"] == 1700 and t["invalid"] == 7, "thruster status decodes identically")
e = A.decode_envelope(bytes.fromhex(out["ENV"]))
check(e and e[0] == A.ID_IMU and e[1] == 5 and e[2] == 77 and len(e[3]) == 57, "envelope: node, epoch, counter, payload")
cmd = A.thruster_command((90, 45, 30, 20), 1500, 1)
check(cmd.hex() == "105a2d1e14dc050100", "thruster command matches C++ layout (target + 8 bytes)")
for bad in (dict(thruster_us=2500), dict(servos=(181, 0, 0, 0)), dict(relay_mask=4)):
    try:
        A.thruster_command(**bad); check(False, "rejects %s" % bad)
    except ValueError:
        check(True, "rejects invalid command %s" % bad)
d = tempfile.mkdtemp(); p = os.path.join(d, "fresh.json")
f = A.NodeFreshness(p)
check(f.accept(0x11, 3, 10, 0.0) and f.accept(0x11, 3, 11, 0.01), "fresh sensor data accepted")
check(not f.accept(0x11, 3, 11, 0.02) and not f.accept(0x11, 3, 5, 0.03), "duplicate / older sensor data rejected")
check(not f.accept(0x11, 2, 999, 0.04), "data from an older sensor boot rejected")
f.accept(0x11, 3, 200, 2.0)
g = A.NodeFreshness(p)            # Jetson restart
check(not g.accept(0x11, 3, 150, 0.0) and g.accept(0x11, 3, 201, 0.0), "after Jetson restart: saved freshness still applies")
print("RESULT: %d passed, %d failed" % (ok, fail)); sys.exit(1 if fail else 0)
