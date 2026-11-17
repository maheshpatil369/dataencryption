#!/usr/bin/env python3
"""
gen_keys.py - generate the 6 AES-256 link keys of the AUV and one key file
per device.

    python3 gen_keys.py --out keys

    K1 Sensor   -> Master      (Sensor encrypts,   Master decrypts)
    K2 IMU      -> Master      (IMU encrypts,      Master decrypts)
    K3 Thruster -> Master      (Thruster encrypts, Master decrypts)
    K4 Master   -> Thruster    (Master encrypts,   Thruster decrypts)
    K5 Master   -> Jetson      (Master encrypts,   Jetson decrypts)
    K6 Jetson   -> Master      (Jetson encrypts,   Master decrypts)

Creates:
    keys/Sensor/AUV_Keys_Secret.h     K1            (32 B)
    keys/IMU/AUV_Keys_Secret.h        K2            (32 B)
    keys/Thruster/AUV_Keys_Secret.h   K3, K4        (64 B)
    keys/Master/AUV_Keys_Secret.h     K1..K6        (192 B)
    keys/Jetson/jetson_keys.json      K5, K6        (64 B)
    keys/FINGERPRINTS.txt             safe to share; compare with boot messages

Copy each AUV_Keys_Secret.h into the matching sketch folder. NEVER commit or
share these files. Always regenerate ALL keys together.
"""
import argparse, hashlib, json, os, secrets, stat

ID = {"Master": 0x01, "Jetson": 0x02, "Thruster": 0x10, "Sensor": 0x11, "IMU": 0x12}
KEYS = {  # name: (sender, receiver)
    "K1": ("Sensor", "Master"), "K2": ("IMU", "Master"), "K3": ("Thruster", "Master"),
    "K4": ("Master", "Thruster"), "K5": ("Master", "Jetson"), "K6": ("Jetson", "Master"),
}
ZERO = bytes(32)


def fp(key):  # same as AUV_keyFingerprint(): printed with Serial.print(fp, HEX)
    return "%X" % int.from_bytes(hashlib.sha256(b"AUV-KEY-FINGERPRINT-v1" + key).digest()[:4], "little")


def carr(b):
    return ", ".join("0x%02x" % x for x in b)


def struct(name, local, peer, tx, rx, comment):
    return ["/* %s */" % comment,
            "static const AUV_LinkKeys %s = {" % name,
            "    0x%02x, 0x%02x," % (ID[local], ID[peer]),
            "    { %s },  /* txKey */" % carr(tx),
            "    { %s }   /* rxKey */" % carr(rx), "};", ""]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="keys")
    a = ap.parse_args()
    k = {n: secrets.token_bytes(32) for n in KEYS}

    files = {
        "Sensor":   [("AUV_KEYS_SENSOR_MASTER", "Sensor", "Master", k["K1"], ZERO, "K1 encrypt only (fp %s); no rx key" % fp(k["K1"]))],
        "IMU":      [("AUV_KEYS_IMU_MASTER", "IMU", "Master", k["K2"], ZERO, "K2 encrypt only (fp %s); no rx key" % fp(k["K2"]))],
        "Thruster": [("AUV_KEYS_THRUSTER_MASTER", "Thruster", "Master", k["K3"], k["K4"],
                      "tx K3 (fp %s), rx K4 (fp %s)" % (fp(k["K3"]), fp(k["K4"])))],
        "Master":   [("AUV_KEYS_MASTER_SENSOR", "Master", "Sensor", ZERO, k["K1"], "rx K1 only (fp %s)" % fp(k["K1"])),
                     ("AUV_KEYS_MASTER_IMU", "Master", "IMU", ZERO, k["K2"], "rx K2 only (fp %s)" % fp(k["K2"])),
                     ("AUV_KEYS_MASTER_THRUSTER", "Master", "Thruster", k["K4"], k["K3"],
                      "tx K4 (fp %s), rx K3 (fp %s)" % (fp(k["K4"]), fp(k["K3"]))),
                     ("AUV_KEYS_MASTER_JETSON", "Master", "Jetson", k["K5"], k["K6"],
                      "tx K5 (fp %s), rx K6 (fp %s)" % (fp(k["K5"]), fp(k["K6"])))],
    }
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, ".gitignore"), "w") as f:
        f.write("*\n")
    for dev, structs in files.items():
        out = ["/* AUV_Keys_Secret.h for %s - GENERATED, SECRET. Do not commit, do not share. */" % dev,
               "#ifndef AUV_KEYS_SECRET_H", "#define AUV_KEYS_SECRET_H", "#include <AUV_Security.h>", ""]
        for s in structs:
            out += struct(*s)
        out += ["#endif", ""]
        d = os.path.join(a.out, dev)
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, "AUV_Keys_Secret.h")
        with open(p, "w") as f:
            f.write("\n".join(out))
        os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)
    d = os.path.join(a.out, "Jetson")
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, "jetson_keys.json")
    with open(p, "w") as f:
        json.dump({"K5_master_to_jetson": k["K5"].hex(), "K6_jetson_to_master": k["K6"].hex()}, f, indent=1)
    os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)
    lines = ["%s  %-8s -> %-8s  fingerprint %s" % (n, s, r, fp(k[n])) for n, (s, r) in KEYS.items()]
    with open(os.path.join(a.out, "FINGERPRINTS.txt"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    print("\n6 keys = 192 bytes. Files written to", os.path.abspath(a.out))


if __name__ == "__main__":
    main()
