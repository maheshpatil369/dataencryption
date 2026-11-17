// C++ side of the C++ <-> Python interoperability test.
// Plays the MASTER end of the Master<->Jetson link with the demo keys.
// stdin commands (one per line):  T <ms> | HB | TX <hexpayload> | RX <hexframe> | REBOOT | QUIT
#define AUV_ALLOW_DEMO_KEYS 1
#include <AUV_Security.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <iostream>

static AUV_RamFlash flash;
static AUV_NonceManager nonce;
static AUV_SecureLink link;
static uint32_t nowMs = 1000;

static void boot() {
    AUV_LinkKeys k; AUV_demoLinkKeys(AUV_ID_MASTER, AUV_ID_JETSON, k);
    if (nonce.begin(flash) == AUV_ERR_NVM_INVALID) nonce.provision(flash, 1);
    link.begin(k, nonce);
    printf("EPOCH %lu\n", (unsigned long)nonce.epoch());
}
static void hexOut(const char *tag, const uint8_t *b, size_t n) {
    printf("%s ", tag); for (size_t i = 0; i < n; i++) printf("%02x", b[i]); printf("\n");
}
static size_t unhex(const std::string &h, uint8_t *out, size_t cap) {
    size_t n = 0; for (size_t i = 0; i + 1 < h.size() && n < cap; i += 2) out[n++] = (uint8_t)std::stoul(h.substr(i, 2), 0, 16);
    return n;
}
int main() {
    boot();
    std::string line;
    while (std::getline(std::cin, line)) {
        uint8_t buf[512], f[AUV_MAX_FRAME]; size_t n;
        if (line.rfind("T ", 0) == 0) { nowMs = (uint32_t)std::stoul(line.substr(2)); printf("OK\n"); }
        else if (line == "HB") { AUV_Status s = link.buildHeartbeat(f, sizeof f, &n); if (s == AUV_OK) hexOut("FRAME", f, n); else printf("ERR %s\n", AUV_statusName(s)); }
        else if (line.rfind("TX ", 0) == 0) {
            size_t pl = unhex(line.substr(3), buf, sizeof buf);
            AUV_Status s = link.buildFrame(AUV_TYPE_TELEMETRY, buf, (uint8_t)pl, f, sizeof f, &n);
            if (s == AUV_OK) hexOut("FRAME", f, n); else printf("ERR %s\n", AUV_statusName(s));
        } else if (line.rfind("RX ", 0) == 0) {
            size_t fl = unhex(line.substr(3), buf, sizeof buf);
            AUV_RxMessage m; int got = 0; AUV_Status last = AUV_OK;
            for (size_t i = 0; i < fl; i++) {
                AUV_Status s = link.rxByte(buf[i], nowMs, m);
                if (s == AUV_MSG_READY) { got++; printf("DELIVERED %02x ", m.type); for (int k = 0; k < m.len; k++) printf("%02x", m.payload[k]); printf("\n"); }
                else if (s != AUV_PENDING && s != AUV_OK) last = s;
            }
            if (!got) printf("NONE %s\n", AUV_statusName(last));
        } else if (line == "REBOOT") { link.end(); boot(); }
        else if (line == "QUIT") break;
        fflush(stdout);
    }
}
