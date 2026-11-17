/*
 * AUV_TestSuite.h
 * ---------------------------------------------------------------------------
 * Complete test-suite for the AUV_Security library.
 * The SAME file runs on the STM32 (AUV_SelfTest.ino) and on a PC (host_test),
 * so results are directly comparable.
 *
 * Every test prints:  [PASS|FAIL] Tnn.x description  (expected: ...)
 * and the final line: RESULT: <passed> passed, <failed> failed
 *
 * The platform supplies two functions through AUV_runAllTests():
 *     print(const char *line)   and   micros32()  (time base for benchmarks)
 * ---------------------------------------------------------------------------
 */
#ifndef AUV_TEST_SUITE_H
#define AUV_TEST_SUITE_H

#include <stdio.h>
#include <AUV_Security.h>

typedef void (*AUV_PrintFn)(const char *);
typedef uint32_t (*AUV_MicrosFn)(void);

namespace auvtest {

static AUV_PrintFn  g_print = 0;
static AUV_MicrosFn g_micros = 0;
static uint32_t g_pass = 0, g_fail = 0;
static char g_line[160];

static void out(const char *s) { if (g_print) g_print(s); }

static char g_outBuf[240];
static void check(bool ok, const char *id, const char *desc, const char *expected) {
    if (ok) g_pass++; else g_fail++;
    snprintf(g_outBuf, sizeof(g_outBuf), "[%s] %s %s  (expected: %s)", ok ? "PASS" : "FAIL", id, desc, expected);
    out(g_outBuf);
}

static void section(const char *name) {
    snprintf(g_line, sizeof(g_line), "---- %s ----", name);
    out(g_line);
}

/* deterministic PRNG for fuzzing (not for crypto) */
static uint32_t g_rng = 0x12345678;
static uint32_t rnd() { g_rng ^= g_rng << 13; g_rng ^= g_rng >> 17; g_rng ^= g_rng << 5; return g_rng; }

/* -------------------------- simulated device ---------------------------- */
struct Dev {
    AUV_RamFlash     flash;
    AUV_NonceManager nonce;
    AUV_SecureLink   link;
    AUV_LinkKeys     keys;
};

/* A small pool reused by every test keeps RAM use inside a Blue Pill (20 KB). */
static Dev g_dev[4];
static Dev &fresh(int i) {
    Dev &d = g_dev[i];
    d.link.end();
    d.flash.wipe();
    d.flash.failProgramAfter = -1;
    d.flash.failEraseHalfway = false;
    return d;
}

static AUV_Status bootDev(Dev &d, uint8_t local, uint8_t peer, bool provisionIfBlank = true) {
    AUV_demoLinkKeys(local, peer, d.keys);
    AUV_Status s = d.nonce.begin(d.flash);
    if (s == AUV_ERR_NVM_INVALID && provisionIfBlank) s = d.nonce.provision(d.flash, 1);
    if (s != AUV_OK) return s;
    return d.link.begin(d.keys, d.nonce);
}

/* feed a frame byte by byte; returns number of delivered messages */
static int feed(AUV_SecureLink &rx, const uint8_t *f, size_t n, uint32_t now,
                AUV_RxMessage &m, AUV_Status *lastErr = 0) {
    int delivered = 0;
    AUV_Status le = AUV_OK;
    for (size_t i = 0; i < n; i++) {
        AUV_Status s = rx.rxByte(f[i], now, m);
        if (s == AUV_MSG_READY) delivered++;
        else if (s != AUV_PENDING && s != AUV_OK) le = s;
    }
    if (lastErr) *lastErr = le;
    return delivered;
}

/* Run the 3-frame handshake so both sides know each other's epoch. */
static bool handshake(Dev &a, Dev &b, uint32_t now) {
    uint8_t f[AUV_MAX_FRAME]; size_t n; AUV_RxMessage m;
    if (a.link.buildHeartbeat(f, sizeof f, &n) != AUV_OK) return false;
    feed(b.link, f, n, now, m);                     /* b learns a's epoch */
    if (b.link.buildHeartbeat(f, sizeof f, &n) != AUV_OK) return false;
    int d1 = feed(a.link, f, n, now, m);            /* a: echo ok -> delivered */
    if (a.link.buildHeartbeat(f, sizeof f, &n) != AUV_OK) return false;
    int d2 = feed(b.link, f, n, now, m);
    return d1 == 1 && d2 == 1;
}

static bool hexEq(const uint8_t *a, const uint8_t *b, size_t n) { return memcmp(a, b, n) == 0; }

/* ============================ T00: KAT ================================== */
static void testKnownAnswer() {
    section("T00 Known-answer tests (NIST GCM spec, AES-256)");
    static AUV_Encryptor e; static AUV_Decryptor d;
    static const uint8_t K0[32] = {0};
    static const uint8_t IV0[12] = {0};
    uint8_t tag[16], ct[64], pt[64];

    /* Test case 13: K=0, IV=0, P=empty */
    static const uint8_t T13[16] = {0x53,0x0f,0x8a,0xfb,0xc7,0x45,0x36,0xb9,0xa9,0x63,0xb4,0xf1,0xc4,0xcb,0x73,0x8b};
    e.katEncrypt(K0, IV0, 12, 0, 0, 0, 0, ct, tag);
    check(hexEq(tag, T13, 16), "T00.1", "GCM-AES256 TC13 tag", "530f8afb...cb738b");

    /* Test case 14: K=0, IV=0, P=16 zero bytes */
    static const uint8_t C14[16] = {0xce,0xa7,0x40,0x3d,0x4d,0x60,0x6b,0x6e,0x07,0x4e,0xc5,0xd3,0xba,0xf3,0x9d,0x18};
    static const uint8_t T14[16] = {0xd0,0xd1,0xc8,0xa7,0x99,0x99,0x6b,0xf0,0x26,0x5b,0x98,0xb5,0xd4,0x8a,0xb9,0x19};
    static const uint8_t Z16[16] = {0};
    e.katEncrypt(K0, IV0, 12, 0, 0, Z16, 16, ct, tag);
    check(hexEq(ct, C14, 16) && hexEq(tag, T14, 16), "T00.2", "GCM-AES256 TC14 ciphertext+tag", "cea7403d.. / d0d1c8a7..");

    static const uint8_t K15[32] = {0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08,
                                    0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08};
    static const uint8_t IV15[12] = {0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,0xde,0xca,0xf8,0x88};
    static const uint8_t P15[64] = {
        0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,
        0x86,0xa7,0xa9,0x53,0x15,0x34,0xf7,0xda,0x2e,0x4c,0x30,0x3d,0x8a,0x31,0x8a,0x72,
        0x1c,0x3c,0x0c,0x95,0x95,0x68,0x09,0x53,0x2f,0xcf,0x0e,0x24,0x49,0xa6,0xb5,0x25,
        0xb1,0x6a,0xed,0xf5,0xaa,0x0d,0xe6,0x57,0xba,0x63,0x7b,0x39,0x1a,0xaf,0xd2,0x55};
    static const uint8_t C15[64] = {
        0x52,0x2d,0xc1,0xf0,0x99,0x56,0x7d,0x07,0xf4,0x7f,0x37,0xa3,0x2a,0x84,0x42,0x7d,
        0x64,0x3a,0x8c,0xdc,0xbf,0xe5,0xc0,0xc9,0x75,0x98,0xa2,0xbd,0x25,0x55,0xd1,0xaa,
        0x8c,0xb0,0x8e,0x48,0x59,0x0d,0xbb,0x3d,0xa7,0xb0,0x8b,0x10,0x56,0x82,0x88,0x38,
        0xc5,0xf6,0x1e,0x63,0x93,0xba,0x7a,0x0a,0xbc,0xc9,0xf6,0x62,0x89,0x80,0x15,0xad};
    static const uint8_t T15[16] = {0xb0,0x94,0xda,0xc5,0xd9,0x34,0x71,0xbd,0xec,0x1a,0x50,0x22,0x70,0xe3,0xcc,0x6c};
    e.katEncrypt(K15, IV15, 12, 0, 0, P15, 64, ct, tag);
    check(hexEq(ct, C15, 64) && hexEq(tag, T15, 16), "T00.3", "GCM-AES256 TC15 (64 B, no AAD)", "522dc1f0.. / b094dac5..");

    /* Test case 16: same key/IV, 60-byte P, 20-byte AAD */
    static const uint8_t A16[20] = {0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,0xab,0xad,0xda,0xd2};
    static const uint8_t T16[16] = {0x76,0xfc,0x6e,0xce,0x0f,0x4e,0x17,0x68,0xcd,0xdf,0x88,0x53,0xbb,0x2d,0x55,0x1b};
    e.katEncrypt(K15, IV15, 12, A16, 20, P15, 60, ct, tag);
    check(hexEq(ct, C15, 60) && hexEq(tag, T16, 16), "T00.4", "GCM-AES256 TC16 (60 B + 20 B AAD)", "522dc1f0.. / 76fc6ece..");

    bool ok = d.katDecrypt(K15, IV15, 12, A16, 20, C15, 60, T16, pt);
    check(ok && hexEq(pt, P15, 60), "T00.5", "TC16 decrypt + verify", "tag OK, plaintext = P");
    uint8_t badTag[16]; memcpy(badTag, T16, 16); badTag[15] ^= 1;
    ok = d.katDecrypt(K15, IV15, 12, A16, 20, C15, 60, badTag, pt);
    check(!ok, "T00.6", "TC16 with 1-bit tag error", "rejected");

    /* Protocol-level vector generated independently with Python
     * 'cryptography' (AESGCM): checks header/AAD/nonce layout. */
    static const uint8_t PK[32] = {0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,
                                   0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f};
    static const uint8_t PF[43] = {0xa5,0x5a,0x01,0x20,0x01,0x10,0x08,0x07,0x00,0x00,0x00,0x2a,0x00,0x00,0x00,0x03,
        0x00,0x00,0x00,0x3a,0xe1,0x1f,0x62,0x99,0xe4,0x1f,0xd4,0x87,0xd1,0x60,0x4b,0xff,0xcc,0xbc,0xba,0x0e,
        0x70,0x82,0x05,0x7c,0x5a,0x05,0xd3};
    AUV_Header h; h.version = 1; h.type = AUV_TYPE_COMMAND; h.src = 0x01; h.dst = 0x10; h.len = 8;
    h.epoch = 7; h.counter = 42; h.echo = 3;
    uint8_t cmd[8] = {90, 45, 30, 20, 0xDC, 0x05, 1, 0}; /* 1500 us LE */
    uint8_t frame[AUV_MAX_FRAME]; size_t n = 0;
    static AUV_Encryptor pe; pe.begin(PK);
    AUV_Status s = pe.seal(h, cmd, frame, sizeof frame, &n);
    check(s == AUV_OK && n == 43 && hexEq(frame, PF, 43), "T00.7", "protocol frame matches Python reference", "43 identical bytes");
    static AUV_Decryptor pd; pd.begin(PK);
    AUV_Header h2; AUV_decodeHeader(PF, h2);
    uint8_t out[AUV_MAX_PAYLOAD];
    s = pd.open(PF, 43, h2, out);
    check(s == AUV_OK && hexEq(out, cmd, 8), "T00.8", "Python-made frame decrypts in C++", "OK, payload = command");
}

/* ===================== T01: successful round trip ======================= */
static void testRoundTrip() {
    section("T01 Successful encryption and decryption");
    Dev &m = fresh(0); Dev &t = fresh(1);
    uint32_t now = 1000;
    bool ok = bootDev(m, AUV_ID_MASTER, AUV_ID_THRUSTER) == AUV_OK &&
              bootDev(t, AUV_ID_THRUSTER, AUV_ID_MASTER) == AUV_OK;
    check(ok, "T01.1", "both devices boot, provision and start link", "AUV_OK");
    check(handshake(m, t, now), "T01.2", "epoch handshake completes in 3 frames", "both sides deliver");

    uint8_t f[AUV_MAX_FRAME]; size_t n; AUV_RxMessage msg;
    for (uint8_t len = 0; len <= AUV_MAX_PAYLOAD; len += 8) {
        uint8_t p[AUV_MAX_PAYLOAD];
        for (uint8_t i = 0; i < len; i++) p[i] = (uint8_t)(i * 7 + len);
        m.link.buildFrame(AUV_TYPE_TELEMETRY, p, len, f, sizeof f, &n);
        bool notPlain = len < 4 || memcmp(f + AUV_HEADER_SIZE, p, len) != 0;
        int d = feed(t.link, f, n, now, msg);
        bool good = d == 1 && msg.len == len && memcmp(msg.payload, p, len) == 0 && notPlain &&
                    n == (size_t)AUV_OVERHEAD + len;
        snprintf(g_line, sizeof g_line, "round trip, payload %u bytes (frame %u)", len, (unsigned)(AUV_OVERHEAD + len));
        check(good, "T01.3", g_line, "delivered, identical, ciphertext != plaintext");
    }
    /* same plaintext twice -> different ciphertext (fresh nonce) */
    uint8_t p[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t f2[AUV_MAX_FRAME]; size_t n2;
    m.link.buildFrame(AUV_TYPE_TELEMETRY, p, 16, f, sizeof f, &n);
    m.link.buildFrame(AUV_TYPE_TELEMETRY, p, 16, f2, sizeof f2, &n2);
    check(memcmp(f + AUV_HEADER_SIZE, f2 + AUV_HEADER_SIZE, 16 + 16) != 0, "T01.4",
          "same plaintext twice gives different ciphertext+tag", "different");
    check(m.link.linkUp(now) && t.link.linkUp(now), "T01.5", "linkUp() true on both ends", "true");
}

/* ======================= T02: incorrect key ============================= */
static void testWrongKey() {
    section("T02 Incorrect key");
    Dev &m = fresh(0); Dev &t = fresh(1);
    uint32_t now = 1000;
    bootDev(m, AUV_ID_MASTER, AUV_ID_THRUSTER);
    bootDev(t, AUV_ID_THRUSTER, AUV_ID_MASTER);
    /* replace the thruster's rx key with a different key */
    AUV_LinkKeys wrong = t.keys;
    AUV_demoKey(0x55, 0x66, wrong.rxKey);
    t.link.begin(wrong, t.nonce);
    uint8_t f[AUV_MAX_FRAME]; size_t n; AUV_RxMessage msg; AUV_Status e;
    uint8_t p[8] = {90, 90, 90, 90, 0xDC, 0x05, 0, 0};
    int delivered = 0;
    for (int i = 0; i < 20; i++) {
        m.link.buildFrame(AUV_TYPE_COMMAND, p, 8, f, sizeof f, &n);
        delivered += feed(t.link, f, n, now, msg, &e);
    }
    check(delivered == 0 && t.link.stats().authFailures == 20, "T02.1",
          "20 frames encrypted with another key", "0 delivered, 20 AUTH_FAILED");
    bool zeroed = true; for (int i = 0; i < 8; i++) if (msg.payload[i]) zeroed = false;
    check(zeroed, "T02.2", "no plaintext leaks into the output buffer on failure", "buffer zeroed");
    check(!t.link.linkUp(now), "T02.3", "link stays DOWN with wrong key", "linkUp false");

    /* sender using a key of another node (Sensor key) to impersonate Master */
    AUV_LinkKeys sensorKeys; AUV_demoLinkKeys(AUV_ID_SENSOR, AUV_ID_MASTER, sensorKeys);
    static AUV_Encryptor rogue; rogue.begin(sensorKeys.rxKey); /* master->sensor key */
    AUV_Header h; h.version = 1; h.type = AUV_TYPE_COMMAND; h.src = AUV_ID_MASTER; h.dst = AUV_ID_THRUSTER;
    h.len = 8; h.epoch = 999; h.counter = 1; h.echo = t.nonce.epoch();
    rogue.seal(h, p, f, sizeof f, &n);
    Dev &t2 = fresh(2); bootDev(t2, AUV_ID_THRUSTER, AUV_ID_MASTER);
    h.echo = t2.nonce.epoch();
    static AUV_Encryptor rogue2; rogue2.begin(sensorKeys.rxKey); rogue2.seal(h, p, f, sizeof f, &n);
    int d = feed(t2.link, f, n, now, msg, &e);
    check(d == 0 && e == AUV_ERR_AUTH_FAILED, "T02.4",
          "Sensor-link key used to forge a Master->Thruster command", "AUTH_FAILED");

    AUV_LinkKeys same = m.keys; memcpy(same.rxKey, same.txKey, 32);
    check(AUV_validateLinkKeys(same) == AUV_ERR_KEY_INVALID, "T02.5", "tx key == rx key", "KEY_INVALID");
    AUV_LinkKeys zero = m.keys; memset(zero.txKey, 0, 32);
    check(AUV_validateLinkKeys(zero) == AUV_ERR_KEY_INVALID, "T02.6", "all-zero key", "KEY_INVALID");
    check(AUV_isDemoKey(m.keys.txKey, AUV_ID_MASTER, AUV_ID_THRUSTER), "T02.7",
          "public demo keys are recognised (refused unless AUV_ALLOW_DEMO_KEYS)", "detected");
}

/* ============ T03/T04: modified ciphertext / tag / header =============== */
static void testTamper() {
    section("T03 Modified encrypted data / T04 modified tag / header");
    Dev &m = fresh(0); Dev &t = fresh(1);
    uint32_t now = 1000;
    bootDev(m, AUV_ID_MASTER, AUV_ID_THRUSTER);
    bootDev(t, AUV_ID_THRUSTER, AUV_ID_MASTER);
    handshake(m, t, now);
    uint8_t p[32]; for (int i = 0; i < 32; i++) p[i] = (uint8_t)i;
    uint8_t f[AUV_MAX_FRAME], g[AUV_MAX_FRAME]; size_t n; AUV_RxMessage msg;
    int delivered = 0, tried = 0;
    /* every bit of the ciphertext */
    for (int byte = 0; byte < 32; byte++) {
        for (int bit = 0; bit < 8; bit++) {
            m.link.buildFrame(AUV_TYPE_TELEMETRY, p, 32, f, sizeof f, &n);
            memcpy(g, f, n);
            g[AUV_HEADER_SIZE + byte] ^= (uint8_t)(1 << bit);
            delivered += feed(t.link, g, n, now, msg); tried++;
            feed(t.link, f, n, now, msg);   /* genuine frame still accepted afterwards */
            now += 10;                      /* 100 Hz pacing (keeps DoS limiter out of this test) */
        }
    }
    snprintf(g_line, sizeof g_line, "%d single-bit flips in ciphertext", tried);
    check(delivered == 0, "T03.1", g_line, "0 delivered");
    check(t.link.stats().rxDelivered >= (uint32_t)tried, "T03.2", "genuine frame after each tampered one", "all delivered");

    /* every bit of the tag */
    delivered = 0; tried = 0;
    for (int byte = 0; byte < 16; byte++) for (int bit = 0; bit < 8; bit++) {
        m.link.buildFrame(AUV_TYPE_TELEMETRY, p, 32, f, sizeof f, &n);
        f[AUV_HEADER_SIZE + 32 + byte] ^= (uint8_t)(1 << bit);
        delivered += feed(t.link, f, n, now, msg); tried++;
        now += 10;
    }
    check(delivered == 0, "T04.1", "128 single-bit flips in the tag", "0 delivered");

    /* header (AAD) fields that still pass structural checks */
    const int fields[] = {3, 11, 12, 15, 7};  /* type, counter lo/hi, echo, epoch */
    const char *names[] = {"type COMMAND->TELEMETRY", "counter +1", "counter byte 1", "echo", "epoch +1"};
    for (int i = 0; i < 5; i++) {
        m.link.buildFrame(AUV_TYPE_COMMAND, p, 8, f, sizeof f, &n);
        if (fields[i] == 3) f[3] = AUV_TYPE_TELEMETRY; else f[fields[i]] ^= 0x01;
        AUV_Status e; int d = feed(t.link, f, n, now, msg, &e);
        snprintf(g_line, sizeof g_line, "header field changed: %s", names[i]);
        check(d == 0, "T04.2", g_line, "rejected (AUTH_FAILED or freshness)");
    }
    /* truncated tag: drop the last byte, then silence */
    m.link.buildFrame(AUV_TYPE_TELEMETRY, p, 32, f, sizeof f, &n);
    int d = feed(t.link, f, n - 1, now, msg);
    t.link.poll(now + 20);
    check(d == 0 && t.link.lastError() == AUV_ERR_FRAME_TIMEOUT, "T04.3", "frame with missing tag byte", "FRAME_TIMEOUT, dropped");
}

/* ===================== T05: invalid / reused nonce ====================== */
static void testNonce() {
    section("T05 Invalid nonce / nonce reuse prevention");
    Dev &m = fresh(0); Dev &t = fresh(1);
    uint32_t now = 1000;
    bootDev(m, AUV_ID_MASTER, AUV_ID_THRUSTER);
    bootDev(t, AUV_ID_THRUSTER, AUV_ID_MASTER);
    handshake(m, t, now);
    uint8_t p[8] = {0}; uint8_t f[AUV_MAX_FRAME]; size_t n; AUV_RxMessage msg; AUV_Status e;

    m.link.buildFrame(AUV_TYPE_TELEMETRY, p, 8, f, sizeof f, &n);
    memset(f + 7, 0, 4);                       /* epoch = 0 */
    int d = feed(t.link, f, n, now, msg, &e);
    check(d == 0 && e == AUV_ERR_BAD_EPOCH, "T05.1", "epoch field = 0", "BAD_EPOCH before crypto");

    m.link.buildFrame(AUV_TYPE_TELEMETRY, p, 8, f, sizeof f, &n);
    AUV_putU32(f + 11, AUV_getU32(f + 11) + 1000);   /* counter changed -> different nonce */
    d = feed(t.link, f, n, now, msg, &e);
    check(d == 0 && e == AUV_ERR_AUTH_FAILED, "T05.2", "counter (nonce part) altered", "AUTH_FAILED");

    static AUV_Encryptor enc; enc.begin(m.keys.txKey);
    AUV_Header h; h.version = 1; h.type = AUV_TYPE_TELEMETRY; h.src = 1; h.dst = 0x10; h.len = 8;
    h.epoch = 5; h.counter = 10; h.echo = 0;
    AUV_Status s1 = enc.seal(h, p, f, sizeof f, &n);
    AUV_Status s2 = enc.seal(h, p, f, sizeof f, &n);       /* same nonce again */
    h.counter = 9;
    AUV_Status s3 = enc.seal(h, p, f, sizeof f, &n);       /* older nonce */
    check(s1 == AUV_OK && s2 != AUV_OK && s3 != AUV_OK, "T05.3",
          "encryptor asked to reuse / go back in nonce", "refused");

    m.link.testSequence().testSet(AUV_COUNTER_LIMIT);
    AUV_Status s = m.link.buildFrame(AUV_TYPE_TELEMETRY, p, 8, f, sizeof f, &n);
    check(s == AUV_ERR_COUNTER_EXHAUSTED, "T05.4", "counter reaches limit", "COUNTER_EXHAUSTED, no frame");

    /* uniqueness over many frames */
    Dev &a = fresh(2); bootDev(a, AUV_ID_MASTER, AUV_ID_THRUSTER);
    uint32_t prevC = 0; bool mono = true;
    for (int i = 0; i < 1000; i++) {
        a.link.buildFrame(AUV_TYPE_TELEMETRY, p, 8, f, sizeof f, &n);
        uint32_t c = AUV_getU32(f + 11);
        if (i > 0 && c != prevC + 1) mono = false;
        prevC = c;
    }
    check(mono, "T05.5", "1000 frames: counter strictly +1 each time", "strictly increasing");
}

/* ========================= T06/T07: duplicates / replay ================= */
static void testReplay() {
    section("T06 Duplicate packets / T07 Replay attacks");
    Dev &m = fresh(0); Dev &t = fresh(1);
    uint32_t now = 1000;
    bootDev(m, AUV_ID_MASTER, AUV_ID_THRUSTER);
    bootDev(t, AUV_ID_THRUSTER, AUV_ID_MASTER);
    handshake(m, t, now);
    uint8_t p[8] = {90, 90, 90, 90, 0x6C, 0x07, 1, 0};  /* thruster 1900 us */
    static uint8_t rec[10][AUV_MAX_FRAME]; size_t rn[10]; AUV_RxMessage msg; AUV_Status e;
    for (int i = 0; i < 10; i++) m.link.buildFrame(AUV_TYPE_COMMAND, p, 8, rec[i], AUV_MAX_FRAME, &rn[i]);

    int d = feed(t.link, rec[0], rn[0], now, msg);
    int d2 = feed(t.link, rec[0], rn[0], now, msg, &e);
    check(d == 1 && d2 == 0 && e == AUV_ERR_REPLAY, "T06.1", "same frame twice", "1st delivered, 2nd REPLAY");
    for (int i = 1; i < 10; i++) feed(t.link, rec[i], rn[i], now, msg);
    d = feed(t.link, rec[4], rn[4], now, msg, &e);
    check(d == 0 && e == AUV_ERR_REPLAY, "T07.1", "replay of an older recorded command", "REPLAY (before crypto)");
    check(t.link.stats().preRejected >= 2, "T07.2", "replays rejected without spending GCM time", "preRejected counted");

    /* receiver reboots: RAM replay state is lost, attacker replays capture */
    t.link.end();
    bootDev(t, AUV_ID_THRUSTER, AUV_ID_MASTER);   /* new epoch from flash */
    int got = 0;
    for (int i = 0; i < 10; i++) got += feed(t.link, rec[i], rn[i], now, msg, &e);
    check(got == 0 && e == AUV_ERR_STALE_ECHO, "T07.3",
          "after RECEIVER reboot, replay of all 10 old commands", "0 delivered (STALE_ECHO)");

    /* sender reboots: frames from its previous epoch must be refused */
    Dev &m2 = fresh(2); Dev &t2 = fresh(3);
    bootDev(m2, AUV_ID_MASTER, AUV_ID_THRUSTER);
    bootDev(t2, AUV_ID_THRUSTER, AUV_ID_MASTER);
    handshake(m2, t2, now);
    uint8_t old[AUV_MAX_FRAME]; size_t on;
    m2.link.buildFrame(AUV_TYPE_COMMAND, p, 8, old, sizeof old, &on);  /* captured, never delivered */
    m2.link.end();
    bootDev(m2, AUV_ID_MASTER, AUV_ID_THRUSTER);   /* sender epoch +1 */
    handshake(m2, t2, now);
    d = feed(t2.link, old, on, now, msg, &e);
    check(d == 0 && e == AUV_ERR_OLD_EPOCH, "T07.4", "frame from sender's previous boot", "OLD_EPOCH");
    check(t2.link.replayStats().peerReboots == 1, "T07.5", "receiver noticed sender reboot", "peerReboots = 1");
}

/* ======================= T08: invalid device IDs ======================== */
static void testIds() {
    section("T08 Invalid device IDs / impersonation");
    Dev &m = fresh(0); Dev &t = fresh(1);
    uint32_t now = 1000;
    bootDev(m, AUV_ID_MASTER, AUV_ID_THRUSTER);
    bootDev(t, AUV_ID_THRUSTER, AUV_ID_MASTER);
    handshake(m, t, now);
    uint8_t p[8] = {0}; uint8_t f[AUV_MAX_FRAME]; size_t n; AUV_RxMessage msg; AUV_Status e;
    struct { uint8_t off, val; AUV_Status exp; const char *what; } cases[] = {
        {5, AUV_ID_SENSOR, AUV_ERR_BAD_DST, "dst = Sensor (not me)"},
        {5, AUV_ID_BROADCAST, AUV_ERR_BAD_DST, "dst = broadcast 0xFF"},
        {4, AUV_ID_JETSON, AUV_ERR_BAD_SRC, "src = Jetson (not my peer)"},
        {4, AUV_ID_INVALID, AUV_ERR_BAD_SRC, "src = 0x00"},
        {2, 0x02, AUV_ERR_BAD_VERSION, "version = 2"},
        {3, 0x77, AUV_ERR_BAD_TYPE, "unknown packet type"},
    };
    for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        m.link.buildFrame(AUV_TYPE_COMMAND, p, 8, f, sizeof f, &n);
        f[cases[i].off] = cases[i].val;
        int d = feed(t.link, f, n, now, msg, &e);
        check(d == 0 && e == cases[i].exp, "T08.1", cases[i].what, AUV_statusName(cases[i].exp));
    }
    AUV_LinkKeys k = m.keys; k.peerId = k.localId;
    check(AUV_validateLinkKeys(k) == AUV_ERR_KEY_INVALID, "T08.2", "link configured with local == peer", "KEY_INVALID");
}

/* ======================= T09: invalid lengths =========================== */
static void testLengths() {
    section("T09 Invalid packet lengths / buffer overflow");
    Dev &m = fresh(0); Dev &t = fresh(1);
    uint32_t now = 1000;
    bootDev(m, AUV_ID_MASTER, AUV_ID_THRUSTER);
    bootDev(t, AUV_ID_THRUSTER, AUV_ID_MASTER);
    handshake(m, t, now);
    uint8_t p[AUV_MAX_PAYLOAD + 8] = {0}; uint8_t f[AUV_MAX_FRAME + 8]; size_t n; AUV_RxMessage msg; AUV_Status e;

    m.link.buildFrame(AUV_TYPE_TELEMETRY, p, 8, f, sizeof f, &n);
    f[6] = AUV_MAX_PAYLOAD + 1;
    int d = feed(t.link, f, n, now, msg, &e);
    check(d == 0 && e == AUV_ERR_BAD_LENGTH, "T09.1", "length byte = MAX+1", "BAD_LENGTH, nothing copied");
    m.link.buildFrame(AUV_TYPE_TELEMETRY, p, 8, f, sizeof f, &n);
    f[6] = 0xFF;
    d = feed(t.link, f, n, now, msg, &e);
    check(d == 0 && e == AUV_ERR_BAD_LENGTH, "T09.2", "length byte = 255", "BAD_LENGTH");
    m.link.buildFrame(AUV_TYPE_TELEMETRY, p, 8, f, sizeof f, &n);
    f[6] = 4;   /* claims shorter: tag position wrong */
    d = feed(t.link, f, n, now, msg, &e);
    check(d == 0, "T09.3", "length byte smaller than real payload", "AUTH_FAILED / dropped");
    m.link.buildFrame(AUV_TYPE_HEARTBEAT, 0, 0, f, sizeof f, &n);
    f[6] = 3;
    d = feed(t.link, f, n, now, msg, &e);
    check(d == 0 && e == AUV_ERR_BAD_LENGTH, "T09.4", "heartbeat with non-zero length", "BAD_LENGTH");
    AUV_Status s = m.link.buildFrame(AUV_TYPE_TELEMETRY, p, AUV_MAX_PAYLOAD + 1, f, sizeof f, &n);
    check(s == AUV_ERR_PAYLOAD_TOO_LARGE, "T09.5", "sender asked to send MAX+1 bytes", "PAYLOAD_TOO_LARGE");
    uint8_t small[20];
    s = m.link.buildFrame(AUV_TYPE_TELEMETRY, p, 8, small, sizeof small, &n);
    check(s == AUV_ERR_BUFFER_TOO_SMALL, "T09.6", "output buffer too small", "BUFFER_TOO_SMALL, no overflow");
    /* app-level strict lengths */
    AUV_ThrusterCmd c;
    check(!AUV_decodeThrusterCmd(p, 7, c) && !AUV_decodeThrusterCmd(p, 9, c), "T09.7",
          "thruster command payload of 7 or 9 bytes", "rejected");
}

/* ===================== T10: corrupted UART data ========================= */
static void testCorruption() {
    section("T10 Corrupted UART data / resynchronisation / fuzzing");
    Dev &m = fresh(0); Dev &t = fresh(1);
    uint32_t now = 1000;
    bootDev(m, AUV_ID_MASTER, AUV_ID_THRUSTER);
    bootDev(t, AUV_ID_THRUSTER, AUV_ID_MASTER);
    handshake(m, t, now);
    uint8_t p[16] = {0}; uint8_t f[AUV_MAX_FRAME]; size_t n; AUV_RxMessage msg;

    /* noise, including fake sync bytes, before a genuine frame */
    uint8_t noise[300];
    for (int i = 0; i < 300; i++) noise[i] = (uint8_t)rnd();
    for (int i = 0; i < 300; i += 37) { noise[i] = AUV_SYNC0; if (i + 1 < 300) noise[i + 1] = AUV_SYNC1; }
    int d = feed(t.link, noise, sizeof noise, now, msg);
    t.link.poll(now + 10); now += 10;
    m.link.buildFrame(AUV_TYPE_TELEMETRY, p, 16, f, sizeof f, &n);
    int d2 = feed(t.link, f, n, now, msg);
    check(d == 0 && d2 == 1, "T10.1", "300 noise bytes with fake syncs, then genuine frame", "noise 0, genuine 1");

    /* genuine frame starting inside a truncated frame (cable glitch) */
    uint8_t g[2 * AUV_MAX_FRAME]; size_t gn;
    m.link.buildFrame(AUV_TYPE_TELEMETRY, p, 16, f, sizeof f, &n);
    memcpy(g, f, 20);                    /* first 20 bytes of a frame lost mid-way */
    m.link.buildFrame(AUV_TYPE_TELEMETRY, p, 16, g + 20, sizeof g - 20, &gn);
    d = feed(t.link, g, 20 + gn, now, msg);
    check(d == 1, "T10.2", "partial frame immediately followed by full frame", "full frame recovered");

    /* random corruption of genuine frames */
    int falseAccept = 0, good = 0;
    for (int i = 0; i < 500; i++) {
        m.link.buildFrame(AUV_TYPE_TELEMETRY, p, 16, f, sizeof f, &n);
        int flips = 1 + (int)(rnd() % 4);
        for (int k = 0; k < flips; k++) f[rnd() % n] ^= (uint8_t)(1 + rnd() % 255);
        falseAccept += feed(t.link, f, n, now, msg);
        t.link.poll(now + 10); now += 10;
        m.link.buildFrame(AUV_TYPE_TELEMETRY, p, 16, f, sizeof f, &n);
        good += feed(t.link, f, n, now, msg);
    }
    /* A corrupted frame can only be delivered if the corruption hit nothing
     * (k-flips XOR'ed back to the original): practically impossible. */
    check(falseAccept == 0, "T10.3", "500 randomly corrupted frames", "0 delivered");
    check(good == 500, "T10.4", "500 genuine frames interleaved", "500 delivered");

    /* pure fuzz: random frames with valid-looking headers */
    int fuzzAccept = 0;
    for (int i = 0; i < 2000; i++) {
        uint8_t len = (uint8_t)(rnd() % (AUV_MAX_PAYLOAD + 1));
        AUV_Header h; h.version = 1; h.type = AUV_TYPE_COMMAND; h.src = AUV_ID_MASTER; h.dst = AUV_ID_THRUSTER;
        h.len = len; h.epoch = m.nonce.epoch(); h.counter = 100000 + i; h.echo = t.nonce.epoch();
        AUV_encodeHeader(h, f);
        for (int k = 0; k < len + AUV_TAG_SIZE; k++) f[AUV_HEADER_SIZE + k] = (uint8_t)rnd();
        fuzzAccept += feed(t.link, f, AUV_OVERHEAD + len, now + (uint32_t)i * 5, msg);
    }
    check(fuzzAccept == 0, "T10.5", "2000 forged frames with perfect headers, random body", "0 delivered");
}

/* ===================== T11: communication interruption ================== */
static void testInterruption() {
    section("T11 Communication interruption / thruster failsafe");
    Dev &m = fresh(0); Dev &t = fresh(1);
    uint32_t now = 1000;
    bootDev(m, AUV_ID_MASTER, AUV_ID_THRUSTER);
    bootDev(t, AUV_ID_THRUSTER, AUV_ID_MASTER);
    handshake(m, t, now);
    AUV_ThrusterSafety safety;
    uint8_t f[AUV_MAX_FRAME]; size_t n; AUV_RxMessage msg;
    AUV_ThrusterCmd c = {{10, 20, 30, 40}, 1800, 1, 0}; uint8_t p[8]; AUV_encodeThrusterCmd(c, p);

    check(safety.output().thrusterUs == THRUSTER_NEUTRAL_US && safety.state() == THR_STATE_BOOT_SAFE,
          "T11.1", "thruster output at boot before any command", "neutral, BOOT_SAFE");
    for (int i = 0; i < 10; i++) {   /* 100 ms of 100 Hz commands */
        m.link.buildFrame(AUV_TYPE_COMMAND, p, 8, f, sizeof f, &n);
        if (feed(t.link, f, n, now, msg) == 1) safety.onCommand(msg.payload, msg.len, now);
        safety.update(now, t.link.linkUp(now));
        now += 10;
    }
    check(safety.output().thrusterUs == 1800 && safety.state() == THR_STATE_ACTIVE, "T11.2",
          "valid authenticated commands", "1800 us, ACTIVE");
    /* cable cut: nothing arrives */
    uint32_t cut = now; bool wentSafe = false; uint32_t tSafe = 0;
    for (int i = 0; i < 40; i++) {
        t.link.poll(now);
        safety.update(now, t.link.linkUp(now));
        if (!wentSafe && safety.output().thrusterUs == THRUSTER_NEUTRAL_US) { wentSafe = true; tSafe = now - cut; }
        now += 10;
    }
    snprintf(g_line, sizeof g_line, "UART silent: neutral after %lu ms", (unsigned long)tSafe);
    check(wentSafe && tSafe <= THRUSTER_CMD_TIMEOUT_MS + 20, "T11.3", g_line, "<= 270 ms, state TIMEOUT");
    check(!t.link.linkUp(now), "T11.4", "linkUp() after silence", "false");
    /* link restored */
    m.link.buildFrame(AUV_TYPE_COMMAND, p, 8, f, sizeof f, &n);
    if (feed(t.link, f, n, now, msg) == 1) safety.onCommand(msg.payload, msg.len, now);
    safety.update(now, t.link.linkUp(now));
    check(safety.state() == THR_STATE_ACTIVE && t.link.linkUp(now), "T11.5", "first valid command after restore", "ACTIVE again");
    /* half frame then silence */
    m.link.buildFrame(AUV_TYPE_COMMAND, p, 8, f, sizeof f, &n);
    feed(t.link, f, 10, now, msg);
    t.link.poll(now + AUV_FRAME_GAP_TIMEOUT_MS + 1);
    check(t.link.parserStats().gapTimeouts >= 1, "T11.6", "half frame then UART stops", "partial frame discarded");
    /* invalid commands */
    uint8_t bad[8]; AUV_ThrusterCmd bc = c; bc.thrusterUs = 2500; AUV_encodeThrusterCmd(bc, bad);
    for (int i = 0; i < THRUSTER_MAX_INVALID_STREAK; i++) safety.onCommand(bad, 8, now);
    check(safety.output().thrusterUs == THRUSTER_NEUTRAL_US && safety.state() == THR_STATE_INVALID, "T11.7",
          "authenticated but out-of-range commands (2500 us) x5", "never applied, neutral");
    bc = c; bc.flags = THR_FLAG_LEAK_STOP; AUV_encodeThrusterCmd(bc, bad);
    safety.onCommand(p, 8, now); safety.onCommand(bad, 8, now);
    check(safety.output().thrusterUs == THRUSTER_NEUTRAL_US && safety.state() == THR_STATE_LEAK_STOP, "T11.8",
          "command carrying LEAK_STOP flag", "neutral, LEAK_STOP");
    safety.onCommand(p, 8, now); safety.update(now, true, true);
    check(safety.state() == THR_STATE_LEAK_STOP, "T11.9", "local leak input overrides a valid command", "LEAK_STOP");

    /* local leak logic on the Sensor node (no remote commands exist) */
    AUV_LeakMonitor lm;
    lm.update(0x04); lm.update(0x04);
    check(!lm.active(), "T11.10", "leak seen for 2 samples (debounce 3)", "not yet active");
    lm.update(0x04);
    check(lm.active() && lm.relayLevel() == SENSOR_RELAY_LEAK_STATE, "T11.11",
          "leak seen for 3 samples", "active, relay in leak state");
    lm.update(0x00);
    check(!lm.active() && lm.relayLevel() == SENSOR_RELAY_IDLE_STATE, "T11.12",
          "leak clears (latch off)", "relay back to idle");
}

/* ============== T16: encrypt-only (Sensor/IMU) links ===================== */
static void testTxOnly() {
    section("T16 Encrypt-only Sensor/IMU links");
    Dev &m = fresh(0); Dev &s = fresh(1);
    uint32_t now = 1000;
    static AUV_TxOnlyLink tx;
    AUV_LinkKeys sk, mk;
    AUV_demoLinkKeys(AUV_ID_SENSOR, AUV_ID_MASTER, sk); memset(sk.rxKey, 0, 32);   /* sensor stores K1 only */
    AUV_demoLinkKeys(AUV_ID_MASTER, AUV_ID_SENSOR, mk); memset(mk.txKey, 0, 32);   /* master side: receive only */
    s.nonce.provision(s.flash, 1);
    m.nonce.provision(m.flash, 1);
    check(tx.begin(sk, s.nonce) == AUV_OK, "T16.1", "sensor starts with ONE key (rx key all zero)", "OK");
    check(m.link.begin(mk, m.nonce, AUV_LINK_RX_ONLY) == AUV_OK, "T16.2", "master starts receive-only side", "OK");
    AUV_SensorTelemetry st; memset(&st, 0, sizeof st); st.tick = 7; st.voltage = 12.5f; st.leakMask = 0x02; st.leakActive = 1; st.relay = 1;
    uint8_t p[AUV_SENSOR_TELEM_LEN]; AUV_encodeSensorTelemetry(st, p);
    uint8_t f[AUV_MAX_FRAME]; size_t n; AUV_RxMessage msg;
    int got = 0;
    for (int i = 0; i < 100; i++) {
        tx.buildFrame(AUV_TYPE_TELEMETRY, p, sizeof p, f, sizeof f, &n);
        got += feed(m.link, f, n, now, msg); now += 10;
    }
    AUV_SensorTelemetry back;
    check(got == 100 && AUV_decodeSensorTelemetry(msg.payload, msg.len, back) && back.voltage == 12.5f && back.leakActive == 1,
          "T16.3", "100 encrypt-only telemetry frames, no handshake needed", "100 delivered, decoded");
    int d = feed(m.link, f, n, now, msg);
    check(d == 0 && m.link.lastError() == AUV_ERR_REPLAY, "T16.4", "replayed sensor frame", "REPLAY");
    AUV_Status st2 = m.link.buildFrame(AUV_TYPE_COMMAND, p, 1, f, sizeof f, &n);
    check(st2 == AUV_ERR_NOT_READY, "T16.5", "master tries to SEND on the receive-only link", "refused");
    check(tx.buildFrame(AUV_TYPE_COMMAND, p, 1, f, sizeof f, &n) == AUV_ERR_BAD_TYPE, "T16.6",
          "sensor tries to build a COMMAND", "BAD_TYPE");
    /* sensor reboot: old frames rejected, new epoch accepted */
    uint8_t old[AUV_MAX_FRAME]; size_t on; tx.buildFrame(AUV_TYPE_TELEMETRY, p, sizeof p, old, sizeof old, &on);
    s.nonce.begin(s.flash); tx.begin(sk, s.nonce);
    tx.buildFrame(AUV_TYPE_TELEMETRY, p, sizeof p, f, sizeof f, &n);
    int dn = feed(m.link, f, n, now, msg);
    int dold = feed(m.link, old, on, now, msg);
    check(dn == 1 && dold == 0 && m.link.lastError() == AUV_ERR_OLD_EPOCH, "T16.7",
          "after sensor reboot: new frame vs frame from previous boot", "new accepted, old OLD_EPOCH");
    AUV_LinkKeys bad = sk; memset(bad.txKey, 0, 32);
    check(tx.begin(bad, s.nonce) == AUV_ERR_KEY_INVALID, "T16.8", "encrypt-only node with empty tx key", "KEY_INVALID");
    /* envelope for the Jetson */
    uint8_t env[AUV_MAX_PAYLOAD];
    uint8_t el = AUV_encodeEnvelope(AUV_ID_SENSOR, msg.epoch, msg.counter, msg.payload, msg.len, env);
    check(el == AUV_ENV_HDR + AUV_SENSOR_TELEM_LEN && env[0] == AUV_ID_SENSOR && AUV_getU32(env + 5) == msg.counter,
          "T16.9", "envelope keeps original node id, epoch, counter", "37 bytes");
    uint8_t big[AUV_IMU_TELEM_LEN] = {0};
    check(AUV_encodeEnvelope(AUV_ID_IMU, 1, 2, big, AUV_IMU_TELEM_LEN, env) == AUV_ENV_HDR + AUV_IMU_TELEM_LEN,
          "T16.10", "IMU telemetry fits in one Jetson frame", "66 bytes <= 80");
    snprintf(g_line, sizeof g_line, "RAM: encrypt-only link %u B (two-way link %u B)",
             (unsigned)sizeof(AUV_TxOnlyLink), (unsigned)sizeof(AUV_SecureLink));
    check(sizeof(AUV_TxOnlyLink) < sizeof(AUV_SecureLink) / 2, "T16.11", g_line, "less than half");
}

/* ======================= T12: device reboot ============================= */
static void testReboot() {
    section("T12 Device reboot");
    Dev &m = fresh(0); Dev &t = fresh(1);
    uint32_t now = 1000;
    bootDev(m, AUV_ID_MASTER, AUV_ID_THRUSTER);
    bootDev(t, AUV_ID_THRUSTER, AUV_ID_MASTER);
    uint32_t e1 = m.nonce.epoch();
    handshake(m, t, now);
    uint8_t p[8] = {0}; uint8_t f[AUV_MAX_FRAME]; size_t n; AUV_RxMessage msg;
    static uint32_t seenE[64], seenC[64]; int ns = 0; bool unique = true;
    for (int boot = 0; boot < 4; boot++) {
        for (int i = 0; i < 16; i++) {
            m.link.buildFrame(AUV_TYPE_TELEMETRY, p, 8, f, sizeof f, &n);
            uint32_t ep = AUV_getU32(f + 7), ct = AUV_getU32(f + 11);
            for (int k = 0; k < ns; k++) if (seenE[k] == ep && seenC[k] == ct) unique = false;
            seenE[ns] = ep; seenC[ns] = ct; ns++;
            feed(t.link, f, n, now, msg);
        }
        m.link.end();
        bootDev(m, AUV_ID_MASTER, AUV_ID_THRUSTER);      /* reboot: same flash */
        handshake(m, t, now);
    }
    check(m.nonce.epoch() == e1 + 4, "T12.1", "4 reboots", "epoch +1 per boot");
    check(unique, "T12.2", "(epoch,counter) of 64 frames across 4 boots", "all unique");
    m.link.buildFrame(AUV_TYPE_TELEMETRY, p, 8, f, sizeof f, &n);
    check(feed(t.link, f, n, now, msg) == 1, "T12.3", "receiver accepts rebooted sender after handshake", "delivered");
    check(t.link.replayStats().peerReboots == 4, "T12.4", "receiver counted sender reboots", "4");
    /* links refuse to run before nonce manager is ready */
    Dev &x = fresh(2); static AUV_NonceManager notReady; static AUV_SecureLink l;
    AUV_demoLinkKeys(AUV_ID_MASTER, AUV_ID_THRUSTER, x.keys);
    check(l.begin(x.keys, notReady) != AUV_OK, "T12.5", "link.begin() without a valid epoch", "refused");
}

/* ===================== T13: power failure =============================== */
static void testPowerFail() {
    section("T13 Power failure (flash epoch store)");
    static AUV_NonceManager nm;
    static AUV_RamFlash fl;
    fl.wipe();
    check(nm.begin(fl) == AUV_ERR_NVM_INVALID && !nm.ready(), "T13.1", "blank flash (never provisioned / mass-erased)", "NVM_INVALID, LOCKED");
    check(nm.provision(fl, 1) == AUV_OK && nm.epoch() == 1, "T13.2", "provisioning blank storage", "epoch 1");

    uint32_t maxUsed = nm.epoch(); bool everReused = false; int lockouts = 0;
    /* 300 boots with random power cuts during programming/erase */
    for (int boot = 0; boot < 300; boot++) {
        if (rnd() % 4 == 0) fl.failProgramAfter = (int32_t)(rnd() % 16);
        if (rnd() % 8 == 0) fl.failEraseHalfway = true;
        AUV_Status s = nm.begin(fl);
        fl.failProgramAfter = -1; fl.failEraseHalfway = false;
        if (s == AUV_OK) {
            if (nm.epoch() <= maxUsed) everReused = true;
            maxUsed = nm.epoch();
        } else lockouts++;
    }
    snprintf(g_line, sizeof g_line, "300 boots with random power cuts (%d failed boots refused to run)", lockouts);
    check(!everReused, "T13.3", g_line, "epoch never repeats or goes back");
    snprintf(g_line, sizeof g_line, "flash erases for 300 boots: %lu (page holds %u records)",
             (unsigned long)fl.eraseCount, (unsigned)(fl.pageSize() / 16));
    check(fl.eraseCount < 60, "T13.4", g_line, "~1 erase per page-full, not per boot");

    /* corrupt both pages */
    memset(fl.mem, 0x00, sizeof fl.mem);
    check(nm.begin(fl) == AUV_ERR_NVM_INVALID, "T13.5", "both pages corrupted", "NVM_INVALID, LOCKED (no restart at 1)");
    /* power cut exactly while the new record is being written */
    fl.wipe(); nm.provision(fl, 50);
    fl.failProgramAfter = 5;
    AUV_Status s = nm.begin(fl);                        /* retries in next slot */
    check(s == AUV_OK && nm.epoch() == 51, "T13.6", "first write attempt torn (power glitch), retry succeeds", "epoch 51");
    nm.begin(fl);
    check(nm.epoch() == 52, "T13.7", "next boot after torn record", "epoch 52");
    check(nm.provision(fl, 10) == AUV_OK && nm.epoch() == 53, "T13.8", "provision with LOWER epoch requested", "never goes back (53)");
    /* newest record damaged AFTER it was used (e.g. flash disturb): the
     * previous record must NOT be trusted as the newest -> skip ahead */
    uint32_t used = nm.epoch();
    for (uint32_t off = 0; off + 16 <= fl.pageSize(); off += 16) {      /* find newest record */
        for (int pg = 0; pg < 2; pg++) {
            uint8_t *r = fl.mem[pg] + off;
            if (AUV_getU32(r) == AUV_NVM_MAGIC && AUV_getU32(r + 4) == used) r[6] ^= 0x10;
        }
    }
    s = nm.begin(fl);
    check(s == AUV_OK && nm.epoch() > used && nm.damagedRecordFound(), "T13.9",
          "newest epoch record corrupted after use", "epoch skips ahead (> last used)");
}

/* ====================== T14/T15: 100 Hz and performance ================= */
static void testPerformance() {
    section("T14 100 Hz traffic / T15 memory and timing");
    Dev &m = fresh(0); Dev &t = fresh(1);
    uint32_t now = 1000;
    bootDev(m, AUV_ID_MASTER, AUV_ID_THRUSTER);
    bootDev(t, AUV_ID_THRUSTER, AUV_ID_MASTER);
    handshake(m, t, now);
    uint8_t cmd[8] = {90, 90, 90, 90, 0xDC, 0x05, 0, 0}, tel[AUV_IMU_TELEM_LEN] = {0};
    uint8_t f[AUV_MAX_FRAME]; size_t n; AUV_RxMessage msg;
    int down = 0, okCmd = 0, okTel = 0;
    for (int i = 0; i < 1000; i++) {               /* 10 s simulated, both directions */
        m.link.buildFrame(AUV_TYPE_COMMAND, cmd, 8, f, sizeof f, &n);
        okCmd += feed(t.link, f, n, now, msg);
        t.link.buildFrame(AUV_TYPE_TELEMETRY, tel, sizeof tel, f, sizeof f, &n);
        okTel += feed(m.link, f, n, now + 1, msg);
        if (!t.link.linkUp(now) || !m.link.linkUp(now + 1)) down++;
        now += 10;
    }
    check(okCmd == 1000 && okTel == 1000 && down == 0, "T14.1",
          "10 s at 100 Hz both ways (8 B cmd + 57 B telemetry)", "2000/2000 delivered, link never down");
    /* bandwidth */
    uint32_t bps = 100UL * (AUV_OVERHEAD + 8 + AUV_OVERHEAD + AUV_IMU_TELEM_LEN) * 10UL;
    snprintf(g_line, sizeof g_line, "UART load at 100 Hz: %lu bit/s of 1,000,000 (%lu.%lu %%)",
             (unsigned long)bps, (unsigned long)(bps / 10000), (unsigned long)((bps / 1000) % 10));
    check(bps < 200000UL, "T14.2", g_line, "< 20 %");

    /* DoS limiter: flood of forged frames in one second */
    Dev &t3 = fresh(2); Dev &m3 = fresh(3); bootDev(m3, AUV_ID_MASTER, AUV_ID_THRUSTER); bootDev(t3, AUV_ID_THRUSTER, AUV_ID_MASTER);
    handshake(m3, t3, 5000);
    uint32_t base = 6000;
    for (int i = 0; i < 1500; i++) {
        AUV_Header h; h.version = 1; h.type = AUV_TYPE_COMMAND; h.src = 1; h.dst = 0x10; h.len = 8;
        h.epoch = m3.nonce.epoch(); h.counter = 1000000 + i; h.echo = t3.nonce.epoch();
        AUV_encodeHeader(h, f);
        for (int k = 0; k < 8 + 16; k++) f[AUV_HEADER_SIZE + k] = (uint8_t)rnd();
        feed(t3.link, f, AUV_OVERHEAD + 8, base + (uint32_t)(i * 600 / 1500), msg);
    }
    snprintf(g_line, sizeof g_line, "1500 forged frames in 0.6 s: %lu verified, %lu dropped by limiter",
             (unsigned long)t3.link.stats().authFailures, (unsigned long)t3.link.stats().rateLimited);
    check(t3.link.stats().authFailures <= AUV_MAX_AUTH_PER_SEC && t3.link.stats().rateLimited > 0,
          "T14.3", g_line, "verifications capped at AUV_MAX_AUTH_PER_SEC");

    /* memory */
    snprintf(g_line, sizeof g_line, "RAM: SecureLink %u B, NonceManager %u B, RxMessage %u B, frame buf %u B",
             (unsigned)sizeof(AUV_SecureLink), (unsigned)sizeof(AUV_NonceManager),
             (unsigned)sizeof(AUV_RxMessage), (unsigned)AUV_MAX_FRAME);
    check(sizeof(AUV_SecureLink) < 2048, "T15.1", g_line, "< 2 KB per link, no heap");

    /* timing */
    if (!g_micros) return;
    static const uint8_t sizes[] = {0, 8, 28, 57, 64};
    for (unsigned si = 0; si < sizeof sizes; si++) {
        uint8_t len = sizes[si];
        uint8_t p[AUV_MAX_PAYLOAD] = {0};
        const int N = 50;
        uint32_t encMax = 0, encSum = 0, decMax = 0, decSum = 0;
        for (int i = 0; i < N; i++) {
            uint32_t a = g_micros();
            m.link.buildFrame(len ? AUV_TYPE_TELEMETRY : AUV_TYPE_HEARTBEAT, p, len, f, sizeof f, &n);
            uint32_t b = g_micros();
            int d = feed(t.link, f, n, now, msg);
            uint32_t c = g_micros();
            now += 10;
            (void)d;
            uint32_t te = b - a, td = c - b;
            encSum += te; decSum += td;
            if (te > encMax) encMax = te;
            if (td > decMax) decMax = td;
        }
        snprintf(g_line, sizeof g_line,
                 "payload %2u B: encrypt avg %lu us max %lu us | parse+decrypt avg %lu us max %lu us",
                 len, (unsigned long)(encSum / N), (unsigned long)encMax,
                 (unsigned long)(decSum / N), (unsigned long)decMax);
        out(g_line);
    }
    out("  -> budget at 100 Hz is 10000 us per cycle; see docs for per-node load.");
}

} /* namespace auvtest */

/* Run everything. Returns number of failures. */
inline uint32_t AUV_runAllTests(AUV_PrintFn print, AUV_MicrosFn micros32) {
    using namespace auvtest;
    g_print = print; g_micros = micros32; g_pass = g_fail = 0;
    out("==== AUV_Security self-test v" AUV_SECURITY_LIB_VERSION " ====");
    testKnownAnswer();
    testRoundTrip();
    testWrongKey();
    testTamper();
    testNonce();
    testReplay();
    testIds();
    testLengths();
    testCorruption();
    testInterruption();
    testReboot();
    testPowerFail();
    testTxOnly();
    testPerformance();
    snprintf(g_line, sizeof g_line, "RESULT: %lu passed, %lu failed",
             (unsigned long)g_pass, (unsigned long)g_fail);
    out(g_line);
    return g_fail;
}

#endif /* AUV_TEST_SUITE_H */
