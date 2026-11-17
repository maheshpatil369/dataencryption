/*
 * AUV_SecurityConfig.h
 * ---------------------------------------------------------------------------
 * Central configuration for the AUV secure-link library.
 *
 * Every limit in the library is a compile-time constant defined here, so all
 * buffers are fixed-size and no dynamic memory is ever used.
 *
 * You may override any value by #defining it BEFORE including AUV_Security.h
 * in your sketch, e.g.
 *     #define AUV_LINK_TIMEOUT_MS 150
 *     #include <AUV_Security.h>
 * ---------------------------------------------------------------------------
 */
#ifndef AUV_SECURITY_CONFIG_H
#define AUV_SECURITY_CONFIG_H

#include <stdint.h>
#include <stddef.h>

/* ----------------------------- Protocol ---------------------------------- */
#define AUV_PROTOCOL_VERSION      0x01

/* Two sync bytes. They are also authenticated (part of the AAD). */
#define AUV_SYNC0                 0xA5
#define AUV_SYNC1                 0x5A

/* Largest plaintext payload in one packet. 80 bytes fits the biggest
 * message: IMU telemetry (57 B) forwarded to the Jetson inside a 9-byte
 * envelope (node ID + original epoch + original counter) = 66 B. */
#ifndef AUV_MAX_PAYLOAD
#define AUV_MAX_PAYLOAD           80
#endif

#define AUV_KEY_SIZE              32   /* AES-256 */
#define AUV_NONCE_SIZE            12   /* 96-bit GCM IV (the only size used) */
#define AUV_TAG_SIZE              16   /* full 128-bit GCM tag, never truncated */

/* Header layout (all multi-byte fields little-endian):
 *  [0]  sync0  [1] sync1  [2] version  [3] type  [4] src  [5] dst  [6] len
 *  [7..10]  sender boot epoch
 *  [11..14] sender packet counter
 *  [15..18] echo of the receiver's boot epoch (freshness proof)          */
#define AUV_HEADER_SIZE           19
#define AUV_OVERHEAD              (AUV_HEADER_SIZE + AUV_TAG_SIZE)        /* 35 */
#define AUV_MAX_FRAME             (AUV_OVERHEAD + AUV_MAX_PAYLOAD)        /* 115 */

/* ----------------------------- Device IDs -------------------------------- */
/* 0x00 and 0xFF are reserved and always rejected. */
#define AUV_ID_INVALID            0x00
#define AUV_ID_MASTER             0x01
#define AUV_ID_JETSON             0x02
#define AUV_ID_THRUSTER           0x10
#define AUV_ID_SENSOR             0x11
#define AUV_ID_IMU                0x12
#define AUV_ID_BROADCAST          0xFF   /* never accepted: no broadcast keys */

/* ----------------------------- Packet types ------------------------------ */
#define AUV_TYPE_HEARTBEAT        0x01   /* empty payload, keeps link alive */
#define AUV_TYPE_TELEMETRY        0x10   /* slave -> master/Jetson          */
#define AUV_TYPE_COMMAND          0x20   /* master/Jetson -> slave          */
#define AUV_TYPE_STATUS           0x30   /* slave error / state report      */

/* ----------------------------- Link modes -------------------------------- */
/* DUPLEX  : both directions (Thruster<->Master, Master<->Jetson)
 * RX_ONLY : this side only receives (Master side of Sensor and IMU links).
 *           The sender never receives, so there is no echo freshness proof;
 *           the counter/epoch replay check still applies and the Jetson keeps
 *           a persistent per-node freshness record (see docs).
 * The send-only side (Sensor, IMU) uses the separate AUV_TxOnlyLink class. */
enum AUV_LinkMode : uint8_t {
    AUV_LINK_DUPLEX  = 0,
    AUV_LINK_RX_ONLY = 1
};

/* ----------------------------- Timing ------------------------------------ */
/* If no fresh authenticated packet arrives within this time the link is
 * reported DOWN. Thruster firmware must go to neutral when the link is down. */
#ifndef AUV_LINK_TIMEOUT_MS
#define AUV_LINK_TIMEOUT_MS       200    /* 20 missed packets at 100 Hz */
#endif

/* A partially received frame is discarded if the gap between bytes exceeds
 * this. One 99-byte frame takes ~1 ms at 1 Mbaud. */
#ifndef AUV_FRAME_GAP_TIMEOUT_MS
#define AUV_FRAME_GAP_TIMEOUT_MS  5
#endif

/* Denial-of-service limiter: maximum number of GCM tag verifications per
 * second per link. Legitimate traffic needs ~100-200. Frames beyond this are
 * dropped WITHOUT running crypto, so a flood of forged frames cannot use all
 * the CPU. Genuine frames may be dropped too during a flood, which makes the
 * link time out and the thruster go to neutral (fail-safe). */
#ifndef AUV_MAX_AUTH_PER_SEC
#define AUV_MAX_AUTH_PER_SEC      400
#endif

/* ----------------------------- Counters ---------------------------------- */
/* A link stops transmitting before its 32-bit counter can wrap. Reboot
 * (new epoch) is then required. At 100 Hz this is ~497 days of uptime. */
#define AUV_COUNTER_LIMIT         0xFFFFFFF0UL
/* Epoch 0 means "unknown" on the wire, so valid epochs are 1..LIMIT. */
#define AUV_EPOCH_LIMIT           0xFFFFFFF0UL

/* ----------------------------- Key safety -------------------------------- */
/* The example sketches ship with a PUBLIC demo key set so the bench tests
 * work out of the box. A link refuses to start with the demo keys unless
 * the sketch defines AUV_ALLOW_DEMO_KEYS 1. Never define it on the vehicle. */
#ifndef AUV_ALLOW_DEMO_KEYS
#define AUV_ALLOW_DEMO_KEYS       0
#endif

/* ----------------------------- Status codes ------------------------------ */
enum AUV_Status : uint8_t {
    AUV_OK = 0,
    AUV_MSG_READY,              /* a fresh authenticated message was delivered */
    AUV_PENDING,                /* need more bytes */

    /* framing / header errors (no crypto was run) */
    AUV_ERR_BAD_SYNC,
    AUV_ERR_BAD_VERSION,
    AUV_ERR_BAD_TYPE,
    AUV_ERR_BAD_LENGTH,
    AUV_ERR_BAD_SRC,            /* unknown / unexpected sender ID */
    AUV_ERR_BAD_DST,            /* packet not addressed to this device */
    AUV_ERR_BAD_EPOCH,          /* epoch 0 or out of range */
    AUV_ERR_FRAME_TIMEOUT,      /* UART gap inside a frame */
    AUV_ERR_RATE_LIMITED,       /* DoS limiter dropped the frame */

    /* freshness errors */
    AUV_ERR_REPLAY,             /* duplicate or older counter in same epoch */
    AUV_ERR_OLD_EPOCH,          /* sender epoch older than one already seen */
    AUV_ERR_STALE_ECHO,         /* authentic but not proven fresh for us */

    /* crypto errors */
    AUV_ERR_AUTH_FAILED,        /* GCM tag mismatch: tampered / wrong key */

    /* local errors */
    AUV_ERR_NOT_READY,          /* link not started (keys/nonce store) */
    AUV_ERR_BUFFER_TOO_SMALL,
    AUV_ERR_PAYLOAD_TOO_LARGE,
    AUV_ERR_COUNTER_EXHAUSTED,  /* reboot required */
    AUV_ERR_KEY_INVALID,
    AUV_ERR_DEMO_KEY_REFUSED,
    AUV_ERR_NVM_INVALID,        /* epoch storage empty/corrupt: provision */
    AUV_ERR_NVM_WRITE,          /* flash write/verify failed */
    AUV_ERR_NVM_OVERLAP,        /* epoch storage overlaps program flash */
    AUV_ERR_EPOCH_EXHAUSTED,
    AUV_ERR_KEY_MISMATCH,       /* storage provisioned for different keys */
    AUV_ERR_NULL
};

inline const char *AUV_statusName(AUV_Status s) {
    switch (s) {
        case AUV_OK: return "OK";
        case AUV_MSG_READY: return "MSG_READY";
        case AUV_PENDING: return "PENDING";
        case AUV_ERR_BAD_SYNC: return "BAD_SYNC";
        case AUV_ERR_BAD_VERSION: return "BAD_VERSION";
        case AUV_ERR_BAD_TYPE: return "BAD_TYPE";
        case AUV_ERR_BAD_LENGTH: return "BAD_LENGTH";
        case AUV_ERR_BAD_SRC: return "BAD_SRC";
        case AUV_ERR_BAD_DST: return "BAD_DST";
        case AUV_ERR_BAD_EPOCH: return "BAD_EPOCH";
        case AUV_ERR_FRAME_TIMEOUT: return "FRAME_TIMEOUT";
        case AUV_ERR_RATE_LIMITED: return "RATE_LIMITED";
        case AUV_ERR_REPLAY: return "REPLAY";
        case AUV_ERR_OLD_EPOCH: return "OLD_EPOCH";
        case AUV_ERR_STALE_ECHO: return "STALE_ECHO";
        case AUV_ERR_AUTH_FAILED: return "AUTH_FAILED";
        case AUV_ERR_NOT_READY: return "NOT_READY";
        case AUV_ERR_BUFFER_TOO_SMALL: return "BUFFER_TOO_SMALL";
        case AUV_ERR_PAYLOAD_TOO_LARGE: return "PAYLOAD_TOO_LARGE";
        case AUV_ERR_COUNTER_EXHAUSTED: return "COUNTER_EXHAUSTED";
        case AUV_ERR_KEY_INVALID: return "KEY_INVALID";
        case AUV_ERR_DEMO_KEY_REFUSED: return "DEMO_KEY_REFUSED";
        case AUV_ERR_NVM_INVALID: return "NVM_INVALID";
        case AUV_ERR_NVM_WRITE: return "NVM_WRITE";
        case AUV_ERR_NVM_OVERLAP: return "NVM_OVERLAP";
        case AUV_ERR_EPOCH_EXHAUSTED: return "EPOCH_EXHAUSTED";
        case AUV_ERR_KEY_MISMATCH: return "KEY_MISMATCH";
        case AUV_ERR_NULL: return "NULL_ARG";
    }
    return "UNKNOWN";
}

/* Compile-time sanity checks */
static_assert(AUV_MAX_PAYLOAD > 0 && AUV_MAX_PAYLOAD <= 200, "payload must fit uint8 length with margin");
static_assert(AUV_HEADER_SIZE == 19, "header layout changed: update parser and Python side");

#endif /* AUV_SECURITY_CONFIG_H */
