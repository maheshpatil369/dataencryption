/*
 * AUV_Packet.h
 * ---------------------------------------------------------------------------
 * Secure packet format, header encode/decode, nonce construction and a
 * fixed-buffer UART stream parser with resynchronisation.
 *
 * Wire format (all integers little-endian):
 *
 *   off  size  field
 *   0    1     sync0  = 0xA5
 *   1    1     sync1  = 0x5A
 *   2    1     version (0x01)
 *   3    1     type    (HEARTBEAT / TELEMETRY / COMMAND / STATUS)
 *   4    1     src     sender device ID
 *   5    1     dst     receiver device ID
 *   6    1     len     plaintext payload length, 0..AUV_MAX_PAYLOAD
 *   7    4     epoch   sender boot epoch (persistent, +1 every boot)
 *   11   4     counter sender packet counter (per link, +1 every packet)
 *   15   4     echo    last boot epoch of the RECEIVER seen by the sender
 *   19   len   ciphertext (AES-256-GCM)
 *   19+len 16  GCM tag
 *
 *   AAD (authenticated, not encrypted) = bytes 0..18 (the whole header).
 *   Nonce (never transmitted, rebuilt by the receiver) =
 *       epoch(4) || counter(4) || src(1) || dst(1) || 0x00 || 0x00
 *
 * The parser never reads past its fixed buffer: the length byte is checked
 * against AUV_MAX_PAYLOAD before any payload byte is stored.
 * ---------------------------------------------------------------------------
 */
#ifndef AUV_PACKET_H
#define AUV_PACKET_H

#include <string.h>
#include "AUV_SecurityConfig.h"

/* ------------------------- little-endian helpers ------------------------- */
inline void AUV_putU32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v);       p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
inline uint32_t AUV_getU32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
inline void AUV_putU16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
inline uint16_t AUV_getU16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }

/* Volatile write so the compiler cannot optimise the wipe away. */
inline void AUV_secureZero(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

/* ------------------------------ header ----------------------------------- */
struct AUV_Header {
    uint8_t  version;
    uint8_t  type;
    uint8_t  src;
    uint8_t  dst;
    uint8_t  len;
    uint32_t epoch;
    uint32_t counter;
    uint32_t echo;
};

inline bool AUV_isKnownType(uint8_t t) {
    return t == AUV_TYPE_HEARTBEAT || t == AUV_TYPE_TELEMETRY ||
           t == AUV_TYPE_COMMAND   || t == AUV_TYPE_STATUS;
}

inline bool AUV_isValidId(uint8_t id) {
    return id != AUV_ID_INVALID && id != AUV_ID_BROADCAST;
}

inline void AUV_encodeHeader(const AUV_Header &h, uint8_t out[AUV_HEADER_SIZE]) {
    out[0] = AUV_SYNC0;
    out[1] = AUV_SYNC1;
    out[2] = h.version;
    out[3] = h.type;
    out[4] = h.src;
    out[5] = h.dst;
    out[6] = h.len;
    AUV_putU32(out + 7,  h.epoch);
    AUV_putU32(out + 11, h.counter);
    AUV_putU32(out + 15, h.echo);
}

inline void AUV_decodeHeader(const uint8_t in[AUV_HEADER_SIZE], AUV_Header &h) {
    h.version = in[2];
    h.type    = in[3];
    h.src     = in[4];
    h.dst     = in[5];
    h.len     = in[6];
    h.epoch   = AUV_getU32(in + 7);
    h.counter = AUV_getU32(in + 11);
    h.echo    = AUV_getU32(in + 15);
}

/* Structural validation only (no crypto, no freshness). Cheap, so it runs
 * before any expensive work and rejects malformed / misaddressed frames. */
inline AUV_Status AUV_validateHeader(const uint8_t *raw, const AUV_Header &h,
                                     uint8_t localId, uint8_t expectedSrc) {
    if (raw[0] != AUV_SYNC0 || raw[1] != AUV_SYNC1) return AUV_ERR_BAD_SYNC;
    if (h.version != AUV_PROTOCOL_VERSION)          return AUV_ERR_BAD_VERSION;
    if (!AUV_isKnownType(h.type))                   return AUV_ERR_BAD_TYPE;
    if (h.len > AUV_MAX_PAYLOAD)                    return AUV_ERR_BAD_LENGTH;
    if (h.type == AUV_TYPE_HEARTBEAT && h.len != 0) return AUV_ERR_BAD_LENGTH;
    if (!AUV_isValidId(h.src) || h.src != expectedSrc) return AUV_ERR_BAD_SRC;
    if (h.dst != localId)                           return AUV_ERR_BAD_DST;
    if (h.epoch == 0 || h.epoch > AUV_EPOCH_LIMIT)  return AUV_ERR_BAD_EPOCH;
    if (h.echo > AUV_EPOCH_LIMIT)                   return AUV_ERR_BAD_EPOCH;
    return AUV_OK;
}

/* Nonce = epoch || counter || src || dst || 0 || 0.
 * Unique for a given key because each key belongs to exactly one
 * (src -> dst) direction, epochs never repeat for a device and counters never
 * repeat within an epoch. */
inline void AUV_buildNonce(uint8_t src, uint8_t dst, uint32_t epoch,
                           uint32_t counter, uint8_t nonce[AUV_NONCE_SIZE]) {
    AUV_putU32(nonce, epoch);
    AUV_putU32(nonce + 4, counter);
    nonce[8]  = src;
    nonce[9]  = dst;
    nonce[10] = 0;
    nonce[11] = 0;
}

/* --------------------------- stream parser ------------------------------- */
struct AUV_ParserStats {
    uint32_t framesComplete;
    uint32_t headerRejects;
    uint32_t gapTimeouts;
    uint32_t bytesDiscarded;
};

class AUV_FrameParser {
public:
    AUV_FrameParser() : _local(0), _peer(0), _len(0), _need(0), _lastByteMs(0),
                        _lastError(AUV_OK) {
        memset(&_stats, 0, sizeof(_stats));
        memset(&_hdr, 0, sizeof(_hdr));
    }

    void begin(uint8_t localId, uint8_t expectedPeerId) {
        _local = localId;
        _peer = expectedPeerId;
        reset();
    }

    void reset() {
        AUV_secureZero(_buf, sizeof(_buf));
        _len = 0;
        _need = 0;
    }

    /* Feed one received byte.
     * Returns AUV_PENDING        - frame not complete yet
     *         AUV_MSG_READY      - a structurally valid frame is in frame()
     *         AUV_ERR_xxx        - a frame was dropped (parser already resynced)
     * After AUV_MSG_READY the caller MUST call consumeFrame() or rejectFrame()
     * before pushing more bytes. */
    AUV_Status push(uint8_t b, uint32_t nowMs) {
        AUV_Status gap = AUV_OK;
        if (_len > 0 && (uint32_t)(nowMs - _lastByteMs) > AUV_FRAME_GAP_TIMEOUT_MS) {
            _stats.gapTimeouts++;
            _stats.bytesDiscarded += _len;
            reset();
            gap = AUV_ERR_FRAME_TIMEOUT;
        }
        _lastByteMs = nowMs;

        if (_need != 0 && _len >= _need) {
            /* caller forgot consume/reject: protect the buffer */
            reset();
        }

        if (_len == 0 && b != AUV_SYNC0) { _stats.bytesDiscarded++; return gap == AUV_OK ? AUV_PENDING : gap; }
        if (_len == 1 && b != AUV_SYNC1) {
            _stats.bytesDiscarded++;
            _len = 0;
            if (b == AUV_SYNC0) { _buf[0] = b; _len = 1; }
            return gap == AUV_OK ? AUV_PENDING : gap;
        }
        if (_len >= AUV_MAX_FRAME) { reset(); return AUV_ERR_BAD_LENGTH; } /* defensive */

        _buf[_len++] = b;
        AUV_Status st = evaluate();
        if (st == AUV_PENDING && gap != AUV_OK) return gap;
        return st;
    }

    /* Call periodically (e.g. every loop) to drop a half-received frame when
     * the UART goes quiet (cable interruption, sender reset). */
    AUV_Status poll(uint32_t nowMs) {
        if (_len > 0 && (uint32_t)(nowMs - _lastByteMs) > AUV_FRAME_GAP_TIMEOUT_MS) {
            _stats.gapTimeouts++;
            _stats.bytesDiscarded += _len;
            reset();
            return AUV_ERR_FRAME_TIMEOUT;
        }
        return AUV_OK;
    }

    /* Frame accepted: clear the buffer. */
    void consumeFrame() { reset(); }

    /* Frame failed authentication or freshness: drop its first byte and
     * look for another sync inside the remaining bytes, so that a corrupted
     * frame cannot hide a genuine frame that started inside it.
     * May return AUV_MSG_READY if another complete frame is already buffered. */
    AUV_Status rejectFrame() {
        dropBefore(nextSync(1));
        return evaluate();
    }

    const uint8_t   *frame() const    { return _buf; }
    uint16_t         frameLen() const { return _need; }
    const AUV_Header &header() const  { return _hdr; }
    const AUV_ParserStats &stats() const { return _stats; }
    AUV_Status       lastError() const { return _lastError; }
    uint16_t         buffered() const { return _len; }

private:
    /* Decide what we have after new bytes were appended / buffer moved.
     * Iterative (no recursion) so stack use is constant inside RTOS tasks. */
    AUV_Status evaluate() {
        AUV_Status firstErr = AUV_PENDING;
        for (;;) {
            if (_len < AUV_HEADER_SIZE) { _need = 0; return firstErr; }
            if (_need == 0) {
                AUV_decodeHeader(_buf, _hdr);
                AUV_Status v = AUV_validateHeader(_buf, _hdr, _local, _peer);
                if (v != AUV_OK) {
                    _stats.headerRejects++;
                    _lastError = v;
                    if (firstErr == AUV_PENDING) firstErr = v;
                    dropBefore(nextSync(1));
                    continue;
                }
                _need = (uint16_t)(AUV_HEADER_SIZE + _hdr.len + AUV_TAG_SIZE);
            }
            if (_len < _need) return firstErr;
            _stats.framesComplete++;
            return AUV_MSG_READY;
        }
    }

    /* Index of the next candidate sync at or after 'start' (or _len). */
    uint16_t nextSync(uint16_t start) const {
        uint16_t i = start;
        while (i < _len) {
            if (_buf[i] == AUV_SYNC0 && (i + 1 >= _len || _buf[i + 1] == AUV_SYNC1)) break;
            i++;
        }
        return i;
    }

    /* Discard the first 'n' buffered bytes. */
    void dropBefore(uint16_t n) {
        if (n > _len) n = _len;
        _stats.bytesDiscarded += n;
        uint16_t remain = (uint16_t)(_len - n);
        if (remain > 0) memmove(_buf, _buf + n, remain);
        AUV_secureZero(_buf + remain, sizeof(_buf) - remain);
        _len = remain;
        _need = 0;
    }

    uint8_t  _buf[AUV_MAX_FRAME];
    uint8_t  _local, _peer;
    uint16_t _len, _need;
    uint32_t _lastByteMs;
    AUV_Header _hdr;
    AUV_ParserStats _stats;
    AUV_Status _lastError;
};

#endif /* AUV_PACKET_H */
