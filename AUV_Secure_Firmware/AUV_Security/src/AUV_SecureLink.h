/*
 * AUV_SecureLink.h
 * ---------------------------------------------------------------------------
 * One authenticated + encrypted UART link between this device and ONE peer.
 * Combines: frame parser, encryptor, decryptor, replay guard, DoS limiter,
 * link-alive timer.
 *
 * Threading / RTOS / DMA:
 *   - No heap, no delay(), no Serial calls, no interrupts disabled.
 *   - buildFrame() only fills your buffer; YOU send it (Serial.write, HAL
 *     DMA, etc.). So the existing DMA TX path is kept.
 *   - rxByte() takes bytes from wherever your RX code gets them (Serial,
 *     DMA ring buffer). Never call it from an ISR (GCM takes time).
 *   - TX side (buildFrame) and RX side (rxByte/poll) may run in two
 *     different tasks. Each side must be used by only ONE task.
 *
 * Usage:
 *   AUV_NonceManager nonces;   AUV_DefaultFlash flash;   AUV_SecureLink link;
 *   setup(): nonces.begin(flash); link.begin(MY_KEYS, nonces);
 *   TX:      link.buildFrame(AUV_TYPE_TELEMETRY, data, n, buf, sizeof buf, &len);
 *   RX:      if (link.rxByte(b, millis(), msg) == AUV_MSG_READY) handle(msg);
 *   Safety:  if (!link.linkUp(millis())) goSafe();
 * ---------------------------------------------------------------------------
 */
#ifndef AUV_SECURE_LINK_H
#define AUV_SECURE_LINK_H

#include "AUV_SecurityConfig.h"
#include "AUV_Packet.h"
#include "AUV_KeyManager.h"
#include "AUV_NonceManager.h"
#include "AUV_ReplayProtection.h"
#include "AUV_Encrypt.h"
#include "AUV_Decrypt.h"

struct AUV_RxMessage {
    uint8_t  type;
    uint8_t  len;
    uint32_t epoch;     /* sender boot epoch */
    uint32_t counter;   /* sender packet counter (use as sequence number) */
    uint8_t  payload[AUV_MAX_PAYLOAD];
};

struct AUV_LinkStats {
    uint32_t txFrames;
    uint32_t rxDelivered;
    uint32_t authFailures;
    uint32_t rateLimited;
    uint32_t preRejected;     /* replay / old epoch caught before crypto */
};

class AUV_SecureLink {
public:
    AUV_SecureLink() : _mode(AUV_LINK_DUPLEX), _nonces(0), _local(0), _peer(0), _ready(false),
                       _lastFreshMs(0), _everFresh(false), _rateWindow(0),
                       _rateCount(0), _lastError(AUV_OK), _txFp(0), _rxFp(0) {
        memset(&_stats, 0, sizeof(_stats));
    }
    ~AUV_SecureLink() { end(); }

    /* keys     : this link's key material (from AUV_Keys_Secret.h)
     * nonces   : the device's nonce manager, already begin()-ed successfully */
    AUV_Status begin(const AUV_LinkKeys &keys, AUV_NonceManager &nonces,
                     AUV_LinkMode mode = AUV_LINK_DUPLEX) {
        end();
        _mode = mode;
        bool tx = (mode == AUV_LINK_DUPLEX);
        AUV_Status s = AUV_validateLinkKeys(keys, tx, true);
        if (s != AUV_OK) return setErr(s);
        if (!nonces.ready()) return setErr(nonces.status() == AUV_OK ? AUV_ERR_NOT_READY : nonces.status());
        if (tx) { s = _enc.begin(keys.txKey); if (s != AUV_OK) return setErr(s); }
        s = _dec.begin(keys.rxKey); if (s != AUV_OK) { _enc.end(); return setErr(s); }
        _txFp = tx ? AUV_keyFingerprint(keys.txKey) : 0;
        _rxFp = AUV_keyFingerprint(keys.rxKey);
        _nonces = &nonces;
        _local = keys.localId;
        _peer = keys.peerId;
        _parser.begin(_local, _peer);
        _replay.reset();
        _seq.reset();               /* safe: epoch is new for this boot */
        _everFresh = false;
        _lastFreshMs = 0;
        _rateWindow = 0;
        _rateCount = 0;
        memset(&_stats, 0, sizeof(_stats));
        _ready = true;
        _lastError = AUV_OK;
        return AUV_OK;
    }

    /* Wipe keys and state (e.g. tamper response, shutdown). */
    void end() {
        _enc.end();
        _dec.end();
        _parser.reset();
        _ready = false;
        _everFresh = false;
    }

    bool ready() const { return _ready; }

    /* ------------------------------ TX --------------------------------- */
    AUV_Status buildFrame(uint8_t type, const uint8_t *payload, uint8_t len,
                          uint8_t *out, size_t outCap, size_t *outLen) {
        if (!_ready || !_nonces || !_nonces->ready() || _mode != AUV_LINK_DUPLEX) return setErr(AUV_ERR_NOT_READY);
        if (!AUV_isKnownType(type)) return setErr(AUV_ERR_BAD_TYPE);
        if (type == AUV_TYPE_HEARTBEAT && len != 0) return setErr(AUV_ERR_BAD_LENGTH);
        if (len > AUV_MAX_PAYLOAD) return setErr(AUV_ERR_PAYLOAD_TOO_LARGE);
        if (outCap < (size_t)AUV_OVERHEAD + len) return setErr(AUV_ERR_BUFFER_TOO_SMALL);
        AUV_Header h;
        h.version = AUV_PROTOCOL_VERSION;
        h.type = type;
        h.src = _local;
        h.dst = _peer;
        h.len = len;
        h.epoch = _nonces->epoch();
        if (!_seq.take(h.counter)) return setErr(AUV_ERR_COUNTER_EXHAUSTED);
        h.echo = _replay.peerEpoch();
        AUV_Status s = _enc.seal(h, payload, out, outCap, outLen);
        if (s != AUV_OK) return setErr(s);
        _stats.txFrames++;
        return AUV_OK;
    }

    AUV_Status buildHeartbeat(uint8_t *out, size_t outCap, size_t *outLen) {
        return buildFrame(AUV_TYPE_HEARTBEAT, 0, 0, out, outCap, outLen);
    }

    /* ------------------------------ RX --------------------------------- */
    /* Returns AUV_MSG_READY when 'msg' holds a fresh, authenticated message.
     * Any other value means nothing to act on (AUV_PENDING = keep feeding). */
    AUV_Status rxByte(uint8_t b, uint32_t nowMs, AUV_RxMessage &msg) {
        if (!_ready) return AUV_ERR_NOT_READY;
        AUV_Status st = _parser.push(b, nowMs);
        AUV_Status firstErr = AUV_PENDING;
        if (st != AUV_PENDING && st != AUV_MSG_READY) { setErr(st); firstErr = st; }
        while (st == AUV_MSG_READY) {
            bool consume = false;
            AUV_Status r = handleFrame(nowMs, msg, consume);
            if (r == AUV_MSG_READY) { _parser.consumeFrame(); return r; }
            setErr(r);
            if (firstErr == AUV_PENDING) firstErr = r;
            st = consume ? (_parser.consumeFrame(), AUV_PENDING) : _parser.rejectFrame();
            if (st != AUV_PENDING && st != AUV_MSG_READY) setErr(st);
        }
        return firstErr;
    }

    /* Call every loop: drops half-received frames after a UART gap. */
    void poll(uint32_t nowMs) {
        if (_ready && _parser.poll(nowMs) != AUV_OK) setErr(AUV_ERR_FRAME_TIMEOUT);
    }

    /* ---------------------------- status ------------------------------- */
    /* true while a fresh authenticated packet arrived within the timeout */
    bool linkUp(uint32_t nowMs) const {
        return _ready && _everFresh && (uint32_t)(nowMs - _lastFreshMs) <= AUV_LINK_TIMEOUT_MS;
    }
    uint32_t msSinceFresh(uint32_t nowMs) const { return _everFresh ? nowMs - _lastFreshMs : 0xFFFFFFFFUL; }
    uint32_t peerEpoch() const { return _replay.peerEpoch(); }
    uint32_t myEpoch() const { return _nonces ? _nonces->epoch() : 0; }
    uint32_t txFingerprint() const { return _txFp; }
    uint32_t rxFingerprint() const { return _rxFp; }
    AUV_Status lastError() const { return _lastError; }
    const AUV_LinkStats &stats() const { return _stats; }
    const AUV_ReplayStats &replayStats() const { return _replay.stats(); }
    const AUV_ParserStats &parserStats() const { return _parser.stats(); }
    uint8_t localId() const { return _local; }
    AUV_LinkMode mode() const { return _mode; }
    uint8_t peerId() const { return _peer; }

    /* test hook */
    AUV_TxSequence &testSequence() { return _seq; }

private:
    AUV_Status setErr(AUV_Status s) { _lastError = s; return s; }

    bool rateOk(uint32_t nowMs) {
        uint32_t w = nowMs / 1000UL;
        if (w != _rateWindow) { _rateWindow = w; _rateCount = 0; }
        if (_rateCount >= AUV_MAX_AUTH_PER_SEC) return false;
        _rateCount++;
        return true;
    }

    AUV_Status handleFrame(uint32_t nowMs, AUV_RxMessage &msg, bool &consume) {
        const AUV_Header &h = _parser.header();
        consume = false;

        /* 1. freshness pre-check, no crypto, no state change */
        AUV_Status s = _replay.precheck(h.epoch, h.counter);
        if (s != AUV_OK) { _stats.preRejected++; _replay.count(s); return s; }

        /* 2. DoS limiter before the expensive GCM verify */
        if (!rateOk(nowMs)) { _stats.rateLimited++; return AUV_ERR_RATE_LIMITED; }

        /* 3. authenticate + decrypt (plaintext released only if tag OK) */
        s = _dec.open(_parser.frame(), _parser.frameLen(), h, msg.payload);
        if (s != AUV_OK) { _stats.authFailures++; return s; }
        consume = true;   /* genuine frame: do not rescan inside it */

        /* 4. commit freshness state (only authenticated packets get here) */
        s = _replay.accept(h.epoch, h.counter);
        if (s != AUV_OK) { AUV_secureZero(msg.payload, sizeof(msg.payload)); return s; }

        /* 5. must be fresh for OUR current boot (two-way links only: an
         *    encrypt-only sender never hears our epoch, so it cannot echo it) */
        if (_mode == AUV_LINK_DUPLEX) {
            s = _replay.checkEcho(h.echo, _nonces->epoch());
            if (s != AUV_OK) { AUV_secureZero(msg.payload, sizeof(msg.payload)); return s; }
        }

        msg.type = h.type;
        msg.len = h.len;
        msg.epoch = h.epoch;
        msg.counter = h.counter;
        if (h.len < AUV_MAX_PAYLOAD) memset(msg.payload + h.len, 0, AUV_MAX_PAYLOAD - h.len);
        _lastFreshMs = nowMs;
        _everFresh = true;
        _stats.rxDelivered++;
        return AUV_MSG_READY;
    }

    AUV_LinkMode      _mode;
    AUV_NonceManager *_nonces;
    AUV_FrameParser   _parser;
    AUV_Encryptor     _enc;
    AUV_Decryptor     _dec;
    AUV_ReplayGuard   _replay;
    AUV_TxSequence    _seq;
    uint8_t  _local, _peer;
    bool     _ready;
    uint32_t _lastFreshMs;
    bool     _everFresh;
    uint32_t _rateWindow, _rateCount;
    AUV_Status _lastError;
    AUV_LinkStats _stats;
    uint32_t _txFp, _rxFp;
};

/* ---------------------------------------------------------------------------
 * AUV_TxOnlyLink - encrypt-and-send only (Sensor and IMU nodes).
 * Holds ONE key (txKey), one AES-GCM context and a counter: about 0.4 KB RAM,
 * no receive buffer, no decryption code path. The echo field is always 0.
 * ------------------------------------------------------------------------- */
class AUV_TxOnlyLink {
public:
    AUV_TxOnlyLink() : _nonces(0), _local(0), _peer(0), _ready(false), _txFrames(0),
                       _lastError(AUV_OK), _fp(0) {}
    ~AUV_TxOnlyLink() { end(); }

    AUV_Status begin(const AUV_LinkKeys &keys, AUV_NonceManager &nonces) {
        end();
        AUV_Status s = AUV_validateLinkKeys(keys, true, false);
        if (s != AUV_OK) return _lastError = s;
        if (!nonces.ready()) return _lastError = (nonces.status() == AUV_OK ? AUV_ERR_NOT_READY : nonces.status());
        s = _enc.begin(keys.txKey);
        if (s != AUV_OK) return _lastError = s;
        _fp = AUV_keyFingerprint(keys.txKey);
        _nonces = &nonces;
        _local = keys.localId;
        _peer = keys.peerId;
        _seq.reset();
        _txFrames = 0;
        _ready = true;
        return _lastError = AUV_OK;
    }
    void end() { _enc.end(); _ready = false; }
    bool ready() const { return _ready; }

    AUV_Status buildFrame(uint8_t type, const uint8_t *payload, uint8_t len,
                          uint8_t *out, size_t outCap, size_t *outLen) {
        if (!_ready || !_nonces || !_nonces->ready()) return _lastError = AUV_ERR_NOT_READY;
        if (type != AUV_TYPE_TELEMETRY && type != AUV_TYPE_STATUS && type != AUV_TYPE_HEARTBEAT)
            return _lastError = AUV_ERR_BAD_TYPE;
        if (type == AUV_TYPE_HEARTBEAT && len != 0) return _lastError = AUV_ERR_BAD_LENGTH;
        if (len > AUV_MAX_PAYLOAD) return _lastError = AUV_ERR_PAYLOAD_TOO_LARGE;
        AUV_Header h;
        h.version = AUV_PROTOCOL_VERSION;
        h.type = type; h.src = _local; h.dst = _peer; h.len = len;
        h.epoch = _nonces->epoch();
        if (!_seq.take(h.counter)) return _lastError = AUV_ERR_COUNTER_EXHAUSTED;
        h.echo = 0;
        AUV_Status s = _enc.seal(h, payload, out, outCap, outLen);
        if (s != AUV_OK) return _lastError = s;
        _txFrames++;
        return AUV_OK;
    }
    uint32_t txFrames() const { return _txFrames; }
    uint32_t txFingerprint() const { return _fp; }
    uint32_t myEpoch() const { return _nonces ? _nonces->epoch() : 0; }
    AUV_Status lastError() const { return _lastError; }
    AUV_TxSequence &testSequence() { return _seq; }

private:
    AUV_NonceManager *_nonces;
    AUV_Encryptor     _enc;
    AUV_TxSequence    _seq;
    uint8_t  _local, _peer;
    bool     _ready;
    uint32_t _txFrames;
    AUV_Status _lastError;
    uint32_t _fp;
};

#endif /* AUV_SECURE_LINK_H */
