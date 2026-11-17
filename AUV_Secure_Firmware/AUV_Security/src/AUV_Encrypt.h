/*
 * AUV_Encrypt.h
 * ---------------------------------------------------------------------------
 * AES-256-GCM sealing of one packet.
 *
 * Uses the "Crypto" library by Rhys Weatherley (Arduino Library Manager),
 * class GCM<AES256> with the documented AuthenticatedCipher API:
 *     setKey(), setIV(), addAuthData(), encrypt(), computeTag(), clear()
 *
 * The AES key schedule is computed ONCE in begin(); every packet only calls
 * setIV(), which is required anyway and costs two AES block operations.
 *
 * The caller (AUV_SecureLink) supplies epoch/counter from AUV_NonceManager,
 * so this class cannot pick a nonce by itself. It also refuses to encrypt
 * twice with the same (epoch, counter) in a row as a last line of defence.
 * ---------------------------------------------------------------------------
 */
#ifndef AUV_ENCRYPT_H
#define AUV_ENCRYPT_H

#include <Crypto.h>
#include <AES.h>
#include <GCM.h>
#include "AUV_SecurityConfig.h"
#include "AUV_Packet.h"

class AUV_Encryptor {
public:
    AUV_Encryptor() : _ready(false), _lastEpoch(0), _lastCounter(0), _used(false) {}
    ~AUV_Encryptor() { end(); }

    AUV_Status begin(const uint8_t key[AUV_KEY_SIZE]) {
        if (!key) return AUV_ERR_NULL;
        _gcm.clear();
        if (!_gcm.setKey(key, AUV_KEY_SIZE)) { _ready = false; return AUV_ERR_KEY_INVALID; }
        _ready = true;
        _used = false;
        return AUV_OK;
    }

    /* Wipe key schedule and state from RAM. */
    void end() {
        _gcm.clear();
        _ready = false;
        _used = false;
    }

    bool ready() const { return _ready; }

    /* Build a complete frame: header | ciphertext | tag.
     * h.type/src/dst/len/epoch/counter/echo must be filled by the caller.
     * Returns AUV_OK and *outLen = AUV_OVERHEAD + h.len. */
    AUV_Status seal(const AUV_Header &h, const uint8_t *payload,
                    uint8_t *out, size_t outCap, size_t *outLen) {
        if (!_ready) return AUV_ERR_NOT_READY;
        if (!out || !outLen || (h.len && !payload)) return AUV_ERR_NULL;
        if (h.len > AUV_MAX_PAYLOAD) return AUV_ERR_PAYLOAD_TOO_LARGE;
        size_t total = (size_t)AUV_OVERHEAD + h.len;
        if (outCap < total) return AUV_ERR_BUFFER_TOO_SMALL;
        if (h.epoch == 0) return AUV_ERR_NOT_READY;
        /* defence in depth: strictly increasing (epoch, counter) */
        if (_used && (h.epoch < _lastEpoch ||
                      (h.epoch == _lastEpoch && h.counter <= _lastCounter)))
            return AUV_ERR_COUNTER_EXHAUSTED;

        uint8_t nonce[AUV_NONCE_SIZE];
        AUV_encodeHeader(h, out);
        AUV_buildNonce(h.src, h.dst, h.epoch, h.counter, nonce);
        _gcm.setIV(nonce, AUV_NONCE_SIZE);
        _gcm.addAuthData(out, AUV_HEADER_SIZE);
        if (h.len) _gcm.encrypt(out + AUV_HEADER_SIZE, payload, h.len);
        _gcm.computeTag(out + AUV_HEADER_SIZE + h.len, AUV_TAG_SIZE);
        AUV_secureZero(nonce, sizeof(nonce));

        _lastEpoch = h.epoch;
        _lastCounter = h.counter;
        _used = true;
        *outLen = total;
        return AUV_OK;
    }

    /* Raw GCM access for known-answer tests (NIST vectors). Not used by the
     * protocol. Never call with a nonce that was used before. */
    bool katEncrypt(const uint8_t *key, const uint8_t *iv, size_t ivLen,
                    const uint8_t *aad, size_t aadLen,
                    const uint8_t *pt, size_t len, uint8_t *ct, uint8_t tag[16]) {
        GCM<AES256> g;
        if (!g.setKey(key, 32)) return false;
        g.setIV(iv, ivLen);
        if (aadLen) g.addAuthData(aad, aadLen);
        if (len) g.encrypt(ct, pt, len);
        g.computeTag(tag, 16);
        g.clear();
        return true;
    }

private:
    GCM<AES256> _gcm;
    bool     _ready;
    uint32_t _lastEpoch, _lastCounter;
    bool     _used;
};

#endif /* AUV_ENCRYPT_H */
