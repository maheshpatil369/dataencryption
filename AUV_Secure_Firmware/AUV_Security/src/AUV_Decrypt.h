/*
 * AUV_Decrypt.h
 * ---------------------------------------------------------------------------
 * AES-256-GCM opening of one packet.
 *
 * "Authenticate before use": GCM's tag is computed over the CIPHERTEXT and the
 * header, so the library hashes the ciphertext while decrypting. The
 * plaintext is written ONLY into this class's private scratch buffer. It is
 * copied to the caller only after checkTag() succeeded (constant-time
 * compare inside the library). On failure the scratch buffer is wiped and
 * the caller's output buffer is left zeroed, so unauthenticated plaintext
 * can never reach command handling.
 * ---------------------------------------------------------------------------
 */
#ifndef AUV_DECRYPT_H
#define AUV_DECRYPT_H

#include <Crypto.h>
#include <AES.h>
#include <GCM.h>
#include "AUV_SecurityConfig.h"
#include "AUV_Packet.h"

class AUV_Decryptor {
public:
    AUV_Decryptor() : _ready(false) { AUV_secureZero(_scratch, sizeof(_scratch)); }
    ~AUV_Decryptor() { end(); }

    AUV_Status begin(const uint8_t key[AUV_KEY_SIZE]) {
        if (!key) return AUV_ERR_NULL;
        _gcm.clear();
        if (!_gcm.setKey(key, AUV_KEY_SIZE)) { _ready = false; return AUV_ERR_KEY_INVALID; }
        _ready = true;
        return AUV_OK;
    }

    void end() {
        _gcm.clear();
        AUV_secureZero(_scratch, sizeof(_scratch));
        _ready = false;
    }

    bool ready() const { return _ready; }

    /* frame   : complete frame (header | ciphertext | tag)
     * h       : decoded header of that frame (already structurally validated)
     * plainOut: caller buffer of at least AUV_MAX_PAYLOAD bytes
     * Returns AUV_OK (plainOut holds h.len bytes) or AUV_ERR_AUTH_FAILED. */
    AUV_Status open(const uint8_t *frame, size_t frameLen, const AUV_Header &h,
                    uint8_t *plainOut) {
        if (!_ready) return AUV_ERR_NOT_READY;
        if (!frame || !plainOut) return AUV_ERR_NULL;
        if (h.len > AUV_MAX_PAYLOAD) return AUV_ERR_BAD_LENGTH;
        if (frameLen != (size_t)AUV_OVERHEAD + h.len) return AUV_ERR_BAD_LENGTH;

        uint8_t nonce[AUV_NONCE_SIZE];
        AUV_buildNonce(h.src, h.dst, h.epoch, h.counter, nonce);
        _gcm.setIV(nonce, AUV_NONCE_SIZE);
        _gcm.addAuthData(frame, AUV_HEADER_SIZE);
        if (h.len) _gcm.decrypt(_scratch, frame + AUV_HEADER_SIZE, h.len);
        bool ok = _gcm.checkTag(frame + AUV_HEADER_SIZE + h.len, AUV_TAG_SIZE);
        AUV_secureZero(nonce, sizeof(nonce));

        if (!ok) {
            AUV_secureZero(_scratch, sizeof(_scratch));
            AUV_secureZero(plainOut, AUV_MAX_PAYLOAD);
            return AUV_ERR_AUTH_FAILED;
        }
        if (h.len) memcpy(plainOut, _scratch, h.len);
        AUV_secureZero(_scratch, sizeof(_scratch));
        return AUV_OK;
    }

    /* Raw GCM access for known-answer tests (NIST vectors). */
    bool katDecrypt(const uint8_t *key, const uint8_t *iv, size_t ivLen,
                    const uint8_t *aad, size_t aadLen,
                    const uint8_t *ct, size_t len, const uint8_t tag[16], uint8_t *pt) {
        GCM<AES256> g;
        if (!g.setKey(key, 32)) return false;
        g.setIV(iv, ivLen);
        if (aadLen) g.addAuthData(aad, aadLen);
        if (len) g.decrypt(pt, ct, len);
        bool ok = g.checkTag(tag, 16);
        g.clear();
        if (!ok && len) AUV_secureZero(pt, len);
        return ok;
    }

private:
    GCM<AES256> _gcm;
    bool    _ready;
    uint8_t _scratch[AUV_MAX_PAYLOAD];
};

#endif /* AUV_DECRYPT_H */
