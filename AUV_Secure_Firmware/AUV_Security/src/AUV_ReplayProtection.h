/*
 * AUV_ReplayProtection.h
 * ---------------------------------------------------------------------------
 * Freshness rules applied to every received packet (per link):
 *
 *  1. Within one sender boot (same epoch) the counter must STRICTLY increase.
 *     UART is point-to-point and never reorders, so no reorder window is
 *     needed: duplicates and older packets are rejected.
 *  2. A packet whose sender epoch is LOWER than one already seen is rejected
 *     (packet recorded before the sender's last reboot).
 *  3. A higher sender epoch is accepted (the sender rebooted) and the counter
 *     tracking restarts for that epoch.
 *  4. Every packet carries an "echo": the receiver's own boot epoch as last
 *     seen by the sender. A packet is DELIVERED to the application only if
 *     echo == our current epoch. Our epoch is new after every boot, so any
 *     packet recorded before our last reboot can never be delivered again -
 *     even though we lost our RAM replay state in that reboot.
 *
 * Rules 1-3 are checked twice: a cheap pre-check before crypto (no state
 * change, saves CPU against replay floods) and again after the GCM tag has
 * been verified, when the state is updated. State is ONLY updated by packets
 * that passed authentication, so forged packets cannot move the window.
 * ---------------------------------------------------------------------------
 */
#ifndef AUV_REPLAY_PROTECTION_H
#define AUV_REPLAY_PROTECTION_H

#include "AUV_SecurityConfig.h"

struct AUV_ReplayStats {
    uint32_t replays;       /* duplicate / older counter, same epoch */
    uint32_t oldEpochs;     /* sender epoch older than known */
    uint32_t staleEchoes;   /* authentic but not fresh for our boot */
    uint32_t peerReboots;   /* sender epoch increased */
};

class AUV_ReplayGuard {
public:
    AUV_ReplayGuard() { reset(); }

    /* Forget everything about the peer (call at our own boot). */
    void reset() {
        _peerEpoch = 0;
        _lastCounter = 0;
        _haveCounter = false;
        _stats.replays = _stats.oldEpochs = _stats.staleEchoes = _stats.peerReboots = 0;
    }

    /* Cheap check BEFORE crypto. Does not modify state. */
    AUV_Status precheck(uint32_t epoch, uint32_t counter) const {
        if (epoch == 0) return AUV_ERR_BAD_EPOCH;
        if (epoch < _peerEpoch) return AUV_ERR_OLD_EPOCH;
        if (epoch == _peerEpoch && _haveCounter && counter <= _lastCounter) return AUV_ERR_REPLAY;
        return AUV_OK;
    }

    /* Call ONLY after the GCM tag verified. Re-checks and updates state. */
    AUV_Status accept(uint32_t epoch, uint32_t counter) {
        AUV_Status s = precheck(epoch, counter);
        if (s != AUV_OK) { count(s); return s; }
        if (epoch > _peerEpoch) {
            if (_peerEpoch != 0) _stats.peerReboots++;
            _peerEpoch = epoch;
        }
        _lastCounter = counter;
        _haveCounter = true;
        return AUV_OK;
    }

    /* Rule 4: is this authenticated packet provably fresh for our boot? */
    AUV_Status checkEcho(uint32_t echo, uint32_t myEpoch) {
        if (myEpoch != 0 && echo == myEpoch) return AUV_OK;
        _stats.staleEchoes++;
        return AUV_ERR_STALE_ECHO;
    }

    void count(AUV_Status s) {
        if (s == AUV_ERR_REPLAY) _stats.replays++;
        else if (s == AUV_ERR_OLD_EPOCH) _stats.oldEpochs++;
    }

    uint32_t peerEpoch() const   { return _peerEpoch; }   /* value we echo back */
    uint32_t lastCounter() const { return _lastCounter; }
    const AUV_ReplayStats &stats() const { return _stats; }

private:
    uint32_t _peerEpoch;
    uint32_t _lastCounter;
    bool     _haveCounter;
    AUV_ReplayStats _stats;
};

#endif /* AUV_REPLAY_PROTECTION_H */
