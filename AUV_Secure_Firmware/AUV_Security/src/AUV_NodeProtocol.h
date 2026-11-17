/*
 * AUV_NodeProtocol.h
 * ---------------------------------------------------------------------------
 * Binary payloads that travel INSIDE the encrypted packets, strict command
 * validation, and the safety state machines that must not depend on the
 * communication link being trustworthy:
 *
 *   - AUV_ThrusterSafety : thruster/servo/relay outputs go to a safe state at
 *                          boot, on link loss, on command timeout, on an
 *                          invalid command stream and on a leak flag.
 *   - AUV_LeakMonitor    : debounced local leak detection; the Sensor node
 *                          takes no remote commands, so nothing can override it.
 *
 * All payloads are fixed-size, little-endian, and decoded with explicit
 * length checks (a payload of the wrong length is rejected, never padded).
 *
 * Values marked [CONFIRM] come from the earlier review of your sketches and
 * must be checked against your hardware (ESC neutral, relay polarity).
 * ---------------------------------------------------------------------------
 */
#ifndef AUV_NODE_PROTOCOL_H
#define AUV_NODE_PROTOCOL_H

#include <string.h>
#include "AUV_SecurityConfig.h"
#include "AUV_Packet.h"

inline void AUV_putF32(uint8_t *p, float f) { uint32_t u; memcpy(&u, &f, 4); AUV_putU32(p, u); }
inline float AUV_getF32(const uint8_t *p) { uint32_t u = AUV_getU32(p); float f; memcpy(&f, &u, 4); return f; }
inline bool AUV_isFiniteF(float f) { return f == f && f < 3.0e38f && f > -3.0e38f; }

/* ============================ THRUSTER ================================== */
#ifndef THRUSTER_MIN_US
#define THRUSTER_MIN_US      1100   /* from Thruster.ino range check */
#endif
#ifndef THRUSTER_MAX_US
#define THRUSTER_MAX_US      1900
#endif
#ifndef THRUSTER_NEUTRAL_US
#define THRUSTER_NEUTRAL_US  1500   /* [CONFIRM] neutral/stop of your ESC */
#endif
#ifndef SERVO_MAX_DEG
#define SERVO_MAX_DEG        180
#endif
#ifndef SERVO_SAFE_DEG
#define SERVO_SAFE_DEG       90     /* [CONFIRM] servo position used in failsafe */
#endif
#ifndef THRUSTER_CMD_TIMEOUT_MS
#define THRUSTER_CMD_TIMEOUT_MS 250 /* no valid command -> neutral */
#endif
#ifndef THRUSTER_MAX_INVALID_STREAK
#define THRUSTER_MAX_INVALID_STREAK 5 /* consecutive invalid cmds -> neutral */
#endif
/* Maximum change of the ESC pulse per accepted command (us). 0 = disabled
 * (keeps the original behaviour). E.g. 100 limits reversal shocks. */
#ifndef THRUSTER_MAX_STEP_US
#define THRUSTER_MAX_STEP_US 0
#endif

#define THR_FLAG_LEAK_STOP   0x01   /* master/Jetson reports a leak: stop */

/* COMMAND payload, master -> thruster, exactly 8 bytes */
struct AUV_ThrusterCmd {
    uint8_t  servo[4];      /* degrees 0..180 (PCA9685 ch 12..15) */
    uint16_t thrusterUs;    /* 1100..1900 */
    uint8_t  relayMask;     /* bit0 relay1 (PB12), bit1 relay2 (PB13) */
    uint8_t  flags;         /* THR_FLAG_* */
};
#define AUV_THRUSTER_CMD_LEN 8

inline void AUV_encodeThrusterCmd(const AUV_ThrusterCmd &c, uint8_t out[AUV_THRUSTER_CMD_LEN]) {
    memcpy(out, c.servo, 4);
    AUV_putU16(out + 4, c.thrusterUs);
    out[6] = c.relayMask;
    out[7] = c.flags;
}

/* Strict validation: every field must be in range, unknown bits rejected. */
inline bool AUV_decodeThrusterCmd(const uint8_t *p, uint8_t len, AUV_ThrusterCmd &c) {
    if (len != AUV_THRUSTER_CMD_LEN) return false;
    for (uint8_t i = 0; i < 4; i++) if (p[i] > SERVO_MAX_DEG) return false;
    uint16_t us = AUV_getU16(p + 4);
    if (us < THRUSTER_MIN_US || us > THRUSTER_MAX_US) return false;
    if (p[6] & ~0x03) return false;
    if (p[7] & ~THR_FLAG_LEAK_STOP) return false;
    memcpy(c.servo, p, 4);
    c.thrusterUs = us;
    c.relayMask = p[6];
    c.flags = p[7];
    return true;
}

enum AUV_ThrusterState : uint8_t {
    THR_STATE_BOOT_SAFE = 0,    /* no valid command since boot */
    THR_STATE_ACTIVE    = 1,
    THR_STATE_TIMEOUT   = 2,    /* commands stopped / link down */
    THR_STATE_LEAK_STOP = 3,
    THR_STATE_INVALID   = 4     /* too many invalid commands */
};

/* STATUS/TELEMETRY payload, thruster -> master, exactly 12 bytes */
struct AUV_ThrusterStatus {
    uint8_t  servo[4];
    uint16_t thrusterUs;
    uint8_t  relayMask;
    uint8_t  relayOutput;   /* actual relay pin state read back */
    uint8_t  state;         /* AUV_ThrusterState */
    uint8_t  reserved;
    uint16_t invalidCmds;   /* saturating counter */
};
#define AUV_THRUSTER_STATUS_LEN 12

inline void AUV_encodeThrusterStatus(const AUV_ThrusterStatus &s, uint8_t out[AUV_THRUSTER_STATUS_LEN]) {
    memcpy(out, s.servo, 4);
    AUV_putU16(out + 4, s.thrusterUs);
    out[6] = s.relayMask; out[7] = s.relayOutput; out[8] = s.state; out[9] = 0;
    AUV_putU16(out + 10, s.invalidCmds);
}
inline bool AUV_decodeThrusterStatus(const uint8_t *p, uint8_t len, AUV_ThrusterStatus &s) {
    if (len != AUV_THRUSTER_STATUS_LEN) return false;
    memcpy(s.servo, p, 4);
    s.thrusterUs = AUV_getU16(p + 4);
    s.relayMask = p[6]; s.relayOutput = p[7]; s.state = p[8]; s.reserved = p[9];
    s.invalidCmds = AUV_getU16(p + 10);
    return true;
}

/* Decides what the thruster node outputs. Pure logic, no hardware access:
 * call update() every loop and write output() to the PCA9685/ESC/relays. */
class AUV_ThrusterSafety {
public:
    AUV_ThrusterSafety() { reset(); }
    void reset() {
        _out = safeCmd();
        _state = THR_STATE_BOOT_SAFE;
        _lastValidMs = 0;
        _haveValid = false;
        _invalidStreak = 0;
        _invalidTotal = 0;
    }
    static AUV_ThrusterCmd safeCmd() {
        AUV_ThrusterCmd c;
        for (uint8_t i = 0; i < 4; i++) c.servo[i] = SERVO_SAFE_DEG;
        c.thrusterUs = THRUSTER_NEUTRAL_US;
        c.relayMask = 0;            /* [CONFIRM] relays OFF is the safe state */
        c.flags = 0;
        return c;
    }
    /* An AUTHENTICATED command payload arrived (only call with payloads
     * delivered by AUV_SecureLink). Returns true if applied. */
    bool onCommand(const uint8_t *p, uint8_t len, uint32_t nowMs) {
        AUV_ThrusterCmd c;
        if (!AUV_decodeThrusterCmd(p, len, c)) {
            _invalidStreak++;
            if (_invalidTotal < 0xFFFF) _invalidTotal++;
            if (_invalidStreak >= THRUSTER_MAX_INVALID_STREAK) enterSafe(THR_STATE_INVALID);
            return false;
        }
        _invalidStreak = 0;
        _lastValidMs = nowMs;
        _haveValid = true;
        if (c.flags & THR_FLAG_LEAK_STOP) { enterSafe(THR_STATE_LEAK_STOP); return true; }
#if THRUSTER_MAX_STEP_US > 0
        int32_t cur = (_state == THR_STATE_ACTIVE) ? _out.thrusterUs : THRUSTER_NEUTRAL_US;
        int32_t d = (int32_t)c.thrusterUs - cur;
        if (d >  THRUSTER_MAX_STEP_US) c.thrusterUs = (uint16_t)(cur + THRUSTER_MAX_STEP_US);
        if (d < -THRUSTER_MAX_STEP_US) c.thrusterUs = (uint16_t)(cur - THRUSTER_MAX_STEP_US);
#endif
        _out = c;
        _state = THR_STATE_ACTIVE;
        return true;
    }
    /* Call every loop with the link status. A local leak input (if wired
     * directly to this node) can be passed as localLeak. */
    void update(uint32_t nowMs, bool linkUp, bool localLeak = false) {
        if (localLeak) { enterSafe(THR_STATE_LEAK_STOP); return; }
        if (_state == THR_STATE_ACTIVE &&
            (!linkUp || (uint32_t)(nowMs - _lastValidMs) > THRUSTER_CMD_TIMEOUT_MS))
            enterSafe(THR_STATE_TIMEOUT);
    }
    const AUV_ThrusterCmd &output() const { return _out; }
    AUV_ThrusterState state() const { return _state; }
    uint16_t invalidCount() const { return _invalidTotal; }
private:
    void enterSafe(AUV_ThrusterState s) { _out = safeCmd(); _state = s; }
    AUV_ThrusterCmd _out;
    AUV_ThrusterState _state;
    uint32_t _lastValidMs;
    bool _haveValid;
    uint8_t _invalidStreak;
    uint16_t _invalidTotal;
};

/* ============================== SENSOR ================================== */
/* The Sensor node is encrypt-only: it accepts NO remote commands. The leak
 * relay is driven only by its own leak inputs (AUV_LeakMonitor below). */
#ifndef SENSOR_RELAY_LEAK_STATE
#define SENSOR_RELAY_LEAK_STATE 1    /* [CONFIRM] relay level when a leak is active */
#endif
#ifndef SENSOR_RELAY_IDLE_STATE
#define SENSOR_RELAY_IDLE_STATE 0    /* [CONFIRM] relay level with no leak */
#endif
#ifndef SENSOR_LEAK_DEBOUNCE
#define SENSOR_LEAK_DEBOUNCE 3       /* consecutive samples (10 ms each) */
#endif
#ifndef SENSOR_LEAK_LATCH
#define SENSOR_LEAK_LATCH 0          /* 1 = keep leak state until power cycle */
#endif

/* TELEMETRY payload, sensor -> master, exactly 28 bytes */
struct AUV_SensorTelemetry {
    uint32_t tick;
    float voltage, current, power, temperature, humidity;
    uint8_t leakMask;      /* bit0..3 = leak1..4 (PB12..PB15) */
    uint8_t relay;         /* actual relay output */
    uint8_t leakActive;    /* 1 = debounced leak active */
    uint8_t flags;         /* bit0 DHT ok, bit1 INA260 ok */
};
#define AUV_SENSOR_TELEM_LEN 28

inline void AUV_encodeSensorTelemetry(const AUV_SensorTelemetry &t, uint8_t o[AUV_SENSOR_TELEM_LEN]) {
    AUV_putU32(o, t.tick);
    AUV_putF32(o + 4, t.voltage); AUV_putF32(o + 8, t.current); AUV_putF32(o + 12, t.power);
    AUV_putF32(o + 16, t.temperature); AUV_putF32(o + 20, t.humidity);
    o[24] = t.leakMask; o[25] = t.relay; o[26] = t.leakActive; o[27] = t.flags;
}
inline bool AUV_decodeSensorTelemetry(const uint8_t *p, uint8_t len, AUV_SensorTelemetry &t) {
    if (len != AUV_SENSOR_TELEM_LEN) return false;
    t.tick = AUV_getU32(p);
    t.voltage = AUV_getF32(p + 4); t.current = AUV_getF32(p + 8); t.power = AUV_getF32(p + 12);
    t.temperature = AUV_getF32(p + 16); t.humidity = AUV_getF32(p + 20);
    t.leakMask = p[24]; t.relay = p[25]; t.leakActive = p[26]; t.flags = p[27];
    return (t.leakMask & 0xF0) == 0 && t.leakActive <= 1 && t.relay <= 1;
}

/* Local leak logic: debounced, no remote override possible. */
class AUV_LeakMonitor {
public:
    AUV_LeakMonitor() : _count(0), _active(false), _latched(false), _mask(0) {}
    /* rawMask: bit i set = leak input i is wet right now. Call at a fixed rate. */
    void update(uint8_t rawMask) {
        _mask = rawMask & 0x0F;
        if (_mask) { if (_count < 255) _count++; }
        else _count = 0;
        if (_count >= SENSOR_LEAK_DEBOUNCE) { _active = true; if (SENSOR_LEAK_LATCH) _latched = true; }
        else if (_count == 0 && !_latched) _active = false;
    }
    bool    active() const { return _active; }
    uint8_t mask() const { return _mask; }
    uint8_t relayLevel() const { return _active ? SENSOR_RELAY_LEAK_STATE : SENSOR_RELAY_IDLE_STATE; }
private:
    uint8_t _count;
    bool _active, _latched;
    uint8_t _mask;
};

/* =============================== IMU ==================================== */
/* TELEMETRY payload, IMU -> master, exactly 57 bytes */
struct AUV_ImuTelemetry {
    uint32_t tick;
    float q[4];        /* qx qy qz qw */
    float accel[3], gyro[3], mag[3];
    uint8_t connected;
};
#define AUV_IMU_TELEM_LEN 57
static_assert(AUV_IMU_TELEM_LEN <= AUV_MAX_PAYLOAD, "IMU telemetry must fit");

inline void AUV_encodeImuTelemetry(const AUV_ImuTelemetry &t, uint8_t o[AUV_IMU_TELEM_LEN]) {
    AUV_putU32(o, t.tick);
    uint8_t *p = o + 4;
    for (uint8_t i = 0; i < 4; i++, p += 4) AUV_putF32(p, t.q[i]);
    for (uint8_t i = 0; i < 3; i++, p += 4) AUV_putF32(p, t.accel[i]);
    for (uint8_t i = 0; i < 3; i++, p += 4) AUV_putF32(p, t.gyro[i]);
    for (uint8_t i = 0; i < 3; i++, p += 4) AUV_putF32(p, t.mag[i]);
    *p = t.connected;
}
inline bool AUV_decodeImuTelemetry(const uint8_t *o, uint8_t len, AUV_ImuTelemetry &t) {
    if (len != AUV_IMU_TELEM_LEN) return false;
    t.tick = AUV_getU32(o);
    const uint8_t *p = o + 4;
    for (uint8_t i = 0; i < 4; i++, p += 4) t.q[i] = AUV_getF32(p);
    for (uint8_t i = 0; i < 3; i++, p += 4) t.accel[i] = AUV_getF32(p);
    for (uint8_t i = 0; i < 3; i++, p += 4) t.gyro[i] = AUV_getF32(p);
    for (uint8_t i = 0; i < 3; i++, p += 4) t.mag[i] = AUV_getF32(p);
    t.connected = *p;
    return t.connected <= 1;
}

/* ===================== Master <-> Jetson envelope ======================== */
/* Telemetry forwarded by the Master keeps the ORIGINAL sender's epoch and
 * counter, so the Jetson can check freshness end to end (and remember it in
 * a file across reboots):
 *     [nodeId (1)] [sender epoch (4)] [sender counter (4)] [node payload]
 * Commands from the Jetson: [target nodeId (1)] [node command payload]. */
#define AUV_ENV_HDR 9
static_assert(AUV_ENV_HDR + AUV_IMU_TELEM_LEN <= AUV_MAX_PAYLOAD, "envelope must fit");

inline uint8_t AUV_encodeEnvelope(uint8_t nodeId, uint32_t epoch, uint32_t counter,
                                  const uint8_t *p, uint8_t len, uint8_t *out) {
    if ((uint16_t)len + AUV_ENV_HDR > AUV_MAX_PAYLOAD) return 0;
    out[0] = nodeId;
    AUV_putU32(out + 1, epoch);
    AUV_putU32(out + 5, counter);
    if (len) memcpy(out + AUV_ENV_HDR, p, len);
    return (uint8_t)(AUV_ENV_HDR + len);
}

#endif /* AUV_NODE_PROTOCOL_H */
