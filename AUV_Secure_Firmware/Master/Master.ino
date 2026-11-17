/*
 * Master.ino  -  AUV Master: secure gateway between the 3 nodes and the Jetson
 * ---------------------------------------------------------------------------
 * Every incoming packet is authenticated and decrypted, checked, and then
 * re-encrypted for the next hop. Nothing is forwarded blindly.
 *
 *   Sensor   --K1-->  Master  --K5 (envelope)-->  Jetson
 *   IMU      --K2-->  Master  --K5 (envelope)-->  Jetson
 *   Thruster --K3-->  Master  --K5 (envelope)-->  Jetson
 *   Jetson   --K6-->  Master  --K4------------->  Thruster   (commands)
 *
 * Telemetry is forwarded inside an envelope [node id | original epoch |
 * original counter | payload], so the Jetson checks freshness end to end.
 *
 * Safety rules enforced here (in addition to the Thruster's own fail-safe):
 *   - Thruster commands are range-checked before re-encryption.
 *   - Leak active, OR no fresh Sensor data for 300 ms -> every command to the
 *     Thruster carries the LEAK_STOP flag (thruster neutral).
 *   - Jetson link down -> the Master sends NEUTRAL commands to the Thruster.
 *
 * BOARD: needs 4 hardware UARTs. Recommended STM32H753 (hardware AES unit).
 * The default pins below exist on STM32F4/F7/H7 parts; check them against
 * your board before wiring. A Blue Pill (3 UARTs) cannot host all 4 links.
 * Set the board in Tools, and USB support = "CDC (generic Serial supersede
 * U(S)ART)" so `Serial` is the USB debug port and USART1 stays free.
 *
 * Libraries: AUV_Security, Crypto (Rhys Weatherley)
 * ---------------------------------------------------------------------------
 */
#if __has_include("AUV_Keys_Secret.h")
  #define AUV_USING_DEMO_KEYS 0
#else
  #define AUV_USING_DEMO_KEYS 1
  #define AUV_ALLOW_DEMO_KEYS 1      /* BENCH ONLY: public keys, no security */
#endif
#include <AUV_Security.h>
#if !AUV_USING_DEMO_KEYS
  #include "AUV_Keys_Secret.h"
#endif
#include <IWatchdog.h>

/* --------------------------- UART pin map -------------------------------- */
/*                      RX      TX       peripheral                          */
#define JETSON_RX       PA10   /* USART1 */
#define JETSON_TX       PA9
#define THRUSTER_RX     PA3    /* USART2 */
#define THRUSTER_TX     PA2
#define SENSOR_RX       PB11   /* USART3 (only RX is used) */
#define SENSOR_TX       PB10
#ifndef MASTER_ENABLE_IMU_LINK
  #if defined(STM32F1xx)
    #define MASTER_ENABLE_IMU_LINK 0   /* Blue Pill: no 4th UART */
    #warning "STM32F1 Blue Pill: IMU link disabled (only 3 UARTs). Use a 4-UART board."
  #else
    #define MASTER_ENABLE_IMU_LINK 1
  #endif
#endif
#define IMU_RX          PC7    /* USART6 (only RX is used); [CONFIRM] free on your board */
#define IMU_TX          PC6
#define LINK_BAUD       1000000
#define JETSON_BAUD     1000000

#define HEARTBEAT_MS        20     /* keep-alive when nothing else was sent */
#define SENSOR_STALE_MS     300    /* no sensor data -> treat as possible leak */
#ifndef MASTER_STOP_ON_SENSOR_LOSS
#define MASTER_STOP_ON_SENSOR_LOSS 1   /* 1 = losing the Sensor (leak) link stops thrusters */
#endif
#define MAX_RX_BYTES_PER_PORT 256  /* per loop pass, bounds worst-case latency */

AUV_Uart JetsonSerial(JETSON_RX, JETSON_TX);
AUV_Uart ThrusterSerial(THRUSTER_RX, THRUSTER_TX);
AUV_Uart SensorSerial(SENSOR_RX, SENSOR_TX);
#if MASTER_ENABLE_IMU_LINK
AUV_Uart ImuSerial(IMU_RX, IMU_TX);
#endif

AUV_DefaultFlash flash;
AUV_NonceManager nonces;
AUV_SecureLink   jetsonLink;    /* duplex: K5 out, K6 in */
AUV_SecureLink   thrusterLink;  /* duplex: K4 out, K3 in */
AUV_SecureLink   sensorLink;    /* receive only: K1 */
#if MASTER_ENABLE_IMU_LINK
AUV_SecureLink   imuLink;       /* receive only: K2 */
#endif

static bool     secOk = false;
static uint8_t  txFrame[AUV_MAX_FRAME];
static uint8_t  env[AUV_MAX_PAYLOAD];
static AUV_RxMessage msg;
static uint32_t lastJetsonTxMs = 0, lastThrusterTxMs = 0, lastPrintMs = 0;
static uint32_t sensorFreshMs = 0;
static bool     sensorSeen = false, leakActive = false, jetsonWasUp = false;
static uint32_t cmdForwarded = 0, cmdRejected = 0, telemForwarded = 0;
static uint32_t cryptoMaxUs = 0;

/* ------------------------------ security -------------------------------- */
static AUV_Status startLink(AUV_SecureLink &l, const AUV_LinkKeys *prod, uint8_t peer,
                            AUV_LinkMode mode, const __FlashStringHelper *name) {
    AUV_LinkKeys k;
#if AUV_USING_DEMO_KEYS
    (void)prod;
    AUV_demoLinkKeys(AUV_ID_MASTER, peer, k);
    if (mode == AUV_LINK_RX_ONLY) memset(k.txKey, 0, sizeof k.txKey);
#else
    (void)peer;
    memcpy(&k, prod, sizeof k);
#endif
    AUV_Status s = l.begin(k, nonces, mode);
    AUV_secureZero(&k, sizeof k);
    Serial.print(name); Serial.print(F(": ")); Serial.print(AUV_statusName(s));
    Serial.print(F(" rx fp=")); Serial.print(l.rxFingerprint(), HEX);
    if (mode == AUV_LINK_DUPLEX) { Serial.print(F(" tx fp=")); Serial.print(l.txFingerprint(), HEX); }
    Serial.println();
    return s;
}

static bool startSecurity() {
    AUV_Status s = nonces.begin(flash);
#if AUV_USING_DEMO_KEYS
    if (s == AUV_ERR_NVM_INVALID) s = nonces.provision(flash, 1);
    Serial.println(F("WARNING: DEMO KEYS - bench test only, NOT secure"));
#endif
    if (s != AUV_OK) {
        Serial.print(F("SECURITY: epoch store ")); Serial.println(AUV_statusName(s));
        Serial.println(F("Run AUV_Provision on this board. No commands will be forwarded."));
        return false;
    }
    Serial.print(F("Master epoch=")); Serial.println(nonces.epoch());
    bool ok = true;
#if AUV_USING_DEMO_KEYS
    ok &= startLink(jetsonLink,   0, AUV_ID_JETSON,   AUV_LINK_DUPLEX,  F("Jetson  ")) == AUV_OK;
    ok &= startLink(thrusterLink, 0, AUV_ID_THRUSTER, AUV_LINK_DUPLEX,  F("Thruster")) == AUV_OK;
    ok &= startLink(sensorLink,   0, AUV_ID_SENSOR,   AUV_LINK_RX_ONLY, F("Sensor  ")) == AUV_OK;
  #if MASTER_ENABLE_IMU_LINK
    ok &= startLink(imuLink,      0, AUV_ID_IMU,      AUV_LINK_RX_ONLY, F("IMU     ")) == AUV_OK;
  #endif
#else
    ok &= startLink(jetsonLink,   &AUV_KEYS_MASTER_JETSON,   AUV_ID_JETSON,   AUV_LINK_DUPLEX,  F("Jetson  ")) == AUV_OK;
    ok &= startLink(thrusterLink, &AUV_KEYS_MASTER_THRUSTER, AUV_ID_THRUSTER, AUV_LINK_DUPLEX,  F("Thruster")) == AUV_OK;
    ok &= startLink(sensorLink,   &AUV_KEYS_MASTER_SENSOR,   AUV_ID_SENSOR,   AUV_LINK_RX_ONLY, F("Sensor  ")) == AUV_OK;
  #if MASTER_ENABLE_IMU_LINK
    ok &= startLink(imuLink,      &AUV_KEYS_MASTER_IMU,      AUV_ID_IMU,      AUV_LINK_RX_ONLY, F("IMU     ")) == AUV_OK;
  #endif
#endif
    return ok;
}

/* ------------------------------ sending --------------------------------- */
static void track(uint32_t c0) {
    uint32_t us = AUV_cyclesToUs(AUV_cycles() - c0);
    if (us > cryptoMaxUs) cryptoMaxUs = us;
}

static bool sendTo(AUV_SecureLink &l, Stream &port, uint8_t type, const uint8_t *p, uint8_t len) {
    size_t n = 0;
    uint32_t c0 = AUV_cycles();
    AUV_Status s = l.buildFrame(type, p, len, txFrame, sizeof txFrame, &n);
    track(c0);
    if (s != AUV_OK) return false;
    port.write(txFrame, n);
    return true;
}

static void forwardToJetson(uint8_t nodeId, const AUV_RxMessage &m, uint32_t nowMs) {
    uint8_t len = AUV_encodeEnvelope(nodeId, m.epoch, m.counter, m.payload, m.len, env);
    if (len && sendTo(jetsonLink, JetsonSerial, AUV_TYPE_TELEMETRY, env, len)) {
        lastJetsonTxMs = nowMs;
        telemForwarded++;
    }
}

static bool leakStopRequired(uint32_t nowMs) {
    bool stale = !sensorSeen || (uint32_t)(nowMs - sensorFreshMs) > SENSOR_STALE_MS;
    return leakActive || (MASTER_STOP_ON_SENSOR_LOSS && stale);
}

static void sendThrusterCmd(AUV_ThrusterCmd c, uint32_t nowMs) {
    if (leakStopRequired(nowMs)) c.flags |= THR_FLAG_LEAK_STOP;
    uint8_t p[AUV_THRUSTER_CMD_LEN];
    AUV_encodeThrusterCmd(c, p);
    if (sendTo(thrusterLink, ThrusterSerial, AUV_TYPE_COMMAND, p, sizeof p)) lastThrusterTxMs = nowMs;
}

/* ------------------------------ receiving ------------------------------- */
static void onJetson(const AUV_RxMessage &m, uint32_t nowMs) {
    if (m.type != AUV_TYPE_COMMAND || m.len < 1) return;          /* heartbeat: link timer only */
    if (m.payload[0] == AUV_ID_THRUSTER) {
        AUV_ThrusterCmd c;
        if (!AUV_decodeThrusterCmd(m.payload + 1, (uint8_t)(m.len - 1), c)) { cmdRejected++; return; }
        sendThrusterCmd(c, nowMs);                                 /* forward immediately: lowest latency */
        cmdForwarded++;
    } else {
        cmdRejected++;                                             /* Sensor/IMU take no commands */
    }
}

static void onSensor(const AUV_RxMessage &m, uint32_t nowMs) {
    AUV_SensorTelemetry t;
    if (m.type != AUV_TYPE_TELEMETRY || !AUV_decodeSensorTelemetry(m.payload, m.len, t)) return;
    sensorSeen = true;
    sensorFreshMs = nowMs;
    bool wasLeak = leakActive;
    leakActive = t.leakActive != 0;
    if (leakActive && !wasLeak) {                                  /* stop thrusters NOW */
        sendThrusterCmd(AUV_ThrusterSafety::safeCmd(), nowMs);
    }
    forwardToJetson(AUV_ID_SENSOR, m, nowMs);
}

static void pump(AUV_SecureLink &l, Stream &port, uint8_t nodeId, uint32_t nowMs) {
    uint16_t budget = MAX_RX_BYTES_PER_PORT;
    while (budget-- && port.available()) {
        uint32_t c0 = AUV_cycles();
        AUV_Status s = l.rxByte((uint8_t)port.read(), nowMs, msg);
        if (s != AUV_MSG_READY) continue;
        track(c0);
        switch (nodeId) {
            case AUV_ID_JETSON:   onJetson(msg, nowMs); break;
            case AUV_ID_SENSOR:   onSensor(msg, nowMs); break;
            case AUV_ID_THRUSTER: if (msg.type != AUV_TYPE_HEARTBEAT) forwardToJetson(AUV_ID_THRUSTER, msg, nowMs); break;
            case AUV_ID_IMU:      if (msg.type == AUV_TYPE_TELEMETRY) forwardToJetson(AUV_ID_IMU, msg, nowMs); break;
        }
    }
    l.poll(nowMs);
}

/* -------------------------------- setup --------------------------------- */
void setup() {
    Serial.begin(115200);                                          /* USB debug */
    if (IWatchdog.isReset(true)) Serial.println(F("Recovered from WATCHDOG reset"));
    AUV_cyclesInit();
    JetsonSerial.begin(JETSON_BAUD);
    ThrusterSerial.begin(LINK_BAUD);
    SensorSerial.begin(LINK_BAUD);
#if MASTER_ENABLE_IMU_LINK
    ImuSerial.begin(LINK_BAUD);
#endif
    secOk = startSecurity();
    IWatchdog.begin(500000);
}

void loop() {
    uint32_t nowMs = millis();
    if (secOk) {
        /* commands first: they are the latency-critical path */
        pump(jetsonLink,   JetsonSerial,   AUV_ID_JETSON,   nowMs);
        pump(sensorLink,   SensorSerial,   AUV_ID_SENSOR,   nowMs);
        pump(thrusterLink, ThrusterSerial, AUV_ID_THRUSTER, nowMs);
#if MASTER_ENABLE_IMU_LINK
        pump(imuLink,      ImuSerial,      AUV_ID_IMU,      nowMs);
#endif
        bool jetsonUp = jetsonLink.linkUp(nowMs);

        /* Jetson lost: actively hold the thruster at neutral */
        if (!jetsonUp && (uint32_t)(nowMs - lastThrusterTxMs) >= 10)
            sendThrusterCmd(AUV_ThrusterSafety::safeCmd(), nowMs);
        if (jetsonWasUp && !jetsonUp) Serial.println(F("Jetson link DOWN -> thruster neutral"));
        jetsonWasUp = jetsonUp;

        /* keep-alives so both sides learn each other's epoch quickly */
        if ((uint32_t)(nowMs - lastJetsonTxMs) >= HEARTBEAT_MS) {
            size_t n = 0;
            if (jetsonLink.buildHeartbeat(txFrame, sizeof txFrame, &n) == AUV_OK) JetsonSerial.write(txFrame, n);
            lastJetsonTxMs = nowMs;
        }
        if ((uint32_t)(nowMs - lastThrusterTxMs) >= HEARTBEAT_MS) {
            size_t n = 0;
            if (thrusterLink.buildHeartbeat(txFrame, sizeof txFrame, &n) == AUV_OK) ThrusterSerial.write(txFrame, n);
            lastThrusterTxMs = nowMs;
        }
    }

    IWatchdog.reload();

    if (nowMs - lastPrintMs >= 2000) {
        lastPrintMs = nowMs;
        Serial.print(F("jetson=")); Serial.print(jetsonLink.linkUp(nowMs));
        Serial.print(F(" thr=")); Serial.print(thrusterLink.linkUp(nowMs));
        Serial.print(F(" sens=")); Serial.print(sensorLink.linkUp(nowMs));
#if MASTER_ENABLE_IMU_LINK
        Serial.print(F(" imu=")); Serial.print(imuLink.linkUp(nowMs));
#endif
        Serial.print(F(" leakStop=")); Serial.print(leakStopRequired(nowMs));
        Serial.print(F(" cmd fwd/rej=")); Serial.print(cmdForwarded); Serial.print('/'); Serial.print(cmdRejected);
        Serial.print(F(" telem=")); Serial.print(telemForwarded);
        Serial.print(F(" authFail=")); Serial.print(jetsonLink.stats().authFailures + thrusterLink.stats().authFailures +
                                                    sensorLink.stats().authFailures
#if MASTER_ENABLE_IMU_LINK
                                                    + imuLink.stats().authFailures
#endif
                                                    );
        Serial.print(F(" maxCryptoUs=")); Serial.println(cryptoMaxUs);
        cryptoMaxUs = 0;
    }
}
