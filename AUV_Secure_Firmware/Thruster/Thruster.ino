/*
 * Thruster.ino  -  AUV Thruster node (STM32F103 Blue Pill), ENCRYPT + DECRYPT
 * ---------------------------------------------------------------------------
 * Receives commands from the Master (decrypted with K4), drives 4 servos,
 * the ESC and 2 relays, and sends its status back at 100 Hz (encrypted with K3).
 *
 * Only commands that pass ALL of these are applied:
 *   AES-256-GCM tag check -> replay check -> fresh for this boot -> exact
 *   length and value ranges (servo 0-180, thruster 1100-1900 us, relay bits).
 *
 * Fail-safe (AUV_ThrusterSafety): neutral thruster, safe servo angle and
 * relays off at boot, when the link is down (200 ms), when no valid command
 * arrives for 250 ms, after 5 invalid commands in a row, or on a leak flag.
 *
 * Hardware (from the earlier review of Thruster.ino):
 *   PCA9685          I2C1 SDA PB7 / SCL PB6, address 0x40, servos on ch 12-15
 *   ESC signal       PB3 (Servo library, 50 Hz)
 *   Relay 1 / 2      PB12 / PB13
 *   Link to Master   USART2 TX PA2 -> Master RX, RX PA3 <- Master TX
 *   Debug            Serial (USART1 PA9/PA10) 115200
 *
 * Libraries: AUV_Security, Crypto (Rhys Weatherley),
 *            Adafruit PWM Servo Driver Library, Servo (built into STM32duino)
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

#include <Wire.h>
#include <Adafruit_PWMServoDriver.h>
#include <Servo.h>
#include <IWatchdog.h>

#define LINK_RX        PA3
#define LINK_TX        PA2
#define LINK_BAUD      1000000
#define PIN_ESC        PB3
#define PIN_RELAY1     PB12
#define PIN_RELAY2     PB13
#define PCA_ADDR       0x40
#define SERVO_CH0      12            /* servos on PCA9685 channels 12..15 */
#define SERVO_MIN_US   500           /* [CONFIRM] pulse at 0 degrees   */
#define SERVO_MAX_US   2500          /* [CONFIRM] pulse at 180 degrees */
#define STATUS_PERIOD_US 10000UL     /* 100 Hz status */
#define MAX_RX_BYTES_PER_LOOP 256    /* bound the time spent on one UART burst */

AUV_Uart LinkSerial(LINK_RX, LINK_TX);
AUV_DefaultFlash   flash;
AUV_NonceManager   nonces;
AUV_SecureLink     link;
AUV_ThrusterSafety safety;
Adafruit_PWMServoDriver pca(PCA_ADDR);
Servo esc;

bool linkOk = false;
AUV_ThrusterCmd applied;               /* what is on the outputs right now */
bool appliedValid = false;
uint8_t frame[AUV_MAX_FRAME];
AUV_RxMessage msg;
uint32_t nextStatusUs = 0, lastPrintMs = 0;
uint32_t decSum = 0, decMax = 0, decCount = 0, encSum = 0, encMax = 0, encCount = 0;

static bool startSecurity() {
    AUV_Status s = nonces.begin(flash);
#if AUV_USING_DEMO_KEYS
    if (s == AUV_ERR_NVM_INVALID) s = nonces.provision(flash, 1);
#endif
    if (s != AUV_OK) {
        Serial.print(F("SECURITY: epoch store ")); Serial.println(AUV_statusName(s));
        Serial.println(F("Run AUV_Provision on this board. Outputs stay in SAFE state."));
        return false;
    }
    AUV_LinkKeys k;
#if AUV_USING_DEMO_KEYS
    AUV_demoLinkKeys(AUV_ID_THRUSTER, AUV_ID_MASTER, k);
    Serial.println(F("WARNING: DEMO KEYS - bench test only, NOT secure"));
#else
    memcpy(&k, &AUV_KEYS_THRUSTER_MASTER, sizeof k);
#endif
    s = link.begin(k, nonces, AUV_LINK_DUPLEX);
    AUV_secureZero(&k, sizeof k);
    if (s != AUV_OK) { Serial.print(F("SECURITY: link ")); Serial.println(AUV_statusName(s)); return false; }
    Serial.print(F("Secure link up. epoch=")); Serial.print(nonces.epoch());
    Serial.print(F(" K3 fp=")); Serial.print(link.txFingerprint(), HEX);
    Serial.print(F(" K4 fp=")); Serial.println(link.rxFingerprint(), HEX);
    return true;
}

static uint16_t servoUs(uint8_t deg) {
    return (uint16_t)(SERVO_MIN_US + (uint32_t)deg * (SERVO_MAX_US - SERVO_MIN_US) / 180U);
}

/* Write outputs only when they change: fewer I2C transfers, less jitter. */
static void applyOutputs(const AUV_ThrusterCmd &c) {
    if (!appliedValid || c.thrusterUs != applied.thrusterUs) esc.writeMicroseconds(c.thrusterUs);
    for (uint8_t i = 0; i < 4; i++)
        if (!appliedValid || c.servo[i] != applied.servo[i]) pca.writeMicroseconds(SERVO_CH0 + i, servoUs(c.servo[i]));
    if (!appliedValid || c.relayMask != applied.relayMask) {
        digitalWrite(PIN_RELAY1, (c.relayMask & 0x01) ? HIGH : LOW);
        digitalWrite(PIN_RELAY2, (c.relayMask & 0x02) ? HIGH : LOW);
    }
    applied = c;
    appliedValid = true;
}

static void serviceLink(uint32_t nowMs) {
    uint16_t budget = MAX_RX_BYTES_PER_LOOP;
    while (budget-- && LinkSerial.available()) {
        uint32_t c0 = AUV_cycles();
        AUV_Status s = link.rxByte((uint8_t)LinkSerial.read(), nowMs, msg);
        if (s != AUV_MSG_READY) continue;
        uint32_t us = AUV_cyclesToUs(AUV_cycles() - c0);   /* last byte: tag check + decrypt */
        decSum += us; decCount++; if (us > decMax) decMax = us;
        if (msg.type == AUV_TYPE_COMMAND) safety.onCommand(msg.payload, msg.len, nowMs);
        /* HEARTBEAT: only refreshes the link timer (done inside rxByte) */
    }
    link.poll(nowMs);
}

static void sendStatus() {
    AUV_ThrusterStatus st;
    const AUV_ThrusterCmd &o = safety.output();
    memcpy(st.servo, o.servo, 4);
    st.thrusterUs = o.thrusterUs;
    st.relayMask = o.relayMask;
    st.relayOutput = (uint8_t)((digitalRead(PIN_RELAY1) == HIGH ? 1 : 0) | (digitalRead(PIN_RELAY2) == HIGH ? 2 : 0));
    st.state = safety.state();
    st.reserved = 0;
    st.invalidCmds = safety.invalidCount();
    uint8_t p[AUV_THRUSTER_STATUS_LEN];
    AUV_encodeThrusterStatus(st, p);
    size_t n = 0;
    uint32_t c0 = AUV_cycles();
    if (link.buildFrame(AUV_TYPE_STATUS, p, sizeof p, frame, sizeof frame, &n) != AUV_OK) return;
    uint32_t us = AUV_cyclesToUs(AUV_cycles() - c0);
    LinkSerial.write(frame, n);
    encSum += us; encCount++; if (us > encMax) encMax = us;
}

void setup() {
    /* 1. outputs to the safe state BEFORE anything else */
#if defined(STM32F1xx)
    __HAL_RCC_AFIO_CLK_ENABLE();
    __HAL_AFIO_REMAP_SWJ_NOJTAG();      /* PB3 is a JTAG pin: free it, keep SWD (ST-LINK) */
#endif
    pinMode(PIN_RELAY1, OUTPUT); digitalWrite(PIN_RELAY1, LOW);
    pinMode(PIN_RELAY2, OUTPUT); digitalWrite(PIN_RELAY2, LOW);
    esc.attach(PIN_ESC, 1000, 2000);
    esc.writeMicroseconds(THRUSTER_NEUTRAL_US);

    Serial.begin(115200);
    if (IWatchdog.isReset(true)) Serial.println(F("Recovered from WATCHDOG reset - outputs safe"));
    AUV_cyclesInit();

    Wire.begin();
    Wire.setClock(400000);
    pca.begin();
    pca.setOscillatorFrequency(27000000);
    pca.setPWMFreq(50);
    applyOutputs(AUV_ThrusterSafety::safeCmd());

    LinkSerial.begin(LINK_BAUD);
    linkOk = startSecurity();
    IWatchdog.begin(500000);                      /* hang -> reset -> safe outputs */
    nextStatusUs = micros() + STATUS_PERIOD_US;
}

void loop() {
    uint32_t nowMs = millis();
    if (linkOk) serviceLink(nowMs);

    safety.update(nowMs, linkOk && link.linkUp(nowMs));
    applyOutputs(safety.output());

    uint32_t nowUs = micros();
    if ((int32_t)(nowUs - nextStatusUs) >= 0) {
        nextStatusUs += STATUS_PERIOD_US;
        if ((int32_t)(nowUs - nextStatusUs) > (int32_t)STATUS_PERIOD_US) nextStatusUs = nowUs + STATUS_PERIOD_US;
        if (linkOk) sendStatus();
    }

    IWatchdog.reload();

    if (nowMs - lastPrintMs >= 2000) {
        lastPrintMs = nowMs;
        Serial.print(F("state=")); Serial.print(safety.state());
        Serial.print(F(" esc=")); Serial.print(safety.output().thrusterUs);
        Serial.print(F(" link=")); Serial.print(link.linkUp(nowMs));
        Serial.print(F(" rx=")); Serial.print(link.stats().rxDelivered);
        Serial.print(F(" authFail=")); Serial.print(link.stats().authFailures);
        Serial.print(F(" replay=")); Serial.print(link.replayStats().replays);
        if (decCount) { Serial.print(F(" dec avg/max us=")); Serial.print(decSum / decCount); Serial.print('/'); Serial.print(decMax); }
        if (encCount) { Serial.print(F(" enc avg/max us=")); Serial.print(encSum / encCount); Serial.print('/'); Serial.print(encMax); }
        Serial.println();
        decSum = decCount = decMax = encSum = encCount = encMax = 0;
    }
}
