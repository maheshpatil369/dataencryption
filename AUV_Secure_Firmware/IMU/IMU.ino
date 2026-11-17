/*
 * IMU.ino  -  AUV IMU node (STM32F103 Blue Pill), ENCRYPT-ONLY
 * ---------------------------------------------------------------------------
 * Sends orientation (quaternion), acceleration, gyro and magnetometer data
 * from a BNO086 to the Master at 100 Hz, encrypted with AES-256-GCM key K2.
 * Receives nothing, decrypts nothing.
 *
 * Hardware (from the earlier review of IIMU_1.ino):
 *   BNO086           I2C1  SDA PB7 / SCL PB6, address 0x4B
 *   Link to Master   USART2  TX PA2 -> Master RX   (PA3 not needed)
 *   Debug            Serial (USART1 PA9/PA10) 115200
 *
 * Loop design (no RTOS needed): the loop never blocks. Sensor events are
 * drained every pass; a frame is sent exactly every 10 ms on a micros()
 * schedule, so the period does not drift.
 *
 * Libraries: AUV_Security, Crypto (Rhys Weatherley),
 *            SparkFun BNO08x Cortex Based IMU (SparkFun_BNO08x_Arduino_Library)
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
#include <SparkFun_BNO08x_Arduino_Library.h>
#include <IWatchdog.h>

#define LINK_RX        PA3
#define LINK_TX        PA2
#define LINK_BAUD      1000000
#define BNO_ADDR       0x4B
#define PERIOD_US      10000UL      /* 100 Hz */
#define REPORT_MS      10           /* BNO086 report interval */
#define IMU_STALE_MS   100          /* no event for this long -> connected = 0 */

AUV_Uart LinkSerial(LINK_RX, LINK_TX);
AUV_DefaultFlash flash;
AUV_NonceManager nonces;
AUV_TxOnlyLink   link;
BNO08x           imu;

AUV_ImuTelemetry tel;
bool     imuStarted = false, linkOk = false;
uint32_t lastEventMs = 0, nextSendUs = 0, lastPrintMs = 0;
uint32_t encSum = 0, encMax = 0, encCount = 0, sendErr = 0;
uint8_t  payload[AUV_IMU_TELEM_LEN];
uint8_t  frame[AUV_MAX_FRAME];

static void enableReports() {
    imu.enableRotationVector(REPORT_MS);
    imu.enableAccelerometer(REPORT_MS);
    imu.enableGyro(REPORT_MS);
    imu.enableMagnetometer(REPORT_MS);
}

static bool startSecurity() {
    AUV_Status s = nonces.begin(flash);
#if AUV_USING_DEMO_KEYS
    if (s == AUV_ERR_NVM_INVALID) s = nonces.provision(flash, 1);
#endif
    if (s != AUV_OK) {
        Serial.print(F("SECURITY: epoch store ")); Serial.println(AUV_statusName(s));
        Serial.println(F("Run AUV_Provision on this board. Telemetry disabled."));
        return false;
    }
    AUV_LinkKeys k;
#if AUV_USING_DEMO_KEYS
    AUV_demoLinkKeys(AUV_ID_IMU, AUV_ID_MASTER, k);
    memset(k.rxKey, 0, sizeof k.rxKey);
    Serial.println(F("WARNING: DEMO KEYS - bench test only, NOT secure"));
#else
    memcpy(&k, &AUV_KEYS_IMU_MASTER, sizeof k);
#endif
    s = link.begin(k, nonces);
    AUV_secureZero(&k, sizeof k);
    if (s != AUV_OK) { Serial.print(F("SECURITY: link ")); Serial.println(AUV_statusName(s)); return false; }
    Serial.print(F("Secure link up. epoch=")); Serial.print(nonces.epoch());
    Serial.print(F(" K2 fp=")); Serial.println(link.txFingerprint(), HEX);
    return true;
}

static void serviceImu() {
    if (!imuStarted) return;
    if (imu.wasReset()) enableReports();          /* sensor rebooted: re-arm reports */
    uint8_t budget = 8;                           /* bound the time spent per loop pass */
    while (budget-- && imu.getSensorEvent()) {
        lastEventMs = millis();
        switch (imu.getSensorEventID()) {
            case SENSOR_REPORTID_ROTATION_VECTOR:
                tel.q[0] = imu.getQuatI(); tel.q[1] = imu.getQuatJ();
                tel.q[2] = imu.getQuatK(); tel.q[3] = imu.getQuatReal();
                break;
            case SENSOR_REPORTID_ACCELEROMETER:
                tel.accel[0] = imu.getAccelX(); tel.accel[1] = imu.getAccelY(); tel.accel[2] = imu.getAccelZ();
                break;
            case SENSOR_REPORTID_GYROSCOPE_CALIBRATED:
                tel.gyro[0] = imu.getGyroX(); tel.gyro[1] = imu.getGyroY(); tel.gyro[2] = imu.getGyroZ();
                break;
            case SENSOR_REPORTID_MAGNETIC_FIELD:
                tel.mag[0] = imu.getMagX(); tel.mag[1] = imu.getMagY(); tel.mag[2] = imu.getMagZ();
                break;
            default:
                break;
        }
    }
}

static void sendTelemetry() {
    tel.tick = millis();
    tel.connected = (imuStarted && (uint32_t)(tel.tick - lastEventMs) < IMU_STALE_MS) ? 1 : 0;
    AUV_encodeImuTelemetry(tel, payload);
    size_t n = 0;
    uint32_t c0 = AUV_cycles();
    AUV_Status s = link.buildFrame(AUV_TYPE_TELEMETRY, payload, sizeof payload, frame, sizeof frame, &n);
    uint32_t us = AUV_cyclesToUs(AUV_cycles() - c0);
    if (s != AUV_OK) { sendErr++; return; }
    LinkSerial.write(frame, n);
    encSum += us; encCount++;
    if (us > encMax) encMax = us;
}

void setup() {
    Serial.begin(115200);
    if (IWatchdog.isReset(true)) Serial.println(F("Recovered from WATCHDOG reset"));
    AUV_cyclesInit();
    memset(&tel, 0, sizeof tel);
    tel.q[3] = 1.0f;

    Wire.begin();
    Wire.setClock(400000);
    imuStarted = imu.begin(BNO_ADDR, Wire);
    if (imuStarted) enableReports();
    else Serial.println(F("BNO086 not found - sending connected=0"));

    LinkSerial.begin(LINK_BAUD);
    linkOk = startSecurity();
    IWatchdog.begin(500000);
    nextSendUs = micros() + PERIOD_US;
}

void loop() {
    serviceImu();

    uint32_t nowUs = micros();
    if ((int32_t)(nowUs - nextSendUs) >= 0) {
        nextSendUs += PERIOD_US;
        if ((int32_t)(nowUs - nextSendUs) > (int32_t)PERIOD_US) nextSendUs = nowUs + PERIOD_US; /* resync after a stall */
        if (linkOk) sendTelemetry();
    }

    IWatchdog.reload();

    uint32_t nowMs = millis();
    if (nowMs - lastPrintMs >= 2000 && encCount) {
        lastPrintMs = nowMs;
        Serial.print(F("tx=")); Serial.print(link.txFrames());
        Serial.print(F(" enc avg/max us=")); Serial.print(encSum / encCount);
        Serial.print('/'); Serial.print(encMax);
        Serial.print(F(" imu=")); Serial.print(tel.connected);
        Serial.print(F(" err=")); Serial.println(sendErr);
        encSum = encCount = encMax = 0;
    }
}
