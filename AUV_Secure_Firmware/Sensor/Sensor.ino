/*
 * Sensor.ino  -  AUV Sensor node (STM32F103 Blue Pill), ENCRYPT-ONLY
 * ---------------------------------------------------------------------------
 * Sends power, environment and leak telemetry to the Master at 100 Hz,
 * encrypted and authenticated with AES-256-GCM using key K1.
 * This node receives NOTHING: no decryption, no remote commands, so no
 * message can switch off leak protection.
 *
 * Hardware (from the earlier review of DHT_11.ino):
 *   DHT11            PA0
 *   INA260           I2C1  SDA PB7 / SCL PB6, address 0x40
 *   Leak sensors     PB12 PB13 PB14 PB15  (active LOW, internal pull-ups)
 *   Leak relay       PB0
 *   Link to Master   USART2  TX PA2 -> Master RX   (PA3 not needed)
 *   Debug            Serial (USART1 PA9/PA10) 115200
 *
 * FreeRTOS tasks (priority high -> low):
 *   Safety     100 Hz  leak inputs -> relay, watchdog       (never waits on comms)
 *   Telemetry  100 Hz  INA260 + encrypt + send               (vTaskDelayUntil, no drift)
 *   Env        0.5 Hz  DHT11 (slow, blocking ~25 ms) + debug print
 *
 * Libraries: AUV_Security (this project), Crypto (Rhys Weatherley),
 *            STM32duino FreeRTOS, Adafruit INA260, DHT sensor library (Adafruit)
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

#include <STM32FreeRTOS.h>
#include <Wire.h>
#include <Adafruit_INA260.h>
#include <DHT.h>
#include <IWatchdog.h>

/* ------------------------------ pins ------------------------------------ */
#define PIN_DHT        PA0
#define PIN_RELAY      PB0
static const uint32_t LEAK_PINS[4] = {PB12, PB13, PB14, PB15};
#define LINK_RX        PA3
#define LINK_TX        PA2
#define LINK_BAUD      1000000
#define TELEMETRY_PERIOD_MS 10      /* 100 Hz */

/* ------------------------------ objects --------------------------------- */
AUV_Uart LinkSerial(LINK_RX, LINK_TX);
AUV_DefaultFlash flash;
AUV_NonceManager nonces;
AUV_TxOnlyLink   link;
Adafruit_INA260  ina;
DHT              dht(PIN_DHT, DHT11);
AUV_LeakMonitor  leak;

/* shared state (written by one task, read by others; copied in a critical section) */
struct Shared {
    float temperature, humidity;
    uint8_t dhtOk;
    uint8_t leakMask, leakActive, relay;
} volatile g;

volatile uint32_t g_telemAlive = 0;    /* last tick the telemetry task ran */
volatile uint32_t g_encMaxUs = 0, g_encSumUs = 0, g_encCount = 0, g_sendErrors = 0;
bool g_inaOk = false;
bool g_linkOk = false;

/* ------------------------------ helpers --------------------------------- */
static uint8_t readLeakRaw() {
    uint8_t m = 0;
    for (uint8_t i = 0; i < 4; i++) if (digitalRead(LEAK_PINS[i]) == LOW) m |= (uint8_t)(1U << i);
    return m;
}

static bool startSecurity() {
    AUV_Status s = nonces.begin(flash);
#if AUV_USING_DEMO_KEYS
    if (s == AUV_ERR_NVM_INVALID) s = nonces.provision(flash, 1);   /* bench only */
#endif
    if (s != AUV_OK) {
        Serial.print(F("SECURITY: epoch store ")); Serial.println(AUV_statusName(s));
        Serial.println(F("Run AUV_Provision on this board. Telemetry disabled; leak relay still active."));
        return false;
    }
    AUV_LinkKeys k;
#if AUV_USING_DEMO_KEYS
    AUV_demoLinkKeys(AUV_ID_SENSOR, AUV_ID_MASTER, k);
    memset(k.rxKey, 0, sizeof k.rxKey);
    Serial.println(F("WARNING: DEMO KEYS - bench test only, NOT secure"));
#else
    memcpy(&k, &AUV_KEYS_SENSOR_MASTER, sizeof k);
#endif
    s = link.begin(k, nonces);
    AUV_secureZero(&k, sizeof k);                /* key now only inside the AES context */
    if (s != AUV_OK) { Serial.print(F("SECURITY: link ")); Serial.println(AUV_statusName(s)); return false; }
    Serial.print(F("Secure link up. epoch=")); Serial.print(nonces.epoch());
    Serial.print(F(" K1 fp=")); Serial.println(link.txFingerprint(), HEX);
    if (nonces.damagedRecordFound()) Serial.println(F("NOTE: damaged epoch record skipped (check flash)"));
    return true;
}

/* ------------------------------ tasks ----------------------------------- */
static void TaskSafety(void *) {
    TickType_t last = xTaskGetTickCount();
    for (;;) {
        leak.update(readLeakRaw());
        uint8_t level = leak.relayLevel();
        digitalWrite(PIN_RELAY, level);
        taskENTER_CRITICAL();
        g.leakMask = leak.mask(); g.leakActive = leak.active(); g.relay = level;
        taskEXIT_CRITICAL();
        /* feed the watchdog only while telemetry is alive (or disabled) */
        uint32_t now = millis();
        if (!g_linkOk || (uint32_t)(now - g_telemAlive) < 200) IWatchdog.reload();
        vTaskDelayUntil(&last, pdMS_TO_TICKS(10));
    }
}

static void TaskTelemetry(void *) {
    static uint8_t payload[AUV_SENSOR_TELEM_LEN];
    static uint8_t frame[AUV_MAX_FRAME];
    TickType_t last = xTaskGetTickCount();
    for (;;) {
        AUV_SensorTelemetry t;
        t.tick = millis();
        if (g_inaOk) {
            t.voltage = ina.readBusVoltage() / 1000.0f;   /* mV -> V */
            t.current = ina.readCurrent() / 1000.0f;      /* mA -> A */
            t.power   = ina.readPower() / 1000.0f;        /* mW -> W */
        } else {
            t.voltage = t.current = t.power = 0.0f;
        }
        taskENTER_CRITICAL();
        t.temperature = g.temperature; t.humidity = g.humidity;
        t.leakMask = g.leakMask; t.leakActive = g.leakActive; t.relay = g.relay;
        t.flags = (uint8_t)((g.dhtOk ? 1 : 0) | (g_inaOk ? 2 : 0));
        taskEXIT_CRITICAL();

        if (g_linkOk) {
            AUV_encodeSensorTelemetry(t, payload);
            size_t n = 0;
            uint32_t c0 = AUV_cycles();
            AUV_Status s = link.buildFrame(AUV_TYPE_TELEMETRY, payload, sizeof payload, frame, sizeof frame, &n);
            uint32_t us = AUV_cyclesToUs(AUV_cycles() - c0);
            if (s == AUV_OK) {
                LinkSerial.write(frame, n);               /* one call, interrupt-driven TX */
                g_encSumUs += us; g_encCount++;
                if (us > g_encMaxUs) g_encMaxUs = us;
            } else {
                g_sendErrors++;
            }
        }
        g_telemAlive = millis();
        vTaskDelayUntil(&last, pdMS_TO_TICKS(TELEMETRY_PERIOD_MS));
    }
}

static void TaskEnv(void *) {
    for (;;) {
        float h = dht.readHumidity();
        float c = dht.readTemperature();
        bool ok = !(isnan(h) || isnan(c));
        taskENTER_CRITICAL();
        if (ok) { g.humidity = h; g.temperature = c; }
        g.dhtOk = ok;
        taskEXIT_CRITICAL();

        if (g_encCount) {
            Serial.print(F("tx=")); Serial.print(link.txFrames());
            Serial.print(F(" enc avg/max us=")); Serial.print(g_encSumUs / g_encCount);
            Serial.print('/'); Serial.print(g_encMaxUs);
            Serial.print(F(" leak=")); Serial.print(g.leakMask, BIN);
            Serial.print(F(" err=")); Serial.println(g_sendErrors);
            g_encSumUs = 0; g_encCount = 0; g_encMaxUs = 0;
        }
        vTaskDelay(pdMS_TO_TICKS(2000));             /* DHT11: max 1 reading per second */
    }
}

/* ------------------------------ setup ----------------------------------- */
void setup() {
    /* safety outputs first, before anything that can fail */
    pinMode(PIN_RELAY, OUTPUT);
    digitalWrite(PIN_RELAY, SENSOR_RELAY_IDLE_STATE);
    for (uint8_t i = 0; i < 4; i++) pinMode(LEAK_PINS[i], INPUT_PULLUP);

    Serial.begin(115200);
    if (IWatchdog.isReset(true)) Serial.println(F("Recovered from WATCHDOG reset"));
    AUV_cyclesInit();

    Wire.begin();
    Wire.setClock(400000);                        /* shorter I2C reads = less jitter */
    g_inaOk = ina.begin(0x40, &Wire);
    dht.begin();

    LinkSerial.begin(LINK_BAUD);
    g_linkOk = startSecurity();                   /* flash epoch write happens here, before RTOS */

    IWatchdog.begin(500000);                      /* 500 ms */

    xTaskCreate(TaskSafety,    "safety", 256, NULL, tskIDLE_PRIORITY + 3, NULL);
    xTaskCreate(TaskTelemetry, "telem",  512, NULL, tskIDLE_PRIORITY + 2, NULL);
    xTaskCreate(TaskEnv,       "env",    384, NULL, tskIDLE_PRIORITY + 1, NULL);
    vTaskStartScheduler();
    Serial.println(F("FreeRTOS failed to start"));
    for (;;) {}
}

void loop() {}   /* not used with FreeRTOS */
