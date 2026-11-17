/*
 * AUV_SelfTest.ino - runs the complete AUV_Security test-suite ON THE BOARD
 * and measures real encryption/decryption times with the CPU cycle counter.
 *
 * Upload to any STM32 (Blue Pill: Generic STM32F1, F103C8), open the Serial
 * Monitor at 115200. The last line must read "RESULT: <n> passed, 0 failed".
 * Uses public demo keys and a RAM flash simulation: it never writes the
 * board's real flash and is safe to run on any node.
 */
#define AUV_ALLOW_DEMO_KEYS 1
#include <AUV_Security.h>
#include "AUV_TestSuite.h"

static void boardPrint(const char *s) { Serial.println(s); }
static uint32_t boardMicros() { return AUV_preciseMicros(); }

void setup() {
    Serial.begin(115200);
    while (!Serial && millis() < 3000) {}
    delay(500);
    AUV_cyclesInit();
    Serial.print(F("CPU clock: ")); Serial.print(SystemCoreClock / 1000000UL); Serial.print(F(" MHz, cycle counter: "));
    Serial.println(AUV_cyclesAvailable() ? F("DWT") : F("not available, using micros()"));
    AUV_runAllTests(boardPrint, boardMicros);
}

void loop() {}
