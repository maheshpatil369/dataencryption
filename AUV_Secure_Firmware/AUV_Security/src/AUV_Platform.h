/*
 * AUV_Platform.h  -  small STM32duino helpers used by the example sketches
 *
 *  - AUV_Uart          : the UART class name differs between STM32duino 2.x
 *                        (HardwareSerial) and 3.x (Uart). Use AUV_Uart.
 *  - AUV_cycles*()     : DWT cycle counter for real execution-time
 *                        measurements (falls back to micros() if a clone MCU
 *                        has no working DWT).
 *  - AUV_sendFrame()   : write a whole frame to a UART without per-byte
 *                        overhead (Serial.write of a buffer).
 */
#ifndef AUV_PLATFORM_H
#define AUV_PLATFORM_H

#if defined(ARDUINO_ARCH_STM32)
#include <Arduino.h>

#if defined(STM32_CORE_VERSION_MAJOR) && (STM32_CORE_VERSION_MAJOR >= 3)
typedef Uart AUV_Uart;
#else
typedef HardwareSerial AUV_Uart;
#endif

static bool g_auvDwtOk = false;

inline void AUV_cyclesInit() {
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CYCCNT = 0;
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
    uint32_t a = DWT->CYCCNT;
    for (volatile int i = 0; i < 100; i++) {}
    g_auvDwtOk = (DWT->CYCCNT != a);
}
inline bool AUV_cyclesAvailable() { return g_auvDwtOk; }
inline uint32_t AUV_cycles() { return g_auvDwtOk ? DWT->CYCCNT : micros() * (SystemCoreClock / 1000000UL); }
inline uint32_t AUV_cyclesToUs(uint32_t c) { return c / (SystemCoreClock / 1000000UL); }
/* microsecond time base with cycle resolution (wraps every ~59 s at 72 MHz,
 * fine for differences) */
inline uint32_t AUV_preciseMicros() { return g_auvDwtOk ? AUV_cyclesToUs(DWT->CYCCNT) : micros(); }

inline void AUV_sendFrame(Stream &s, const uint8_t *f, size_t n) { s.write(f, n); }

#endif /* ARDUINO_ARCH_STM32 */
#endif /* AUV_PLATFORM_H */
