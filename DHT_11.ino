/*
 * ============================================================================
 *  STM32F1 + FreeRTOS  |  Sensor Telemetry Node (Production)
 * ----------------------------------------------------------------------------
 *  - DHT11 (temp/humidity), INA260 (V/I/P), 4x digital leak sensor, relay
 *  - USART2 @1,000,000 baud: continuous telemetry TX via DMA (non-blocking)
 *  - RX via plain byte-at-a-time RXNE interrupt (rare host commands)
 *  - Independent Watchdog (IWDG, ~4 s) fed only when ALL tasks are alive
 *  - Proper locking: dataMutex protects shared data, txSemaphore guards DMA TX
 *  - SEQ field + generous TX timeout to make packet loss observable/rare
 *
 *  FIX (see telemetry_race_fix.md): sendTelemetry() used to snprintf() into
 *  the shared static telemetryTxBuf BEFORE confirming the previous DMA
 *  transfer had finished reading that same buffer. If the previous transfer
 *  was still in flight, the DMA channel kept reading from addresses that had
 *  already been overwritten with the NEW packet's bytes (while its transfer
 *  length was still fixed to the OLD packet's length) -> spliced/truncated
 *  frames on the wire (headerless "half packets") and occasional torn SEQ
 *  digits that looked like phantom MCU reboots to the host, even though
 *  tick_ms proved the MCU never actually reset.
 *
 *  Fixed by acquiring txSemaphore FIRST (which blocks until the previous
 *  DMA transfer has genuinely completed and released it) and only THEN
 *  formatting into telemetryTxBuf, so no writer can ever touch the buffer
 *  while DMA still owns it. See sendTelemetry() / uartSendDmaLocked().
 * ============================================================================
 */


#include <STM32FreeRTOS.h>
#include <Wire.h>
#include <Adafruit_INA260.h>
#include <DHT.h>
#include <Arduino.h>
#include <stm32f1xx_hal.h>
#include <stm32f1xx_hal_dma.h>
#include <stm32f1xx_hal_uart.h>

/* ------------------------------ Pin mapping ------------------------------ */
#define DHTPIN PA0  // DHT11 data
#define DHTTYPE DHT11
#define LEAK_PIN_1 PB12  // digital leak switch (active LOW)
#define LEAK_PIN_2 PB13  // digital leak switch (active LOW)
#define LEAK_PIN_3 PB14  // digital leak switch (active LOW)
#define LEAK_PIN_4 PB15  // digital leak switch (active LOW)
//These are the digital pins connected to the leak sensor 

#define ERROR_LED PC13

/* Relay: assumed free pin — change if PB0 is used elsewhere on your board.
 * RELAY_ACTIVE_LEVEL defaults to LOW because most cheap 5V relay modules
 * (single/dual-channel with an opto-isolator) trigger ON when the control
 * pin is pulled LOW. If yours is an active-HIGH module, just flip this. */
#define RELAY_PIN PB0
#define RELAY_ACTIVE_LEVEL   LOW
#define RELAY_INACTIVE_LEVEL HIGH

/* ------------------------------ Config ----------------------------------- */

#define CMD_BUF_SIZE 64  // one short command line ("PING\r\n") is plenty
#define TX_BUF_SIZE 220  // packet grew (SEQ/RELAY fields) — sized with margin
#define DEBUG_TX_TIMEOUT_MS 15

/* Generous but bounded: telemetry period is 100 ms and a full packet takes
 * well under 1 ms to transmit at 1 Mbps, so 80 ms of headroom before we give
 * up on a send makes a genuine drop (as opposed to display artifacts on the
 * host side) extremely unlikely, while still leaving slack before the next
 * scheduled tick so a stuck DMA channel can't cascade-delay every packet. */
#define TX_ACQUIRE_TIMEOUT pdMS_TO_TICKS(80)

#define TELEMETRY_PERIOD_MS 10  // continuous stream rate (10 Hz)
#define INA_PERIOD_MS 100
#define LEAK_PERIOD_MS 20
#define DHT_PERIOD_MS 2000  // DHT11 hardware limit: 1 read / 2 s

/* Watchdog: LSI ~40 kHz / 64 prescaler, reload 2499  ->  ~4 s timeout */
#define IWDG_RELOAD_VALUE 2499
#define WDG_CHECK_PERIOD_MS 3000  // all tasks must check in within this window


/* Task alive bits (event group) */
#define INA_ALIVE (1 << 0)
#define DHT_ALIVE (1 << 1)
#define LEAK_ALIVE (1 << 2)
#define UART_ALIVE (1 << 3)
#define TELE_ALIVE (1 << 4)
#define ALL_ALIVE (INA_ALIVE | DHT_ALIVE | LEAK_ALIVE | UART_ALIVE | TELE_ALIVE)
// these are the event group to monitor the activaty of all the tasks 


/* ------------------------------ Objects ---------------------------------- */
DHT dht(DHTPIN, DHTTYPE);
Adafruit_INA260 ina260;
static bool inaPresent = false;

UART_HandleTypeDef huart2;
DMA_HandleTypeDef hdma_usart2_tx;  // TX: DMA1 Channel4
DMA_HandleTypeDef hdma_usart2_rx;  // RX: DMA1 Channel5 — circular, no IRQ needed (see below)

/* RX circular DMA buffer. DMA hardware fills this continuously as bytes
 * arrive — completely independent of the CPU or any interrupt vector, so
 * nothing here can ever conflict with the core's USARTx_IRQHandler (see
 * the long comment above vUartRxTask for why we can't touch that at all).
 * The task periodically compares its DMA write-position against where it
 * last read up to; that comparison IS the "flag" — no boolean needed,
 * since DMA guarantees no byte is lost between polls (up to buffer size). */
#define RX_DMA_BUF_SIZE 128
static uint8_t rxDmaBuffer[RX_DMA_BUF_SIZE];
static uint16_t rxReadPos = 0;

/* Static TX buffers: DMA outlives the calling function, stack buffers are fatal */
static char telemetryTxBuf[TX_BUF_SIZE];
static char debugTxBuf[128];

/* Diagnostics: lets you PROVE whether packets are actually lost in firmware */

static volatile uint32_t txSeq = 0;        // increments on every telemetry attempt
static volatile uint32_t txDropCount = 0;  // increments whenever a send fails

typedef enum { RELAY_MODE_AUTO = 0, RELAY_MODE_FORCE_ON, RELAY_MODE_FORCE_OFF } RelayMode_t;
static volatile RelayMode_t relayMode = RELAY_MODE_AUTO;

typedef struct {
  float temperature;
  float humidity;
  float voltage;  // V
  float current;  // mA  (clamped >= 0, see vIna260Task)
  float power;    // mW
  uint16_t adcValue;
  bool leak_p_1;
  bool leak_p_2;
  bool leak_p_3;
  bool leak_p_4;
  bool relayActive;
} SensorData_t;

static SensorData_t sensorData = { 0 };

/* ------------------------------ RTOS handles ------------------------------ */
static SemaphoreHandle_t txSemaphore = NULL;  // guards the single DMA TX channel
static SemaphoreHandle_t dataMutex = NULL;    // guards sensorData
static EventGroupHandle_t aliveEvents = NULL;
static TaskHandle_t uartRxTaskHandle = NULL;

/* ========================================================================== */
/*  WATCHDOG (register-level IWDG — no HAL module dependency)                 */
/* ========================================================================== */
static void watchdogInit(void) {
  IWDG->KR = 0x5555;              // unlock
  IWDG->PR = 0x04;                // prescaler /64
  IWDG->RLR = IWDG_RELOAD_VALUE;  // ~4 s @ 40 kHz LSI
  IWDG->KR = 0xAAAA;              // load
  IWDG->KR = 0xCCCC;              // start (cannot be stopped except by reset)
}

static inline void watchdogFeed(void) {
  IWDG->KR = 0xAAAA;
}

/* ========================================================================== */
/*  DMA / UART ISRs                                                           */
/* ========================================================================== */
static void TxDmaCpltCallback(DMA_HandleTypeDef* hdma) {
  (void)hdma;
  BaseType_t woken = pdFALSE;
  CLEAR_BIT(huart2.Instance->CR3, USART_CR3_DMAT);
  xSemaphoreGiveFromISR(txSemaphore, &woken);  // release TX only here
  portYIELD_FROM_ISR(woken);
}

static void TxDmaErrorCallback(DMA_HandleTypeDef* hdma) {
  (void)hdma;
  BaseType_t woken = pdFALSE;
  CLEAR_BIT(huart2.Instance->CR3, USART_CR3_DMAT);
  xSemaphoreGiveFromISR(txSemaphore, &woken);  // never leak the semaphore
  portYIELD_FROM_ISR(woken);
}

extern "C" void DMA1_Channel7_IRQHandler(void) {
  HAL_DMA_IRQHandler(&hdma_usart2_tx);
}

/* IMPORTANT: no USART2_IRQHandler is defined anywhere in this file, and
 * none ever should be. The linker error you hit —
 *   "multiple definition of `USART2_IRQHandler'"
 * — proves the STM32duino core (SrcWrapper) compiles in its own strong
 * definition of that handler for every USART instance the chip physically
 * has, regardless of whether the sketch uses Arduino's Serial API for it.
 * Marking our version __attribute__((weak)) (an earlier iteration of this
 * file) didn't fix anything — it just made our code silently LOSE to the
 * core's handler instead of failing to link, meaning our RXNE logic was
 * never actually executing, and whatever the core's own handler does with
 * a peripheral we're driving via raw HAL (not the Arduino Serial object)
 * is the most likely real cause of the reset-on-command crash. Since this
 * applies to every USARTx vector on the chip, not just USART2, the only
 * robust fix is to never touch USARTx_IRQHandler at all — RX uses a
 * circular DMA buffer instead (see MX_DMA_Init / vUartRxTask), which only
 * needs DMA1_Channel6_IRQn territory, a vector the core does NOT claim. */

/* ========================================================================== */
/*  HARDWARE INIT                                                             */
/* ========================================================================== */
static void MX_GPIO_Init(void) {
  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_GPIOC_CLK_ENABLE();

  GPIO_InitTypeDef gpio = { 0 };

  gpio.Pin = GPIO_PIN_2;  // USART2 TX
  gpio.Mode = GPIO_MODE_AF_PP;
  gpio.Speed = GPIO_SPEED_FREQ_HIGH;
  HAL_GPIO_Init(GPIOA, &gpio);

  gpio.Pin = GPIO_PIN_3;  // USART2 RX
  gpio.Mode = GPIO_MODE_INPUT;
  gpio.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(GPIOA, &gpio);
}

static void MX_DMA_Init(void) {
  __HAL_RCC_DMA1_CLK_ENABLE();

  /* TX: DMA1 Ch4, one-shot, IRQ-driven completion (needed so the TX
   * semaphore is released promptly for back-to-back telemetry packets). */
  hdma_usart2_tx.Instance = DMA1_Channel7;
  hdma_usart2_tx.Init.Direction = DMA_MEMORY_TO_PERIPH;
  hdma_usart2_tx.Init.PeriphInc = DMA_PINC_DISABLE;
  hdma_usart2_tx.Init.MemInc = DMA_MINC_ENABLE;
  hdma_usart2_tx.Init.PeriphDataAlignment = DMA_PDATAALIGN_BYTE;
  hdma_usart2_tx.Init.MemDataAlignment = DMA_MDATAALIGN_BYTE;
  hdma_usart2_tx.Init.Mode = DMA_NORMAL;
  hdma_usart2_tx.Init.Priority = DMA_PRIORITY_LOW;
  HAL_DMA_Init(&hdma_usart2_tx);
  __HAL_LINKDMA(&huart2, hdmatx, hdma_usart2_tx);

  hdma_usart2_tx.XferCpltCallback = TxDmaCpltCallback;
  hdma_usart2_tx.XferErrorCallback = TxDmaErrorCallback;

  HAL_NVIC_SetPriority(DMA1_Channel7_IRQn, 6, 0);
  HAL_NVIC_EnableIRQ(DMA1_Channel7_IRQn);

  /* RX: DMA1 Ch5, circular. Deliberately NO interrupt enabled/needed here —
   * circular mode means the hardware just keeps wrapping and overwriting
   * the buffer forever with zero CPU involvement. vUartRxTask reads
   * hdma_usart2_rx.Instance->CNDTR periodically to see how far the DMA
   * write pointer has advanced since it last looked; that comparison is
   * the only "notification" mechanism needed, and it never touches an
   * interrupt vector, so it can never conflict with the core. */
  hdma_usart2_rx.Instance = DMA1_Channel6;
  hdma_usart2_rx.Init.Direction = DMA_PERIPH_TO_MEMORY;
  hdma_usart2_rx.Init.PeriphInc = DMA_PINC_DISABLE;
  hdma_usart2_rx.Init.MemInc = DMA_MINC_ENABLE;
  hdma_usart2_rx.Init.PeriphDataAlignment = DMA_PDATAALIGN_BYTE;
  hdma_usart2_rx.Init.MemDataAlignment = DMA_MDATAALIGN_BYTE;
  hdma_usart2_rx.Init.Mode = DMA_CIRCULAR;
  hdma_usart2_rx.Init.Priority = DMA_PRIORITY_HIGH;
  HAL_DMA_Init(&hdma_usart2_rx);
  __HAL_LINKDMA(&huart2, hdmarx, hdma_usart2_rx);
}

static void MX_USART2_UART_Init(void) {
  __HAL_RCC_USART2_CLK_ENABLE();

  huart2.Instance = USART2;
  huart2.Init.BaudRate = 1000000;
  huart2.Init.WordLength = UART_WORDLENGTH_8B;
  huart2.Init.StopBits = UART_STOPBITS_1;
  huart2.Init.Parity = UART_PARITY_NONE;
  huart2.Init.Mode = UART_MODE_TX_RX;
  huart2.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart2.Init.OverSampling = UART_OVERSAMPLING_16;
  HAL_UART_Init(&huart2);
}

/* ========================================================================== */
/*  UART TX (DMA, non-blocking, semaphore released by ISR)                    */
/* ========================================================================== */
static bool uartSendDmaRaw(const uint8_t* data, uint16_t len) {
  if (HAL_DMA_Start_IT(&hdma_usart2_tx,
                       (uint32_t)data,
                       (uint32_t)&huart2.Instance->DR,
                       len)
      != HAL_OK) {
    return false;
  }
  SET_BIT(huart2.Instance->CR3, USART_CR3_DMAT);
  return true;
}

/* Acquire TX channel, start DMA. Semaphore is returned by the DMA ISR,
 * NOT here — that is what makes back-to-back transfers safe. */
static bool uartSendDma(const uint8_t* data, uint16_t len, TickType_t timeout) {
  if (txSemaphore == NULL || len == 0) return false;
  if (xSemaphoreTake(txSemaphore, timeout) != pdTRUE) {
    txDropCount++;   // couldn't even acquire the channel in time
    return false;
  }

  if (!uartSendDmaRaw(data, len)) {
    xSemaphoreGive(txSemaphore);  // start failed -> release immediately
    txDropCount++;
    return false;
  }
  return true;  // released later by TxDmaCpltCallback
}

/* FIX: variant used when the caller has ALREADY taken txSemaphore itself
 * (see sendTelemetry() below). Never re-acquires the semaphore — it just
 * starts the transfer, or releases it back on failure. This lets a caller
 * hold the lock across "format into shared buffer" + "start DMA" as one
 * atomic-with-respect-to-the-buffer sequence, instead of taking the lock
 * only at send time (which is what let a still-in-flight DMA transfer be
 * clobbered by the next snprintf() in the original code). */
static bool uartSendDmaLocked(const uint8_t* data, uint16_t len) {
  if (!uartSendDmaRaw(data, len)) {
    xSemaphoreGive(txSemaphore);  // start failed -> release immediately
    txDropCount++;
    return false;
  }
  return true;  // released later by TxDmaCpltCallback
}

void debugprintf(const char* format, ...) {
  if (txSemaphore == NULL) return;
  if (xSemaphoreTake(txSemaphore, pdMS_TO_TICKS(DEBUG_TX_TIMEOUT_MS)) != pdTRUE)
    return;

  va_list args;
  va_start(args, format);
  int len = vsnprintf(debugTxBuf, sizeof(debugTxBuf), format, args);
  va_end(args);

  if (len <= 0) {
    xSemaphoreGive(txSemaphore);
    return;
  }
  if (len >= (int)sizeof(debugTxBuf)) {
    len = sizeof(debugTxBuf) - 1;
  }
  if (!uartSendDmaRaw((const uint8_t*)debugTxBuf, (uint16_t)len))
    xSemaphoreGive(txSemaphore);
}


/* ========================================================================== */
/*  TELEMETRY                                                                 */
/* ========================================================================== */
static void sendTelemetry(void) {
  SensorData_t snap;

  /* Short, bounded lock: copy shared data, then format/transmit lock-free */
  if (xSemaphoreTake(dataMutex, pdMS_TO_TICKS(10)) != pdTRUE) return;
  snap = sensorData;
  xSemaphoreGive(dataMutex);

  /* FIX: acquire the TX channel BEFORE touching telemetryTxBuf, not after
   * formatting into it. xSemaphoreTake() only succeeds once the PREVIOUS
   * DMA transfer has actually completed and released the semaphore (see
   * TxDmaCpltCallback/TxDmaErrorCallback), so once we're past this line
   * nothing can still be reading telemetryTxBuf — it's safe to overwrite.
   * If the channel doesn't free up within TX_ACQUIRE_TIMEOUT, skip this
   * cycle rather than risk corrupting an in-flight transfer; SEQ still
   * increments so the host sees a clean, honest gap instead of a garbled
   * or falsely-decreasing SEQ value. */
  if (txSemaphore == NULL) return;
  if (xSemaphoreTake(txSemaphore, TX_ACQUIRE_TIMEOUT) != pdTRUE) {
    txDropCount++;
    ++txSeq;
    return;
  }

  uint32_t nowTick = (uint32_t)xTaskGetTickCount();
  uint32_t seq = ++txSeq;   // increments even on failed sends -> gaps are visible to the host

  char vBuf[12], iBuf[12], pBuf[12], tBuf[12], hBuf[12];
  dtostrf(snap.voltage, 1, 2, vBuf);
  dtostrf(snap.current, 1, 2, iBuf);
  dtostrf(snap.power, 1, 2, pBuf);
  dtostrf(snap.temperature, 1, 1, tBuf);
  dtostrf(snap.humidity, 1, 1, hBuf);

  int len = snprintf(telemetryTxBuf,
                     sizeof(telemetryTxBuf),
                     "AA55,SEQ:%lu,%lu,%s,%s,%s,%s,"
                     "%d,%d,%d,%d,%d,55AA\r\n",
                     (unsigned long)seq,
                     (unsigned long)nowTick,
                     vBuf,
                     iBuf,
                     tBuf,
                     hBuf,
                     snap.leak_p_1 ? 1 : 0,
                     snap.leak_p_2 ? 1 : 0,
                     snap.leak_p_3 ? 1 : 0,
                     snap.leak_p_4 ? 1 : 0,
                     snap.relayActive ? 1 : 0);

  if (len > 0) {
    uartSendDmaLocked((const uint8_t*)telemetryTxBuf, (uint16_t)len);
  } else {
    xSemaphoreGive(txSemaphore);  // nothing to send — don't leak the lock
  }
}

/* Streams sensor data continuously at TELEMETRY_PERIOD_MS with no drift */
static void vTelemetryTask(void* arg) {
  (void)arg;
  TickType_t lastWake = xTaskGetTickCount();
  for (;;) {
    sendTelemetry();
    xEventGroupSetBits(aliveEvents, TELE_ALIVE);
    vTaskDelayUntil(&lastWake, pdMS_TO_TICKS(TELEMETRY_PERIOD_MS));
  }
}

/* ========================================================================== */
/*  UART RX TASK — DMA + polling, NO interrupt vector touched at all.        */
/*                                                                            */
/*  DMA silently absorbs every incoming byte into rxDmaBuffer in a hardware  */
/*  circular buffer, with zero CPU involvement — so unlike naive register    */
/*  polling, a whole burst like "PING\n" arriving in ~50µs can never be      */
/*  lost between our polls, no matter how the poll timing lines up. Every    */
/*  poll cycle we just compare "how far has DMA's write pointer advanced     */
/*  since I last looked" and drain exactly that many new bytes — that        */
/*  comparison is the flag-check pattern requested, just backed by a         */
/*  hardware pointer instead of a boolean so no data can be silently lost.   */
/* ========================================================================== */
static void vUartRxTask(void* arg) {
  const uint8_t pong[] = "Pong\r\n";
  (void)arg;

  SET_BIT(huart2.Instance->CR3, USART_CR3_DMAR);
  HAL_DMA_Start(&hdma_usart2_rx,
               (uint32_t)&huart2.Instance->DR,
               (uint32_t)rxDmaBuffer,
               RX_DMA_BUF_SIZE);

  char line[CMD_BUF_SIZE];
  uint16_t lineLen = 0;

  for (;;) {
    vTaskDelay(pdMS_TO_TICKS(10));   // 10 ms — plenty responsive for rare, short commands
    xEventGroupSetBits(aliveEvents, UART_ALIVE);

    if (__HAL_UART_GET_FLAG(&huart2, UART_FLAG_ORE)) {
      __HAL_UART_CLEAR_OREFLAG(&huart2);   // shouldn't happen with DMA draining RDR, but be safe
    }

    uint16_t writePos = (uint16_t)(RX_DMA_BUF_SIZE - hdma_usart2_rx.Instance->CNDTR);

    while (rxReadPos != writePos) {
      char c = (char)rxDmaBuffer[rxReadPos];
      rxReadPos = (uint16_t)((rxReadPos + 1) % RX_DMA_BUF_SIZE);

      if (c == '\n') {
        line[lineLen] = '\0';

        if (strstr(line, "PING") != NULL) {
          uartSendDma(pong, sizeof(pong) - 1, TX_ACQUIRE_TIMEOUT);
        } else if (strstr(line, "RELAY_ON") != NULL) {
          relayMode = RELAY_MODE_FORCE_ON;
          bool relayOn =  true;
          sensorData.relayActive = relayOn;
          //uartSendDma((const uint8_t*)"RELAY=ON\r\n", 10, TX_ACQUIRE_TIMEOUT);
        } else if (strstr(line, "RELAY_OFF") != NULL) {
          relayMode = RELAY_MODE_FORCE_OFF;
          bool relayOn =  false;
          sensorData.relayActive = relayOn;
          //uartSendDma((const uint8_t*)"RELAY=OFF\r\n", 11, TX_ACQUIRE_TIMEOUT);
        } else if (strstr(line, "RELAY_AUTO") != NULL) {
          relayMode = RELAY_MODE_AUTO;
         //  uartSendDma((const uint8_t*)"RELAY=AUTO\r\n", 12, TX_ACQUIRE_TIMEOUT);
        }
        lineLen = 0;
      } else if (c != '\r') {
        if (lineLen < (CMD_BUF_SIZE - 1)) {
          line[lineLen++] = c;
        } else {
          lineLen = 0;   // overflow -> discard and restart this line
        }
      }
    }
  }
}

/* ========================================================================== */
/*  SENSOR TASKS                                                              */
/* ========================================================================== */
static void vDhtTask(void* arg) {
  (void)arg;
  TickType_t lastWake = xTaskGetTickCount();
  for (;;) {
    /* DHT read is slow & bit-banged — do it OUTSIDE any lock */
    float t = dht.readTemperature();
    float h = dht.readHumidity();

    if (xSemaphoreTake(dataMutex, portMAX_DELAY) == pdTRUE) {
      if (!isnan(t)) sensorData.temperature = t;
      if (!isnan(h)) sensorData.humidity = h;
      xSemaphoreGive(dataMutex);
    }
    xEventGroupSetBits(aliveEvents, DHT_ALIVE);
    vTaskDelayUntil(&lastWake, pdMS_TO_TICKS(DHT_PERIOD_MS));
  }
}

static void vIna260Task(void* arg) {
  (void)arg;
  TickType_t lastWake = xTaskGetTickCount();
  for (;;) {
    if (inaPresent) {
      /* I2C reads outside the lock; lock held only for the copy */
      float v = ina260.readBusVoltage() / 1000.0f;  // V
      float i = ina260.readCurrent();               // mA
      float p = ina260.readPower();                 // mW

      /* Current is physically one-directional in this system, so a
       * negative reading is measurement noise near zero load (the
       * INA260's current LSB is 1.25 mA), not a real reverse current.
       * Clamp rather than report a value that can't actually occur. */
      if (i < 0.0f) i = 0.0f;

      if (xSemaphoreTake(dataMutex, portMAX_DELAY) == pdTRUE) {
        sensorData.voltage = v;
        sensorData.current = i;
        sensorData.power = p;
        xSemaphoreGive(dataMutex);
      }
    }
    xEventGroupSetBits(aliveEvents, INA_ALIVE);
    vTaskDelayUntil(&lastWake, pdMS_TO_TICKS(INA_PERIOD_MS));
  }
}

static void vLeakTask(void* arg) {
  (void)arg;
  TickType_t lastWake = xTaskGetTickCount();
  for (;;) {
    bool leak_p_1 = (digitalRead(LEAK_PIN_1) == LOW);
    bool leak_p_2 = (digitalRead(LEAK_PIN_2) == LOW);
    bool leak_p_3 = (digitalRead(LEAK_PIN_3) == LOW);
    bool leak_p_4 = (digitalRead(LEAK_PIN_4) == LOW);
    bool anyLeak  = leak_p_1 || leak_p_2 || leak_p_3 || leak_p_4;

    /* Relay state: leak-driven by default, but a host command (RELAY_ON /
     * RELAY_OFF / RELAY_AUTO, see vUartRxTask) can force it regardless of
     * leak state. Written outside the lock (GPIO write is atomic / not
     * shared data), then the resulting state is recorded under the lock
     * for telemetry — using relayOn (the ACTUAL commanded state), not
     * anyLeak, so RELAY= in the packet always matches reality even while
     * a manual override is active. */
    RelayMode_t mode = relayMode;
    bool relayOn = (mode == RELAY_MODE_FORCE_ON)  ? true
                 : (mode == RELAY_MODE_FORCE_OFF) ? false
                 : anyLeak;
    digitalWrite(RELAY_PIN, relayOn ? RELAY_ACTIVE_LEVEL : RELAY_INACTIVE_LEVEL);

    if (xSemaphoreTake(dataMutex, portMAX_DELAY) == pdTRUE) {
      sensorData.leak_p_1 = leak_p_1;
      sensorData.leak_p_2 = leak_p_2;
      sensorData.leak_p_3 = leak_p_3;
      sensorData.leak_p_4 = leak_p_4;
      //sensorData.relayActive = relayOn;

      xSemaphoreGive(dataMutex);
    }
    xEventGroupSetBits(aliveEvents, LEAK_ALIVE);
    vTaskDelayUntil(&lastWake, pdMS_TO_TICKS(LEAK_PERIOD_MS));
  }
}

/* ========================================================================== */
/*  WATCHDOG SUPERVISOR — feeds IWDG only when every task has checked in      */
/* ========================================================================== */
static void vWatchdogTask(void* arg) {
  (void)arg;
  for (;;) {
    EventBits_t bits = xEventGroupWaitBits(aliveEvents,
                                           ALL_ALIVE,
                                           pdTRUE,  // clear on exit
                                           pdTRUE,  // wait for ALL bits
                                           pdMS_TO_TICKS(WDG_CHECK_PERIOD_MS));
    if ((bits & ALL_ALIVE) == ALL_ALIVE) {
      watchdogFeed();
    }
    /* If any task is hung, IWDG expires (~4 s) and the MCU resets itself. */
  }
}

/* ========================================================================== */
/*  SETUP                                                                     */
/* ========================================================================== */
static void fatalError(void) {
  pinMode(ERROR_LED, OUTPUT);
  for (;;) {  // watchdog will reset us; blink until then
    digitalWrite(ERROR_LED, !digitalRead(ERROR_LED));
    for (volatile uint32_t i = 0; i < 200000; i++) {}
  }
}

void setup() {
  /* NOTE: no Serial.begin() call. USART2 (PA9/PA10) is not the board's
   */
  HAL_Init();

  /* REQUIRED for FreeRTOS on Cortex-M: the kernel's ISR-safe APIs
   * (xxxFromISR) mask interrupts via BASEPRI, which only behaves
   * correctly when the NVIC priority grouping is "4 bits pre-emption,
   * 0 bits sub-priority". STM32's power-on-reset grouping is NOT this —
   * without setting it explicitly, HAL_NVIC_SetPriority() calls below
   * don't land where FreeRTOS expects, and the FIRST time an ISR that
   * calls a FreeRTOS xxxFromISR() function actually fires (e.g. the
   * USART2 RXNE handler, only exercised once you send a UART command),
   * it can corrupt the kernel mid-critical-section -> hang -> watchdog
   * reset ~4s later (which is exactly why SEQ restarted from 1: that's
   * a fresh boot, not a stall). This must be set before any
   * HAL_NVIC_SetPriority() call, so it goes here, right after HAL_Init(). */
  HAL_NVIC_SetPriorityGrouping(NVIC_PRIORITYGROUP_4);

  SystemClock_Config();  //Running at 72 MHZ
  MX_GPIO_Init();
  MX_DMA_Init();
  MX_USART2_UART_Init();

  Wire.begin();
  Wire.setClock(400000);  // 400 kHz fast-mode I2C: 4x faster INA reads
  analogReadResolution(12);
  pinMode(LEAK_PIN_1, INPUT_PULLUP);
  pinMode(LEAK_PIN_2, INPUT_PULLUP);
  pinMode(LEAK_PIN_3, INPUT_PULLUP);
  pinMode(LEAK_PIN_4, INPUT_PULLUP);

  pinMode(RELAY_PIN, OUTPUT);
  digitalWrite(RELAY_PIN, RELAY_INACTIVE_LEVEL);  // fail-safe: relay OFF until first leak check

  dht.begin();
  inaPresent = ina260.begin();  // stored; task skips reads if sensor absent

  /* RTOS objects — created and VERIFIED before any task can touch them */
  txSemaphore = xSemaphoreCreateBinary();
  dataMutex = xSemaphoreCreateMutex();
  aliveEvents = xEventGroupCreate();
  if (txSemaphore == NULL || dataMutex == NULL || aliveEvents == NULL) {
    fatalError();
  }
  xSemaphoreGive(txSemaphore);  // TX channel starts free

  /* Priorities: watchdog > telemetry/RX > fast sensors > slow DHT */
  BaseType_t ok = pdPASS;
  ok &= xTaskCreate(vWatchdogTask, "WDG", 192, NULL, 4, NULL);
  ok &= xTaskCreate(vTelemetryTask, "TELE", 512, NULL, 3, NULL);
  ok &= xTaskCreate(vUartRxTask, "UARTRX", 384, NULL, 3, &uartRxTaskHandle);
  ok &= xTaskCreate(vLeakTask, "LEAK", 192, NULL, 2, NULL);
  ok &= xTaskCreate(vIna260Task, "INA260", 256, NULL, 2, NULL);
  ok &= xTaskCreate(vDhtTask, "DHT11", 256, NULL, 1, NULL);
  if (ok != pdPASS) {
    fatalError();
  }

  /* Start the watchdog LAST — from here on, the system must stay healthy */
  watchdogInit();

  vTaskStartScheduler();

  fatalError();  // scheduler returned: out of heap
}

void loop() {
}
