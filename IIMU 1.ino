#include <Arduino.h>
#include <STM32FreeRTOS.h>
#include <Wire.h>
#include <SparkFun_BNO08x_Arduino_Library.h>
#include <stdarg.h>
#include <string.h>
#include <stm32f1xx_hal.h>
#include <stm32f1xx_hal_dma.h>
#include <stm32f1xx_hal_uart.h>

/* ------------------------------ Configuration ---------------------------- */

#define SENSOR_SDA_PIN PB7
#define SENSOR_SCL_PIN PB6
#define BNO08X_ADDR 0x4B
#define I2C_CLOCK_HZ 100000UL   /* confirmed working; 400kHz broke begin() */
#define ERROR_LED PC13
#define DEBUG 0
#define CMD_BUF_SIZE 64
#define TX_BUF_SIZE 220
#define RX_DMA_BUF_SIZE 128
#define DEBUG_TX_TIMEOUT_MS 15
#define IMU_POWERUP_DELAY_MS 1000
#define IMU_BEGIN_RETRIES 10
#define IMU_BEGIN_RETRY_MS 200

#define TX_ACQUIRE_TIMEOUT pdMS_TO_TICKS(4)   /* short drop instead of stall */
#define TELEMETRY_PERIOD_MS 10    /* 100 Hz continuous stream rate */
#define IMU_RATE_MS 2            /* 100 Hz IMU sample rate */
#define IMU_ACCEL_RATE_MS 10
#define IMU_MANGONO_RATE_MS 10

#define UART_POLL_MS 2
#define CONN_CHECK_PERIOD_MS 500  /* re-probe interval for a dead bus */
#define WDG_CHECK_PERIOD_MS 400   /* Watchdog check window (~400 ms) */
#define IWDG_PRESCALER 0x04       /* prescaler /64 */
#define IWDG_RELOAD_VALUE 2500    /* ~4 s timeout @ 40 kHz LSI */

/* ------------------------------ Task Alive Bits -------------------------- */

#define IMU_ALIVE (1 << 0)
#define UART_ALIVE (1 << 1)
#define TELE_ALIVE (1 << 2)
#define ALL_ALIVE (IMU_ALIVE | UART_ALIVE | TELE_ALIVE)


static volatile bool imuStarted = false;


/* ------------------------------ Types & Structures ----------------------- */
typedef struct {
  float roll, pitch, yaw;
  float qx, qy, qz, qw;
  float ax, ay, az;
  float gx, gy, gz;
  float mx, my, mz;
  bool isDeviceConnected;
} SensorData_t;

/* ------------------------------ Hardware & Globals ----------------------- */
TwoWire SENSOR_I2C(SENSOR_SDA_PIN, SENSOR_SCL_PIN);
BNO08x imu;

UART_HandleTypeDef huart2;
DMA_HandleTypeDef hdma_usart2_tx;  // DMA1 Channel 7
DMA_HandleTypeDef hdma_usart2_rx;  // DMA1 Channel 6

static uint8_t rxDmaBuffer[RX_DMA_BUF_SIZE];
static uint16_t rxReadPos = 0;

static char telemetryTxBuf[TX_BUF_SIZE];
static char debugTxBuf[128];

static volatile uint32_t txSeq = 0;
static volatile uint32_t txDropCount = 0;
static volatile uint32_t imuDeadlineMiss = 0;
static volatile uint8_t debugVerbose = 0;

static SensorData_t sensorData = { 0 };

/* FreeRTOS Handles */
static SemaphoreHandle_t txSemaphore = NULL;
static SemaphoreHandle_t dataMutex = NULL;
static EventGroupHandle_t aliveEvents = NULL;
static TaskHandle_t uartRxTaskHandle = NULL;

/* ------------------------------ Function Prototypes ---------------------- */
static void watchdogInit(void);
static inline void watchdogFeed(void);
static bool uartSendDmaRaw(const uint8_t* data, uint16_t len);
static bool uartSendDma(const uint8_t* data, uint16_t len, TickType_t timeout);
static void sendTelemetry(void);
bool checkConnection(void);

/* ========================================================================== */
/*  WATCHDOG ROUTINES                                                         */
/* ========================================================================== */
static void watchdogInit(void) {
  IWDG->KR = 0x5555;              // unlock
  IWDG->PR = IWDG_PRESCALER;      // /64
  IWDG->RLR = IWDG_RELOAD_VALUE;  // ~4 s @ 40 kHz LSI
  IWDG->KR = 0xAAAA;              // load
  IWDG->KR = 0xCCCC;              // start
}

static inline void watchdogFeed(void) {
  IWDG->KR = 0xAAAA;
}

/* ========================================================================== */
/*  DMA ISR CALLBACKS                                                         */
/* ========================================================================== */
static void TxDmaCpltCallback(DMA_HandleTypeDef* hdma) {
  (void)hdma;
  BaseType_t woken = pdFALSE;
  CLEAR_BIT(huart2.Instance->CR3, USART_CR3_DMAT);
  xSemaphoreGiveFromISR(txSemaphore, &woken);
  portYIELD_FROM_ISR(woken);
}

static void TxDmaErrorCallback(DMA_HandleTypeDef* hdma) {
  (void)hdma;
  BaseType_t woken = pdFALSE;
  CLEAR_BIT(huart2.Instance->CR3, USART_CR3_DMAT);
  xSemaphoreGiveFromISR(txSemaphore, &woken);
  portYIELD_FROM_ISR(woken);
}

extern "C" void DMA1_Channel7_IRQHandler(void) {
  HAL_DMA_IRQHandler(&hdma_usart2_tx);
}

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

  pinMode(ERROR_LED, OUTPUT);
  digitalWrite(ERROR_LED, HIGH);   /* PC13 active low: HIGH = off */
}

static void MX_DMA_Init(void) {
  __HAL_RCC_DMA1_CLK_ENABLE();

  // TX DMA setup
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

  // RX DMA setup (Circular Mode)
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
/*  UART TRANSMISSION FUNCTIONS                                               */
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

static bool uartSendDma(const uint8_t* data, uint16_t len, TickType_t timeout) {
  if (txSemaphore == NULL || len == 0) return false;
  if (xSemaphoreTake(txSemaphore, timeout) != pdTRUE) {
    txDropCount++;
    return false;
  }

  if (!uartSendDmaRaw(data, len)) {
    xSemaphoreGive(txSemaphore);
    txDropCount++;
    return false;
  }
  return true;
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

#define DBG(...) do { if (debugVerbose) debugprintf(__VA_ARGS__); } while (0)

/* Bare blocking send - no DMA, no semaphore, no RTOS object required.
 * Guarantees boot-time diagnostics reach the host even if setup() fails
 * before txSemaphore exists. */
static void uartSendBlocking(const char* s) {
  while (*s) {
    while (!(huart2.Instance->SR & USART_SR_TXE)) { }
    huart2.Instance->DR = (uint8_t)*s++;
  }
  while (!(huart2.Instance->SR & USART_SR_TC)) { }
}

/* ========================================================================== */
/*  TELEMETRY OUTPUT                                                          */
/* ========================================================================== */
static void sendTelemetry(void) {
  SensorData_t snap;

  if (xSemaphoreTake(dataMutex, pdMS_TO_TICKS(3)) != pdTRUE) return;
  snap = sensorData;
  xSemaphoreGive(dataMutex);

  uint32_t nowTick = (uint32_t)xTaskGetTickCount();

  char qxBuf[12], qyBuf[12], qzBuf[12], qwBuf[12];
  char axBuf[12], ayBuf[12], azBuf[12];
  char gxBuf[12], gyBuf[12], gzBuf[12];
  char mxBuf[12], myBuf[12], mzBuf[12];

  dtostrf(snap.qx, 1, 4, qxBuf);
  dtostrf(snap.qy, 1, 4, qyBuf);
  dtostrf(snap.qz, 1, 4, qzBuf);
  dtostrf(snap.qw, 1, 4, qwBuf);

  dtostrf(snap.ax, 1, 3, axBuf);
  dtostrf(snap.ay, 1, 3, ayBuf);
  dtostrf(snap.az, 1, 3, azBuf);

  dtostrf(snap.gx, 1, 3, gxBuf);
  dtostrf(snap.gy, 1, 3, gyBuf);
  dtostrf(snap.gz, 1, 3, gzBuf);

  dtostrf(snap.mx, 1, 3, mxBuf);
  dtostrf(snap.my, 1, 3, myBuf);
  dtostrf(snap.mz, 1, 3, mzBuf);

  int len = snprintf(telemetryTxBuf,
                     sizeof(telemetryTxBuf),
                     "AA55,SEQ:%lu,%lu,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%d,55FF\r\n",
                     (unsigned long)(txSeq + 1),
                     (unsigned long)nowTick,
                     qxBuf, qyBuf, qzBuf, qwBuf,
                     axBuf, ayBuf, azBuf,
                     gxBuf, gyBuf, gzBuf,
                     mxBuf, myBuf, mzBuf,
                     snap.isDeviceConnected ? 1 : 0);

  if (len > 0 && len < (int)sizeof(telemetryTxBuf)) {
    if (uartSendDma((const uint8_t*)telemetryTxBuf, (uint16_t)len, TX_ACQUIRE_TIMEOUT)) {
      txSeq++;
    }
  }
}

/* ========================================================================== */
/*  TASKS                                                                     */
/* ========================================================================== */

/* Watchdog Task */
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
    } else {
      DBG("[WD] miss: got=0x%02X need=0x%02X\r\n", (unsigned)bits, (unsigned)ALL_ALIVE);
    }
  }
}

/* Telemetry Task */
static void vTelemetryTask(void* arg) {
  (void)arg;
  TickType_t lastWake = xTaskGetTickCount();
  for (;;) {
    sendTelemetry();
    xEventGroupSetBits(aliveEvents, TELE_ALIVE);
    vTaskDelayUntil(&lastWake, pdMS_TO_TICKS(TELEMETRY_PERIOD_MS));
  }
}

/* UART RX Task */
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
    vTaskDelay(pdMS_TO_TICKS(UART_POLL_MS));
    xEventGroupSetBits(aliveEvents, UART_ALIVE);

    if (__HAL_UART_GET_FLAG(&huart2, UART_FLAG_ORE)) {
      __HAL_UART_CLEAR_OREFLAG(&huart2);
      DBG("[WARN] USART overrun cleared\r\n");
    }

    uint16_t writePos = (uint16_t)(RX_DMA_BUF_SIZE - hdma_usart2_rx.Instance->CNDTR);

    while (rxReadPos != writePos) {
      char c = (char)rxDmaBuffer[rxReadPos];
      rxReadPos = (uint16_t)((rxReadPos + 1) % RX_DMA_BUF_SIZE);

      if (c == '\n') {
        line[lineLen] = '\0';

        if (strstr(line, "PING") != NULL) {
          uartSendDma(pong, sizeof(pong) - 1, TX_ACQUIRE_TIMEOUT);
        } 
        lineLen = 0;
      } else if (c != '\r') {
        if (lineLen < (CMD_BUF_SIZE - 1)) {
          line[lineLen++] = c;
        } else {
          lineLen = 0;
        }
      }
    }
  }
}

/* IMU Sensor Task (BNO086) - fixed rate */
static void vTaskIMU(void* arg) {
  (void)arg;
  TickType_t lastWakeTime = xTaskGetTickCount();
  bool busOk = true;
  TickType_t lastCheck = 0;

  for (;;) {
    xEventGroupSetBits(aliveEvents, IMU_ALIVE);
    TickType_t now = xTaskGetTickCount();

    /* Only re-probe a bus already believed down, not every cycle. */
    if (!busOk && (now - lastCheck) >= pdMS_TO_TICKS(CONN_CHECK_PERIOD_MS)) {
      busOk = checkConnection();
      lastCheck = now;
    }

    if (busOk) {
      if (imu.wasReset()) {
        DBG("[IMU] reset detected, re-enabling reports\r\n");
        imu.enableRotationVector(IMU_RATE_MS);
        imu.enableLinearAccelerometer(IMU_ACCEL_RATE_MS);
        imu.enableGyro(IMU_RATE_MS);
        imu.enableMagnetometer(IMU_MANGONO_RATE_MS);
      }

      bool got = false;
      for (uint8_t i = 0; i < 12; i++) {
        if (!imu.getSensorEvent()) break;
        got = true;

        uint8_t eventId = imu.getSensorEventID();

        if (eventId == SENSOR_REPORTID_ROTATION_VECTOR) {
          float newRoll = imu.getRoll() * 180.0f / PI;
          float newPitch = imu.getPitch() * 180.0f / PI;
          float newYaw = imu.getYaw() * 180.0f / PI;

          if (!isnan(newRoll) && !isnan(newPitch) && !isnan(newYaw)) {
            if (xSemaphoreTake(dataMutex, pdMS_TO_TICKS(2)) == pdTRUE) {
              sensorData.roll = newRoll;
              sensorData.pitch = newPitch;
              sensorData.yaw = newYaw;

              sensorData.qx = imu.getQuatI();
              sensorData.qy = imu.getQuatJ();
              sensorData.qz = imu.getQuatK();
              sensorData.qw = imu.getQuatReal();

              sensorData.isDeviceConnected = true;
              xSemaphoreGive(dataMutex);
            }
          }
        } else if (eventId == SENSOR_REPORTID_LINEAR_ACCELERATION) {
          if (xSemaphoreTake(dataMutex, pdMS_TO_TICKS(2)) == pdTRUE) {
            sensorData.ax = imu.getLinAccelX();
            sensorData.ay = imu.getLinAccelY();
            sensorData.az = imu.getLinAccelZ();
            sensorData.isDeviceConnected = true;
            xSemaphoreGive(dataMutex);
          }
       
        } else if (eventId == SENSOR_REPORTID_GYROSCOPE_CALIBRATED) {
          if (xSemaphoreTake(dataMutex, pdMS_TO_TICKS(2)) == pdTRUE) {
            sensorData.gx = imu.getGyroX();
            sensorData.gy = imu.getGyroY();
            sensorData.gz = imu.getGyroZ();
            sensorData.isDeviceConnected = true;
            xSemaphoreGive(dataMutex);
          }
        } else if (eventId == SENSOR_REPORTID_MAGNETIC_FIELD) {
          if (xSemaphoreTake(dataMutex, pdMS_TO_TICKS(2)) == pdTRUE) {
            sensorData.mx = imu.getMagX();
            sensorData.my = imu.getMagY();
            sensorData.mz = imu.getMagZ();
            sensorData.isDeviceConnected = true;
            xSemaphoreGive(dataMutex);
          }
        }
      }
      if (!got) busOk = checkConnection();

    } else {
      if (xSemaphoreTake(dataMutex, pdMS_TO_TICKS(2)) == pdTRUE) {
        sensorData.isDeviceConnected = false;
        xSemaphoreGive(dataMutex);
      }
    }

    if ((xTaskGetTickCount() - now) > pdMS_TO_TICKS(IMU_RATE_MS)) {
      imuDeadlineMiss++;
    }

    vTaskDelayUntil(&lastWakeTime, pdMS_TO_TICKS(IMU_RATE_MS));
  }
}

/* ========================================================================== */
/*  HELPERS & SETUP                                                           */
/* ========================================================================== */
bool checkConnection(void) {
  SENSOR_I2C.beginTransmission(BNO08X_ADDR);
  return (SENSOR_I2C.endTransmission() == 0);
}

static void fatalError(const char* msg = NULL) {
  if (msg) {
    uartSendBlocking("\r\n[FATAL] ");
    uartSendBlocking(msg);
    uartSendBlocking("\r\n");
  }
  pinMode(ERROR_LED, OUTPUT);
  for (;;) {
    digitalWrite(ERROR_LED, !digitalRead(ERROR_LED));
    for (volatile uint32_t i = 0; i < 200000; i++) {}
  }
}

extern "C" void vApplicationStackOverflowHook(TaskHandle_t xTask, char *pcName) {
  (void)xTask; (void)pcName;
  fatalError("Stack overflow");
}

extern "C" void vApplicationMallocFailedHook(void) {
  fatalError("Malloc failed");
}

void setup() {
  /* HAL_Init() / SetPriorityGrouping() intentionally NOT called - the
   * STM32duino core already performs both before setup() runs. */
 // NVIC_SystemReset();
  HAL_Delay(200);
  HAL_Init();
  SystemClock_Config(); 
  MX_GPIO_Init();
  MX_DMA_Init();
  MX_USART2_UART_Init();

#if DEBUG
  uartSendBlocking("\r\n[BOOT] UART up @ 1000000 8N1\r\n");
#endif

  SENSOR_I2C.begin();
  SENSOR_I2C.setClock(I2C_CLOCK_HZ);
 // uartSendBlocking("[BOOT] I2C init done\r\n");
  HAL_Delay(100);
  if (!imu.begin(BNO08X_ADDR, SENSOR_I2C)) {
   // fatalError("IMU not found - check wiring/power/address");
  }
  //uartSendBlocking("[BOOT] IMU found OK\r\n");

  imu.enableRotationVector(IMU_RATE_MS);
  imu.enableLinearAccelerometer(IMU_ACCEL_RATE_MS);
  imu.enableGyro(IMU_RATE_MS);
  imu.enableMagnetometer(IMU_MANGONO_RATE_MS);

  /* RTOS Objects */
  txSemaphore = xSemaphoreCreateBinary();
  dataMutex = xSemaphoreCreateMutex();
  aliveEvents = xEventGroupCreate();

  if (txSemaphore == NULL || dataMutex == NULL || aliveEvents == NULL) {
    //fatalError("RTOS object alloc failed");
  }
  xSemaphoreGive(txSemaphore);
  //uartSendBlocking("[BOOT] RTOS objects created OK\r\n");

  /* Tasks Setup */
  BaseType_t ok = pdPASS;
  ok &= xTaskCreate(vWatchdogTask, "WDG", 192, NULL, 4, NULL);
  ok &= xTaskCreate(vTelemetryTask, "TELE", 384, NULL, 3, NULL);
  ok &= xTaskCreate(vUartRxTask, "UARTRX", 384, NULL, 3, &uartRxTaskHandle);
  ok &= xTaskCreate(vTaskIMU, "IMU", 512, NULL, 3, NULL);

  if (ok != pdPASS) {
    //fatalError("Task create failed");
  }
 // uartSendBlocking("[BOOT] Tasks created OK, starting scheduler\r\n");

  watchdogInit(); 
  vTaskStartScheduler();

  fatalError("Scheduler returned");
}

void loop() {
  // Managed by FreeRTOS
}
