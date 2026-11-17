# AUV secure firmware – setup, upload and test

Six AES-256-GCM keys, one per data direction:

| Key | Direction | Encrypts | Decrypts |
|---|---|---|---|
| K1 | Sensor → Master | Sensor | Master |
| K2 | IMU → Master | IMU | Master |
| K3 | Thruster → Master | Thruster | Master |
| K4 | Master → Thruster | Master | Thruster |
| K5 | Master → Jetson | Master | Jetson |
| K6 | Jetson → Master | Jetson | Master |

Sensor and IMU only encrypt and send. Thruster, Master and Jetson encrypt and decrypt.

## Folder structure

```
Arduino/
├── libraries/
│   └── AUV_Security/                 <- copy the library folder here
│       ├── library.properties
│       ├── src/                      AUV_Encrypt.h, AUV_Decrypt.h, AUV_KeyManager.h,
│       │                             AUV_NonceManager.h, AUV_ReplayProtection.h,
│       │                             AUV_Packet.h, AUV_SecurityConfig.h, AUV_SecureLink.h,
│       │                             AUV_NodeProtocol.h, AUV_Platform.h, AUV_Security.h
│       ├── examples/AUV_SelfTest/    on-board test-suite + timing
│       └── extras/                   jetson/, tools/gen_keys.py, host_test/
├── Sensor/    Sensor.ino    build_opt.h   (+ AUV_Keys_Secret.h you generate)
├── IMU/       IMU.ino       build_opt.h   (+ AUV_Keys_Secret.h)
├── Thruster/  Thruster.ino  build_opt.h   (+ AUV_Keys_Secret.h)
├── Master/    Master.ino    build_opt.h   (+ AUV_Keys_Secret.h)
└── AUV_Provision/ AUV_Provision.ino
```

## 1. Install

1. Arduino IDE → File → Preferences → Additional boards manager URLs:
   `https://github.com/stm32duino/BoardManagerFiles/raw/main/package_stmicroelectronics_index.json`
2. Boards Manager → install **STM32 MCU based boards** (STMicroelectronics).
3. Install **STM32CubeProgrammer** (needed for ST-LINK upload).
4. Library Manager → install:
   - **Crypto** by Rhys Weatherley (all nodes)
   - **STM32duino FreeRTOS** (Sensor)
   - **Adafruit INA260 Library** and **DHT sensor library** by Adafruit (Sensor; accept the Adafruit BusIO / Unified Sensor dependencies)
   - **SparkFun BNO08x Cortex Based IMU** (IMU)
   - **Adafruit PWM Servo Driver Library** (Thruster)
   - `Servo` and `IWatchdog` are built into the STM32 core.
5. Copy the `AUV_Security` folder into `Documents/Arduino/libraries/` and restart the IDE.

## 2. Board settings (Tools menu)

| Setting | Blue Pill nodes (Sensor, IMU, Thruster) | Master |
|---|---|---|
| Board | Generic STM32F1 series | Your 4-UART board (H753 recommended) |
| Board part number | BluePill F103C8 (or the exact part) | Exact part |
| U(S)ART support | Enabled (generic 'Serial') | Enabled (no generic 'Serial') |
| USB support | None | CDC (generic 'Serial' supersede U(S)ART) |
| Optimize | **Faster (-O2)** – about 15% faster crypto | **Faster (-O2)** |
| Upload method | STM32CubeProgrammer (SWD) | STM32CubeProgrammer (SWD) |

`build_opt.h` in each sketch folder raises the UART buffers to 256 bytes so a whole frame (max 115 bytes) never overflows at 1 Mbaud.

## 3. Keys

```
python3 AUV_Security/extras/tools/gen_keys.py --out keys
```

Copy `keys/<Node>/AUV_Keys_Secret.h` into that node's sketch folder, and `keys/Jetson/jetson_keys.json` to the Jetson (`chmod 600`). Never commit them.

Without `AUV_Keys_Secret.h` a sketch builds with PUBLIC demo keys and prints `WARNING: DEMO KEYS` – bench testing only.

Each board prints its key fingerprints at boot; compare with `keys/FINGERPRINTS.txt`.

## 4. Provision once per board

Upload `AUV_Provision`, open the Serial Monitor (115200, Newline), type `PROVISION`, then `BOOTTEST` (epoch must go up by 1). Then upload the node firmware. Normal re-uploads keep the epoch store. A full chip erase removes it: provision again, with **new keys**.

## 5. Wiring

| From | To |
|---|---|
| Sensor PA2 (TX) | Master PB11 (USART3 RX) |
| IMU PA2 (TX) | Master PC7 (USART6 RX) [check your board] |
| Thruster PA2 (TX) | Master PA3 (USART2 RX) |
| Thruster PA3 (RX) | Master PA2 (USART2 TX) |
| Master PA9 (USART1 TX) | Jetson UART RX |
| Master PA10 (USART1 RX) | Jetson UART TX |
| GND | GND on every board (common) |

All 3.3 V logic, 1 Mbaud 8N1. A Blue Pill Master has only 3 UARTs: the sketch then disables the IMU link with a compiler warning.

## 6. Test in this order (no live thruster)

1. `AUV_SelfTest` on one Blue Pill → last line `RESULT: … 0 failed`; note the printed encrypt/decrypt µs.
2. Thruster + Master on the bench, Jetson script running:
   `python3 auv_secure_link.py --port /dev/ttyTHS1 --keys jetson_keys.json --provision` (first run only)
   Master prints `jetson=1 thr=1`; Thruster prints `state=1 link=1`.
3. Pull the Jetson cable → Master prints `Jetson link DOWN`, Thruster goes to `esc=1500`.
4. Pull the Thruster cable → Thruster `state=2` (timeout) within 250 ms.
5. Wet a leak sensor → Sensor relay switches; Master `leakStop=1`; Thruster `state=3`.
6. Reset each board in turn → links recover by themselves, `authFail` stays 0.

## Fail-safe summary

- Thruster: neutral + relays off at boot, on link loss (200 ms), command timeout (250 ms), 5 invalid commands, leak flag, watchdog reset.
- Master: leak or no Sensor data for 300 ms → every thruster command carries LEAK_STOP; Jetson down → neutral commands.
- Sensor: leak relay is local and debounced; the node accepts no commands at all.

## Values to confirm on your hardware ([CONFIRM] in the code)

ESC neutral (1500 µs), servo pulse range (500–2500 µs), servo safe angle (90°), relay level during a leak, IMU UART pins on the Master board.
