# FSOL-XDAGMINER — ESP32 Embedded Mining Device

Firmware for a standalone ESP32-based cryptocurrency mining device. The application is mining; the engineering is embedded systems on a constrained microcontroller.

## Embedded engineering

- **Constrained-device programming** — Arduino framework on ESP32, working within tight RAM/flash budgets
- **Networking** — WiFi client with secure connections, mDNS service discovery, UPnP port handling
- **Embedded web server** — on-device configuration interface (`WebServer.h`), no companion app required
- **Cryptography on hardware** — SHA-256 via mbedtls, hardware random number generator (`esp_random.h`), AES
- **Reliability** — task watchdog timers, persistent configuration via Preferences (survives power loss)
- **Data interchange** — JSON API (ArduinoJson) on a microcontroller

## Structure

| File | Purpose |
|------|---------|
| `NameCoinMiner001.ino` / `Nameminer.ino` | Main firmware |
| `WebServer.h` | On-device configuration web server |
| `hashingFunctions.cpp`, `cryptoops.cpp` | Hashing and cryptographic operations |
| `ArduinoJson.h` | JSON parsing for the config API |

## Hardware

ESP32 development board. Configure via the on-device web interface after flashing.

---

Built by Charles Prescott. Part of an embedded-systems thread of work alongside larger software projects — [Verdict](https://github.com/Fibinachi/Verdict) (agentic jury simulation) and [GRID](https://github.com/Fibinachi/grid-demos) (4.9M-record geospatial dataset).
