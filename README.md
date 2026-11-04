# KRNL v0.3 - ESP32 Wi-Fi Recon HUD

KRNL is a standalone Arduino firmware for a classic ESP32 with a 320 x 240 ILI9341 display, XPT2046 resistive touch controller, microSD storage, and a TSOP1838B IR receiver.

It provides a touchscreen dashboard for 2.4 GHz access-point discovery, AP history and heuristic anomaly flags, receive-only 802.11 management-frame monitoring, IR pulse diagnostics, local logs, CSV exports, and selective PCAP capture.

> [!IMPORTANT]
> This repository is based on source inspection. The current firmware has not been compiled or tested on physical hardware in this repository.

## Documentation

The complete guide covers components, wiring, architecture, features, setup, operation, SD records, limitations, and troubleshooting:

- [Download the PDF field guide](docs/KRNL_v0.3_README.pdf)

## Hardware

- Classic ESP32 development board
- ILI9341 SPI TFT, 320 x 240
- XPT2046 resistive touchscreen controller
- SPI microSD interface and card
- TSOP1838B 38 kHz IR receiver

### Pin map

| ESP32 GPIO | Connection |
|---:|---|
| 18 | Shared SPI SCK |
| 19 | Shared SPI MISO |
| 23 | Shared SPI MOSI |
| 27 | TFT CS |
| 26 | TFT D/C |
| 25 | TFT RESET |
| 33 | Touch CS |
| 32 | Touch IRQ |
| 13 | SD CS |
| 21 | IR receiver OUT |

Use the documentation for each physical module to determine supply voltage, ground, backlight wiring, and the TSOP1838B package pin order.

## Implemented features

- Asynchronous Wi-Fi scans with a bounded 40-entry AP cache
- SSID, BSSID, RSSI, channel, authentication, sightings, and change history
- 16-sample RSSI graph and channel occupancy view
- Watchlist, learned baseline, adaptive scan cadence, and heuristic anomaly scores
- Receive-only packet monitor for selected 802.11 management subtypes
- Selective PCAP storage for beacon and probe-response frames
- IR burst timing diagnostics
- Touch calibration, manual clock, local PIN gate, and persistent preferences
- Session logs, scan CSV files, summaries, alerts, and security audit records
- Optional BLE scan support behind `KRNL_ENABLE_BLE` (disabled by default)

## Build

1. Install the Espressif Arduino-ESP32 board package.
2. Install Adafruit GFX, Adafruit ILI9341, and XPT2046_Touchscreen.
3. Open [`firmware/KRNL_v0_3/KRNL_v0_3.ino`](firmware/KRNL_v0_3/KRNL_v0_3.ino) in Arduino IDE.
4. Select the actual classic ESP32 board and serial port.
5. Keep `KRNL_ENABLE_BLE` set to `0` for the first build.
6. Compile, upload, and open Serial Monitor at 115200 baud.

The source recommends a Huge APP partition when BLE is enabled. Exact board-package and library versions have not yet been pinned.

## Important behavior

The UI describes Wi-Fi discovery as passive, but the current call is `WiFi.scanNetworks(true, showHidden)`. This enables asynchronous scanning and leaves the API's passive argument at its default value of `false`. The packet-monitor feature is a separate receive-only path.

Radar positions are deterministic visualizations derived from BSSID and RSSI. They do not represent measured direction or physical distance. Anomaly scores are heuristics and do not prove an intrusion.

Use wireless monitoring features only on networks and spectrum you are authorized to observe, and follow local law.

## Storage

Runtime records are written below `/krnl` on the SD card, including session logs, per-scan CSV files, latest snapshots, summaries, alerts, security events, IR events, packet-monitor events, baselines, configuration snapshots, and PCAP captures.

The SD card is not encrypted. SSIDs and BSSIDs are stored in clear text, and the four-digit PIN is only a local interface gate.

## Known limitations

- No compilation or hardware validation is included yet.
- A watched AP can produce repeated missing alerts because the missed-scan counter can remain at one.
- The asynchronous scan service has no application-level timeout recovery.
- The AP cache, log queues, packet queue, and PCAP snap length are deliberately bounded.
- Time is entered manually and has no date, timezone, RTC, or NTP synchronization.
- Some SD writes and removals do not verify their result.
- Touch calibration, time/PIN dialogs, and optional BLE scanning block the main loop.

See the PDF guide for the full engineering notes and troubleshooting matrix.

## Repository status

This is an early hardware project release. Contributions that add reproducible build metadata, hardware validation, or narrowly scoped fixes are welcome.
