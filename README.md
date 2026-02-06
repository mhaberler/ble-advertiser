# BLE Advertise & Decode Toolkit

ESP32-based BLE advertisement replayer driven by JSON commands over serial, plus a Python packet decoder for pcapng captures.

## Hardware

Tested on:
- M5Stack NanoC6
- M5Stamp C3U
- Seeed XIAO ESP32-C6
- AtomS3 / AtomS3U (ESP32-S3)

Will not work as-is on ESP32-P4 and friends.

## Build & Flash

Requires [Pioarduino](https://github.com/pioarduino/platform-espressif32). Currently uses Espressif Arduino version 3.3.6.

```bash
# Build for M5Stack NanoC6
pio run -e m5stack_nanoc6

# Upload
pio run -e m5stack_nanoc6 -t upload --upload-port /dev/cu.usbmodem1121401

# Monitor serial
pio device monitor -b 115200
```

## Firmware Usage

The device reads newline-terminated JSON commands from serial (115200 baud). Each command configures and starts a BLE advertisement.

### JSON Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mac` | string | `"C0:DE:BA:BE:00:01"` | Random MAC address to advertise from |
| `name` | string | `""` | Device name (sent in scan response) |
| `adv` | string (hex) | — | Raw advertising data bytes |
| `service_uuid` | string | — | Service UUID (16-bit, 32-bit, or 128-bit) |
| `service_data` | string (hex) | — | Service data payload (requires `service_uuid`) |
| `scan_raw` | string (hex) | — | Raw scan response data bytes |
| `appearance` | uint16 | `0` | GAP appearance value |
| `duration` | ulong (ms) | `1000` | Broadcast duration; `0` = infinite |

### Examples

**Basic advertisement with name:**
```json
{"mac":"F1:E2:D3:C4:B5:A6","adv":"0201060303AAFE","name":"MySpoofedDevice","appearance":832,"duration":10000}
```

**Infinite broadcast with raw scan response:**
```json
{"mac":"E5:77:AA:BB:CC:DD","adv":"0201060303AAFE","scan_raw":"09ff4c00020a00000000010203","duration":0}
```

**BTHome v2 sensor (16-bit UUID `FCD2`):**
```json
{"mac":"C1:D2:E3:F4:A5:B6","name":"DIY-sensor","service_uuid":"FCD2","service_data":"440c0c30414b0843e50062c063ffff6390290a00","duration":15000}
```

Service data breakdown (BTHome v2, device info byte `0x44`):
- `0x0C 0c30` — voltage: 12.300 V
- `0x41 4b08` — distance: 214.3 m
- `0x43 e500` — current: 0.229 A
- `0x62 c063ffff` — speed (signed): -0.040000 m/s
- `0x63 90290a00` — acceleration (signed): 0.666000 m/s²

**Eddystone beacon (16-bit UUID `FEAA`):**
```json
{"mac":"C1:D2:E3:F4:A5:B6","adv":"020106","service_uuid":"FEAA","service_data":"00f211223344","duration":5000}
```

**128-bit UUID service data:**
```json
{"mac":"C1:D2:E3:F4:A5:B6","service_uuid":"12345678-1234-1234-1234-123456789abc","service_data":"0102030405","duration":5000}
```

**Minimal — just raw adv bytes, default MAC, 1s duration:**
```json
{"adv":"0201060303AAFE"}
```

## BLE Decoder

Python script to decode BLE packets from pcapng captures. Use it to inspect captured advertisements and extract the exact hex payloads, UUIDs, and service data needed to construct JSON commands for the firmware.

**Workflow:** Capture BLE traffic (e.g. with a Nordic sniffer) → decode with `ble_decoder.py` → copy the relevant fields into a JSON command → replay via serial.

### Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install scapy
```

### Run

```bash
# Default file (ble.pcapng)
python ble_decoder.py

# Custom file
python ble_decoder.py /path/to/capture.pcapng
```

### Decoded Output

The decoder parses:
- BLE advertising PDU types (ADV_IND, ADV_SCAN_IND, SCAN_REQ, SCAN_RSP, etc.)
- Advertiser MAC address and address type (public/random)
- GAP AD structures: Flags, Name, TX Power, Service Data, Manufacturer Data
- **BTHome v2** measurements (UUID `0xFCD2`): voltage, temperature, humidity, pressure, speed, acceleration, and more
- Summary with unique addresses and packet counts

Example output:
```
Packet #1
  Access Address: 0x8E89BED6
  Type: Advertising
  ADV Type: ADV_SCAN_IND
  Advertiser Address: 48:CA:43:3A:34:05
  Advertising Data Structures:
    - Flags (0x01)
      Flags: LE General Discoverable, BR/EDR Not Supported
    - Service Data - 16-bit UUID (0x16)
      UUID: 0xFCD2
      Protocol: BTHome v2
      Measurements:
        - voltage: 10.32V
        - speed_signed: 2.2m/s
        - acceleration_signed: 0.368m/s²
```

## Project Structure

```
├── src/
│   └── ble-advertise.cpp   # ESP32 firmware
├── boards/
│   └── m5stack_nanoc6.json  # Custom board definition
├── ble_decoder.py           # Python pcapng decoder
├── ble.pcapng               # Sample capture
├── command.json             # Example JSON commands
└── platformio.ini           # Build configuration
```

### Related projects

https://github.com/ericbarch/BLECast
https://github.com/lucascoelhof/ESP32BleAdvertise/blob/master/src/ESP32BleAdvertise.h
https://github.com/dramco-edu/ble-scan-adv-esp32/blob/main/src/main.cpp
https://github.com/Wovyn/esp32-ble-advertisement-scanner-xiaomi-sensor-decoder/blob/main/src/esp32-ble-advertisement-scanner-xiaomi-sensor-decoder.ino
https://github.com/teodorandrei/esp32_blespoof_gui
https://github.com/cifertech/nRFBox/blob/main/README.md
https://github.com/ckcr4lyf/EvilAppleJuice-ESP32/blob/master/src/EvilAppleJuice-ESP32-INO/EvilAppleJuice-ESP32-INO.ino
https://github.com/tjpetz/mbed_BLE_GAP_advertiser/blob/main/mbed_BLE_GAP_advertiser.ino
https://github.com/peterk54/ESP32BLESimpleAdvertiser/blob/master/examples/manufacturerdata/manufacturerdata.ino
https://github.com/peterk54/ESP32BLESimpleAdvertiser/blob/master/examples/receiver/receiver.ino
https://github.com/peterk54/ESP32BLESimpleAdvertiser/blob/master/examples/servicedata/servicedata.ino
https://github.com/bchevreau/xgimi-ble-advertiser/blob/main/components/xgimi_ble_advertiser/xgimi_ble_advertiser.h
https://github.com/suo235/esp32_ble_simple_advertise/blob/master/main/main.cpp
https://github.com/cvonk/BLEscan/tree/main
https://github.com/pvvx/ADV_BLE2UART.git

