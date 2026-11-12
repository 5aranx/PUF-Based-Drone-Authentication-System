# ESP32 PUF Drone Firmware

ESP-IDF C firmware for SRAM PUF reading, dark-bit masking, BCH fuzzy extraction, and challenge-response authentication.

## Modules

- `components/bch/`: Portable, standalone $\text{BCH}(255, 131, t=18)$ codec over $\text{GF}(2^8)$ with Berlekamp-Massey and Chien search.
- `main/puf.c`: Reads uninitialized SRAM memory, performs temporal majority voting across power cycles, and creates dark-bit masks.
- `main/fuzzy_extractor.c`: Implements the code-offset fuzzy extractor:
  - Enrollment: $H = P_{\text{selected}} \oplus \text{BCH}(K)$
  - Reconstruction: $C' = P'_{\text{selected}} \oplus H \implies \text{BCH\_Decode}(C') \to K$
- `main/auth_client.c`: Handles network requests to the Ground Station, including single-use challenge nonces and `HMAC-SHA256` generation via mbedTLS.
- `main/main.c`: Boot state machine (`BOOT` $\to$ `PUF_READ` $\to$ `RECONSTRUCT` $\to$ `NET_CONNECT` $\to$ `AUTH` $\to$ `LIVE` / `DENY`).

## Building & Flashing

```bash
# Configure WiFi SSID, server endpoint, and device credentials
idf.py menuconfig

# Build firmware
idf.py build

# Flash to connected ESP32
idf.py -p /dev/ttyUSB0 flash monitor
```
