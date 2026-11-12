# PUF-Based Drone Authentication System

A hardware-rooted authentication and session management system for Unmanned Aerial Vehicles (UAVs) using **SRAM Physically Unclonable Functions (PUFs)** and **Fuzzy Extractors**.

Derived from microscopic manufacturing variations across silicon transistors, cryptographic keys are reconstructed dynamically at boot time from uninitialized SRAM physics and **never stored in flash memory**.

---

## Architecture Overview

```
                      +---------------------------------------+
                      |             DRONE (ESP32)             |
                      |                                       |
                      |  [ SRAM Uninitialized Power-Up ]      |
                      |                  |                    |
                      |                  v                    |
                      |  [ Majority Voting + Dark-Bit Mask ]  |
                      |                  |                    |
                      |                  v                    |
  NVS Flash           |        P' ⊕ Helper Data H             |
 [ H + Mask ] ------> |                  |                    |
                      |                  v                    |
                      |       [ BCH(255,131,t=18) Decode ]    |
                      |                  |                    |
                      |                  v                    |
                      |       Transient Key K (128-bit)       |
                      |                  |                    |
                      |                  v                    |
                      |       [ HMAC-SHA256 Challenge ]      |
                      +------------------|--------------------+
                                         |
                       WiFi / HTTP / TLS |  1. GET /challenge
                                         |  2. Nonce N
                                         |  3. POST /verify {HMAC(K, ID||N||ts)}
                                         |  4. JWT Session Token (HKDF)
                                         v
                      +---------------------------------------+
                      |         GROUND CONTROL STATION        |
                      |             (Flask Backend)           |
                      |                                       |
                      |  - Single-Use Nonce Store (60s TTL)   |
                      |  - Constant-time HMAC Verification    |
                      |  - Brute-Force Rate Limiting (Lockout)|
                      |  - HKDF-SHA256 Session Key Derivation |
                      |  - Real-Time Tactical Dashboard (SSE) |
                      +---------------------------------------+
```

---

## Key Security Properties

| Attack Vector | Traditional Flash Key | SRAM PUF System |
|---|---|---|
| **Flash Dumping (UART / JTAG / Desolder)** | Attacker extracts secret key; clones device completely. | Flash contains only public helper data $H$ and bitmask. $K$ is mathematically unclonable. |
| **Silicon Cloning (Same ESP32 Model)** | Firmware cloned to identical chip runs identically. | Different silicon die has ~50% inter-chip Hamming distance. BCH decode fails and halts boot. |
| **Replay Attack** | Captured challenge/response can be replayed if static. | Cryptographic nonces are single-use and burned immediately upon verification attempts. |
| **Cold Boot Memory Extraction** | Key persists in static memory. | Key $K$ is zeroised immediately after handshake completion. |

---

## Mathematical Foundation: Fuzzy Extractor

SRAM cells resolve to 0 or 1 based on sub-micron threshold voltage mismatches ($\Delta V_{th}$) between cross-coupled inverter pairs:
1. **Enrollment (One-Time Provisioning on Bench):**
   - Sample uninitialized SRAM over $N$ power cycles ($N \approx 32$).
   - Determine stable bits via temporal majority vote; create dark-bit mask.
   - Generate random 128-bit secret key $K$.
   - Compute BCH codeword $C = \text{BCH\_Encode}(K)$.
   - Generate public helper data:
     $$H = P_{\text{selected}} \oplus C$$
   - Store $(H, \text{mask})$ in NVS flash; commit $K$ to backend and zeroise from RAM.

2. **Reconstruction (Every Boot in Field):**
   - Sample noisy SRAM pattern $P' = P \oplus e$ where $e$ is the sparse noise vector.
   - Apply mask and XOR with helper data $H$:
     $$C' = P'_{\text{selected}} \oplus H = (P \oplus e) \oplus (P \oplus C) = C \oplus e$$
   - Run BCH decoder:
     $$\text{BCH\_Decode}(C') \to K$$
   - Up to $t=18$ bit errors are corrected automatically.

---

## Repository Structure

```
puf-drone/
├── firmware/                       # ESP-IDF C Firmware for ESP32
│   ├── CMakeLists.txt              # Top-level build definition
│   ├── Kconfig.projbuild           # Menuconfig options (WiFi, Server URL, Device ID)
│   ├── components/
│   │   └── bch/                    # Portable BCH(255, 131, t=18) GF(2^8) codec
│   │       ├── bch.c
│   │       ├── bch.h
│   │       └── CMakeLists.txt
│   └── main/
│       ├── main.c                  # State machine & FreeRTOS tasks
│       ├── puf.c / puf.h           # SRAM sampling, majority voting, dark-bit masking
│       ├── fuzzy_extractor.c / .h  # Code-offset helper data generation & reconstruction
│       └── auth_client.c / .h      # HTTP / mbedTLS HMAC-SHA256 handshake
│
├── backend/                        # Flask Ground Control Station Backend
│   ├── app.py                      # REST endpoints & Server-Sent Events (SSE)
│   ├── config.py                   # Security parameters, timeouts, and thresholds
│   ├── models.py                   # SQLite storage (device registry, nonces, audit log)
│   ├── puf_crypto.py               # Constant-time HMAC, HKDF, and JWT session handling
│   ├── templates/dashboard.html    # Tactical dark-mode command dashboard
│   └── static/dashboard.js         # Real-time event consumer & artificial horizon canvas
│
├── sim/                            # Software Simulation & Verification Suite
│   ├── sim_puf.py                  # Realistic SRAM PUF silicon model (noise + inter-chip distance)
│   ├── bch_soft.py                 # Python BCH codec wrapper
│   ├── fuzzy_extractor.py          # Python fuzzy extractor implementation
│   ├── sim_enrollment.py           # Simulated device provisioning tool
│   ├── sim_auth.py                 # Multi-scenario flight authorization test client
│   └── run_demo.sh                 # End-to-end automated demonstration script
│
├── diagrams/                       # Architecture and threat model diagrams (DOT & PNG)
└── PUF_Drone_Authentication.md     # Reference notes and specifications
```

---

## Quick Start (Automated Simulation & Demo)

To run the complete system on a local machine without physical ESP32 hardware:

```bash
# Run the end-to-end automated demo
cd /home/savi/Projects/puf-drone/sim
./run_demo.sh
```

The script will:
1. Boot the Flask GCS server on `http://127.0.0.1:5000`.
2. Provision two simulated aircraft (`DRONE-001` and `DRONE-002`) through the majority-voting enrollment pipeline.
3. Authenticate `DRONE-001` with simulated SRAM noise (demonstrating real-time BCH error correction).
4. Simulate an impostor device using identical firmware on a different physical die (verifying immediate rejection).
5. Attempt a replay attack using an intercepted authentication token (verifying single-use nonce destruction).

### Viewing the Tactical Dashboard

Start the backend:
```bash
cd /home/savi/Projects/puf-drone/backend
source .venv/bin/activate
python3 app.py
```

Navigate to `http://localhost:5000/dashboard` in your browser to view:
- **Fleet status** (🟢 LIVE, 🟡 AUTH, 🔴 DENIED, ⚫ OFFLINE)
- **Live telemetry** with pitch/roll attitude indicator
- **Real-time audit log** streaming security events via SSE
- **Interactive replay attack simulator button**

---

## ESP-IDF Firmware Compilation

The firmware is designed for Espressif ESP32 chips using ESP-IDF v4.4+:

```bash
cd /home/savi/Projects/puf-drone/firmware

# Configure WiFi SSID, server endpoint, and device credentials
idf.py menuconfig

# Build firmware
idf.py build

# Flash to connected ESP32
idf.py -p /dev/ttyUSB0 flash monitor
```
