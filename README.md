<div align="center">

# 🛰️ PUF-Based Drone Authentication System
### Hardware-Rooted Silicon Authentication & Zero-Storage Key Derivation for UAVs

[![ESP-IDF](https://img.shields.io/badge/ESP--IDF-v4.4+-E7352C?style=flat&logo=espressif&logoColor=white)](https://github.com/espressif/esp-idf)
[![C99](https://img.shields.io/badge/Language-C99-00599C?style=flat&logo=c&logoColor=white)](https://en.cppreference.com/w/c/99)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Backend-Flask_3.0-000000?style=flat&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Crypto](https://img.shields.io/badge/Security-mbedTLS_%7C_HMAC--SHA256-green?style=flat&logo=lock&logoColor=white)](https://tls.mbed.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

<br/>

<p align="center">
  <b>A zero-flash-storage cryptographic authentication architecture for autonomous unmanned aerial systems.</b><br/>
  Keys are dynamically reconstructed at power-on from microscopic transistor manufacturing tolerances across uninitialized SRAM cells, rendering physical flash-extraction and firmware-cloning attacks cryptographically infeasible.
</p>

</div>

---

## 📌 Executive Summary

Conventional UAV defense architectures anchor root-of-trust identity to static private keys persisted in non-volatile flash memory (SPI NOR / EEPROM). In contested environments, captured airframes can be rapidly compromised via non-invasive UART/JTAG memory dumping, side-channel probing, or chip-off desoldering—allowing adversary operators to clone legitimate aircraft identities into rogue aerial platforms.

This system replaces static stored secrets with a **Physically Unclonable Function (PUF)** derived directly from deep-submicron process variations in uninitialized silicon. By coupling hardware SRAM power-up states with a **Code-Offset Fuzzy Extractor** ($\text{BCH}(255,131,t=18)$ over $\text{GF}(2^8)$), a transient 128-bit key $K$ is reconstituted strictly in volatile memory during boot, used for zero-knowledge mutual challenge-response authentication, and immediately zeroised. **A complete firmware dump yields only non-confidential public helper data ($H$) and stability masks.**

---

## 📐 System Architecture

<div align="center">
  <img src="diagrams/01_architecture.png" alt="System Architecture Diagram" width="850px"/>
</div>

The architecture consists of two interconnected nodes:
1. **Airframe Node (ESP32 SoC):**
   - **SRAM PUF Region:** Extracts uninitialized power-up states from a reserved `.noinit` DRAM region prior to C runtime zero-initialization.
   - **Filter Pipeline:** Applies temporal majority voting across multi-boot power cycles and dark-bit masking to eliminate thermally unstable bit positions.
   - **BCH Codec:** Corrects residual run-time bit errors using Berlekamp-Massey decoding and Chien search algorithms.
   - **Flight Inhibit Latch:** Locks electronic speed controller (ESC) motor outputs in a hardware-inhibited state until mutual authentication succeeds.
2. **Ground Control Station (Flask Backend):**
   - **Device Registry:** Manages public helper records, stability bitmasks, and verification commitments ($H, \text{mask}, \text{Commit}(K)$).
   - **Single-Use Nonce Cache:** Enforces 60-second TTL single-use nonce issuance to prevent packet replay.
   - **Rate Limiter & Audit Logger:** Implements constant-time HMAC comparison and automated account lockouts after consecutive failed handshakes.
   - **Tactical Dashboard:** Real-time Server-Sent Events (SSE) telemetry visualization with pitch/roll artificial horizon monitoring.

---

## 🔬 Mathematical Foundation: Fuzzy Extractor

SRAM cells resolve to bistable values ($0$ or $1$) at power-on based on infinitesimal threshold voltage differentials ($\Delta V_{\text{th}}$) between cross-coupled inverter pairs. This physical mismatch is stochastic, permanent, and unique to every silicon wafer.

```
                  +---------------------------+
                  |  Vdd (Power-Up Voltage)   |
                  +-------------+-------------+
                                |
                   +------------+------------+
                   |                         |
              [PMOS Q1]                 [PMOS Q2]
                   |                         |
                   +------* (Node A) *-------+
                   |      |           |      |
                   |      +----[Gate Q4      |
                   |           Gate Q3]------+
              [NMOS Q3]                 [NMOS Q4]
                   |                         |
                  +-------------+-------------+
                  |         GND (0V)          |
                  +---------------------------+
       * Threshold Voltage Imbalance (ΔVth) dictates initial resolution *
```

### 1. Enrollment Phase (Bench Provisioning)

<div align="center">
  <img src="diagrams/02_enrollment.png" alt="Enrollment Flowchart" width="600px"/>
</div>

During factory bench calibration:
1. The device undergoes $N$ power cycles ($N = 32$). The uninitialized SRAM region is read at the earliest stage of boot.
2. **Temporal Majority Voting:** A bit $i$ is assigned stable value $1$ if observed as $1$ in $>50\%$ of power boots:
   $$\text{Vote}(b_i) = \begin{cases} 1 & \sum_{j=1}^N b_i^{(j)} > \frac{N}{2} \\ 0 & \text{otherwise} \end{cases}$$
3. **Dark-Bit Masking:** Bits with any transition variance ($\sum b_i \notin \{0, N\}$) are classified as "dark" (flickering/noisy) and masked out.
4. An ephemeral 128-bit secret key $K$ is generated using the hardware True Random Number Generator (TRNG).
5. The key is encoded into a systematic codeword using $\text{BCH}(255, 131, t=18)$:
   $$C = \text{BCH\_Encode}(K)$$
6. Public helper data $H$ is computed via code-offset:
   $$H = P_{\text{selected}} \oplus C$$
7. $(H, \text{mask})$ are written to NVS flash; the backend registers $(H, \text{mask}, \text{SHA256}(K))$; $K$ is zeroised from RAM.

### 2. Reconstruction Phase (Field Boot)

<div align="center">
  <img src="diagrams/03_authentication.png" alt="Authentication Flowchart" width="600px"/>
</div>

On every operational boot in the field:
1. The SRAM pattern is sampled under ambient physical conditions ($P' = P \oplus e$, where $e$ is a sparse environmental error vector).
2. The enrolled mask selects valid bit positions: $P'_{\text{selected}}$.
3. The helper data is applied:
   $$C' = P'_{\text{selected}} \oplus H = (P_{\text{selected}} \oplus e) \oplus (P_{\text{selected}} \oplus C) = C \oplus e$$
4. The BCH decoder executes Berlekamp-Massey and corrects up to $t=18$ bit errors:
   $$\text{BCH\_Decode}(C') \to K$$
5. If bit errors $e \le 18$, key $K$ is restored identically. If $e > 18$ (e.g. counterfeit chip or severe die damage), decoding fails and flight is inhibited.

---

## 🛡️ Threat Model & Security Analysis

<div align="center">
  <img src="diagrams/05_threat_model.png" alt="Threat Model Matrix" width="600px"/>
</div>

| Threat / Attack Vector | Attack Mechanism | Traditional Flash Storage | PUF-Based Architecture |
|---|---|---|---|
| **Flash Memory Extraction** | Attacker dumps flash via UART, SPI sniffer, or desoldering. | **Compromised:** Private keys extracted directly from storage. | **Mitigated:** Flash contains only public helper data $H$ and mask. Information-theoretically secure. |
| **Silicon Cloning (Counterfeiting)** | Attacker flashes identical binary onto another chip of the same model. | **Compromised:** Clone runs identical firmware with valid credentials. | **Mitigated:** Inter-chip Hamming distance is $\approx 50\%$. BCH decoding fails completely; motors stay inhibited. |
| **Challenge Replay Attack** | Intercepts legitimate wireless authentication handshake frames. | **Vulnerable** if tokens or nonces are poorly invalidated. | **Mitigated:** Ground Station enforces single-use 32-byte nonces burned atomically on evaluation. |
| **Volatile RAM Probing** | Cold boot attacks or memory dumping while UAV is active. | **Vulnerable:** Key sits permanently in memory. | **Mitigated:** Key $K$ is immediately wiped (`memset_s`) right after computing the HMAC token. |

---

## ⚙️ Firmware State Machine & Resilience

<div align="center">
  <img src="diagrams/04_firmware_states.png" alt="Firmware State Machine" width="750px"/>
</div>

The ESP32 firmware executes a deterministic state machine engineered for failsafe operation:

```
[BOOT] ──(<5ms)──► [PUF_READ] ──(4 kbit)──► [RECONSTRUCT]
                                                   │
                         ┌─────────────────────────┴─────────────────────────┐
                         ▼ (Decode Success)                                  ▼ (Decode Fail)
                  [NET_CONNECT]                                           [DENY]
                         │ (WiFi + TLS Link)                        (Inhibit Motor ESCs,
                         ▼                                           Log Critical Fault)
                  [CHALLENGE_AUTH]
                         │
        ┌────────────────┴────────────────┐
        ▼ (HMAC Valid)                    ▼ (Fail x5)
     [LIVE]                            [LOCKOUT]
 (Telemetry @ 10 Hz,              (Security Backoff,
  Token Refresh)                   Halt Flight Ops)
```

- **Boot Memory Safeguards:** The PUF buffer is mapped to an uninitialized `.noinit` link section, preventing standard runtime zero-fill loops from overwriting the raw power-up analog state.
- **RTC Fast Memory Counters:** Majority voting counters persist across soft resets (`esp_restart()`) using `RTC_NOINIT_ATTR` memory blocks without touching flash.
- **Hardware Interlocks:** General Purpose Input/Output (GPIO) pins tied to motor speed controllers are pulled low at boot and only asserted upon successful verification.

---

## 📊 Concrete Parameters & Physical Metrics

| Parameter | Specification | Purpose / Rationale |
|---|---|---|
| **Raw SRAM Sample Size** | 4,096 bits (512 Bytes) | Sufficient pool to filter stable cells across process spread |
| **Temporal Voting Rounds** | $N = 32$ power cycles | Eliminates marginal cells with bistable probability near 0.5 |
| **Stable Cell Yield** | ~38% – 42% (~1,550 bits) | Bits exhibiting 100% agreement across all enrollment boots |
| **Error Correction Code** | $\text{BCH}(255, 131, t=18)$ | Corrects up to 18 bit errors over 255-bit codeword ($7.05\%$ error rate) |
| **Cryptographic Key ($K$)** | 128 bits | Symmetric root key for HMAC-SHA256 and HKDF derivation |
| **Helper Data ($H$) Size** | 34 Bytes | Stored in NVS along with bitmask ($\approx 300\text{ Bytes}$ total) |
| **Inter-Chip Hamming Distance** | **$49.5\% \pm 1.2\%$** | Near-ideal physical uniqueness across different ESP32 dies |
| **Intra-Chip Bit Error Rate** | **$2.8\% \pm 0.9\%$** | Comfortably within the $7.05\%$ BCH error correction boundary |

---

## 🗂️ Repository Structure

```
puf-drone/
├── firmware/                       # ESP-IDF C Firmware
│   ├── components/bch/             # Standalone BCH(255, 131, t=18) GF(2^8) Codec
│   │   ├── bch.c / bch.h           # Encoder & Berlekamp-Massey/Chien decoder
│   │   └── CMakeLists.txt
│   ├── main/
│   │   ├── main.c                  # Core state machine, RTOS tasks, motor latch
│   │   ├── puf.c / puf.h           # SRAM sampling, majority voting, dark-bit masking
│   │   ├── fuzzy_extractor.c / .h  # Code-offset helper data generation & reconstruction
│   │   └── auth_client.c / .h      # HTTP/TLS HMAC-SHA256 handshake client
│   ├── Kconfig.projbuild           # Menuconfig schema (WiFi, GCS URL, Device ID)
│   └── CMakeLists.txt
│
├── backend/                        # Ground Control Station (GCS) Backend
│   ├── app.py                      # RESTful API endpoints & Server-Sent Events (SSE)
│   ├── config.py                   # TTL, rate limiting, and security configurations
│   ├── models.py                   # SQLite datastore (device registry, nonces, audit log)
│   ├── puf_crypto.py               # Constant-time HMAC, HKDF session keys, and JWT tokens
│   ├── templates/dashboard.html    # Tactical dark-mode mission dashboard
│   └── static/dashboard.js         # Real-time event consumer & artificial horizon canvas
│
├── sim/                            # Verification & Simulation Suite
│   ├── sim_puf.py                  # Realistic SRAM silicon model (noise + physical spread)
│   ├── bch_soft.py                 # Python BCH wrapper matching C firmware logic
│   ├── fuzzy_extractor.py          # Python fuzzy extractor implementation
│   ├── sim_enrollment.py           # Bench enrollment automation tool
│   ├── sim_auth.py                 # Multi-scenario flight authorization test harness
│   └── run_demo.sh                 # End-to-end automated demonstration script
│
├── diagrams/                       # High-resolution architectural schematics (DOT & PNG)
└── PUF_Drone_Authentication.md     # Engineering whitepaper and technical notes
```

---

## 🚀 Quick Start Guide

### 1. Run Automated Simulation (No Hardware Required)

The repository provides a complete software simulation reproducing ESP32 silicon SRAM physics, majority voting, BCH decoding, and backend handshakes:

```bash
# Clone the repository
git clone https://github.com/5aranx/PUF-Based-Drone-Authentication-System.git
cd PUF-Based-Drone-Authentication-System/sim

# Run the automated end-to-end demonstration
./run_demo.sh
```

**What the demo executes:**
1. Starts the Flask Ground Station on `http://127.0.0.1:5000`.
2. Provisions simulated airframes (`DRONE-001`, `DRONE-002`) through bench power-cycle voting.
3. Authenticates legitimate drone under simulated noise (verifies BCH error correction).
4. Tests an **impostor drone** with identical firmware on a different die (verifies rejection).
5. Tests a **replay attack** with an intercepted payload (verifies single-use nonce destruction).

### 2. Launch the Ground Control Station Dashboard

```bash
cd PUF-Based-Drone-Authentication-System/backend
source .venv/bin/activate
python3 app.py
```

Open **`http://localhost:5000/dashboard`** in your browser to inspect:
- **Fleet Grid:** Live flight clearances (🟢 LIVE, 🟡 AUTH, 🔴 DENIED, ⚫ OFFLINE).
- **Attitude Horizon:** Canvas-rendered artificial horizon tracking telemetry heading/pitch.
- **Audit Feed:** Live streaming cryptographic events via Server-Sent Events (SSE).
- **Attack Simulator:** Interactive button to trigger captured handshake replays.

### 3. Flash to Physical ESP32 Hardware

```bash
cd PUF-Based-Drone-Authentication-System/firmware

# Configure WiFi AP, server endpoint, and device identifiers
idf.py menuconfig

# Build and flash to connected target
idf.py build
idf.py -p /dev/ttyUSB0 flash monitor
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">
  <sub>Engineered with precision for secure autonomous systems.</sub><br/>
  <b>Made by Saransh Singh</b>
</div>
