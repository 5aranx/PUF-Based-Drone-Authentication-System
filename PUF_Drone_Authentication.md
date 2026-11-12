# PUF-Based Drone Authentication System

Reference notes for the project on Saransh's resume — what it is, why it works, and how to build it.

Diagrams (PNG, 150 dpi) live in `diagrams/`:

| File | Shows |
|---|---|
| `01_architecture.png` | system block diagram, ESP32 node ↔ Flask backend |
| `02_enrollment.png` | one-time provisioning flow |
| `03_authentication.png` | boot-time key reconstruction + challenge/response |
| `04_firmware_states.png` | firmware state machine, failure handling |
| `05_threat_model.png` | what each attack does and why it fails |

---

## 1. The problem

A drone talks to a ground control station (GCS). To stop a rogue aircraft from
being trusted, the GCS must know *this* airframe is *this* airframe.

The usual answer is a secret key in flash. That fails in the field:

- flash can be dumped over UART/JTAG or by desoldering the chip;
- a captured drone hands the attacker both firmware and key;
- with the key copied, a completely different aircraft passes as the original.

## 2. The idea: derive the key from physics, never store it

Every SRAM cell is two cross-coupled inverters. At power-up both sides race
from mid-rail and the cell falls to 0 or 1 depending on which transistor has the
slightly lower threshold voltage. That mismatch comes from dopant fluctuation
and line-edge roughness — random at manufacture, impossible to control.

Consequences:

- **unique** — two ESP32s from the same wafer give ~50 % different patterns;
- **reproducible** — the same chip gives nearly the same pattern every boot;
- **unclonable** — you cannot copy it, and it is not stored anywhere in flash.

So the device key becomes `K = f(power-up SRAM pattern)`. Nothing secret sits in
flash; a firmware dump yields only *helper data*, which is useless on its own.

### The noise problem

A few percent of cells are marginal and resolve randomly, and the error rate
drifts with temperature and supply ramp. Raw PUF output is therefore *close* to
the enrolled value but not identical — `P' = P ⊕ e`, with `e` a sparse error
vector. Two standard fixes:

1. **Temporal majority vote** — power-cycle 20–50 times, keep a bit if it won
   more than half the votes. Kills the coin-flip cells.
2. **Dark-bit masking** — drop bits that flipped at all during enrollment.
3. **BCH error correction** — correct whatever noise is left at run time.

### Fuzzy extractor (the maths)

```
enrollment:      C = BCH(K)            codeword
                 H = P_selected ⊕ C    helper data (public)

reconstruction:  C' = P'_selected ⊕ H
                    = (P ⊕ e) ⊕ (P ⊕ C)
                    = C ⊕ e            ← only the few flipped bits
                 BCH_decode(C') → K
```

`H` is public and leaks nothing: for any key guess there is a PUF pattern that
produces it. This is the standard code-offset construction.

Concrete parameters that fit one ESP32 comfortably:

| Item | Value |
|---|---|
| raw PUF bits read | 4096 |
| bits kept after voting + masking | ~2000 |
| selected for one block | 255 (most stable) |
| code | BCH(255, 131, t = 18) |
| key length | 128 bits (payload 131, top 3 bits fixed) |
| helper data stored | 255 bits + mask ≈ 300 B |

## 3. Enrollment — one time, on the bench

See `diagrams/02_enrollment.png`.

```
 power-cycle N times, read SRAM at earliest boot
                    │
                    ▼
      per-bit majority vote  →  stable bitmap
                    │
                    ▼
      mask = bits that never flipped;  drop the rest
                    │
                    ▼
      K = 128 random bits from hardware TRNG   (never stored)
                    │
                    ▼
      C = BCH(K);   H = P_selected ⊕ C
                    │
                    ▼
      flash: H + mask        server: device_id → mask, H, hash(K)
                    │
                    ▼
      zeroise K in RAM  →  ENROLLED
```

The server keeps `K` (or a commitment to it) because it must verify HMACs later.
The drone keeps only `H` and `mask`.

## 4. Authentication — every boot

See `diagrams/03_authentication.png`.

```
 boot → read P′ → apply mask → C′ = P′ ⊕ H → BCH decode → K
                                        │
                              fail ─────┘ (e > t: aged, damaged, wrong chip)
                                        │            → motors inhibited
                                        ▼
                     Wi-Fi / TLS up, MQTT session
                                        │
   1  drone  → server   HELLO {device_id}
   2  server → drone    nonce N   (32 B, single use, 60 s TTL)
   3  drone  → server   R = HMAC-SHA256(K, device_id ‖ N ‖ ts)
   4  server → drone    session token (JWT, 15 min), key = HKDF(K, N)
                                        │
                                        ▼
                          telemetry signed + encrypted
```

`K` never crosses the link. A captured `(HELLO, N, R)` triple cannot be replayed
because `N` is burned after one use.

## 5. Why each attack fails

See `diagrams/05_threat_model.png`.

| Attack | Outcome |
|---|---|
| Dump flash, copy firmware | only `H` + `mask` inside — no key |
| Replay a captured handshake | nonce already used |
| Buy the same ESP32, flash same firmware | different die → ~50 % bit difference → BCH decode fails |
| Read SRAM from outside | SRAM is internal; needs decapping, out of scope for a hackathon |
| Physically move the enrolled chip to another airframe | **not prevented** — a PUF proves *which chip*, not *which aircraft*. Mitigate by binding the chip to an airframe ID at provisioning, or adding a secure element |

## 6. Implementation

### Firmware (ESP-IDF)

**a. Reserve a region the boot path never writes.**

```c
// linker: add a .noinit section, excluded from zero-init
__attribute__((section(".noinit"), aligned(4)))
static uint8_t puf_raw[512];

void app_main(void) {
    puf_read(puf_raw, sizeof puf_raw);   // must be the very first thing
    ...
}
```

On ESP32 the ROM bootloader and `cpu_start` touch part of DRAM, so measure which
region is actually left alone — dump it on several cold boots and keep the bytes
that vary per chip but stay constant per chip. RTC slow memory is an alternative
that survives resets and is not cleared by the C runtime.

**b. Majority vote across boots.** Store per-bit counters in RTC memory
(`RTC_NOINIT_ATTR`), which survives `esp_restart()`, then loop:

```c
for (int i = 0; i < N_BOOTS; i++) {
    count_bits(puf_raw, counters, sizeof puf_raw);
    esp_restart();                 // counters survive in RTC memory
}
```

**c. BCH.** Any compact C implementation works — the kernel's `lib/bch.c` or a
small `(255,131,t=18)` encoder/decoder. Keep it in `components/bch/`.

**d. HMAC.** mbedTLS ships with ESP-IDF:

```c
mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                key, 16, msg, msg_len, out);
```

**e. Storage.** `nvs_set_blob(handle, "puf_h", h, 32)` and the mask alongside.
Mark the namespace read-only after provisioning.

**f. Transport.** `esp_mqtt_client` over TLS on 8883, or `esp_http_client` for a
plain REST demo. TLS is what stops a passive sniffer from seeing telemetry; the
PUF is what stops an active impostor.

### Backend (Flask)

```python
POST /enroll      # admin token only, run once per unit
  {device_id, mask, helper, k_commit}      → 201

GET  /challenge?device_id=...
  nonce = secrets.token_bytes(32)
  store[nonce] = (device_id, time() + 60)  → {nonce: b64}

POST /verify
  {device_id, nonce, ts, mac}
  check nonce unused + fresh, ts within ±30 s
  expect = hmac.new(K[device_id], device_id || nonce || ts, sha256)
  hmac.compare_digest(expect, mac)         → {token: jwt}
```

Notes that matter for the demo:

- `hmac.compare_digest`, never `==`.
- burn the nonce on first use, even on failure;
- 5 failures → 30 s lockout per `device_id`;
- log every attempt to the dashboard feed.

### Dashboard

One page, three panels: fleet list with auth state (green/amber/red), live
telemetry, and a scrolling auth log. Add a "replay attack" button that resends a
captured frame — judges see it get rejected in real time.

## 7. Demo script (HackfinX)

1. Enrol two ESP32s on the bench; show `H` and `mask` in the flash dump.
2. Drone A boots, authenticates in under a second, dashboard turns green.
3. Flash identical firmware to a third ESP32 (the impostor) → decode fails,
   dashboard turns red, log shows `PUF_MISMATCH`.
4. Replay Drone A's last handshake from a laptop → `NONCE_REUSED`.
5. Pull the flash dump up on screen and point out there is no key in it.

## 8. Honest limitations

- SRAM PUF drifts with temperature and aging; leave headroom in `t`.
- Classic ESP32 has no PUF peripheral — this is a software PUF. ESP32-S3 adds an
  HMAC peripheral and eFuse that pair well with it.
- Helper data must be protected from fault injection in a real product; for a
  hackathon, document it as future work.
- A PUF identifies a *chip*. Bind it to an airframe at provisioning if the threat
  model includes chip transplants.
