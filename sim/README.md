# PUF Drone Simulator & Test Suite

Software simulation of ESP32 SRAM physics, majority-voting enrollment, and authentication attack scenarios.

## Components

- `sim_puf.py`: Models uninitialized SRAM cells with realistic physical noise (~3% bit-flip probability per read) and inter-chip Hamming distance (~50%).
- `bch_soft.py`: Software BCH codec wrapper.
- `fuzzy_extractor.py`: High-level code-offset fuzzy extractor matching the firmware implementation.
- `sim_enrollment.py`: Performs simulated power-cycling, majority voting, dark-bit mask generation, and backend registration.
- `sim_auth.py`: Runs flight authorization handshakes under three distinct conditions:
  1. Legitimate drone boot (verifies error-correction capability).
  2. Impostor silicon chip (verifies physical unclonability).
  3. Replay attack (verifies single-use nonce destruction).
- `run_demo.sh`: Orchestrates the complete automated end-to-end demo.

## Running the Simulator

```bash
cd /home/savi/Projects/puf-drone/sim
source .venv/bin/activate

# Execute full automated test suite
./run_demo.sh
```
