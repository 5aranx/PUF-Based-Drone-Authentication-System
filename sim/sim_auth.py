#!/usr/bin/env python3
"""
Simulate the boot-time authentication flow for a drone.
Demonstrates:
  1. Normal auth (should succeed)
  2. Impostor auth (different chip_id, same device_id — should fail at BCH)
  3. Replay attack (should fail with NONCE_REUSED)
"""
import sys, os, argparse, time, hashlib, hmac, requests
from sim_puf import SimPUF
from fuzzy_extractor import FuzzyExtractor
from bch_soft import BCH_CODE_BYTES

DEFAULT_SERVER = "http://127.0.0.1:5000"

class SimDrone:
    def __init__(self, chip_id: str, device_id: str, server: str):
        self.chip_id = chip_id
        self.device_id = device_id
        self.server = server
        self.puf = SimPUF(chip_id=chip_id)
        self.fe = FuzzyExtractor()
        # Load enrollment data from server (in real life it's in NVS flash)
        self._helper = None
        self._mask = None

    def _load_enrollment_data(self):
        """Fetch helper and mask from server (simulates reading from NVS)."""
        resp = requests.get(f"{self.server}/api/device/{self.device_id}")
        if resp.status_code != 200:
            raise RuntimeError(f"Device {self.device_id} not found on server")
        data = resp.json()
        self._helper = bytes.fromhex(data["helper"])
        self._mask_bits = None
        self._mask_bytes = bytes.fromhex(data["mask"])

    def reconstruct_key(self) -> bytes | None:
        """Simulate boot: read PUF, apply mask, reconstruct K."""
        if self._helper is None:
            self._load_enrollment_data()

        # Simulate one boot read (with noise)
        import numpy as np
        raw_bits = self.puf.read()   # noisy
        # Apply mask: select stable bit positions
        mask_bits = np.unpackbits(np.frombuffer(self._mask_bytes, dtype=np.uint8))[:len(raw_bits)]
        selected_bits = self.puf.select_bits(raw_bits, mask_bits, BCH_CODE_BYTES * 8)
        p_prime = self.puf.bits_to_bytes(selected_bits)[:BCH_CODE_BYTES]

        key, errors = self.fe.reconstruct(p_prime, self._helper)
        if key is None:
            print(f"[DRONE:{self.device_id}] BCH decode FAILED — wrong chip or too much noise")
            return None
        print(f"[DRONE:{self.device_id}] Key reconstructed ({errors} bit errors corrected): {key.hex()}")
        return key

    def authenticate(self) -> str | None:
        """Run full challenge/response auth. Returns JWT token or None."""
        key = self.reconstruct_key()
        if key is None:
            return None

        # Step 1: Get challenge nonce
        resp = requests.get(f"{self.server}/challenge?device_id={self.device_id}")
        if resp.status_code != 200:
            print(f"[DRONE:{self.device_id}] Challenge failed: {resp.status_code} {resp.text}")
            return None
        nonce_hex = resp.json()["nonce"]
        print(f"[DRONE:{self.device_id}] Got nonce: {nonce_hex[:16]}...")

        # Step 2: Compute HMAC response
        ts_str = str(int(time.time()))
        msg = f"{self.device_id}|{nonce_hex}|{ts_str}".encode()
        mac = hmac.new(key, msg, hashlib.sha256).hexdigest()

        # Step 3: Verify
        resp = requests.post(f"{self.server}/verify", json={
            "device_id": self.device_id,
            "nonce": nonce_hex,
            "ts": ts_str,
            "mac": mac,
        })
        if resp.status_code == 200:
            token = resp.json()["token"]
            print(f"[DRONE:{self.device_id}] ✓ AUTH OK — JWT: {token[:40]}...")
            return token, nonce_hex
        else:
            print(f"[DRONE:{self.device_id}] ✗ Auth REJECTED: {resp.json()}")
            return None, None

def demo_replay(server: str, device_id: str, nonce_hex: str):
    """Attempt to replay a captured handshake."""
    print(f"\n[REPLAY] Attempting replay of nonce {nonce_hex[:16]}...")
    resp = requests.post(f"{server}/verify", json={
        "device_id": device_id,
        "nonce": nonce_hex,
        "ts": str(int(time.time())),
        "mac": "deadbeef" * 8,
    })
    print(f"[REPLAY] Server response: {resp.status_code} {resp.json()}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulate drone authentication")
    parser.add_argument("--chip-id", default="CHIP-ALPHA-001")
    parser.add_argument("--device-id", default="DRONE-001")
    parser.add_argument("--server", default=DEFAULT_SERVER)
    parser.add_argument("--impostor-chip-id", help="Run impostor test with this chip ID")
    parser.add_argument("--replay", action="store_true", help="Demo replay attack after auth")
    args = parser.parse_args()

    print("=" * 60)
    print("SCENARIO 1: Legitimate drone authentication")
    print("=" * 60)
    drone = SimDrone(args.chip_id, args.device_id, args.server)
    result = drone.authenticate()
    if result:
        token, nonce_hex = result
    else:
        token, nonce_hex = None, None

    if args.impostor_chip_id:
        print("\n" + "=" * 60)
        print(f"SCENARIO 2: Impostor drone ({args.impostor_chip_id})")
        print("=" * 60)
        impostor = SimDrone(args.impostor_chip_id, args.device_id, args.server)
        impostor._helper = drone._helper
        impostor._mask_bytes = drone._mask_bytes
        impostor.authenticate()

    if args.replay and nonce_hex:
        print("\n" + "=" * 60)
        print("SCENARIO 3: Replay attack")
        print("=" * 60)
        demo_replay(args.server, args.device_id, nonce_hex)
