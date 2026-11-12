#!/usr/bin/env python3
"""
Simulate the one-time enrollment flow for a drone on the bench.
Runs the full enrollment locally and registers the device with the backend server.
"""
import sys, os, argparse, hashlib, requests
from sim_puf import SimPUF
from fuzzy_extractor import FuzzyExtractor
from bch_soft import BCH_CODE_BYTES

DEFAULT_SERVER = "http://127.0.0.1:5000"
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "admin-secret")

def enroll_drone(chip_id: str, device_id: str, server: str, n_votes: int = 32):
    print(f"[ENROLL] Starting enrollment for {device_id} (chip: {chip_id})")
    
    puf = SimPUF(chip_id=chip_id)
    fe = FuzzyExtractor()
    
    print(f"[ENROLL] Running {n_votes} simulated power cycles for majority vote...")
    stable, mask = puf.enrollment_reads(n=n_votes)
    
    n_stable = mask.sum()
    print(f"[ENROLL] Stable bits: {n_stable}/{len(stable)} ({100*n_stable/len(stable):.1f}%)")
    
    # Select most-stable bits for BCH codeword length
    selected_bits = puf.select_bits(stable, mask, BCH_CODE_BYTES * 8)
    p_selected = puf.bits_to_bytes(selected_bits)[:BCH_CODE_BYTES]
    
    # Generate key and enroll
    key, helper, k_commit = fe.enroll(p_selected)
    
    print(f"[ENROLL] Key K:       {key.hex()}")
    print(f"[ENROLL] Helper H:    {helper.hex()}")
    print(f"[ENROLL] K commit:    {k_commit}")
    print(f"[ENROLL] Mask (first 32 bits): {bin(int.from_bytes(puf.bits_to_bytes(mask[:32]), 'big'))}")
    
    # Register with backend
    mask_bytes = puf.bits_to_bytes(mask)
    payload = {
        "device_id": device_id,
        "mask": mask_bytes.hex(),
        "helper": helper.hex(),
        "k_commit": k_commit,
        "k_hex": key.hex(),   # In production, only k_commit would be sent
    }
    
    resp = requests.post(
        f"{server}/enroll",
        json=payload,
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"}
    )
    
    if resp.status_code == 201:
        print(f"[ENROLL] ✓ Device {device_id} enrolled successfully!")
        # Zeroise key
        key = b'\x00' * 16
        return True
    else:
        print(f"[ENROLL] ✗ Enrollment failed: {resp.status_code} {resp.text}")
        return False

def demo_inter_chip_distance():
    """Show that two different chips have ~50% Hamming distance."""
    puf_a = SimPUF("CHIP-ALPHA-001")
    puf_b = SimPUF("CHIP-BETA-999")
    dist = puf_a.inter_chip_distance(puf_b)
    print(f"[DEMO] Inter-chip Hamming distance: {dist:.1%} (expected ~50%)")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enroll a simulated drone PUF")
    parser.add_argument("--chip-id", default="CHIP-ALPHA-001")
    parser.add_argument("--device-id", default="DRONE-001")
    parser.add_argument("--server", default=DEFAULT_SERVER)
    parser.add_argument("--votes", type=int, default=32)
    parser.add_argument("--demo-distance", action="store_true")
    args = parser.parse_args()
    
    if args.demo_distance:
        demo_inter_chip_distance()
    
    success = enroll_drone(args.chip_id, args.device_id, args.server, args.votes)
    sys.exit(0 if success else 1)
