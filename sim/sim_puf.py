"""
SimPUF — Software simulation of an ESP32 SRAM Physical Unclonable Function.

The real PUF is the power-up state of SRAM cells. This simulator models:
  - Per-chip unique stable pattern (seeded by chip_id)
  - Per-boot noise (a small fraction of bits flip randomly)
  - Majority voting across N boots to find stable bits
  - Dark-bit masking (bits that ever flipped during voting)
"""

import numpy as np
import hashlib
import os

class SimPUF:
    def __init__(self, chip_id: str, n_bits: int = 4096, noise_rate: float = 0.03):
        """
        chip_id: unique string identifying this chip (like a serial number)
        n_bits: total SRAM bits sampled
        noise_rate: fraction of bits that might flip on any given read
        """
        # Derive a deterministic stable pattern from chip_id (like real SRAM physics)
        seed = int(hashlib.sha256(chip_id.encode()).hexdigest(), 16) % (2**32)
        rng = np.random.default_rng(seed)
        # True stable pattern for this chip
        self._stable = rng.integers(0, 2, size=n_bits, dtype=np.uint8)
        self._n_bits = n_bits
        self._noise_rate = noise_rate

    def read(self) -> np.ndarray:
        """Simulate one power-on read: stable pattern + noise."""
        noise_mask = np.random.random(self._n_bits) < self._noise_rate
        return (self._stable ^ noise_mask.astype(np.uint8))

    def enrollment_reads(self, n: int = 32) -> tuple[np.ndarray, np.ndarray]:
        """
        Perform N simulated power cycles.
        Returns (stable_bits, mask) where mask[i]=1 means bit i never flipped.
        """
        reads = np.array([self.read() for _ in range(n)])
        vote_counts = reads.sum(axis=0)
        # Majority vote
        stable = (vote_counts > n // 2).astype(np.uint8)
        # Mask: bits that resolved the same way every single boot
        mask = ((vote_counts == 0) | (vote_counts == n)).astype(np.uint8)
        return stable, mask

    def bits_to_bytes(self, bits: np.ndarray) -> bytes:
        """Pack bit array into bytes (MSB first per byte)."""
        # Pad to multiple of 8
        pad = (8 - len(bits) % 8) % 8
        bits = np.concatenate([bits, np.zeros(pad, dtype=np.uint8)])
        return bytes(np.packbits(bits))

    def select_bits(self, stable: np.ndarray, mask: np.ndarray, n_select: int) -> np.ndarray:
        """Pick the first n_select stable (mask==1) bits."""
        indices = np.where(mask == 1)[0][:n_select]
        return stable[indices]

    def inter_chip_distance(self, other: 'SimPUF') -> float:
        """Hamming distance between two chips' stable patterns (should be ~50%)."""
        return float(np.mean(self._stable != other._stable))
