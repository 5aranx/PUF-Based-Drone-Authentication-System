"""
Software fuzzy extractor matching the firmware implementation.
Uses code-offset construction: H = P_selected XOR BCH(K)
"""
import os
import hashlib
from bch_soft import BCHCodec, BCH_CODE_BYTES

class FuzzyExtractor:
    def __init__(self):
        self._bch = BCHCodec()

    def enroll(self, p_selected_bytes: bytes, key: bytes = None) -> tuple[bytes, bytes, str]:
        """
        Enroll a PUF pattern.
        p_selected_bytes: BCH_CODE_BYTES (34 bytes) of selected PUF bits
        key: 16-byte key (generated randomly if None)
        Returns: (key, helper_data, k_commit_hex)
        """
        assert len(p_selected_bytes) == BCH_CODE_BYTES
        if key is None:
            key = os.urandom(16)
        assert len(key) == 16
        
        codeword = self._bch.encode(key)
        helper = bytes(a ^ b for a, b in zip(p_selected_bytes, codeword))
        k_commit = hashlib.sha256(key).hexdigest()
        return key, helper, k_commit

    def reconstruct(self, p_prime_bytes: bytes, helper: bytes) -> tuple[bytes | None, int]:
        """
        Reconstruct key from noisy PUF reading and helper data.
        Returns (key, errors_corrected) or (None, -1) on failure.
        """
        assert len(p_prime_bytes) == BCH_CODE_BYTES
        assert len(helper) == BCH_CODE_BYTES
        c_prime = bytes(a ^ b for a, b in zip(p_prime_bytes, helper))
        return self._bch.decode(c_prime)
