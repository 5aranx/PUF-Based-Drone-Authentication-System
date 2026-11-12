"""
BCH(255, 131, t=18) wrapper using bchlib.
Provides encode/decode for 128-bit keys.
"""
import bchlib

BCH_T = 18          # error correction capability (up to 18 bit errors)
BCH_DATA_BYTES = 16  # 128-bit key
BCH_ECC_BYTES = 18   # 124 parity bits stored across 18 bytes
BCH_CODE_BYTES = BCH_DATA_BYTES + BCH_ECC_BYTES  # 34 bytes

class BCHCodec:
    def __init__(self):
        self._bch = bchlib.BCH(t=BCH_T, m=8)  # GF(2^8), t=18, poly 0x11d

    def encode(self, data_128bit: bytes) -> bytes:
        """
        Encode 16-byte (128-bit) key K into a BCH codeword (34 bytes: 16 data + 18 ecc).
        """
        assert len(data_128bit) == BCH_DATA_BYTES
        ecc = self._bch.encode(data_128bit)
        return data_128bit + ecc

    def decode(self, codeword: bytes) -> tuple[bytes | None, int]:
        """
        Decode 34-byte BCH codeword.
        Returns (data_16bytes, errors_corrected) or (None, -1) on failure.
        """
        if len(codeword) != BCH_CODE_BYTES:
            return None, -1
        data = bytearray(codeword[:BCH_DATA_BYTES])
        ecc = bytearray(codeword[BCH_DATA_BYTES:BCH_DATA_BYTES + BCH_ECC_BYTES])
        try:
            bit_errors = self._bch.decode(data, ecc)
            if bit_errors < 0:
                return None, -1
            self._bch.correct(data, ecc)
            return bytes(data), bit_errors
        except Exception:
            return None, -1
