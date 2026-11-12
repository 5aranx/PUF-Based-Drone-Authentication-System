import hmac
import hashlib
import secrets
import time

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import jwt

from config import SECRET_KEY, JWT_ALGORITHM, JWT_EXPIRY_SECONDS


def verify_hmac(k_hex: str, device_id: str, nonce_hex: str, ts_str: str, mac_hex: str) -> bool:
    """Constant-time HMAC-SHA256 verify. msg = device_id | nonce_hex | ts_str joined by '|'."""
    key = bytes.fromhex(k_hex)
    msg = f"{device_id}|{nonce_hex}|{ts_str}".encode()
    expected = hmac.new(key, msg, hashlib.sha256).digest()
    try:
        provided = bytes.fromhex(mac_hex)
    except ValueError:
        return False
    return hmac.compare_digest(expected, provided)


def derive_session_key(k_hex: str, nonce_hex: str) -> str:
    """HKDF-SHA256(K, nonce) → 32-byte session key, hex-encoded."""
    hkdf = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=bytes.fromhex(nonce_hex),
        info=b"puf-drone-session",
        backend=default_backend(),
    )
    return hkdf.derive(bytes.fromhex(k_hex)).hex()


def issue_jwt(device_id: str, session_key_hex: str) -> str:
    now = int(time.time())
    payload = {
        "sub": device_id,
        "sk": session_key_hex,
        "iat": now,
        "exp": now + JWT_EXPIRY_SECONDS,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)


def generate_nonce() -> str:
    return secrets.token_hex(32)


def decode_jwt(token: str) -> dict:
    """Decode and verify JWT, raising jwt exceptions on failure."""
    return jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
