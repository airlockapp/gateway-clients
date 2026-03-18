"""
HARP cryptographic primitives: AES-256-GCM, X25519, HKDF, Ed25519, Base64url, SHA-256.
Adapted from the HARP reference implementation (harp-samples).
"""

import base64
import hashlib
import os
from typing import NamedTuple

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


AES_KEY_SIZE = 32
AES_NONCE_SIZE = 12
AES_TAG_SIZE = 16


# ── Base64url ────────────────────────────────────────────────


def to_base64url(data: bytes) -> str:
    """Encode bytes to a base64url string (no padding)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def from_base64url(s: str) -> bytes:
    """Decode a base64url string (with or without padding)."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


# ── SHA-256 ──────────────────────────────────────────────────


def sha256_hex(s: str) -> str:
    """Compute lowercase hex SHA-256 of a UTF-8 string."""
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# ── HKDF-SHA256 ──────────────────────────────────────────────


def hkdf_sha256(ikm: bytes, salt: bytes | None, info: bytes, length: int = AES_KEY_SIZE) -> bytes:
    """Derive a key using HKDF-SHA256 (RFC 5869)."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hkdf.derive(ikm)


# ── X25519 ECDH Key Exchange ─────────────────────────────────


class X25519KeyPair(NamedTuple):
    public_key: str  # base64url (raw 32 bytes)
    private_key: str  # base64url (raw 32 bytes)


def generate_x25519_keypair() -> X25519KeyPair:
    """Generate an X25519 keypair for ECDH key agreement."""
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return X25519KeyPair(
        public_key=to_base64url(public_key.public_bytes_raw()),
        private_key=to_base64url(private_key.private_bytes_raw()),
    )


def derive_shared_key(my_private_base64url: str, peer_public_base64url: str) -> str:
    """Derive a shared AES-256 key from X25519 ECDH + HKDF-SHA256.
    Uses info string 'HARP-E2E-AES256GCM' to match the enforcer extension pattern.
    """
    priv_bytes = from_base64url(my_private_base64url)
    pub_bytes = from_base64url(peer_public_base64url)

    private_key = X25519PrivateKey.from_private_bytes(priv_bytes)
    public_key = X25519PublicKey.from_public_bytes(pub_bytes)

    shared_secret = private_key.exchange(public_key)
    info = b"HARP-E2E-AES256GCM"
    derived = hkdf_sha256(shared_secret, salt=None, info=info, length=AES_KEY_SIZE)

    return to_base64url(derived)


# ── AES-256-GCM Encrypt/Decrypt ──────────────────────────────


class EncryptedPayload(NamedTuple):
    alg: str
    data: str  # base64
    nonce: str  # base64
    tag: str  # base64


def aes_gcm_encrypt(key_base64url: str, plaintext: str) -> EncryptedPayload:
    """Encrypt plaintext with AES-256-GCM (detached nonce+tag)."""
    key = from_base64url(key_base64url)
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"Key must be {AES_KEY_SIZE} bytes, got {len(key)}")

    nonce = os.urandom(AES_NONCE_SIZE)
    aesgcm = AESGCM(key)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

    # AESGCM appends 16-byte tag
    ciphertext = ct_with_tag[:-AES_TAG_SIZE]
    tag = ct_with_tag[-AES_TAG_SIZE:]

    return EncryptedPayload(
        alg="AES-256-GCM",
        data=base64.b64encode(ciphertext).decode("ascii"),
        nonce=base64.b64encode(nonce).decode("ascii"),
        tag=base64.b64encode(tag).decode("ascii"),
    )


def aes_gcm_decrypt(key_base64url: str, payload: EncryptedPayload) -> str:
    """Decrypt an AES-256-GCM encrypted payload."""
    key = from_base64url(key_base64url)
    data = base64.b64decode(payload.data)
    nonce = base64.b64decode(payload.nonce)
    tag = base64.b64decode(payload.tag)

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, data + tag, None)
    return plaintext.decode("utf-8")


# ── Ed25519 Signing & Verification ───────────────────────────


class Ed25519KeyPair(NamedTuple):
    public_key: str  # base64url (raw 32 bytes)
    private_key: str  # base64url (raw 32 bytes)


def generate_ed25519_keypair() -> Ed25519KeyPair:
    """Generate an Ed25519 signing keypair."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return Ed25519KeyPair(
        public_key=to_base64url(public_key.public_bytes_raw()),
        private_key=to_base64url(private_key.private_bytes_raw()),
    )


def ed25519_sign(private_key_base64url: str, message: bytes) -> str:
    """Sign a message with Ed25519. Returns base64url signature."""
    priv_bytes = from_base64url(private_key_base64url)
    private_key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
    sig = private_key.sign(message)
    return to_base64url(sig)


def ed25519_verify(public_key_base64url: str, message: bytes, signature_base64url: str) -> bool:
    """Verify an Ed25519 signature. Returns True if valid."""
    pub_bytes = from_base64url(public_key_base64url)
    sig = from_base64url(signature_base64url)
    public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
    try:
        public_key.verify(sig, message)
        return True
    except Exception:
        return False
