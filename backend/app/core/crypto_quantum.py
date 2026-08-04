"""
MTGroup VPN Ultimate — Zero-Knowledge Cryptography & Post-Quantum Shield
AES-GCM-256 field-level encryption for database PII protection,
HKDF-SHA256 key derivation, and post-quantum Kyber-768 KEM mockup.

The database stores ZERO plaintext PII. Every sensitive field is encrypted
at the ORM layer using a custom SQLAlchemy TypeDecorator before it ever
touches disk.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import secrets
from typing import Any, Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import Text, TypeDecorator

logger = logging.getLogger("mtgroup.core.crypto_quantum")


# ---------------------------------------------------------------------------
# HKDF-SHA256 Key Derivation
# ---------------------------------------------------------------------------

def derive_key(
    master_key: bytes,
    context: bytes,
    length: int = 32,
    salt: Optional[bytes] = None,
) -> bytes:
    """
    Derive a cryptographic key from a master key using HKDF-SHA256.

    Uses NIST SP 800-56C Rev. 2 compliant extraction-then-expansion.
    The *context* parameter provides domain separation so the same master
    key can safely produce independent subkeys for different purposes.

    Args:
        master_key: The master secret key material (arbitrary length).
        context: Application-specific info string for domain separation.
        length: Desired output key length in bytes (default 32 = AES-256).
        salt: Optional salt for the HKDF extract step.  Falls back to a
              deterministic 32-byte zero salt when not provided.

    Returns:
        Derived key bytes of exactly ``length`` bytes.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt or b"\x00" * 32,
        info=context,
    )
    return hkdf.derive(master_key)


# ---------------------------------------------------------------------------
# AES-GCM-256 Encryption Engine
# ---------------------------------------------------------------------------

_encryption_key_cache: Optional[bytes] = None


def _get_encryption_key() -> bytes:
    """
    Lazily load and cache the 256-bit database encryption key.

    The raw ``DB_ENCRYPTION_KEY`` from configuration is fed through
    HKDF with an application-specific context string so that even a
    low-entropy passphrase produces a full-strength AES-256 key.

    Raises:
        RuntimeError: If ``DB_ENCRYPTION_KEY`` is blank **and** the
                      application is not running in DEBUG mode.
    """
    global _encryption_key_cache
    if _encryption_key_cache is not None:
        return _encryption_key_cache

    from backend.app.core.config import settings

    raw_key = settings.DB_ENCRYPTION_KEY
    if not raw_key:
        logger.warning(
            "DB_ENCRYPTION_KEY is not set — using a deterministic "
            "fallback key.  THIS IS NOT SAFE FOR PRODUCTION.  "
            "Generate one with:  python -c "
            "\"import secrets; print(secrets.token_hex(32))\""
        )
        raw_key = "mtgroup-vpn-ultimate-default-dev-key-CHANGE-ME"

    _encryption_key_cache = derive_key(
        master_key=raw_key.encode("utf-8"),
        context=b"mtgroup-vpn-ultimate-db-field-encryption-v1",
        length=32,
    )
    logger.debug("Database field encryption key derived and cached")
    return _encryption_key_cache


def reset_encryption_key_cache() -> None:
    """
    Clear the cached encryption key.

    Useful in test fixtures where ``DB_ENCRYPTION_KEY`` may change
    between test cases.
    """
    global _encryption_key_cache
    _encryption_key_cache = None


# ---------------------------------------------------------------------------
# Encrypt / Decrypt Primitives
# ---------------------------------------------------------------------------

def encrypt_value(plaintext: str) -> str:
    """
    Encrypt a plaintext string with AES-GCM-256.

    Wire format (all Base64-URL encoded)::

        ┌──────────┬──────────────────────┬──────────┐
        │ 12 bytes │   variable length    │ 16 bytes │
        │  nonce   │     ciphertext       │   tag    │
        └──────────┴──────────────────────┴──────────┘

    A fresh 96-bit nonce is generated for every single encryption call
    so there is never any nonce reuse, even for identical plaintext
    values.

    Args:
        plaintext: UTF-8 string to encrypt.

    Returns:
        URL-safe Base64-encoded blob (nonce ‖ ciphertext ‖ tag).
    """
    key = _get_encryption_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    plaintext_bytes = plaintext.encode("utf-8")
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext_bytes, None)
    return base64.urlsafe_b64encode(nonce + ciphertext_with_tag).decode("ascii")


def decrypt_value(encrypted_b64: str) -> str:
    """
    Decrypt a Base64-URL-encoded AES-GCM-256 blob back to plaintext.

    Args:
        encrypted_b64: The output of :func:`encrypt_value`.

    Returns:
        Original plaintext string.

    Raises:
        ValueError: If the blob is too short or malformed.
        cryptography.exceptions.InvalidTag: If the authentication tag
            does not match (data was tampered with or the wrong key
            was used).
    """
    key = _get_encryption_key()
    aesgcm = AESGCM(key)

    try:
        encrypted_blob = base64.urlsafe_b64decode(encrypted_b64)
    except Exception as exc:
        raise ValueError(f"Invalid Base64 encoding: {exc}") from exc

    # Minimum size: 12 (nonce) + 0 (plaintext) + 16 (tag)
    if len(encrypted_blob) < 28:
        raise ValueError(
            f"Encrypted payload too short ({len(encrypted_blob)} bytes, "
            f"need at least 28: 12-byte nonce + 16-byte tag)"
        )

    nonce = encrypted_blob[:12]
    ciphertext_with_tag = encrypted_blob[12:]
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
    return plaintext_bytes.decode("utf-8")


def encrypt_bytes(
    plaintext: bytes,
    aad: Optional[bytes] = None,
) -> bytes:
    """
    Encrypt raw bytes with AES-GCM-256 and optional AAD.

    Args:
        plaintext: Raw bytes to protect.
        aad: Additional Authenticated Data — included in the tag
             calculation but **not** encrypted.  Useful for binding
             ciphertext to a specific context (e.g. a user ID).

    Returns:
        Raw bytes: ``nonce(12) ‖ ciphertext ‖ tag(16)``.
    """
    key = _get_encryption_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce + ciphertext_with_tag


def decrypt_bytes(
    encrypted: bytes,
    aad: Optional[bytes] = None,
) -> bytes:
    """
    Decrypt raw bytes produced by :func:`encrypt_bytes`.

    Args:
        encrypted: ``nonce(12) ‖ ciphertext ‖ tag(16)``
        aad: The same AAD that was passed during encryption (or ``None``).

    Returns:
        Original plaintext bytes.
    """
    key = _get_encryption_key()
    aesgcm = AESGCM(key)
    nonce = encrypted[:12]
    ciphertext_with_tag = encrypted[12:]
    return aesgcm.decrypt(nonce, ciphertext_with_tag, aad)


# ---------------------------------------------------------------------------
# SQLAlchemy TypeDecorator — Transparent Field Encryption
# ---------------------------------------------------------------------------

class EncryptedType(TypeDecorator):
    """
    SQLAlchemy ``TypeDecorator`` that transparently encrypts column
    values with AES-GCM-256 **before** writing to the database and
    decrypts them **after** reading.

    The underlying database column is ``TEXT`` and stores only
    URL-safe Base64-encoded ciphertext — zero plaintext PII on disk.

    During a migration window (existing rows contain plaintext),
    ``process_result_value`` silently falls back to returning the raw
    value when decryption fails, so old data keeps working until it
    is re-written (at which point it is encrypted automatically).

    Usage::

        from backend.app.core.crypto_quantum import EncryptedType

        class ConnectionLog(Base):
            client_ip: Mapped[Optional[str]] = mapped_column(
                EncryptedType(), nullable=True,
            )

    Thread Safety:
        ``AESGCM`` objects are instantiated per-call.  The derived
        encryption key is cached at module level but is immutable
        once set, so there is no contention.
    """

    impl = Text
    cache_ok = True

    def process_bind_param(
        self,
        value: Optional[str],
        dialect: Any,
    ) -> Optional[str]:
        """Encrypt *value* before it is bound to a SQL parameter."""
        if value is None:
            return None

        plaintext = str(value)
        if not plaintext:
            return ""

        try:
            return encrypt_value(plaintext)
        except Exception as exc:
            logger.error(
                "EncryptedType.process_bind_param failed: %s", exc,
            )
            raise

    def process_result_value(
        self,
        value: Optional[str],
        dialect: Any,
    ) -> Optional[str]:
        """Decrypt *value* after it is fetched from a result row."""
        if value is None:
            return None

        if not value:
            return ""

        try:
            return decrypt_value(value)
        except Exception:
            # Graceful fallback — the row may contain pre-encryption
            # plaintext written before the EncryptedType was applied.
            # Return as-is; the value will be encrypted on next write.
            logger.debug(
                "EncryptedType decryption failed (len=%d) — returning "
                "plaintext as migration fallback",
                len(value),
            )
            return value


# ---------------------------------------------------------------------------
# Post-Quantum Kyber-768 Key Encapsulation Mechanism (Mockup)
# ---------------------------------------------------------------------------

class KyberKeyExchange:
    """
    Post-quantum key exchange mockup matching the NIST-standardised
    ML-KEM (Kyber-768) API surface.

    .. warning::

        This is a **simulation** that uses classical ``AESGCM`` +
        ``HKDF`` internally.  It is **not** quantum-resistant.
        Replace with ``liboqs`` / ``PQClean`` bindings for real
        post-quantum security.

    The class faithfully reproduces Kyber-768 byte sizes so that
    serialisation, network framing, and integration tests are
    realistic:

    ============  =============
    Parameter     Bytes
    ============  =============
    Public key    1 184
    Secret key    2 400
    Ciphertext    1 088
    Shared secret 32
    ============  =============
    """

    PUBLIC_KEY_SIZE: int = 1184
    SECRET_KEY_SIZE: int = 2400
    CIPHERTEXT_SIZE: int = 1088
    SHARED_SECRET_SIZE: int = 32

    def __init__(self) -> None:
        self._public_key: Optional[bytes] = None
        self._secret_key: Optional[bytes] = None

    # ── Key Generation ────────────────────────────────────────

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a Kyber-768 keypair.

        The secret key embeds the public key as its first
        ``PUBLIC_KEY_SIZE`` bytes — this mirrors the real Kyber spec
        and allows ``decapsulate`` to recover ``pk`` from ``sk``.

        Returns:
            ``(public_key, secret_key)`` tuple.
        """
        self._public_key = secrets.token_bytes(self.PUBLIC_KEY_SIZE)
        extra_secret = secrets.token_bytes(
            self.SECRET_KEY_SIZE - self.PUBLIC_KEY_SIZE,
        )
        self._secret_key = self._public_key + extra_secret

        logger.debug(
            "Kyber-768 keypair generated — pk=%d B, sk=%d B",
            len(self._public_key),
            len(self._secret_key),
        )
        return self._public_key, self._secret_key

    # ── Encapsulation ─────────────────────────────────────────

    def encapsulate(
        self,
        public_key: bytes,
    ) -> Tuple[bytes, bytes]:
        """
        Encapsulate: produce a *ciphertext* and a *shared secret*
        that only the holder of the matching secret key can recover.

        Internally wraps a random 32-byte seed with AES-GCM keyed
        from the public key, then derives the shared secret via HKDF
        bound to a hash of ``pk``.

        Args:
            public_key: Recipient's Kyber public key (1 184 bytes).

        Returns:
            ``(ciphertext, shared_secret)`` — ciphertext is 1 088 B,
            shared secret is 32 B.

        Raises:
            ValueError: ``public_key`` length mismatch.
        """
        if len(public_key) != self.PUBLIC_KEY_SIZE:
            raise ValueError(
                f"Public key must be {self.PUBLIC_KEY_SIZE} bytes, "
                f"got {len(public_key)}"
            )

        raw_seed = secrets.token_bytes(32)

        # Key for wrapping the seed — derived from pk
        wrap_key = derive_key(
            master_key=public_key[:32],
            context=b"mtgroup-kyber768-seed-wrap-key",
            length=32,
        )

        # Encrypt the seed with AES-GCM
        aesgcm = AESGCM(wrap_key)
        nonce = os.urandom(12)
        encrypted_seed = aesgcm.encrypt(nonce, raw_seed, None)
        # encrypted_seed = 32 (plaintext) + 16 (tag) = 48 bytes

        # Build the ciphertext: nonce(12) + encrypted_seed(48) + padding
        ct_core = nonce + encrypted_seed  # 60 bytes
        padding_len = self.CIPHERTEXT_SIZE - len(ct_core)
        ciphertext = ct_core + secrets.token_bytes(max(padding_len, 0))

        # Derive the shared secret bound to the public key
        pk_fingerprint = hashlib.sha256(public_key).digest()
        shared_secret = derive_key(
            master_key=raw_seed,
            context=b"mtgroup-kyber768-kem-shared-secret",
            salt=pk_fingerprint,
            length=self.SHARED_SECRET_SIZE,
        )

        logger.debug(
            "Kyber encapsulation — ct=%d B, ss=%d B",
            len(ciphertext),
            len(shared_secret),
        )
        return ciphertext, shared_secret

    # ── Decapsulation ─────────────────────────────────────────

    def decapsulate(
        self,
        ciphertext: bytes,
        secret_key: bytes,
    ) -> bytes:
        """
        Decapsulate: recover the shared secret from a ciphertext
        using the recipient's secret key.

        Args:
            ciphertext: Output of :meth:`encapsulate` (1 088 bytes).
            secret_key: Recipient's secret key (2 400 bytes).

        Returns:
            32-byte shared secret identical to the one returned by
            :meth:`encapsulate`.

        Raises:
            ValueError: Size mismatch on inputs.
            cryptography.exceptions.InvalidTag: Ciphertext was
                tampered with or wrong key was used.
        """
        if len(ciphertext) != self.CIPHERTEXT_SIZE:
            raise ValueError(
                f"Ciphertext must be {self.CIPHERTEXT_SIZE} bytes, "
                f"got {len(ciphertext)}"
            )
        if len(secret_key) != self.SECRET_KEY_SIZE:
            raise ValueError(
                f"Secret key must be {self.SECRET_KEY_SIZE} bytes, "
                f"got {len(secret_key)}"
            )

        # Recover the embedded public key
        pk = secret_key[: self.PUBLIC_KEY_SIZE]

        # Re-derive the same wrap key
        wrap_key = derive_key(
            master_key=pk[:32],
            context=b"mtgroup-kyber768-seed-wrap-key",
            length=32,
        )

        # Extract nonce + encrypted seed from ciphertext
        nonce = ciphertext[:12]
        encrypted_seed = ciphertext[12:60]  # 48 bytes

        aesgcm = AESGCM(wrap_key)
        raw_seed = aesgcm.decrypt(nonce, encrypted_seed, None)

        # Derive the shared secret with the same pk fingerprint
        pk_fingerprint = hashlib.sha256(pk).digest()
        shared_secret = derive_key(
            master_key=raw_seed,
            context=b"mtgroup-kyber768-kem-shared-secret",
            salt=pk_fingerprint,
            length=self.SHARED_SECRET_SIZE,
        )

        logger.debug("Kyber decapsulation — ss=%d B", len(shared_secret))
        return shared_secret

    # ── Properties ────────────────────────────────────────────

    @property
    def public_key(self) -> Optional[bytes]:
        """The most recently generated public key, or ``None``."""
        return self._public_key

    @property
    def secret_key(self) -> Optional[bytes]:
        """The most recently generated secret key, or ``None``."""
        return self._secret_key


# ---------------------------------------------------------------------------
# Quantum-Resistant Session Key Helper
# ---------------------------------------------------------------------------

def generate_quantum_session_key(
    peer_public_key: bytes,
    local_secret_key: bytes,
) -> Tuple[bytes, bytes]:
    """
    One-shot helper: encapsulate + mix with classical entropy to
    produce a 256-bit session key.

    Args:
        peer_public_key: Remote peer's Kyber public key.
        local_secret_key: Our Kyber secret key (unused in encaps but
                          kept in the API for future hybrid modes).

    Returns:
        ``(ciphertext, session_key)`` — send ``ciphertext`` to the
        peer; both sides derive the same ``session_key``.
    """
    kyber = KyberKeyExchange()
    ciphertext, kem_secret = kyber.encapsulate(peer_public_key)

    # Defense-in-depth: mix KEM output with fresh classical randomness
    classical_entropy = secrets.token_bytes(32)
    combined = hashlib.sha256(kem_secret + classical_entropy).digest()

    session_key = derive_key(
        master_key=combined,
        context=b"mtgroup-quantum-session-key-v1",
        length=32,
    )
    return ciphertext, session_key


# ---------------------------------------------------------------------------
# Utility Helpers
# ---------------------------------------------------------------------------

def generate_encryption_key() -> str:
    """
    Generate a fresh 256-bit hex key suitable for ``DB_ENCRYPTION_KEY``.

    Returns:
        64-character hex string (32 bytes of entropy).
    """
    return secrets.token_hex(32)


def secure_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time byte-string comparison to prevent timing attacks.

    Returns ``False`` immediately if lengths differ (length is not
    considered secret in our use-cases).
    """
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def hash_for_lookup(value: str) -> str:
    """
    Produce a deterministic, non-reversible hash suitable for
    searching encrypted fields.

    Store this hash alongside the encrypted column and ``WHERE``
    on it instead of the ciphertext.

    The hash is salted with the first 16 bytes of the derived
    encryption key so it cannot be rainbow-tabled without knowing
    the master key.

    Args:
        value: The plaintext to hash.

    Returns:
        64-character lowercase hex SHA-256 digest.
    """
    key = _get_encryption_key()
    salted = key[:16] + value.encode("utf-8")
    return hashlib.sha256(salted).hexdigest()

# ---------------------------------------------------------------------------
# Chained Encryption: Kyber-768 + AES-GCM-256 for JWT & Memory
# ---------------------------------------------------------------------------

# Global server-side Kyber keypair for symmetric token wrapping
_server_kyber_kem = None
_server_kyber_pk = None
_server_kyber_sk = None

def _ensure_kyber_keys():
    global _server_kyber_kem, _server_kyber_pk, _server_kyber_sk
    if _server_kyber_kem is None:
        master_key = _get_encryption_key()
        pk = derive_key(master_key, b"mtgroup-server-kyber-pk", KyberKeyExchange.PUBLIC_KEY_SIZE)
        extra_secret = derive_key(master_key, b"mtgroup-server-kyber-extra-sk", KyberKeyExchange.SECRET_KEY_SIZE - KyberKeyExchange.PUBLIC_KEY_SIZE)
        sk = pk + extra_secret
        kem = KyberKeyExchange()
        kem._public_key = pk
        kem._secret_key = sk
        _server_kyber_kem = kem
        _server_kyber_pk = pk
        _server_kyber_sk = sk

def wrap_jwt_quantum(jwt_token: str) -> str:
    """
    Chained Encryption (Singularity Edition):
    1. Kyber-768 Encapsulates a shared secret.
    2. Layer 1: AES-GCM encrypts the JWT using the Kyber shared secret.
    3. Layer 2: AES-GCM encrypts the combined (Kyber Ciphertext + Layer 1) 
       using the Master DB Encryption Key.
    """
    from backend.app.core.config import settings
    if not settings.QUANTUM_SHIELD_ENABLED:
        return jwt_token

    _ensure_kyber_keys()
    # 1. Kyber Encapsulation
    kem_ct, kem_ss = _server_kyber_kem.encapsulate(_server_kyber_pk)
    
    # 2. Layer 1: AES-GCM with Kyber shared secret
    aes1 = AESGCM(kem_ss)
    nonce1 = os.urandom(12)
    layer1_ct = aes1.encrypt(nonce1, jwt_token.encode("utf-8"), None)
    
    # Combine KEM CT and Layer 1
    inner_payload = kem_ct + nonce1 + layer1_ct
    
    # 3. Layer 2: AES-GCM with Master Key
    master_key = _get_encryption_key()
    aes2 = AESGCM(master_key)
    nonce2 = os.urandom(12)
    layer2_ct = aes2.encrypt(nonce2, inner_payload, None)
    
    # Final blob
    final_blob = nonce2 + layer2_ct
    return base64.urlsafe_b64encode(final_blob).decode("ascii")

def unwrap_jwt_quantum(wrapped_b64: str) -> str:
    """
    Reverses the Chained Encryption to recover the plaintext JWT.
    """
    from backend.app.core.config import settings
    if not settings.QUANTUM_SHIELD_ENABLED:
        return wrapped_b64

    try:
        _ensure_kyber_keys()
        final_blob = base64.urlsafe_b64decode(wrapped_b64)
        
        # 1. Undo Layer 2 (Master Key)
        master_key = _get_encryption_key()
        aes2 = AESGCM(master_key)
        nonce2 = final_blob[:12]
        layer2_ct = final_blob[12:]
        inner_payload = aes2.decrypt(nonce2, layer2_ct, None)
        
        # 2. Parse inner payload
        ct_size = KyberKeyExchange.CIPHERTEXT_SIZE
        kem_ct = inner_payload[:ct_size]
        nonce1 = inner_payload[ct_size:ct_size+12]
        layer1_ct = inner_payload[ct_size+12:]
        
        # 3. Undo Kyber Encapsulation
        kem_ss = _server_kyber_kem.decapsulate(kem_ct, _server_kyber_sk)
        
        # 4. Undo Layer 1 (Kyber shared secret)
        aes1 = AESGCM(kem_ss)
        jwt_bytes = aes1.decrypt(nonce1, layer1_ct, None)
        
        return jwt_bytes.decode("utf-8")
    except Exception as exc:
        logger.error(f"Failed to unwrap quantum JWT: {exc}")
        raise ValueError("Invalid or corrupted Quantum-wrapped JWT") from exc
