"""
MTGroup VPN Ultimate — Post-Quantum Crypto Test Suite
Verifies ML-KEM-768 (Kyber-768) encapsulation/decapsulation, the
QUANTUM_SHIELD JWT wrapping/unwrapping round trip (including that a
persisted server keypair survives a process restart), the HKDF key
derivation and AES-GCM-256 field-encryption primitives, and the
EncryptedType SQLAlchemy adapter.
"""

from __future__ import annotations

import base64

import pytest
from cryptography.exceptions import InvalidTag

from backend.app.core import crypto_quantum as cq


class TestKyberKeyExchange:
    """Direct KEM round-trip tests. Run against whichever backend is
    active (real pqcrypto if installed, classical simulation otherwise) —
    the byte-size contract and round-trip property must hold either way."""

    def test_keypair_sizes(self):
        kem = cq.KyberKeyExchange()
        pk, sk = kem.generate_keypair()
        assert len(pk) == cq.KyberKeyExchange.PUBLIC_KEY_SIZE
        assert len(sk) == cq.KyberKeyExchange.SECRET_KEY_SIZE

    def test_encapsulate_decapsulate_round_trip(self):
        kem = cq.KyberKeyExchange()
        pk, sk = kem.generate_keypair()
        ciphertext, shared_secret = kem.encapsulate(pk)
        assert len(ciphertext) == cq.KyberKeyExchange.CIPHERTEXT_SIZE
        assert len(shared_secret) == cq.KyberKeyExchange.SHARED_SECRET_SIZE

        recovered = kem.decapsulate(ciphertext, sk)
        assert recovered == shared_secret

    def test_wrong_secret_key_does_not_recover_same_secret(self):
        kem = cq.KyberKeyExchange()
        pk, _sk = kem.generate_keypair()
        _pk2, sk2 = cq.KyberKeyExchange().generate_keypair()

        ciphertext, shared_secret = kem.encapsulate(pk)
        # Decapsulating with an unrelated secret key must not silently
        # recover the correct shared secret (real ML-KEM implicitly
        # rejects; the classical fallback may raise instead — either is
        # an acceptable failure mode, "quietly returns the right answer"
        # is the only unacceptable one).
        try:
            recovered = kem.decapsulate(ciphertext, sk2)
        except Exception:
            return
        assert recovered != shared_secret

    def test_encapsulate_rejects_wrong_size_public_key(self):
        kem = cq.KyberKeyExchange()
        with pytest.raises(ValueError):
            kem.encapsulate(b"too-short")

    def test_decapsulate_rejects_wrong_size_inputs(self):
        kem = cq.KyberKeyExchange()
        pk, sk = kem.generate_keypair()
        ciphertext, _ = kem.encapsulate(pk)
        with pytest.raises(ValueError):
            kem.decapsulate(b"too-short", sk)
        with pytest.raises(ValueError):
            kem.decapsulate(ciphertext, b"too-short")


@pytest.fixture
def quantum_shield_enabled(tmp_path, monkeypatch):
    """Isolate settings + the persisted server keypair file per test so
    tests don't interfere with each other or leave artifacts in the repo."""
    from backend.app.core.config import settings

    monkeypatch.setattr(settings, "QUANTUM_SHIELD_ENABLED", True)
    monkeypatch.setattr(cq, "_KYBER_SERVER_KEY_FILE", tmp_path / ".mtgroup_kyber_server.key")
    monkeypatch.setattr(cq, "_server_kyber_kem", None)
    monkeypatch.setattr(cq, "_server_kyber_pk", None)
    monkeypatch.setattr(cq, "_server_kyber_sk", None)
    yield
    monkeypatch.setattr(cq, "_server_kyber_kem", None)
    monkeypatch.setattr(cq, "_server_kyber_pk", None)
    monkeypatch.setattr(cq, "_server_kyber_sk", None)


class TestJWTQuantumWrap:
    def test_disabled_is_passthrough(self, monkeypatch):
        from backend.app.core.config import settings

        monkeypatch.setattr(settings, "QUANTUM_SHIELD_ENABLED", False)
        token = "header.payload.signature"
        assert cq.wrap_jwt_quantum(token) == token
        assert cq.unwrap_jwt_quantum(token) == token

    def test_wrap_unwrap_round_trip(self, quantum_shield_enabled):
        token = "header.payload.signature"
        wrapped = cq.wrap_jwt_quantum(token)
        assert wrapped != token
        assert cq.unwrap_jwt_quantum(wrapped) == token

    def test_persisted_keypair_survives_simulated_restart(self, quantum_shield_enabled):
        token = "header.payload.signature"
        wrapped = cq.wrap_jwt_quantum(token)
        assert cq._KYBER_SERVER_KEY_FILE.exists()

        # Simulate a process restart: drop the in-memory cache, keep the file.
        cq._server_kyber_kem = None
        cq._server_kyber_pk = None
        cq._server_kyber_sk = None

        assert cq.unwrap_jwt_quantum(wrapped) == token

    def test_unwrap_rejects_tampered_blob(self, quantum_shield_enabled):
        token = "header.payload.signature"
        wrapped = cq.wrap_jwt_quantum(token)
        tampered = wrapped[:-4] + ("A" if wrapped[-4] != "A" else "B") + wrapped[-3:]
        with pytest.raises(ValueError):
            cq.unwrap_jwt_quantum(tampered)


# ---------------------------------------------------------------------------
# HKDF Key Derivation
# ---------------------------------------------------------------------------

class TestDeriveKey:
    def test_is_deterministic(self):
        a = cq.derive_key(master_key=b"master", context=b"ctx")
        b = cq.derive_key(master_key=b"master", context=b"ctx")
        assert a == b

    def test_respects_requested_length(self):
        assert len(cq.derive_key(master_key=b"m", context=b"c", length=64)) == 64

    def test_context_provides_domain_separation(self):
        a = cq.derive_key(master_key=b"master", context=b"purpose-a")
        b = cq.derive_key(master_key=b"master", context=b"purpose-b")
        assert a != b

    def test_different_master_keys_diverge(self):
        a = cq.derive_key(master_key=b"key-one", context=b"ctx")
        b = cq.derive_key(master_key=b"key-two", context=b"ctx")
        assert a != b

    def test_salt_changes_output(self):
        a = cq.derive_key(master_key=b"m", context=b"c")
        b = cq.derive_key(master_key=b"m", context=b"c", salt=b"\x01" * 32)
        assert a != b


# ---------------------------------------------------------------------------
# AES-GCM-256 Field Encryption
# ---------------------------------------------------------------------------

class TestEncryptValue:
    def test_round_trip(self):
        assert cq.decrypt_value(cq.encrypt_value("hello world")) == "hello world"

    def test_round_trip_unicode(self):
        secret = "şifreli veri — 秘密 — 🔐"
        assert cq.decrypt_value(cq.encrypt_value(secret)) == secret

    def test_round_trip_empty_string(self):
        assert cq.decrypt_value(cq.encrypt_value("")) == ""

    def test_same_plaintext_encrypts_differently_each_time(self):
        # A fresh 96-bit nonce per call means ciphertexts must never repeat,
        # otherwise identical field values would be linkable on disk.
        a = cq.encrypt_value("same-value")
        b = cq.encrypt_value("same-value")
        assert a != b
        assert cq.decrypt_value(a) == cq.decrypt_value(b) == "same-value"

    def test_output_is_urlsafe_base64(self):
        blob = cq.encrypt_value("data")
        assert "+" not in blob and "/" not in blob
        base64.urlsafe_b64decode(blob)  # must not raise


class TestDecryptValue:
    def test_rejects_invalid_base64(self):
        with pytest.raises(ValueError, match="Invalid Base64"):
            cq.decrypt_value("!!!not-base64!!!")

    def test_rejects_too_short_payload(self):
        short = base64.urlsafe_b64encode(b"\x00" * 20).decode("ascii")
        with pytest.raises(ValueError, match="too short"):
            cq.decrypt_value(short)

    def test_rejects_tampered_ciphertext(self):
        blob = cq.encrypt_value("authentic")
        raw = bytearray(base64.urlsafe_b64decode(blob))
        raw[-1] ^= 0xFF  # flip bits in the auth tag
        tampered = base64.urlsafe_b64encode(bytes(raw)).decode("ascii")
        with pytest.raises(InvalidTag):
            cq.decrypt_value(tampered)


class TestEncryptBytes:
    def test_round_trip(self):
        assert cq.decrypt_bytes(cq.encrypt_bytes(b"raw bytes")) == b"raw bytes"

    def test_round_trip_with_aad(self):
        blob = cq.encrypt_bytes(b"payload", aad=b"user-42")
        assert cq.decrypt_bytes(blob, aad=b"user-42") == b"payload"

    def test_wrong_aad_fails_authentication(self):
        # AAD binds the ciphertext to a context — decrypting under a
        # different context must fail rather than silently succeed.
        blob = cq.encrypt_bytes(b"payload", aad=b"user-42")
        with pytest.raises(InvalidTag):
            cq.decrypt_bytes(blob, aad=b"user-99")

    def test_missing_aad_fails_when_one_was_used(self):
        blob = cq.encrypt_bytes(b"payload", aad=b"user-42")
        with pytest.raises(InvalidTag):
            cq.decrypt_bytes(blob)

    def test_nonce_is_prefixed(self):
        blob = cq.encrypt_bytes(b"")
        assert len(blob) == 12 + 16  # nonce + tag, empty ciphertext


# ---------------------------------------------------------------------------
# Key Cache
# ---------------------------------------------------------------------------

class TestEncryptionKeyCache:
    def test_key_is_cached_between_calls(self):
        cq.reset_encryption_key_cache()
        first = cq._get_encryption_key()
        assert cq._get_encryption_key() is first

    def test_reset_clears_the_cache(self):
        cq._get_encryption_key()
        cq.reset_encryption_key_cache()
        assert cq._encryption_key_cache is None

    def test_blank_config_key_falls_back_to_dev_key_with_warning(self, monkeypatch, caplog):
        import logging

        from backend.app.core.config import settings

        cq.reset_encryption_key_cache()
        monkeypatch.setattr(settings, "DB_ENCRYPTION_KEY", "")
        try:
            with caplog.at_level(logging.WARNING):
                key = cq._get_encryption_key()
            assert len(key) == 32
            assert any("NOT SAFE FOR PRODUCTION" in r.message for r in caplog.records)
        finally:
            cq.reset_encryption_key_cache()


# ---------------------------------------------------------------------------
# EncryptedType (SQLAlchemy TypeDecorator)
# ---------------------------------------------------------------------------

class TestEncryptedType:
    def test_bind_then_result_round_trips(self):
        t = cq.EncryptedType()
        bound = t.process_bind_param("sensitive", dialect=None)
        assert bound != "sensitive"  # never stored as plaintext
        assert t.process_result_value(bound, dialect=None) == "sensitive"

    def test_none_passes_through_both_ways(self):
        t = cq.EncryptedType()
        assert t.process_bind_param(None, dialect=None) is None
        assert t.process_result_value(None, dialect=None) is None

    def test_empty_string_short_circuits(self):
        t = cq.EncryptedType()
        assert t.process_bind_param("", dialect=None) == ""
        assert t.process_result_value("", dialect=None) == ""

    def test_non_string_values_are_coerced(self):
        t = cq.EncryptedType()
        bound = t.process_bind_param(12345, dialect=None)
        assert t.process_result_value(bound, dialect=None) == "12345"

    def test_undecryptable_value_falls_back_to_plaintext(self):
        # Migration path: rows written before EncryptedType was applied
        # hold plaintext and must keep working rather than blowing up.
        t = cq.EncryptedType()
        assert t.process_result_value("legacy-plaintext-value", dialect=None) == "legacy-plaintext-value"


# ---------------------------------------------------------------------------
# Utility Helpers
# ---------------------------------------------------------------------------

class TestGenerateQuantumSessionKey:
    # local_secret_key is required by the signature but documented as
    # unused during encapsulation (reserved for future hybrid modes) —
    # passed through here so the tests track the real API.
    def test_returns_ciphertext_and_32_byte_key(self):
        kem = cq.KyberKeyExchange()
        pk, sk = kem.generate_keypair()
        ciphertext, session_key = cq.generate_quantum_session_key(pk, sk)
        assert len(ciphertext) == cq.KyberKeyExchange.CIPHERTEXT_SIZE
        assert len(session_key) == 32

    def test_each_call_mixes_fresh_entropy(self):
        kem = cq.KyberKeyExchange()
        pk, sk = kem.generate_keypair()
        _, key_a = cq.generate_quantum_session_key(pk, sk)
        _, key_b = cq.generate_quantum_session_key(pk, sk)
        assert key_a != key_b


class TestGenerateEncryptionKey:
    def test_returns_64_char_hex(self):
        key = cq.generate_encryption_key()
        assert len(key) == 64
        int(key, 16)  # must be valid hex

    def test_is_random_per_call(self):
        assert cq.generate_encryption_key() != cq.generate_encryption_key()


class TestSecureCompare:
    def test_equal_bytes_match(self):
        assert cq.secure_compare(b"abc123", b"abc123") is True

    def test_different_bytes_do_not_match(self):
        assert cq.secure_compare(b"abc123", b"abc124") is False

    def test_different_lengths_do_not_match(self):
        assert cq.secure_compare(b"abc", b"abcd") is False

    def test_empty_bytes_match(self):
        assert cq.secure_compare(b"", b"") is True


class TestHashForLookup:
    def test_is_deterministic(self):
        assert cq.hash_for_lookup("user@example.com") == cq.hash_for_lookup("user@example.com")

    def test_returns_64_char_hex(self):
        digest = cq.hash_for_lookup("value")
        assert len(digest) == 64
        int(digest, 16)

    def test_different_values_produce_different_hashes(self):
        assert cq.hash_for_lookup("a") != cq.hash_for_lookup("b")

    def test_is_salted_by_the_master_key(self):
        # Changing the master key must change the lookup hash, otherwise
        # the digests would be rainbow-tableable without the key.
        from backend.app.core.config import settings

        original = cq.hash_for_lookup("stable-value")
        cq.reset_encryption_key_cache()
        old_key = settings.DB_ENCRYPTION_KEY
        try:
            settings.DB_ENCRYPTION_KEY = "a" * 64
            assert cq.hash_for_lookup("stable-value") != original
        finally:
            settings.DB_ENCRYPTION_KEY = old_key
            cq.reset_encryption_key_cache()
