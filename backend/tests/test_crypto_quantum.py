"""
MTGroup VPN Ultimate — Post-Quantum Crypto Test Suite
Verifies ML-KEM-768 (Kyber-768) encapsulation/decapsulation and the
QUANTUM_SHIELD JWT wrapping/unwrapping round trip, including that a
persisted server keypair survives a process restart.
"""

from __future__ import annotations

import pytest

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
