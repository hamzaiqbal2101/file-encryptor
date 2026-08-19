"""Tests for the key derivation functions."""

from __future__ import annotations

import secrets

import pytest

from file_encryptor.kdf import (
    ARGON2_TIME_COST,
    KDF_ARGON2ID,
    KDF_PBKDF2,
    KEY_LENGTH,
    SALT_LENGTH,
    UnsupportedKDFError,
    derive_key,
)

from tests.conftest import PASSPHRASE


def _salt() -> bytes:
    return secrets.token_bytes(SALT_LENGTH)


def test_pbkdf2_returns_32_bytes():
    key = derive_key(KDF_PBKDF2, PASSPHRASE.encode(), _salt(), 100_000)
    assert len(key) == KEY_LENGTH == 32


def test_pbkdf2_is_deterministic():
    salt = _salt()
    k1 = derive_key(KDF_PBKDF2, PASSPHRASE.encode(), salt, 100_000)
    k2 = derive_key(KDF_PBKDF2, PASSPHRASE.encode(), salt, 100_000)
    assert k1 == k2


def test_pbkdf2_differs_with_different_salt():
    k1 = derive_key(KDF_PBKDF2, PASSPHRASE.encode(), _salt(), 100_000)
    k2 = derive_key(KDF_PBKDF2, PASSPHRASE.encode(), _salt(), 100_000)
    assert k1 != k2


def test_pbkdf2_differs_with_different_iterations():
    salt = _salt()
    k1 = derive_key(KDF_PBKDF2, PASSPHRASE.encode(), salt, 100_000)
    k2 = derive_key(KDF_PBKDF2, PASSPHRASE.encode(), salt, 200_000)
    assert k1 != k2


def test_pbkdf2_matches_reference_implementation():
    """Cross-check against the standard library's PBKDF2 implementation."""
    import hashlib

    salt = b"0123456789abcdef"
    key = derive_key(KDF_PBKDF2, b"test-passphrase", salt, 100_000)
    expected = hashlib.pbkdf2_hmac(
        "sha256", b"test-passphrase", salt, 100_000, dklen=KEY_LENGTH
    )
    assert key == expected


@pytest.mark.parametrize("kdf_id", [0, 3, 255, 99])
def test_unknown_kdf_raises(kdf_id):
    with pytest.raises(UnsupportedKDFError):
        derive_key(kdf_id, PASSPHRASE.encode(), _salt(), 100_000)


def test_argon2id_returns_32_bytes():
    key = derive_key(KDF_ARGON2ID, PASSPHRASE.encode(), _salt(), 0)
    assert len(key) == KEY_LENGTH == 32


def test_argon2id_is_deterministic():
    salt = _salt()
    k1 = derive_key(KDF_ARGON2ID, PASSPHRASE.encode(), salt, 0)
    k2 = derive_key(KDF_ARGON2ID, PASSPHRASE.encode(), salt, 0)
    assert k1 == k2


def test_argon2id_differs_with_different_passphrase():
    salt = _salt()
    k1 = derive_key(KDF_ARGON2ID, b"one passphrase", salt, 0)
    k2 = derive_key(KDF_ARGON2ID, b"two passphrase", salt, 0)
    assert k1 != k2


def test_argon2_parameters_are_fixed():
    assert ARGON2_TIME_COST == 3