"""Tests for the streaming AES-256-GCM helpers."""

from __future__ import annotations

import secrets

import pytest
from cryptography.exceptions import InvalidTag

from file_encryptor.crypto import GCMDecryptor, GCMEncryptor


def _encrypt_stream(plaintext: bytes, nonce: bytes = None, aad: bytes = b""):
    nonce = nonce or secrets.token_bytes(12)
    key = secrets.token_bytes(32)
    enc = GCMEncryptor(key, nonce, aad)
    out = b"".join(enc.update(plaintext[i : i + 7]) for i in range(0, len(plaintext), 7))
    tag = enc.finalize()
    return key, nonce, tag, out


def test_round_trip_with_aad():
    key, nonce, tag, ciphertext = _encrypt_stream(b"hello world", aad=b"header")
    dec = GCMDecryptor(key, nonce, tag, b"header")
    assert b"".join(dec.update(ciphertext[i : i + 5]) for i in range(0, len(ciphertext), 5)) == b"hello world"
    dec.finalize()  # must not raise


def test_empty_plaintext_round_trip():
    key, nonce, tag, ciphertext = _encrypt_stream(b"", aad=b"aad")
    dec = GCMDecryptor(key, nonce, tag, b"aad")
    assert dec.update(ciphertext) == b""
    dec.finalize()


def test_tampered_ciphertext_raises_invalid_tag():
    key, nonce, tag, ciphertext = _encrypt_stream(b"secret data", aad=b"aad")
    corrupted = bytearray(ciphertext)
    corrupted[len(corrupted) // 2] ^= 0xFF
    dec = GCMDecryptor(key, nonce, tag, b"aad")
    dec.update(bytes(corrupted))
    with pytest.raises(InvalidTag):
        dec.finalize()


def test_tampered_aad_raises_invalid_tag():
    key, nonce, tag, ciphertext = _encrypt_stream(b"secret data", aad=b"aad")
    dec = GCMDecryptor(key, nonce, tag, b"different aad")
    dec.update(ciphertext)
    with pytest.raises(InvalidTag):
        dec.finalize()


def test_wrong_key_raises_invalid_tag():
    _, nonce, tag, ciphertext = _encrypt_stream(b"secret data", aad=b"aad")
    dec = GCMDecryptor(secrets.token_bytes(32), nonce, tag, b"aad")
    dec.update(ciphertext)
    with pytest.raises(InvalidTag):
        dec.finalize()


def test_wrong_tag_raises_invalid_tag():
    key, nonce, _, ciphertext = _encrypt_stream(b"secret data", aad=b"aad")
    bad_tag = secrets.token_bytes(16)
    dec = GCMDecryptor(key, nonce, bad_tag, b"aad")
    dec.update(ciphertext)
    with pytest.raises(InvalidTag):
        dec.finalize()


def test_double_finalize_encryptor_raises():
    enc = GCMEncryptor(secrets.token_bytes(32), secrets.token_bytes(12), b"")
    enc.update(b"x")
    enc.finalize()
    with pytest.raises(RuntimeError):
        enc.finalize()


def test_double_finalize_decryptor_raises():
    key, nonce, tag, ciphertext = _encrypt_stream(b"data")
    dec = GCMDecryptor(key, nonce, tag, b"")
    dec.update(ciphertext)
    dec.finalize()
    with pytest.raises(RuntimeError):
        dec.finalize()


def test_tag_is_16_bytes():
    _, _, tag, _ = _encrypt_stream(b"x")
    assert len(tag) == 16


def test_bad_nonce_length_rejected():
    with pytest.raises(ValueError, match="nonce"):
        GCMEncryptor(secrets.token_bytes(32), b"short", b"")
    with pytest.raises(ValueError, match="nonce"):
        GCMDecryptor(secrets.token_bytes(32), b"short", b"0" * 16, b"")


def test_bad_tag_length_rejected():
    with pytest.raises(ValueError, match="tag"):
        GCMDecryptor(secrets.token_bytes(32), secrets.token_bytes(12), b"tiny", b"")