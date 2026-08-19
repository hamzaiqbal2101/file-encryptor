"""Tests for the .fenc container format and file-name prefix."""

from __future__ import annotations

import pytest

from file_encryptor.fileformat import (
    HEADER_LENGTH,
    MAGIC,
    FormatError,
    Header,
    build_header,
    build_name_prefix,
    parse_header,
    parse_name_prefix,
)
from file_encryptor.kdf import KDF_ARGON2ID, KDF_PBKDF2, UnsupportedKDFError


def _header_bytes(kdf_id=KDF_PBKDF2, iterations=480_000, salt=b"0" * 16, nonce=b"1" * 12):
    return build_header(kdf_id, iterations, salt, nonce)


def test_header_length_is_fixed():
    assert len(_header_bytes()) == HEADER_LENGTH == 38


def test_header_round_trip_pbkdf2():
    h = parse_header(_header_bytes(KDF_PBKDF2, 480_000))
    assert h == Header(kdf_id=KDF_PBKDF2, iterations=480_000, salt=b"0" * 16, nonce=b"1" * 12)


def test_header_round_trip_argon2id():
    h = parse_header(_header_bytes(KDF_ARGON2ID, 0))
    assert h.kdf_id == KDF_ARGON2ID
    assert h.iterations == 0


def test_header_magic():
    assert MAGIC == b"FENC"
    raw = bytearray(_header_bytes())
    raw[0] = ord("X")
    with pytest.raises(FormatError, match="magic"):
        parse_header(bytes(raw))


def test_header_version():
    raw = bytearray(_header_bytes())
    raw[4] = 99
    with pytest.raises(FormatError, match="version"):
        parse_header(bytes(raw))


def test_header_unknown_kdf():
    raw = bytearray(_header_bytes())
    raw[5] = 7
    with pytest.raises(FormatError, match="KDF"):
        parse_header(bytes(raw))


def test_header_argon2id_with_nonzero_params():
    raw = bytearray(_header_bytes(KDF_ARGON2ID, 0))
    raw[6:10] = (123).to_bytes(4, "big")
    with pytest.raises(FormatError, match="zero parameter field"):
        parse_header(bytes(raw))


def test_header_wrong_length():
    with pytest.raises(FormatError, match="header is"):
        parse_header(b"FENC" + b"x" * 10)


def test_build_header_unknown_kdf():
    with pytest.raises(UnsupportedKDFError):
        build_header(9, 0, b"0" * 16, b"1" * 12)


def test_build_header_bad_salt_length():
    with pytest.raises(ValueError, match="salt"):
        build_header(KDF_PBKDF2, 1000, b"short", b"1" * 12)


def test_build_header_bad_nonce_length():
    with pytest.raises(ValueError, match="nonce"):
        build_header(KDF_PBKDF2, 1000, b"0" * 16, b"x")


def test_name_prefix_round_trip():
    for name in ("secret.txt", "日本語ドキュメント.md", "a" * 300):
        prefix = build_name_prefix(name)
        assert parse_name_prefix(prefix) == name


def test_name_prefix_stores_length_first():
    prefix = build_name_prefix("abc.txt")
    assert prefix[:2] == (7).to_bytes(2, "big")
    assert prefix[2:] == b"abc.txt"


def test_name_prefix_rejects_oversized_name():
    with pytest.raises(ValueError, match="too long"):
        build_name_prefix("x" * 70_000)


def test_name_prefix_truncated_stream():
    with pytest.raises(ValueError, match="truncated"):
        parse_name_prefix((100).to_bytes(2, "big") + b"only a few bytes")


def test_name_prefix_short_stream():
    with pytest.raises(ValueError, match="too short"):
        parse_name_prefix(b"\x00")