"""Shared fixtures for the file-encryptor test suite."""

from __future__ import annotations

from pathlib import Path

import pytest

TEST_ITERATIONS = 100_000
PASSPHRASE = "Correct Horse Battery Staple"
WRONG_PASSPHRASE = "wrong passphrase"


@pytest.fixture
def tmp_dir(tmp_path: Path) -> Path:
    """A fresh scratch directory per test."""
    return tmp_path


@pytest.fixture
def plaintext_path(tmp_path: Path) -> Path:
    """A small plaintext file of known content."""
    path = tmp_path / "secret.txt"
    path.write_bytes(b"attack at dawn\n" * 1000)
    return path


@pytest.fixture
def encrypted_path(tmp_path: Path) -> Path:
    """A pre-encrypted .fenc container produced with TEST_ITERATIONS."""
    from file_encryptor import encrypt_file

    plain = tmp_path / "secret.txt"
    plain.write_bytes(b"attack at dawn\n" * 1000)
    enc = tmp_path / "secret.txt.fenc"
    encrypt_file(plain, enc, PASSPHRASE, iterations=TEST_ITERATIONS)
    return enc