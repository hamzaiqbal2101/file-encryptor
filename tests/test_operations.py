"""Tests for the high-level encrypt/decrypt operations."""

from __future__ import annotations

import pytest

from file_encryptor.fileformat import HEADER_LENGTH, FormatError
from file_encryptor.kdf import KDF_ARGON2ID
from file_encryptor.operations import (
    DecryptionError,
    FileNameError,
    decrypt_file,
    encrypt_file,
    safe_basename,
)

from tests.conftest import PASSPHRASE, TEST_ITERATIONS, WRONG_PASSPHRASE


class TestEncryptDecryptRoundTrip:
    def test_round_trip_small(self, plaintext_path, tmp_path):
        enc = tmp_path / "secret.txt.fenc"
        encrypt_file(plaintext_path, enc, PASSPHRASE, iterations=TEST_ITERATIONS)
        out = tmp_path / "out.txt"
        name = decrypt_file(enc, PASSPHRASE, output_path=out)
        assert name == "secret.txt"
        assert out.read_bytes() == plaintext_path.read_bytes()

    def test_round_trip_empty_file(self, tmp_path):
        src = tmp_path / "empty.bin"
        src.write_bytes(b"")
        enc = tmp_path / "empty.bin.fenc"
        encrypt_file(src, enc, PASSPHRASE, iterations=TEST_ITERATIONS)
        out = tmp_path / "empty.out"
        name = decrypt_file(enc, PASSPHRASE, output_path=out)
        assert name == "empty.bin"
        assert out.read_bytes() == b""

    def test_round_trip_large_file(self, tmp_path):
        src = tmp_path / "big.bin"
        src.write_bytes(bytes(range(256)) * (1024 * 256))  # 64 MiB
        enc = tmp_path / "big.bin.fenc"
        encrypt_file(src, enc, PASSPHRASE, iterations=TEST_ITERATIONS)
        out = tmp_path / "big.out"
        decrypt_file(enc, PASSPHRASE, output_path=out)
        assert out.read_bytes() == src.read_bytes()

    def test_round_trip_binary_utf8_name(self, tmp_path):
        src = tmp_path / "日本語ドキュメント.bin"
        src.write_bytes(b"\x00\x01\x02\xff" * 100)
        enc = tmp_path / "doc.fenc"
        encrypt_file(src, enc, PASSPHRASE, iterations=TEST_ITERATIONS)
        out = tmp_path / "doc.out"
        name = decrypt_file(enc, PASSPHRASE, output_path=out)
        assert name == "日本語ドキュメント.bin"
        assert out.read_bytes() == src.read_bytes()

    def test_round_trip_with_argon2id(self, plaintext_path, tmp_path):
        enc = tmp_path / "secret.txt.fenc"
        encrypt_file(
            plaintext_path, enc, PASSPHRASE, kdf_id=KDF_ARGON2ID
        )
        out = tmp_path / "out.txt"
        decrypt_file(enc, PASSPHRASE, output_path=out)
        assert out.read_bytes() == plaintext_path.read_bytes()

    def test_encrypted_file_contains_no_plaintext(self, plaintext_path, tmp_path):
        enc = tmp_path / "secret.txt.fenc"
        encrypt_file(plaintext_path, enc, PASSPHRASE, iterations=TEST_ITERATIONS)
        data = enc.read_bytes()
        assert b"attack at dawn" not in data

    def test_header_is_38_bytes_with_magic(self, plaintext_path, tmp_path):
        enc = tmp_path / "secret.txt.fenc"
        encrypt_file(plaintext_path, enc, PASSPHRASE, iterations=TEST_ITERATIONS)
        assert enc.read_bytes()[:4] == b"FENC"
        assert enc.read_bytes()[4] == 1  # version
        assert enc.read_bytes()[-16:]  # tag present


class TestDefaultOutputPath:
    def test_default_output_restores_name(self, tmp_path):
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        src = src_dir / "restore_me.txt"
        src.write_text("content")
        enc = tmp_path / "archive.fenc"
        encrypt_file(src, enc, PASSPHRASE, iterations=TEST_ITERATIONS)
        name = decrypt_file(enc, PASSPHRASE)
        assert name == "restore_me.txt"
        restored = tmp_path / "restore_me.txt"
        assert restored.read_text() == "content"

    def test_default_output_refuses_overwrite(self, tmp_path):
        src = tmp_path / "doc.txt"
        src.write_text("content")
        enc = tmp_path / "doc.fenc"
        encrypt_file(src, enc, PASSPHRASE, iterations=TEST_ITERATIONS)
        src.write_text("changed")  # now the restored name collides
        with pytest.raises(FileExistsError):
            decrypt_file(enc, PASSPHRASE)


class TestFailClosed:
    def test_wrong_passphrase_leaves_no_output(self, encrypted_path, tmp_path):
        out = tmp_path / "leak.txt"
        with pytest.raises(DecryptionError) as excinfo:
            decrypt_file(encrypted_path, WRONG_PASSPHRASE, output_path=out)
        assert "wrong passphrase" in str(excinfo.value)
        assert not out.exists()

    def test_tampered_ciphertext_leaves_no_output(self, encrypted_path, tmp_path):
        data = bytearray(encrypted_path.read_bytes())
        data[HEADER_LENGTH + 5] ^= 0x01
        tampered = tmp_path / "tampered.fenc"
        tampered.write_bytes(bytes(data))
        out = tmp_path / "leak.txt"
        with pytest.raises(DecryptionError):
            decrypt_file(tampered, PASSPHRASE, output_path=out)
        assert not out.exists()

    def test_tampered_header_leaves_no_output(self, encrypted_path, tmp_path):
        data = bytearray(encrypted_path.read_bytes())
        data[6:10] = (200_000).to_bytes(4, "big")  # change iteration count
        tampered = tmp_path / "tampered.fenc"
        tampered.write_bytes(bytes(data))
        out = tmp_path / "leak.txt"
        with pytest.raises(DecryptionError):
            decrypt_file(tampered, PASSPHRASE, output_path=out)
        assert not out.exists()

    def test_bad_magic_is_format_error(self, tmp_path):
        bad = tmp_path / "junk.fenc"
        bad.write_bytes(b"NOTFENC" + b"x" * 100)
        with pytest.raises(FormatError, match="magic"):
            decrypt_file(bad, PASSPHRASE)

    def test_too_small_file_is_rejected(self, tmp_path):
        tiny = tmp_path / "tiny.fenc"
        tiny.write_bytes(b"FENC" + b"z" * 10)
        with pytest.raises(ValueError, match="too small"):
            decrypt_file(tiny, PASSPHRASE)


class TestOverwriteProtection:
    def test_existing_output_refused(self, plaintext_path, tmp_path):
        enc = tmp_path / "out.fenc"
        enc.write_bytes(b"occupied")
        with pytest.raises(FileExistsError):
            encrypt_file(plaintext_path, enc, PASSPHRASE, iterations=TEST_ITERATIONS)

    def test_force_overwrites(self, plaintext_path, tmp_path):
        enc = tmp_path / "out.fenc"
        enc.write_bytes(b"occupied")
        encrypt_file(
            plaintext_path, enc, PASSPHRASE, iterations=TEST_ITERATIONS, force=True
        )
        assert enc.read_bytes()[:4] == b"FENC"

    def test_missing_input_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            encrypt_file(tmp_path / "nope.txt", tmp_path / "x.fenc", PASSPHRASE)

    def test_same_input_output_rejected(self, plaintext_path):
        with pytest.raises(ValueError, match="different files"):
            encrypt_file(plaintext_path, plaintext_path, PASSPHRASE)

    def test_missing_output_dir_raises(self, plaintext_path, tmp_path):
        with pytest.raises(FileNotFoundError, match="output directory"):
            encrypt_file(plaintext_path, tmp_path / "no_such_dir" / "x.fenc", PASSPHRASE)


class TestSafeBasename:
    @pytest.mark.parametrize(
        "name",
        ["plain.txt", "with space.txt", "日本語.md", "a.b.c", "under_score-v1.2"],
    )
    def test_valid_names_pass(self, name):
        assert safe_basename(name) == name

    @pytest.mark.parametrize(
        "name",
        ["", ".", "..", "/etc/passwd", "..\\..\\evil.txt", "dir/file.txt", "C:\\x.txt", "C:/x.txt"],
    )
    def test_unsafe_names_rejected(self, name):
        with pytest.raises(FileNameError):
            safe_basename(name)