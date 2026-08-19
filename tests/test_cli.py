"""Tests for the command-line interface."""

from __future__ import annotations

from pathlib import Path

import pytest

from file_encryptor import cli

from tests.conftest import PASSPHRASE, TEST_ITERATIONS, WRONG_PASSPHRASE


@pytest.fixture
def stub_passphrase(monkeypatch):
    """Replace the interactive prompt with a canned passphrase."""

    def _install(value=PASSPHRASE):
        monkeypatch.setattr(cli, "get_passphrase", lambda **kw: value)

    return _install


def test_encrypt_and_decrypt_success(plaintext_path, tmp_path, stub_passphrase):
    stub_passphrase()
    enc = tmp_path / "secret.txt.fenc"
    assert (
        cli.main(
            [
                "encrypt",
                "-i",
                str(plaintext_path),
                "-o",
                str(enc),
                "--kdf-iterations",
                str(TEST_ITERATIONS),
            ]
        )
        == 0
    )
    out = tmp_path / "out.txt"
    assert (
        cli.main(["decrypt", "-i", str(enc), "-o", str(out)]) == 0
    )
    assert out.read_bytes() == plaintext_path.read_bytes()


def test_decrypt_wrong_passphrase_returns_1(
    encrypted_path, tmp_path, stub_passphrase
):
    stub_passphrase(WRONG_PASSPHRASE)
    out = tmp_path / "leak.txt"
    assert cli.main(["decrypt", "-i", str(encrypted_path), "-o", str(out)]) == 1
    assert not out.exists()


def test_missing_input_returns_3(tmp_path, stub_passphrase):
    stub_passphrase()
    assert (
        cli.main(
            [
                "encrypt",
                "-i",
                str(tmp_path / "nope.txt"),
                "-o",
                str(tmp_path / "x.fenc"),
            ]
        )
        == 3
    )


def test_existing_output_without_force_returns_3(
    plaintext_path, tmp_path, stub_passphrase
):
    stub_passphrase()
    enc = tmp_path / "out.fenc"
    enc.write_bytes(b"occupied")
    assert (
        cli.main(
            [
                "encrypt",
                "-i",
                str(plaintext_path),
                "-o",
                str(enc),
                "--kdf-iterations",
                str(TEST_ITERATIONS),
            ]
        )
        == 3
    )


def test_corrupt_container_returns_3(tmp_path, stub_passphrase):
    stub_passphrase()
    bad = tmp_path / "junk.fenc"
    bad.write_bytes(b"NOTFENC" + b"x" * 64)
    assert cli.main(["decrypt", "-i", str(bad), "-o", str(tmp_path / "o.txt")]) == 3


def test_no_subcommand_exits_2():
    with pytest.raises(SystemExit) as excinfo:
        cli.main([])
    assert excinfo.value.code == 2


def test_missing_required_input_exits_2():
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["encrypt", "-o", "out.fenc"])
    assert excinfo.value.code == 2


def test_iterations_below_minimum_exits_2(plaintext_path, tmp_path):
    with pytest.raises(SystemExit) as excinfo:
        cli.main(
            [
                "encrypt",
                "-i",
                str(plaintext_path),
                "-o",
                str(tmp_path / "x.fenc"),
                "--kdf-iterations",
                "1000",
            ]
        )
    assert excinfo.value.code == 2


def test_invalid_kdf_choice_exits_2(plaintext_path, tmp_path):
    with pytest.raises(SystemExit) as excinfo:
        cli.main(
            [
                "encrypt",
                "-i",
                str(plaintext_path),
                "-o",
                str(tmp_path / "x.fenc"),
                "--kdf",
                "scrypt",
            ]
        )
    assert excinfo.value.code == 2


def test_default_output_name_is_input_plus_fenc(
    plaintext_path, tmp_path, stub_passphrase
):
    stub_passphrase()
    assert (
        cli.main(
            [
                "encrypt",
                "-i",
                str(plaintext_path),
                "--kdf-iterations",
                str(TEST_ITERATIONS),
            ]
        )
        == 0
    )
    default_out = Path(str(plaintext_path) + ".fenc")
    assert default_out.exists()