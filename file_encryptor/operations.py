"""High-level encrypt and decrypt operations.

Both operations are fail-closed: all output is written to a temporary file in
the destination directory and only moved into place (via :func:`os.replace`,
an atomic rename) after the entire operation has succeeded. Any failure --
including GCM authentication failure during decryption -- removes the
temporary file and leaves no partial or corrupt output behind.

During decryption the authentication tag is not verified until the final
:meth:`~file_encryptor.crypto.GCMDecryptor.finalize` call, so even a tampered
or wrongly-keyed stream never produces a visible output file.
"""

from __future__ import annotations

import os
import secrets
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag

from .crypto import GCMDecryptor, GCMEncryptor
from .fileformat import (
    HEADER_LENGTH,
    NONCE_LENGTH,
    SALT_LENGTH,
    TAG_LENGTH,
    build_header,
    build_name_prefix,
    parse_header,
    parse_name_prefix,
)
from .kdf import KDF_PBKDF2, derive_key

CHUNK_SIZE = 64 * 1024


class DecryptionError(Exception):
    """Raised when GCM authentication fails during decryption.

    This intentionally covers both a wrong passphrase and a corrupted or
    tampered file; callers must not distinguish the two, otherwise the error
    message becomes an oracle that leaks information about the passphrase.
    """


class FileNameError(ValueError):
    """Raised when an encrypted file name is unsafe or unparseable."""


def safe_basename(name: str) -> str:
    """Sanitise an encrypted file name for use as an output path.

    Only the base name is accepted: directory separators, drive letters, and
    the special names ``.`` and ``..`` are rejected so a hostile archive can
    never redirect output outside the destination directory.

    Args:
        name: The decrypted original file name.

    Returns:
        The cleaned base name.

    Raises:
        FileNameError: If the name is empty, a path separator, or a special
            name.
    """
    if not name or name in (".", ".."):
        raise FileNameError("encrypted file name is empty or a special name")
    if name.startswith(("/", "\\")) or any(c in name for c in ("/", "\\")):
        raise FileNameError("encrypted file name contains a path separator")
    if name.endswith(":") or ":" in name.split("\\")[0].split("/")[0]:
        raise FileNameError("encrypted file name contains a drive prefix")
    return name


def _open_output(output: Path, force: bool) -> None:
    """Ensure the destination is writable and does not clobber files."""
    if output.exists() and not force:
        raise FileExistsError(
            f"output already exists: {output} (use --force to overwrite)"
        )
    parent = output.parent
    if not parent.exists():
        raise FileNotFoundError(f"output directory does not exist: {parent}")


def _passphrase_bytes(passphrase: str) -> bytes:
    """Encode the passphrase as UTF-8 bytes for the KDF."""
    return passphrase.encode("utf-8")


def _atomic_write(output: Path, temp: Path) -> None:
    """Atomically move ``temp`` into place, deleting it on failure."""
    try:
        os.replace(temp, output)
    except BaseException:
        _discard(temp)
        raise


def _discard(path: Path) -> None:
    """Best-effort removal of a temporary or partial file."""
    try:
        os.unlink(path)
    except OSError:
        pass


def encrypt_file(
    input_path: Path,
    output_path: Path,
    passphrase: str,
    kdf_id: int = KDF_PBKDF2,
    iterations: int = 480_000,
    force: bool = False,
) -> None:
    """Encrypt ``input_path`` into the ``.fenc`` container at ``output_path``.

    Args:
        input_path: The plaintext file to encrypt.
        output_path: Destination for the ``.fenc`` file.
        passphrase: Passphrase from which the key is derived.
        kdf_id: :data:`KDF_PBKDF2` (default) or :data:`KDF_ARGON2ID`.
        iterations: PBKDF2 iteration count (ignored for Argon2id).
        force: Overwrite an existing output file.

    Raises:
        FileNotFoundError: If the input file or output directory is missing.
        FileExistsError: If the output exists and ``force`` is false.
        OSError: On any I/O failure; no partial output is left behind.
    """
    input_path = Path(input_path)
    output_path = Path(output_path)

    if input_path.resolve() == output_path.resolve():
        raise ValueError("input and output must be different files")

    _open_output(output_path, force)

    salt = secrets.token_bytes(SALT_LENGTH)
    nonce = secrets.token_bytes(NONCE_LENGTH)
    header = build_header(kdf_id, iterations, salt, nonce)
    key = derive_key(
        kdf_id, _passphrase_bytes(passphrase), salt, iterations
    )
    encryptor = GCMEncryptor(key, nonce, header)

    output_dir = output_path.parent
    fd, temp_name = tempfile.mkstemp(
        prefix=f".{output_path.name}.", suffix=".tmp", dir=output_dir
    )
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as out, input_path.open("rb") as src:
            out.write(header)
            name_prefix = build_name_prefix(input_path.name)
            out.write(encryptor.update(name_prefix))
            while True:
                chunk = src.read(CHUNK_SIZE)
                if not chunk:
                    break
                out.write(encryptor.update(chunk))
            out.write(encryptor.finalize())
        _atomic_write(output_path, temp)
    except BaseException:
        _discard(temp)
        raise


def decrypt_file(
    input_path: Path,
    passphrase: str,
    output_path: Path | None = None,
    force: bool = False,
) -> str:
    """Decrypt a ``.fenc`` container and write the recovered plaintext.

    The original file name is recovered from the (encrypted) plaintext stream
    and returned. If ``output_path`` is None the plaintext is written next to
    the container under the recovered name (sanitised against path traversal).

    Args:
        input_path: The ``.fenc`` file to decrypt.
        passphrase: Passphrase from which the key is derived.
        output_path: Destination for the recovered plaintext; defaults to the
            input directory and the recovered file name.
        force: Overwrite an existing output file.

    Returns:
        The recovered original file name.

    Raises:
        FileNotFoundError: If the input file or output directory is missing.
        FileExistsError: If the output exists and ``force`` is false.
        FormatError: If the file is not a valid ``.fenc`` container.
        DecryptionError: If GCM authentication fails (wrong passphrase or
            tampered file). No output file is created or left behind.
    """
    input_path = Path(input_path)
    if output_path is not None:
        output_path = Path(output_path)
        if input_path.resolve() == output_path.resolve():
            raise ValueError("input and output must be different files")
        _open_output(output_path, force)

    size = input_path.stat().st_size
    if size < HEADER_LENGTH + TAG_LENGTH:
        raise ValueError(
            f"file too small to be a valid .fenc container ({size} bytes)"
        )

    with input_path.open("rb") as src:
        header_bytes = src.read(HEADER_LENGTH)
        header = parse_header(header_bytes)
        key = derive_key(
            header.kdf_id,
            _passphrase_bytes(passphrase),
            header.salt,
            header.iterations,
        )

        ciphertext_end = size - TAG_LENGTH
        src.seek(ciphertext_end)
        tag = src.read(TAG_LENGTH)
        src.seek(HEADER_LENGTH)

        ciphertext_len = ciphertext_end - HEADER_LENGTH

        decryptor = GCMDecryptor(key, header.nonce, tag, header_bytes)

        # The first chunk carries the encrypted file-name prefix.
        first = src.read(min(CHUNK_SIZE, ciphertext_len))
        first_plain = decryptor.update(first)
        try:
            original_name = parse_name_prefix(first_plain)
        except ValueError as exc:
            raise DecryptionError(
                "authentication failed: wrong passphrase or the file was "
                "corrupted or tampered"
            ) from exc

        if output_path is None:
            output_path = input_path.parent / safe_basename(original_name)
            _open_output(output_path, force)

        output_dir = output_path.parent
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{output_path.name}.", suffix=".tmp", dir=output_dir
        )
        temp = Path(temp_name)
        try:
            with os.fdopen(fd, "wb") as out:
                name_bytes = original_name.encode("utf-8")
                out.write(first_plain[2 + len(name_bytes):])

                remaining = ciphertext_len - len(first)
                while remaining > 0:
                    chunk = src.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        break
                    out.write(decryptor.update(chunk))
                    remaining -= len(chunk)

                try:
                    decryptor.finalize()
                except InvalidTag as exc:
                    raise DecryptionError(
                        "authentication failed: wrong passphrase or the file was "
                        "corrupted or tampered"
                    ) from exc
            _atomic_write(output_path, temp)
        except DecryptionError:
            _discard(temp)
            raise
        except BaseException:
            _discard(temp)
            raise

    return safe_basename(original_name)