"""Definition of the ``.fenc`` container format.

Byte layout of a ``.fenc`` file (all integers big-endian)::

    +----------------+------------+---------+------------+------------+------------+
    | magic "FENC"   | version    | kdf_id  | kdf params | salt       | nonce      |
    | (4 bytes)      | (1 byte)   | (1 byte)| (4 bytes)  | (16 bytes) | (12 bytes) |
    +----------------+------------+---------+------------+------------+------------+
    | ciphertext (streamed, any length)                                       | tag |
    |                                                                        |(16)|
    +-----------------------------------------------------------------------------+

The 38-byte fixed header (``MAGIC + version + kdf_id + kdf params + salt +
nonce``) is bound to the ciphertext as GCM additional authenticated data (AAD).
Any tampering with the header -- swapping the salt, nonce, or KDF parameters --
therefore fails authentication during decryption.

The KDF parameter field is always 4 bytes and holds the PBKDF2 iteration count
(0 for Argon2id, whose parameters are fixed by this implementation). Keeping
this field fixed-width means the header can be parsed without knowing the KDF
in advance.

Inside the plaintext stream, the original file name is stored first as a
2-byte big-endian length followed by its UTF-8 bytes, so decryption can restore
the original name. The name travels through the GCM stream, so it is encrypted
like the rest of the file.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .kdf import KDF_ARGON2ID, KDF_PBKDF2, UnsupportedKDFError

MAGIC = b"FENC"
VERSION = 1

KDF_PARAMS_LENGTH = 4
SALT_LENGTH = 16
NONCE_LENGTH = 12
TAG_LENGTH = 16

HEADER_LENGTH = len(MAGIC) + 1 + 1 + KDF_PARAMS_LENGTH + SALT_LENGTH + NONCE_LENGTH

_NAME_LENGTH_BYTES = 2
MAX_NAME_LENGTH = 0xFFFF  # largest value representable in _NAME_LENGTH_BYTES


@dataclass(frozen=True)
class Header:
    """Parsed fixed header of a ``.fenc`` file."""

    kdf_id: int
    iterations: int
    salt: bytes
    nonce: bytes

    @property
    def kdf_params(self) -> bytes:
        """The 4-byte KDF parameter field, big-endian iteration count."""
        return struct.pack(">I", self.iterations)


class FormatError(ValueError):
    """Raised when bytes do not look like a valid ``.fenc`` header."""


def build_header(kdf_id: int, iterations: int, salt: bytes, nonce: bytes) -> bytes:
    """Serialise the 38-byte fixed header for ``kdf_id``.

    Args:
        kdf_id: One of :data:`KDF_PBKDF2` or :data:`KDF_ARGON2ID`.
        iterations: PBKDF2 iteration count (written as 0 for Argon2id).
        salt: 16-byte salt.
        nonce: 12-byte GCM nonce.

    Returns:
        The serialised header bytes.

    Raises:
        UnsupportedKDFError: If ``kdf_id`` is unknown.
    """
    if kdf_id not in (KDF_PBKDF2, KDF_ARGON2ID):
        raise UnsupportedKDFError(f"unknown KDF identifier: {kdf_id!r}")
    if len(salt) != SALT_LENGTH:
        raise ValueError(f"salt must be {SALT_LENGTH} bytes, got {len(salt)}")
    if len(nonce) != NONCE_LENGTH:
        raise ValueError(f"nonce must be {NONCE_LENGTH} bytes, got {len(nonce)}")

    stored_iterations = 0 if kdf_id == KDF_ARGON2ID else iterations
    return b"".join(
        (
            MAGIC,
            bytes([VERSION]),
            bytes([kdf_id]),
            struct.pack(">I", stored_iterations),
            salt,
            nonce,
        )
    )


def parse_header(raw: bytes) -> Header:
    """Parse and validate a 38-byte ``.fenc`` header.

    Args:
        raw: Exactly ``HEADER_LENGTH`` bytes.

    Returns:
        A :class:`Header` with validated fields.

    Raises:
        FormatError: If the bytes are not a valid header (bad magic, version,
            length, KDF id, or non-zero Argon2id parameter field).
    """
    if len(raw) != HEADER_LENGTH:
        raise FormatError(
            f"header is {len(raw)} bytes, expected {HEADER_LENGTH}"
        )

    magic, version, kdf_id, iterations, salt, nonce = struct.unpack(
        ">4sBBI16s12s", raw
    )
    if magic != MAGIC:
        raise FormatError(f"not a file-encryptor file (bad magic {magic!r})")
    if version != VERSION:
        raise FormatError(f"unsupported format version {version}")
    if kdf_id not in (KDF_PBKDF2, KDF_ARGON2ID):
        raise FormatError(f"unsupported KDF identifier {kdf_id}")

    if kdf_id == KDF_ARGON2ID:
        # Argon2id parameters are fixed by this implementation.
        if iterations != 0:
            raise FormatError(
                f"Argon2id files must have a zero parameter field, got {iterations}"
            )

    return Header(kdf_id=kdf_id, iterations=iterations, salt=salt, nonce=nonce)


def build_name_prefix(name: str) -> bytes:
    """Encode the plaintext stream prefix for the original file name.

    The name is encoded as a 2-byte big-endian length followed by its UTF-8
    bytes. It is written through the GCM stream so it is encrypted and
    authenticated along with the file content.

    Args:
        name: The original base file name.

    Returns:
        The prefix bytes.

    Raises:
        ValueError: If the UTF-8 encoding is longer than 65535 bytes.
    """
    encoded = name.encode("utf-8")
    if len(encoded) > MAX_NAME_LENGTH:
        raise ValueError(
            f"file name is too long ({len(encoded)} bytes > {MAX_NAME_LENGTH})"
        )
    return struct.pack(">H", len(encoded)) + encoded


def parse_name_prefix(raw: bytes) -> str:
    """Decode the file-name prefix from the start of a plaintext stream.

    Args:
        raw: At least ``_NAME_LENGTH_BYTES`` bytes of the plaintext stream.

    Returns:
        The original file name.

    Raises:
        ValueError: If the encoded length exceeds the available bytes.
    """
    if len(raw) < _NAME_LENGTH_BYTES:
        raise ValueError("plaintext stream too short to contain a file name")
    (length,) = struct.unpack(">H", raw[:_NAME_LENGTH_BYTES])
    body = raw[_NAME_LENGTH_BYTES:]
    if len(body) < length:
        raise ValueError(
            f"truncated file name: header says {length} bytes, only {len(body)} available"
        )
    return body[:length].decode("utf-8")