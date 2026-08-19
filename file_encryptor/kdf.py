"""Key derivation functions (KDFs) for the file-encryptor.

Two KDFs are supported, both selected by a one-byte identifier that is
persisted in the encrypted file header so that decryption always uses the
exact same derivation settings as encryption:

- ``KDF_PBKDF2`` (1): PBKDF2-HMAC-SHA256, the most portable option. The
  iteration count is stored in the header and defaults to 480,000 (the OWASP
  2023 recommendation for PBKDF2-HMAC-SHA256).
- ``KDF_ARGON2ID`` (2): Argon2id (RFC 9106), the current password-hashing
  competition winner, exposed via the ``argon2-cffi`` package. Parameters
  follow the RFC 9106 / PHC reference settings (64 MiB memory, time cost 3).

Keys are always 32 bytes (256 bits) because the underlying cipher is AES-256.
"""

from __future__ import annotations

from argon2 import low_level as argon2_low_level
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

KDF_PBKDF2 = 1
KDF_ARGON2ID = 2

KEY_LENGTH = 32
SALT_LENGTH = 16

PBKDF2_DEFAULT_ITERATIONS = 480_000
PBKDF2_MIN_ITERATIONS = 100_000

ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST_KIB = 64 * 1024  # 64 MiB
ARGON2_PARALLELISM = 4

ARGON2_TYPE = argon2_low_level.Type.ID


class UnsupportedKDFError(ValueError):
    """Raised when a KDF identifier is not one of the known constants."""


def derive_key(
    kdf_id: int,
    passphrase: bytes,
    salt: bytes,
    iterations: int,
) -> bytes:
    """Derive a 32-byte AES-256 key from ``passphrase``.

    Args:
        kdf_id: One of :data:`KDF_PBKDF2` or :data:`KDF_ARGON2ID`.
        passphrase: The passphrase bytes (UTF-8 encoded).
        salt: Random per-file salt (16 bytes).
        iterations: PBKDF2 iteration count; ignored for Argon2id.

    Returns:
        The 32-byte derived key.

    Raises:
        UnsupportedKDFError: If ``kdf_id`` is unknown.
    """
    if kdf_id == KDF_PBKDF2:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=salt,
            iterations=iterations,
        )
        return kdf.derive(passphrase)

    if kdf_id == KDF_ARGON2ID:
        return argon2_low_level.hash_secret_raw(
            secret=passphrase,
            salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST_KIB,
            parallelism=ARGON2_PARALLELISM,
            hash_len=KEY_LENGTH,
            type=ARGON2_TYPE,
        )

    raise UnsupportedKDFError(f"unknown KDF identifier: {kdf_id!r}")