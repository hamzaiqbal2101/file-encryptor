"""AES-256-GCM file encryption with PBKDF2/Argon2id key derivation."""

from .fileformat import (
    HEADER_LENGTH,
    MAGIC,
    NONCE_LENGTH,
    TAG_LENGTH,
    VERSION,
)
from .kdf import KDF_ARGON2ID, KDF_PBKDF2
from .operations import DecryptionError, decrypt_file, encrypt_file

__all__ = [
    "KDF_ARGON2ID",
    "KDF_PBKDF2",
    "MAGIC",
    "VERSION",
    "HEADER_LENGTH",
    "NONCE_LENGTH",
    "TAG_LENGTH",
    "DecryptionError",
    "encrypt_file",
    "decrypt_file",
]

__version__ = "1.0.0"