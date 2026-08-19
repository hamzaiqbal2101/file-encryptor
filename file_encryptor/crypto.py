"""Streaming AES-256-GCM encryption/decryption helpers.

These thin wrappers around the ``cryptography`` hazmat primitives make the
chunked read/write loop in :mod:`file_encryptor.operations` explicit and
testable in isolation. They follow the same "finalize once" contract as the
underlying primitives:

- :meth:`GCMEncryptor.finalize` returns the 16-byte authentication tag that
  must be appended to the ciphertext stream.
- :meth:`GCMDecryptor.finalize` raises :class:`cryptography.exceptions.InvalidTag`
  if the tag, nonce, AAD, or any ciphertext byte has been altered.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .fileformat import NONCE_LENGTH, TAG_LENGTH


class GCMEncryptor:
    """Streaming AES-256-GCM encryptor bound to a fixed nonce and AAD."""

    def __init__(self, key: bytes, nonce: bytes, aad: bytes) -> None:
        if len(nonce) != NONCE_LENGTH:
            raise ValueError(f"nonce must be {NONCE_LENGTH} bytes, got {len(nonce)}")
        self._encryptor = Cipher(
            algorithms.AES(key), modes.GCM(nonce)
        ).encryptor()
        self._encryptor.authenticate_additional_data(aad)
        self._finalized = False

    def update(self, chunk: bytes) -> bytes:
        """Encrypt ``chunk`` in place; call before :meth:`finalize`."""
        return self._encryptor.update(chunk)

    def finalize(self) -> bytes:
        """Finalize the stream and return the 16-byte authentication tag.

        Raises:
            RuntimeError: If called more than once.
        """
        if self._finalized:
            raise RuntimeError("encryptor already finalized")
        self._finalized = True
        self._encryptor.finalize()
        tag = self._encryptor.tag
        if len(tag) != TAG_LENGTH:
            raise RuntimeError(
                f"cryptography returned a {len(tag)}-byte tag; expected {TAG_LENGTH}"
            )
        return tag


class GCMDecryptor:
    """Streaming AES-256-GCM decryptor that verifies a provided tag."""

    def __init__(self, key: bytes, nonce: bytes, tag: bytes, aad: bytes) -> None:
        if len(nonce) != NONCE_LENGTH:
            raise ValueError(f"nonce must be {NONCE_LENGTH} bytes, got {len(nonce)}")
        if len(tag) != TAG_LENGTH:
            raise ValueError(f"tag must be {TAG_LENGTH} bytes, got {len(tag)}")
        self._decryptor = Cipher(
            algorithms.AES(key), modes.GCM(nonce, tag)
        ).decryptor()
        self._decryptor.authenticate_additional_data(aad)
        self._finalized = False

    def update(self, chunk: bytes) -> bytes:
        """Decrypt ``chunk`` in place; call before :meth:`finalize`."""
        return self._decryptor.update(chunk)

    def finalize(self) -> None:
        """Verify the authentication tag and finish the stream.

        Raises:
            InvalidTag: If authentication fails (wrong passphrase, tampered
                header, nonce, tag, or ciphertext).
            RuntimeError: If called more than once.
        """
        if self._finalized:
            raise RuntimeError("decryptor already finalized")
        self._finalized = True
        self._decryptor.finalize()