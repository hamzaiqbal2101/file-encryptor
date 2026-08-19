"""Command-line interface for the file-encryptor.

Exit codes:

- ``0`` -- success
- ``1`` -- cryptographic or passphrase failure (authentication failed, policy
  violation, or aborted prompt)
- ``2`` -- command-line usage error (argparse)
- ``3`` -- operational failure (missing file, output exists, invalid or unsafe
  container, I/O error)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .fileformat import FormatError
from .kdf import KDF_ARGON2ID, KDF_PBKDF2, PBKDF2_DEFAULT_ITERATIONS, PBKDF2_MIN_ITERATIONS
from .operations import DecryptionError, FileNameError, encrypt_file, decrypt_file, safe_basename
from .passphrase import PassphraseError, get_passphrase

PBKDF2_MAX_ITERATIONS = 100_000_000


def _positive_iteration_count(value: str) -> int:
    """Validate the ``--kdf-iterations`` argument for PBKDF2."""
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{value!r} is not an integer") from exc
    if parsed < PBKDF2_MIN_ITERATIONS:
        raise argparse.ArgumentTypeError(
            f"must be at least {PBKDF2_MIN_ITERATIONS:,} "
            f"(got {parsed:,})"
        )
    if parsed > PBKDF2_MAX_ITERATIONS:
        raise argparse.ArgumentTypeError(
            f"must be at most {PBKDF2_MAX_ITERATIONS:,} (got {parsed:,})"
        )
    return parsed


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the CLI."""
    parser = argparse.ArgumentParser(
        prog="file-encryptor",
        description=(
            "AES-256-GCM file encryption with PBKDF2/Argon2id key derivation. "
            "Encrypt or decrypt a file using a passphrase."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    encrypt_parser = subparsers.add_parser(
        "encrypt",
        help="Encrypt a file into the .fenc container format.",
        description="Encrypt a file into the .fenc container format.",
    )
    encrypt_parser.add_argument(
        "--input",
        "-i",
        required=True,
        metavar="FILE",
        help="Plaintext file to encrypt.",
    )
    encrypt_parser.add_argument(
        "--output",
        "-o",
        metavar="FILE",
        help="Destination .fenc file (default: <input>.fenc).",
    )
    encrypt_parser.add_argument(
        "--kdf",
        choices=("pbkdf2", "argon2id"),
        default="pbkdf2",
        help="Key derivation function (default: pbkdf2).",
    )
    encrypt_parser.add_argument(
        "--kdf-iterations",
        type=_positive_iteration_count,
        default=PBKDF2_DEFAULT_ITERATIONS,
        metavar="N",
        help=(
            "PBKDF2 iteration count (default: 480,000; minimum: 100,000). "
            "Ignored when --kdf argon2id is used."
        ),
    )
    encrypt_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite the output file if it already exists.",
    )

    decrypt_parser = subparsers.add_parser(
        "decrypt",
        help="Decrypt a .fenc container back to its original file.",
        description="Decrypt a .fenc container back to its original file.",
    )
    decrypt_parser.add_argument(
        "--input",
        "-i",
        required=True,
        metavar="FILE",
        help="The .fenc file to decrypt.",
    )
    decrypt_parser.add_argument(
        "--output",
        "-o",
        metavar="FILE",
        help="Destination file (default: next to input, using the restored name).",
    )
    decrypt_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite the output file if it already exists.",
    )

    return parser


def _run_encrypt(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    output_path = Path(args.output) if args.output else Path(str(input_path) + ".fenc")

    kdf_id = KDF_ARGON2ID if args.kdf == "argon2id" else KDF_PBKDF2

    if kdf_id == KDF_PBKDF2 and args.kdf_iterations < PBKDF2_DEFAULT_ITERATIONS:
        print(
            f"Warning: {args.kdf_iterations:,} iterations is below the recommended "
            f"{PBKDF2_DEFAULT_ITERATIONS:,}.",
            file=sys.stderr,
        )

    passphrase = get_passphrase(confirm=True)
    encrypt_file(
        input_path,
        output_path,
        passphrase,
        kdf_id=kdf_id,
        iterations=args.kdf_iterations,
        force=args.force,
    )
    print(f"Encrypted {input_path} -> {output_path}")
    return 0


def _run_decrypt(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    output_path = Path(args.output) if args.output else None

    # A short historical passphrase must still be able to decrypt a file.
    passphrase = get_passphrase(confirm=False, enforce_minimum=False)

    name = decrypt_file(
        input_path,
        passphrase,
        output_path=output_path,
        force=args.force,
    )
    resolved = (
        input_path.parent / safe_basename(name)
        if output_path is None
        else output_path
    )
    print(f"Decrypted {input_path} -> {resolved} (original name: {name})")
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point; returns the process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "encrypt":
            return _run_encrypt(args)
        return _run_decrypt(args)
    except (DecryptionError, PassphraseError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (OSError, FormatError, FileNameError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3