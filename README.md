# File Encryptor

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/hamzaiqbal2101/file-encryptor/actions/workflows/ci.yml/badge.svg)](https://github.com/hamzaiqbal2101/file-encryptor/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-82%20passing-brightgreen)](#development)

A production-style file encryption tool written in Python. It encrypts files with
**AES-256-GCM** authenticated encryption, derives the key from your passphrase
with **PBKDF2-HMAC-SHA256** or **Argon2id**, streams data in chunks so it can
handle files of any size, and refuses to leave partial output behind on failure.

This is the third project in a cybersecurity portfolio:

1. [Password Strength Checker](https://github.com/hamzaiqbal2101/password-strength-checker)
2. [File Integrity Checker](https://github.com/hamzaiqbal2101/file-integrity-checker)
3. **File Encryptor** (this project)

---

## Features

- **AES-256-GCM**: authenticated encryption that detects any tampering with the
  ciphertext, the header, or the authentication tag. A single flipped bit
  anywhere in the file makes decryption fail loudly.
- **Two key-derivation functions**:
  - `pbkdf2` — PBKDF2-HMAC-SHA256 with **480,000 iterations** by default
    (the OWASP 2023 recommendation), stored per-file so it can be raised later
    without breaking old files.
  - `argon2id` — Argon2id (RFC 9106, the PHC winner) via `argon2-cffi`, with the
    reference parameters (64 MiB memory, time cost 3).
- **Per-file salt and nonce**: a fresh 16-byte salt and 12-byte GCM nonce are
  generated for every encryption, so identical inputs never produce identical
  outputs.
- **Streaming I/O**: the file is processed in 64 KiB chunks; memory use stays
  flat no matter how large the file is.
- **Encrypted metadata**: the original file name travels *inside* the encrypted
  stream, so decryption restores it automatically and it is hidden from anyone
  who can see the `.fenc` file.
- **Fail-closed decryption**: output is written to a temporary file and moved
  into place with an atomic rename only after authentication succeeds. A wrong
  passphrase or tampered file leaves **no output file behind**.
- **Safe paths**: the restored file name is sanitised against path traversal
  (`../`, absolute paths, drive letters) so a hostile container cannot write
  outside the destination directory.
- **CI-ready exit codes** for scripting.

## Installation

Requires Python 3.10+.

```bash
pip install -r requirements.txt
```

To install the console script:

```bash
pip install .
```

## Usage

```bash
# Encrypt a file (you will be prompted for a passphrase twice)
file-encryptor encrypt --input notes.txt --output notes.txt.fenc

# Decrypt it (the original name is restored automatically)
file-encryptor decrypt --input notes.txt.fenc            # writes ./notes.txt

# Decrypt to a specific location
file-encryptor decrypt --input notes.txt.fenc --output restored.txt

# Use Argon2id instead of PBKDF2
file-encryptor encrypt -i notes.txt -o notes.txt.fenc --kdf argon2id

# Tune the PBKDF2 iteration count (min 100,000; below 480,000 warns)
file-encryptor encrypt -i notes.txt -o notes.txt.fenc --kdf-iterations 600000

# Overwrite an existing output file
file-encryptor decrypt -i notes.txt.fenc -o notes.txt --force
```

You can also run it as a module:

```bash
python -m file_encryptor encrypt -i notes.txt -o notes.txt.fenc
```

A sample file lives in [`sample_data/`](sample_data/notes.txt).

### Exit codes

| Code | Meaning                                                        |
|------|----------------------------------------------------------------|
| 0    | Success                                                        |
| 1    | Cryptographic or passphrase failure (authentication failed, policy violation) |
| 2    | Command-line usage error                                        |
| 3    | Operational failure (missing file, output exists, invalid container, I/O error) |

## File format

A `.fenc` file is a self-describing container. All integers are big-endian:

```
+----------------+------------+---------+----------------+------------+------------+
| magic "FENC"   | version    | kdf_id  | kdf params    | salt       | nonce      |
| 4 bytes        | 1 byte     | 1 byte  | 4 bytes       | 16 bytes   | 12 bytes   |
+----------------+------------+---------+----------------+------------+------------+
| ciphertext (any length, streamed)                                          | tag |
|                                                                           | 16B |
+----------------------------------------------------------------------------+-----+
```

- **Header (38 bytes)**: `FENC` magic, format version (1), a KDF identifier
  (`1` = PBKDF2-HMAC-SHA256, `2` = Argon2id), a 4-byte KDF parameter field
  holding the PBKDF2 iteration count (0 for Argon2id, whose parameters are
  fixed by the implementation), the 16-byte salt, and the 12-byte GCM nonce.
- **AAD**: the entire fixed header is bound to the ciphertext as GCM
  *additional authenticated data*, so changing the salt, nonce, or KDF
  parameters is detected at decryption time.
- **Ciphertext**: the plaintext stream, which begins with the encrypted file
  name (a 2-byte big-endian length followed by its UTF-8 bytes) and then the
  file contents. Because the name is inside the GCM stream it is both encrypted
  and authenticated.
- **Tag**: the 16-byte GCM authentication tag, written at the very end so
  streaming can append it after all ciphertext is processed.

The container needs no external metadata: decryption reads the header, derives
the key from your passphrase, and verifies everything with the tag.

## Design decisions

**Why `cryptography` (hazmat)?**
The [`cryptography`](https://cryptography.io/) package is the de-facto standard
for cryptographic primitives in Python. The pycrypto/pycryptodome forks are
legacy or have a poor security track record, and this tool deliberately avoids
rolling its own crypto. The `hazmat` ("hazardous materials") API is used with
care: the only primitives touched are `Cipher(AES, GCM)`, `PBKDF2HMAC`, and
`argon2-cffi`'s low-level hashing, all configured with well-understood
parameters.

**Why AES-256-GCM?**
GCM is an *authenticated encryption* mode: it produces a MAC that proves both
confidentiality **and** integrity. You cannot silently flip a byte, reorder a
chunk, or swap headers without the tag check failing. This is the key
difference from older modes like ECB and CBC:

- **ECB** encrypts each block independently, so identical plaintext blocks
  produce identical ciphertext blocks — patterns leak through, making it a
  known anti-pattern for anything larger than a single block. It is never used
  here.
- **CBC** hides patterns, but it is *unauthenticated*: an attacker can flip
  bits in the ciphertext (which predictably corrupts or alters the plaintext)
  with **no detection**, and it is vulnerable to padding-oracle attacks unless
  combined with a MAC. CBC alone provides confidentiality only.
- **GCM** is an AEAD (authenticated encryption with associated data) mode that
  combines AES-CTR encryption with a GHASH MAC in one operation, giving both
  confidentiality and integrity out of the box. The 16-byte tag produced at
  finalization is the integrity proof; verification is mandatory and cannot be
  skipped. AES-256 is the strongest standard AES variant and is
  hardware-accelerated on modern CPUs.

**Why PBKDF2 and Argon2id instead of a raw hash?**
A passphrase must never be used directly as the AES key, and it must never be
turned into a key with a single fast hash like SHA-256. Reasons:

- The passphrase itself is rarely 32 bytes of uniform entropy; AES keys must be
  random-looking 32-byte values.
- A raw hash is **fast to compute**, so an attacker who steals the `.fenc` file
  can brute-force millions of passphrase guesses per second. A deliberate,
  salted, iterated KDF multiplies the cost of each guess by the KDF work factor
  — 480,000 PBKDF2 iterations, or Argon2id's 64 MiB memory-hard computation —
  which makes offline brute-force dramatically more expensive.
- The salt (16 random bytes per file) means the same passphrase produces a
  different key for every file, so precomputed rainbow tables and cross-file
  key reuse are impossible.

PBKDF2-HMAC-SHA256 is the most portable and widely supported option, which is
why it is the default. Argon2id is the current recommended password hashing
scheme (it is memory-hard, making GPU/ASIC attacks dramatically more expensive).
Both are supported because a user who encrypts files with one tool today should
be able to decrypt them with another tool tomorrow — the KDF id and parameters
are stored in the file, so neither choice locks the data to this program.

**Why 480,000 iterations?**
This matches the OWASP Cheat Sheet recommendation for PBKDF2-HMAC-SHA256 (2023).
The iteration count is stored in the file, so you can raise it over time as
hardware improves; old files remain decryptable because they remember their own
count. The CLI enforces a floor of 100,000 to prevent accidental use of a
cryptographically weak setting and warns below the recommended value.

**Why stream in chunks?**
A naive `read()` of an entire file into memory is a denial-of-service waiting to
happen and fails on files larger than RAM. The tool reads and encrypts 64 KiB at
a time, so memory usage is constant regardless of file size.

**Why encrypt the file name?**
The file name frequently leaks information — `resume.pdf`, `salary.xlsx`,
`tax-2025.doc`. Storing it inside the GCM stream hides it from anyone with
read access to the encrypted file. It is also authenticated, so an attacker
cannot swap one file's name for another's without failing the tag check.

**Why a generic authentication error?**
On decryption failure the tool reports only *"wrong passphrase or the file was
corrupted or tampered"* and never distinguishes the two. A message like "invalid
authentication tag" would let an attacker probe passphrases and learn when they
were *almost* right — a classic padding-oracle style information leak. Failing
closed with a single message closes that channel.

**Why write-then-rename?**
Decryption writes to a temporary file in the destination directory and only
calls `os.replace` (an atomic rename) once the tag verifies. If anything fails,
the temporary file is deleted. The result: you never observe a partial, corrupt,
or attacker-controlled file appearing at the destination path.

## Threat model

**Protects against:**
- Confidentiality loss of **data at rest**: if the `.fenc` file is stolen, the
  disk is lost, or the device is seized, the contents stay unreadable without
  the passphrase — including against casual inspection and forensic recovery
  tools that scan raw disk sectors (the plaintext never touches the disk in
  clear form).
- Undetected tampering: modification of ciphertext, header, or tag.
- Brute-force passphrase guessing offline: mitigated by a strong, salted,
  deliberately slow KDF (480k PBKDF2 iterations or memory-hard Argon2id).
- Metadata leakage of the original file name.
- Path-traversal attacks from a crafted `.fenc` file writing outside the
  destination directory.
- Leftover partial/corrupt output on failed decryption.

**Does not protect against:**
- A weak or reused passphrase. A short passphrase is only a warning at
  encryption time and is never enforced at decryption time (so historical
  files stay decryptable). **Use a long, random passphrase or a password
  manager.**
- Keyloggers, screen-scrapers, or malware already running on your machine while
  you type the passphrase.
- Attacks on the host operating system or hardware (cold-boot attacks, etc.).
- Traffic analysis of *file sizes* — the ciphertext length roughly matches the
  plaintext length plus a small constant, so an observer can infer how large a
  file was.
- **Deniability.** A `.fenc` file is unambiguously identifiable as encrypted
  data, and its existence, size, modification time, and the fact that a
  passphrase exists at all are all visible to anyone with file-system access.
  This tool provides **plausible deniability only in the sense that the
  contents are unreadable without the passphrase** — it cannot hide that the
  file *is* encrypted, and it offers no steganography or hidden-volume
  mechanism.
- **Lost passphrases.** There is **no backdoor, master key, or recovery
  mechanism by design.** If the passphrase is forgotten, the data is
  unrecoverable. This is deliberate: any hidden recovery path would be an
  exploitable weakness. The only mitigation is to keep the passphrase in a
  password manager and test decryption of a small file before trusting it.

## Limitations

- **Single-file scope.** This tool encrypts and decrypts one file at a time.
  It does not encrypt directories, recursively walk trees, or batch processes.
  For whole-disk or many-folder encryption use a dedicated tool such as
  VeraCrypt, BitLocker, or LUKS.
- **Symmetric, passphrase-only.** The key is always derived from a passphrase.
  There is no support for key files, hardware tokens (YubiKey/TPM), or
  asymmetric (public/private key) encryption, so a file cannot be encrypted
  to multiple recipients.
- **Performance trade-off.** The strong KDF settings are intentionally slow
  (that is the point — they slow down attackers too), so encrypting or
  decrypting a file costs a noticeable fraction of a second up front. Large
  files stream at full speed regardless.
- **Metadata is not hidden.** The `.fenc` container reveals its presence, its
  size, and its modification time, and it is detectable as encrypted data (see
  the threat model's *deniability* point).
- **Security depends on the passphrase.** The cryptographic design is sound,
  but the tool is only as strong as the passphrase you choose. The strength
  warning is a heuristic, not a guarantee.

## Development

```bash
# Install dev dependencies
pip install -r requirements.txt

# Run the test suite
python -m pytest -q

# Lint for unused imports and other static issues
python -m pyflakes file_encryptor tests
```

The test suite covers:

- KDF correctness (including a cross-check against the standard library's
  PBKDF2) and determinism
- Header parsing and validation, including malformed input
- Streaming GCM encryption/decryption, tamper and wrong-key detection
- End-to-end round trips for empty, small, large (64 MiB), and binary files
- Fail-closed behaviour: wrong passphrase, tampered ciphertext, tampered header
- Overwrite protection and `--force`
- Path-traversal rejection for restored file names
- CLI exit codes and argument validation

## License

[MIT](LICENSE) © 2026 Hamza Iqbal