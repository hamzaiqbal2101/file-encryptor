"""Passphrase handling: prompting, confirmation, and strength assessment.

The passphrase is never logged or echoed. :func:`getpass.getpass` reads it
from the controlling terminal without echo; confirmation requires it to be
typed twice on the encrypt path to guard against typos.

Passphrase strength is assessed with a lightweight heuristic (length, charset
diversity, repeated-character and dictionary penalisation) that mirrors the
approach used in the companion ``password-strength-checker`` project. It is a
guidance heuristic only -- it is not a replacement for a password manager.
"""

from __future__ import annotations

import getpass
import sys

MIN_PASSPHRASE_LENGTH = 8

_COMMON_SEQUENCES = (
    "abcdefghijklmnopqrstuvwxyz",
    "zyxwvutsrqponmlkjihgfedcba",
    "0123456789",
    "9876543210",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "poiuytrewq",
    "lkjhgfdsa",
    "mnbvcxz",
)

_WEAK_WORDS = (
    "password",
    "passphrase",
    "letmein",
    "admin",
    "qwerty",
    "123456",
    "iloveyou",
    "welcome",
    "monkey",
    "dragon",
    "master",
    "secret",
    "sunshine",
    "princess",
    "football",
)


class PassphraseError(ValueError):
    """Raised for passphrase policy violations (too short or mismatched)."""


def assess_strength(passphrase: str) -> tuple[float, list[str]]:
    """Score a passphrase and list why it is considered weak.

    Args:
        passphrase: The passphrase to assess.

    Returns:
        A tuple of ``(score, issues)`` where ``score`` is 0.0-1.0 and
        ``issues`` describes any weaknesses found.
    """
    issues: list[str] = []
    score = 0.0
    length = len(passphrase)

    if length == 0:
        return 0.0, ["passphrase is empty"]

    # Length contributes up to 0.45.
    if length < 8:
        issues.append(f"too short ({length} characters; minimum is 8)")
    score += min(length / 20.0, 0.45)

    # Charset diversity contributes up to 0.30.
    classes = 0
    if any(c.islower() for c in passphrase):
        classes += 1
    if any(c.isupper() for c in passphrase):
        classes += 1
    if any(c.isdigit() for c in passphrase):
        classes += 1
    if any(not c.isalnum() and not c.isspace() for c in passphrase):
        classes += 1
    score += classes * 0.075
    if classes < 3:
        issues.append("only one character class used" if classes == 1 else "few character classes used")

    # Repeated characters penalise up to 0.10.
    longest_run = 1
    run = 1
    for prev, curr in zip(passphrase, passphrase[1:]):
        run = run + 1 if curr == prev else 1
        longest_run = max(longest_run, run)
    if longest_run >= 4:
        issues.append(f"repeated character run of {longest_run}")
        score -= min(0.10, (longest_run - 3) * 0.03)

    # Keyboard rows, sequences, and weak words penalise up to 0.15.
    lowered = passphrase.lower()
    penalties = 0.0
    for seq in _COMMON_SEQUENCES:
        for window_len in (3, 4, 5):
            for start in range(0, len(seq) - window_len + 1):
                if seq[start:start + window_len] in lowered:
                    penalties += 0.04
                    break
    for word in _WEAK_WORDS:
        if word in lowered:
            penalties += 0.05
            issues.append(f"contains a common weak word ({word!r})")
    score -= min(penalties, 0.15)

    return round(max(score, 0.0), 3), issues


def _read(prompt: str) -> str:
    """Read a passphrase without echo, falling back to a plain prompt."""
    try:
        return getpass.getpass(prompt)
    except (EOFError, KeyboardInterrupt):
        raise PassphraseError("passphrase input aborted")


def get_passphrase(
    confirm: bool = True,
    minimum_length: int = MIN_PASSPHRASE_LENGTH,
    enforce_minimum: bool = True,
) -> str:
    """Prompt the user for a passphrase.

    On the encrypt path (``confirm=True``) the passphrase is requested twice
    and must match; on the decrypt path it is requested once. A weak
    passphrase always produces a warning on stderr, but a short passphrase is
    only rejected when ``enforce_minimum`` is true.

    Args:
        confirm: Require the passphrase to be entered twice and match.
        minimum_length: Minimum accepted length when enforcing.
        enforce_minimum: Reject passphrases shorter than ``minimum_length``.

    Returns:
        The entered passphrase.

    Raises:
        PassphraseError: If confirmation does not match or the passphrase is
            shorter than ``minimum_length`` while enforcement is active.
    """
    while True:
        first = _read("Enter passphrase: ")
        if confirm:
            second = _read("Confirm passphrase: ")
            if first != second:
                print("Passphrases do not match. Try again.", file=sys.stderr)
                continue

        if enforce_minimum and len(first) < minimum_length:
            raise PassphraseError(
                f"passphrase must be at least {minimum_length} characters"
            )

        score, issues = assess_strength(first)
        if issues:
            detail = "; ".join(issues)
            print(
                f"Warning: weak passphrase ({detail}). Consider a longer, "
                "randomly generated one.",
                file=sys.stderr,
            )
        if score >= 0.7:
            print(f"Passphrase strength: strong ({score:.2f}).")
        elif score >= 0.4:
            print(f"Passphrase strength: medium ({score:.2f}).")
        else:
            print(f"Passphrase strength: weak ({score:.2f}).")

        return first