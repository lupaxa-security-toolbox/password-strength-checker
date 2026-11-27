"""Character classes present in a password."""

from __future__ import annotations

import string

CHARACTER_CLASSES = ("lowercase", "uppercase", "digits", "symbols", "spaces", "other_unicode")


def character_counts(password: str) -> dict[str, int]:
    """Count ASCII classes and everything else.

    Parameters
    ----------
    password : str
        Password to inspect. It is not retained.

    Returns
    -------
    dict of str to int
        Counts for lowercase, uppercase, digits, symbols, spaces, and other Unicode.
    """
    counts: dict[str, int] = {}
    for name in CHARACTER_CLASSES:
        counts[name] = 0
    for character in password:
        if character in string.ascii_lowercase:
            counts["lowercase"] += 1
        elif character in string.ascii_uppercase:
            counts["uppercase"] += 1
        elif character in string.digits:
            counts["digits"] += 1
        elif character in string.punctuation:
            counts["symbols"] += 1
        elif character.isspace():
            counts["spaces"] += 1
        else:
            counts["other_unicode"] += 1
    return counts
