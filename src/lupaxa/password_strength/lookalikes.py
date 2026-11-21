"""Characters that look like a different letter or digit.

Cyrillic and Greek homoglyphs are listed explicitly. Other compatibility
forms, such as fullwidth letters and ligatures, come from Unicode NFKC.
Accented letters are left alone. Nothing here changes the zxcvbn score.
"""

from __future__ import annotations

import unicodedata

# Letters that stay themselves under NFKC but look like ASCII in normal fonts.
_HOMOGLYPHS = {
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "і": "i",
    "ѕ": "s",
    "ј": "j",
    "һ": "h",
    "ԛ": "q",
    "ԝ": "w",
    "ԁ": "d",
    "з": "3",
    "А": "A",
    "В": "B",
    "Е": "E",
    "К": "K",
    "М": "M",
    "Н": "H",
    "О": "O",
    "Р": "P",
    "С": "C",
    "Т": "T",
    "Х": "X",
    "І": "I",
    "З": "3",
    "ο": "o",
    "ν": "v",
    "ρ": "p",
    "Α": "A",
    "Β": "B",
    "Ε": "E",
    "Ζ": "Z",
    "Η": "H",
    "Ι": "I",
    "Κ": "K",
    "Μ": "M",
    "Ν": "N",
    "Ο": "O",
    "Ρ": "P",
    "Τ": "T",
    "Υ": "Y",
    "Χ": "X",
}


def find_lookalikes(password: str) -> list[dict[str, str]]:
    """Return distinct characters that look like a different ASCII letter or digit.

    Parameters
    ----------
    password : str
        Password to inspect. It is not retained or rewritten.

    Returns
    -------
    list of dict
        Each item has ``character`` and ``looks_like``, in first-seen order.
    """
    found: list[dict[str, str]] = []
    seen: set[str] = set()
    for character in password:
        if character in seen or character.isascii():
            continue
        seen.add(character)
        similar = _similar_ascii(character)
        if similar is not None:
            found.append({"character": character, "looks_like": similar})
    return found


def _similar_ascii(character: str) -> str | None:
    mapped = _HOMOGLYPHS.get(character)
    if mapped is not None:
        return mapped
    folded = unicodedata.normalize("NFKC", character)
    if folded != character and folded.isascii() and folded.isalnum():
        return folded
    return None
