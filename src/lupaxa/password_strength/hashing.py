"""SHA-1 identifiers for Have I Been Pwned and local banned-hash lists.

Have I Been Pwned addresses a password by the SHA-1 of its UTF-8 bytes.
A banned-hash file uses that same digest. This is a lookup key, not a
password hash stored for authentication.
"""

from __future__ import annotations

import hashlib


def hibp_sha1(password: str) -> str:
    """Return the lowercase SHA-1 hex digest used to identify a password.

    Parameters
    ----------
    password : str
        Password to identify. It is not retained.

    Returns
    -------
    str
        Lowercase 40-character SHA-1 hex digest.
    """
    encoded = password.encode("utf-8")
    # codeql[py/weak-sensitive-data-hashing]: HIBP identifies a password by SHA-1.
    return hashlib.sha1(encoded, usedforsecurity=False).hexdigest()
