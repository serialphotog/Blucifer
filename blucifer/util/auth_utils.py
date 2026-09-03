"""Password hashing helpers for Blucifer."""

import base64
import hashlib

import bcrypt


def _prehash(password: str) -> bytes:
    """
    Reduces a password to a fixed 44-byte token before bcrypt.

    bcrypt silently truncates its input at 72 bytes (and at the first NUL byte),
    so a long password would quietly lose entropy. Hashing to SHA-256 first and
    base64-encoding the digest yields an ASCII, NUL-free value well under 72
    bytes, so the full password always contributes.
    """
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.b64encode(digest)


def hash_password(password: str) -> str:
    """
    Hashes a password with SHA-256 pre-hashing + bcrypt.

    :param password: The password to hash.

    :returns: The bcrypt hash, including the salt and cost parameters.
    """
    return bcrypt.hashpw(_prehash(password), bcrypt.gensalt()).decode("ascii")


def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verifies that a password matches the stored hash.

    The comparison is performed in constant time by bcrypt.

    :param password: The password to verify.
    :param stored_hash: The bcrypt hash to verify against.

    :returns: True if the password matches, else False.
    """
    if not stored_hash:
        # Invalid
        return False

    try:
        return bcrypt.checkpw(_prehash(password), stored_hash.encode("ascii"))
    except ValueError:
        # Malformed hash
        return False
