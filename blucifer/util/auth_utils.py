"""Password hashing helpers for Blucifer."""

import bcrypt


def hash_password(password: str) -> str:
    """
    Hashes a password using bcrypt.

    :param password: The password to hash.

    :returns: The bcrypt hash, including the salt and cost parameters.
    """
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    return hashed.decode("utf-8")


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
        return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))
    except ValueError:
        # Malformed hash
        return False
