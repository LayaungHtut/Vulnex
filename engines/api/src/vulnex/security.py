"""Password hashing and session tokens."""

import hashlib
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

# Argon2id with argon2-cffi defaults: RFC 9106 "second recommended option"
# (t=3, m=64 MiB, p=4). About 50-100 ms per hash on the founder's laptop.
_hasher = PasswordHasher()

# Verified against when the account does not exist, so a login for an unknown email costs the
# same time as one for a known email (no account enumeration by timing).
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))

PASSWORD_MIN = 12
PASSWORD_MAX = 128  # bounds hashing work per request


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(stored_hash or _DUMMY_HASH, password) and stored_hash is not None
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    return _hasher.check_needs_rehash(stored_hash)


def new_session_token() -> str:
    """256 random bits. Only its SHA-256 is stored, so a database leak yields no usable tokens."""
    return secrets.token_urlsafe(32)


def token_digest(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()
