from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

# Initialize the hasher with defaults
ph = PasswordHasher()


def hash_password(password: str) -> str:
    """Creates a secure Argon2id hash with an automatic salt."""
    return ph.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies the password against the stored hash."""
    try:
        return ph.verify(hashed_password, plain_password)
    except VerifyMismatchError:
        return False
    except InvalidHashError:
        return False


def needs_rehash(hashed_password: str) -> bool:
    """Check if a hash needs to be upgraded."""
    return ph.check_needs_rehash(hashed_password)
