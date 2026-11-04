"""
Symmetric encryption for secrets that need to be read back in plaintext
(currently: a Proxmox API token entered via Settings -> Connections), as
opposed to agent secrets and user passwords, which are hashed one-way
elsewhere (see security.py) and never need decrypting.

Fernet (AES-128-CBC + HMAC-SHA256, authenticated) from the `cryptography`
package, not a homemade scheme. The key itself lives outside the DB it
protects -- see config.py's _resolve_secret_key -- same fundamental
requirement any encryption-at-rest design has: the key can't live next
to what it encrypts, or it isn't protecting anything.
"""
from cryptography.fernet import Fernet, InvalidToken

from .config import settings

_fernet = Fernet(settings.secret_key.encode() if isinstance(settings.secret_key, str) else settings.secret_key)


def encrypt(plaintext: str) -> str:
    if not plaintext:
        return ""
    return _fernet.encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    try:
        return _fernet.decrypt(ciphertext.encode()).decode()
    except InvalidToken as e:
        raise ValueError(
            "Could not decrypt a stored secret — KITE_SECRET_KEY has changed "
            "since it was saved. Re-enter it in Settings."
        ) from e
