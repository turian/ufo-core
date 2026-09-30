from base64 import b64decode, b64encode, urlsafe_b64decode, urlsafe_b64encode
from hashlib import sha256
from os import urandom
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

IV_BYTES = 16
KEY_BYTES = 32


def encrypt_attachment(data: bytes) -> tuple[bytes, dict[str, object]]:
    """One attachment into its encrypted form: AES-CTR under a fresh key, the file dict the
    sender carries inside the megolm payload — everything but the mxc url, which the upload
    answers with. The hash covers the ciphertext, per the Matrix attachment scheme."""
    key, iv = urandom(KEY_BYTES), urandom(IV_BYTES)
    ciphertext = _ctr(key, iv, data)
    return (
        ciphertext,
        {
            "key": {
                "kty": "oct",
                "alg": "A256CTR",
                "ext": True,
                "k": urlsafe_b64encode(key).rstrip(b"=").decode(),
            },
            "iv": b64encode(iv).decode(),
            "hashes": {"sha256": _hash(ciphertext)},
            "v": "2",
        },
    )


def decrypt_attachment(ciphertext: bytes, file: dict[str, Any]) -> bytes:
    """The inverse: the file dict a decrypted megolm payload carried. A hash mismatch raises —
    a tampered or truncated attachment never reaches a turn as bytes."""
    key = urlsafe_b64decode(f"{file['key']['k']}===")
    iv = b64decode(file["iv"])
    plaintext = _ctr(key, iv, ciphertext)
    if _hash(ciphertext) != file["hashes"]["sha256"]:
        raise ValueError("attachment hash mismatch")
    return plaintext


def _ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def _hash(data: bytes) -> str:
    return b64encode(sha256(data).digest()).rstrip(b"=").decode()
