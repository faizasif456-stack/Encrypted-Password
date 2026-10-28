import json
import os
from dataclasses import asdict, dataclass

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .errors import IntegrityError

KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16
SALT_SIZE = 16
PUBLIC_KEY_SIZE = 32
WRAP_INFO = b"vaultkeep/v1/key-wrap"


@dataclass(frozen=True)
class KdfParams:
    time_cost: int = 3
    memory_cost: int = 64 * 1024
    parallelism: int = 4

    def to_json(self):
        return json.dumps(asdict(self), sort_keys=True)

    @classmethod
    def from_json(cls, raw):
        return cls(**json.loads(raw))


DEFAULT_KDF = KdfParams()


def random_bytes(size):
    return os.urandom(size)


def new_key():
    return AESGCM.generate_key(bit_length=KEY_SIZE * 8)


def password_hasher(params):
    return PasswordHasher(
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=32,
        salt_len=SALT_SIZE,
    )


def verify_password(password_hash, password):
    try:
        return PasswordHasher().verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def derive_key(password, salt, params):
    return hash_secret_raw(
        password.encode(),
        salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=KEY_SIZE,
        type=Type.ID,
    )


def encrypt(key, plaintext, aad):
    nonce = os.urandom(NONCE_SIZE)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt(key, blob, aad):
    if len(blob) < NONCE_SIZE + TAG_SIZE:
        raise IntegrityError("ciphertext is truncated")
    try:
        return AESGCM(key).decrypt(blob[:NONCE_SIZE], blob[NONCE_SIZE:], aad)
    except InvalidTag:
        raise IntegrityError("authentication failed: data was modified or the key is wrong") from None


def _raw_public(public_key):
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def generate_keypair():
    private = X25519PrivateKey.generate()
    private_raw = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    return private_raw, _raw_public(private.public_key())


def _kek(shared, ephemeral_public, recipient_public):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=None,
        info=WRAP_INFO + ephemeral_public + recipient_public,
    )
    return hkdf.derive(shared)


def wrap_key(recipient_public, key, aad):
    ephemeral = X25519PrivateKey.generate()
    ephemeral_public = _raw_public(ephemeral.public_key())
    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(recipient_public))
    return ephemeral_public + encrypt(_kek(shared, ephemeral_public, recipient_public), key, aad)


def unwrap_key(private_key, blob, aad):
    if len(blob) < PUBLIC_KEY_SIZE + NONCE_SIZE + TAG_SIZE:
        raise IntegrityError("wrapped key is truncated")
    private = X25519PrivateKey.from_private_bytes(private_key)
    ephemeral_public, sealed = blob[:PUBLIC_KEY_SIZE], blob[PUBLIC_KEY_SIZE:]
    recipient_public = _raw_public(private.public_key())
    shared = private.exchange(X25519PublicKey.from_public_bytes(ephemeral_public))
    return decrypt(_kek(shared, ephemeral_public, recipient_public), sealed, aad)
