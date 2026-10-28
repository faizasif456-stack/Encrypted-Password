import pytest

from vaultkeep import crypto
from vaultkeep.errors import IntegrityError
from vaultkeep.passwords import SYMBOLS, generate

from .conftest import FAST_KDF


def test_encrypt_round_trip():
    key = crypto.new_key()
    blob = crypto.encrypt(key, b"hello", b"aad")
    assert crypto.decrypt(key, blob, b"aad") == b"hello"


def test_same_plaintext_gives_different_ciphertext():
    key = crypto.new_key()
    assert crypto.encrypt(key, b"same", b"") != crypto.encrypt(key, b"same", b"")


@pytest.mark.parametrize("position", [0, 12, -1])
def test_tampering_is_detected(position):
    key = crypto.new_key()
    blob = bytearray(crypto.encrypt(key, b"top secret", b"aad"))
    blob[position] ^= 1
    with pytest.raises(IntegrityError):
        crypto.decrypt(key, bytes(blob), b"aad")


def test_wrong_aad_is_rejected():
    key = crypto.new_key()
    blob = crypto.encrypt(key, b"data", b"vault-a")
    with pytest.raises(IntegrityError):
        crypto.decrypt(key, blob, b"vault-b")


def test_wrong_key_is_rejected():
    blob = crypto.encrypt(crypto.new_key(), b"data", b"")
    with pytest.raises(IntegrityError):
        crypto.decrypt(crypto.new_key(), blob, b"")


def test_truncated_ciphertext():
    with pytest.raises(IntegrityError):
        crypto.decrypt(crypto.new_key(), b"short", b"")


def test_derive_key_is_deterministic_per_salt():
    salt = crypto.random_bytes(crypto.SALT_SIZE)
    a = crypto.derive_key("password", salt, FAST_KDF)
    assert a == crypto.derive_key("password", salt, FAST_KDF)
    assert a != crypto.derive_key("password", crypto.random_bytes(crypto.SALT_SIZE), FAST_KDF)
    assert len(a) == crypto.KEY_SIZE


def test_password_hash_is_salted():
    hasher = crypto.password_hasher(FAST_KDF)
    first, second = hasher.hash("password"), hasher.hash("password")
    assert first != second
    assert first.startswith("$argon2id$")
    assert crypto.verify_password(first, "password")
    assert not crypto.verify_password(first, "Password")


def test_key_wrapping():
    private, public = crypto.generate_keypair()
    key = crypto.new_key()
    wrapped = crypto.wrap_key(public, key, b"member")
    assert crypto.unwrap_key(private, wrapped, b"member") == key

    other_private, _ = crypto.generate_keypair()
    with pytest.raises(IntegrityError):
        crypto.unwrap_key(other_private, wrapped, b"member")
    with pytest.raises(IntegrityError):
        crypto.unwrap_key(private, wrapped, b"someone-else")


def test_generated_passwords():
    for _ in range(50):
        pw = generate(16)
        assert len(pw) == 16
        assert any(c.islower() for c in pw)
        assert any(c.isupper() for c in pw)
        assert any(c.isdigit() for c in pw)
        assert any(c in SYMBOLS for c in pw)
    assert not any(c in SYMBOLS for c in generate(30, symbols=False))
    with pytest.raises(ValueError):
        generate(4)
