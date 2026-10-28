import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BLOCK = 16


def ecb_encrypt(key, data):
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def ecb_decrypt(key, data):
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return decryptor.update(data) + decryptor.finalize()


def blocks(data):
    return [data[i:i + BLOCK] for i in range(0, len(data), BLOCK)]


def section(title):
    print(f"\n=== {title} ===")


def des_keyspace():
    section("1. DES key size")
    keys = 2 ** 56
    rate = 10 ** 12
    print(f"DES has 2^56 = {keys:,} possible keys.")
    print(f"At 10^12 guesses/sec that is about {keys / rate / 3600:.0f} hours to try them all.")
    print(f"AES-256 has 2^256 keys, roughly 10^{len(str(2 ** 256)) - 1}. Brute force is not an option.")


def ecb_leaks_patterns():
    section("2. ECB leaks structure")
    key = os.urandom(32)
    message = b"salary=50000PKR;" * 3 + b"salary=90000PKR;"
    ciphertext = ecb_encrypt(key, message)
    for i, block in enumerate(blocks(ciphertext)):
        print(f"block {i}: {block.hex()}")
    print(f"{len(set(blocks(ciphertext)))} unique blocks out of {len(blocks(ciphertext))}.")
    print("Identical plaintext blocks give identical ciphertext blocks, so an observer")
    print("learns which records match without ever touching the key.")

    nonce = os.urandom(12)
    gcm = AESGCM(key).encrypt(nonce, message, None)
    print(f"GCM output for the same message: {len(set(blocks(gcm[:len(message)])))} unique blocks "
          f"out of {len(message) // BLOCK}.")


def ecb_allows_tampering():
    section("3. ECB has no integrity")
    key = os.urandom(32)
    message = b"to:faiz.........amount:00000100" + b"."
    forged_source = b"to:mallory......amount:99999999" + b"."
    ciphertext = ecb_encrypt(key, message)
    attacker_block = ecb_encrypt(key, forged_source)[BLOCK:]
    forged = ciphertext[:BLOCK] + attacker_block
    print(f"original : {ecb_decrypt(key, ciphertext)}")
    print(f"forged   : {ecb_decrypt(key, forged)}")
    print("The block was swapped and decryption raised no error at all.")


def gcm_detects_tampering():
    section("4. GCM authenticates everything")
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    aad = b"vault:work/entry:github"
    sealed = bytearray(AESGCM(key).encrypt(nonce, b"to:faiz amount:100", aad))
    sealed[3] ^= 0x01
    try:
        AESGCM(key).decrypt(nonce, bytes(sealed), aad)
    except InvalidTag:
        print("Flipped one bit: rejected with InvalidTag.")
    original = AESGCM(key).encrypt(nonce, b"to:faiz amount:100", aad)
    try:
        AESGCM(key).decrypt(nonce, original, b"vault:work/entry:aws")
    except InvalidTag:
        print("Moved ciphertext to a different entry: rejected with InvalidTag.")


if __name__ == "__main__":
    des_keyspace()
    ecb_leaks_patterns()
    ecb_allows_tampering()
    gcm_detects_tampering()
