# Security design

This document explains how Vaultkeep protects data, why each primitive was chosen, and what it does not protect against.

## Threat model

**In scope**

- Someone obtains a copy of the database file (stolen laptop, leaked backup).
- Someone with write access to the database tries to modify, swap or replay entries.
- A vault member is removed and should lose access to the vault's current contents.
- A user with a lower role tries to perform actions reserved for a higher role.

**Out of scope**

- Malware running as the user while the vault is unlocked (keyloggers, memory scraping).
- A weak master password. Argon2id slows guessing down, it cannot make `password123` safe.
- A malicious member who already decrypted and copied data before being revoked.

## Key hierarchy

```
master password
   │
   ├── Argon2id(salt_a) ──────────────► password hash  (stored, used to verify login)
   │
   └── Argon2id(salt_b) ──► master key (32 bytes, memory only)
                               │
                               └── AES-256-GCM ──► user's X25519 private key (stored encrypted)
                                                        │
              vault key (random 32 bytes) ◄── X25519 + HKDF + AES-GCM unwrap
                   │
                   └── AES-256-GCM ──► entries and files
```

- Each **user** has an X25519 key pair. The public key is stored in plain form; the private key is encrypted with the user's master key.
- Each **vault** has a random 256-bit key. It is never stored in the clear. For every member, the vault key is wrapped to that member's public key.
- **Wrapping** uses an ephemeral X25519 key, so each wrap is unique. The shared secret goes through HKDF-SHA256 with both public keys in the `info` field, and the resulting key encrypts the vault key with AES-256-GCM.

Because sharing works through public keys, the owner never learns another member's password and members never learn each other's.

## Primitives

| Purpose               | Choice                          | Why                                                            |
|-----------------------|---------------------------------|----------------------------------------------------------------|
| Symmetric encryption  | AES-256-GCM                     | Authenticated: confidentiality and integrity in one primitive   |
| Password hashing      | Argon2id (t=3, m=64 MiB, p=4)   | Memory-hard, winner of the Password Hashing Competition         |
| Key derivation        | Argon2id, separate salt         | Master key is independent from the stored hash                  |
| Key agreement         | X25519                          | Small keys, fast, resistant to common implementation mistakes   |
| KDF for wrapping      | HKDF-SHA256                     | Turns a DH shared secret into a uniform AES key                 |
| Randomness            | `os.urandom`, `secrets`         | OS CSPRNG                                                       |

Argon2 parameters are stored per user, so they can be raised later without breaking older accounts.

## Why AES-GCM and not DES

The earlier academic project compared AES and DES. Both are block ciphers, but DES fails on two counts.

**1. Key size.** DES uses a 56-bit key, which gives 2^56 ≈ 7.2 × 10^16 keys. The EFF's Deep Crack machine searched that space in 56 hours in 1998. Modern GPUs and cloud hardware do it in hours for very little money. AES-256 has 2^256 keys, far beyond any brute-force attack.

**2. Block size.** DES has a 64-bit block. After about 2^32 blocks (32 GB) under one key, collisions become likely and leak plaintext relationships. This is the Sweet32 attack on 3DES. AES uses 128-bit blocks.

**The mode matters as much as the cipher.** A typical classroom implementation uses ECB mode, which encrypts each block separately:

- Identical plaintext blocks produce identical ciphertext blocks, so patterns show through. This is the well-known "ECB penguin".
- There is no integrity check, so an attacker can reorder, replay or splice blocks and the result still decrypts.

GCM fixes both problems. It is a counter mode, so each block is different even when the plaintext repeats, and it adds a 128-bit authentication tag. Any modified bit, or any change to the associated data, makes decryption fail.

Run `python examples/ecb_vs_gcm.py` to see each of these problems demonstrated.

## Associated data binding

Every ciphertext is bound to its context through GCM's additional authenticated data:

| Ciphertext          | AAD                                                   |
|---------------------|-------------------------------------------------------|
| User private key    | `vaultkeep:user:<username>`                           |
| Wrapped vault key   | `vaultkeep:member:<vault_id>:<user_id>:<version>`     |
| Entry or file       | `vaultkeep:entry:<vault_id>:<entry_id>:<kind>:<version>` |

So an attacker with database write access cannot:

- copy an entry from one vault into another,
- swap the payloads of two entries,
- give one user another user's wrapped key,
- put back an entry encrypted under a retired key version.

Each of these fails authentication and is reported by `vaultkeep verify`. The test suite covers each one.

## Nonces

Every encryption uses a fresh random 96-bit nonce. With random nonces, NIST recommends no more than 2^32 encryptions per key. Rotating the key resets that count, and a personal vault will never get close to the limit.

## Access control and revocation

Roles are checked before any operation. Users who are not members get the same "not found" error whether or not the vault exists, so vault names cannot be discovered by probing.

When a member is revoked, Vaultkeep:

1. deletes their membership row and wrapped key,
2. generates a new vault key,
3. decrypts and re-encrypts every entry under the new key and a new version number,
4. wraps the new key for each remaining member.

All of this happens in a single database transaction. If anything fails, nothing changes.

**Limitation:** `viewer` and `editor` both hold the vault key, so the difference between them is enforced by the application, not by cryptography. A viewer who edits the SQLite file directly could write an entry that decrypts correctly. Enforcing write permissions cryptographically would require signed entries, for example Ed25519 signatures from editors that are checked on read. This is listed as future work.

## Login

- Passwords are checked with Argon2id in constant time.
- If the username does not exist, the password is still hashed against a dummy value, so response time does not reveal whether an account exists.
- Every login failure returns the same message.

## Audit log

Each audit record stores `sha256(prev_hash, vault_id, user, action, target, timestamp)`, which links the records into a chain. If any record is edited or deleted, verification fails from that point on.

**Limitation:** the chain proves the log is internally consistent. Someone with write access could rebuild the whole chain from scratch. To prevent that, the head hash would need to be anchored somewhere outside the database, or the records would need to be signed.

## Data at rest

| Stored in plain form            | Stored encrypted                       |
|---------------------------------|----------------------------------------|
| Usernames, vault names          | Passwords, usernames, URLs and notes inside entries |
| Entry names and file names      | File contents                          |
| Timestamps, roles, sizes        | Private keys, vault keys               |
| Audit log                       |                                        |

Entry names are kept in plain form so they can be looked up and listed without decrypting everything. Someone who steals the database can see that an entry called `github` exists, but cannot read its contents. The database file is created with `0600` permissions.

## Future work

- Signed entries, so editor and viewer permissions are enforced by cryptography
- Encrypted entry names
- Clipboard copy with auto-clear
- Hardware key (FIDO2) as a second factor for unlocking
- Zeroizing key material in memory, which pure Python cannot guarantee
