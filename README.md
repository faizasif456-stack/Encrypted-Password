# Vaultkeep

An encrypted password and file vault for the command line, with shared vaults and role-based access.

Built as a follow-up to an academic AES/DES project: same core ideas, but done the way you would actually ship them today — authenticated encryption, a memory-hard KDF, per-user key pairs, and key rotation when someone loses access.

## Features

- **AES-256-GCM** for every secret and file, with a fresh nonce per write
- **Argon2id** for password hashing and for deriving each user's master key
- **X25519 + HKDF** to share a vault key with other users without ever sharing passwords
- **RBAC** with `owner`, `editor` and `viewer` roles per vault
- **Key rotation** on revoke, so removed members' copies of the old key stop working on current data
- **Tamper detection**: ciphertexts are bound to their vault, entry and key version
- **Hash-chained audit log** of every read, write, share and revoke
- Secure password generator
- 40 tests covering crypto, permissions, rotation and tampering

## Install

Requires Python 3.10+.

```bash
git clone https://github.com/<your-username>/vaultkeep.git
cd vaultkeep
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
vaultkeep register faiz
export VAULTKEEP_USER=faiz

vaultkeep vault create work
vaultkeep add work github --username faiz --url https://github.com --generate
vaultkeep get work github --show
vaultkeep get work github --field password

vaultkeep file put work ./contract.pdf
vaultkeep file get work contract.pdf -o ~/Desktop/contract.pdf

vaultkeep list work
vaultkeep vault list
```

### Sharing

```bash
vaultkeep register ali
vaultkeep share work ali --role viewer
vaultkeep role work ali editor
vaultkeep vault members work
vaultkeep revoke work ali
```

| Action                         | viewer | editor | owner |
|--------------------------------|:------:|:------:|:-----:|
| Read secrets and files         |   ✓    |   ✓    |   ✓   |
| List entries, members, verify  |   ✓    |   ✓    |   ✓   |
| Add, update, remove entries    |        |   ✓    |   ✓   |
| Share, change roles, revoke    |        |        |   ✓   |
| Rotate key, view audit, delete |        |        |   ✓   |

### Integrity and audit

```bash
vaultkeep verify work
vaultkeep audit work
vaultkeep rotate work
```

```
2026-10-28 18:36  faiz             create
2026-10-28 18:36  faiz             add           secret:github
2026-10-28 18:36  faiz             read          secret:github
2026-10-28 18:36  faiz             share         ali:viewer
2026-10-28 18:36  faiz             revoke        ali
2026-10-28 18:36  faiz             rotate        v2

Audit chain intact (6 records).
```

### Configuration

| Variable                | Purpose                                         |
|-------------------------|-------------------------------------------------|
| `VAULTKEEP_USER`        | Account to act as (same as `--user`)            |
| `VAULTKEEP_DB`          | Database path, default `~/.vaultkeep/vault.db`  |
| `VAULTKEEP_PASSWORD`    | Master password, for scripting only             |

Putting a master password in an environment variable exposes it to anything that can read your process environment. Use the interactive prompt for real use.

## Why not DES?

```bash
python examples/ecb_vs_gcm.py
```

The demo shows DES's 56-bit keyspace, how ECB mode leaks repeated blocks, how ECB ciphertext can be cut and pasted without detection, and how GCM rejects both. See [SECURITY.md](SECURITY.md) for the full design.

## Tests

```bash
pytest
```

## Project layout

```
src/vaultkeep/
  crypto.py     AES-GCM, Argon2id, X25519 key wrapping
  service.py    accounts, vaults, RBAC, rotation, audit chain
  store.py      SQLite schema and queries
  cli.py        command-line interface
  passwords.py  password generator
tests/          pytest suite
examples/       ECB vs GCM demonstration
```

## License

MIT
