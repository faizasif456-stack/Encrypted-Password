import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from . import crypto
from .errors import AuthError, IntegrityError, NotFound, PermissionDenied, VaultError
from .store import now

ROLES = {"viewer": 1, "editor": 2, "owner": 3}
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,31}$")
MIN_PASSWORD_LENGTH = 12
MAX_FILE_SIZE = 50 * 1024 * 1024
GENESIS = "0" * 64


@dataclass
class Session:
    user_id: int
    username: str
    public_key: bytes
    private_key: bytes = field(repr=False)


@dataclass
class Access:
    vault_id: str
    name: str
    version: int
    role: str
    key: bytes = field(repr=False)


def _user_aad(username):
    return f"vaultkeep:user:{username}".encode()


def _member_aad(vault_id, user_id, version):
    return f"vaultkeep:member:{vault_id}:{user_id}:{version}".encode()


def _entry_aad(vault_id, entry_id, kind, version):
    return f"vaultkeep:entry:{vault_id}:{entry_id}:{kind}:{version}".encode()


def _chain_hash(prev_hash, vault_id, username, action, target, at):
    payload = json.dumps([prev_hash, vault_id, username, action, target, at], separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def _check_name(value, what):
    value = value.strip().lower()
    if not NAME_RE.match(value):
        raise VaultError(f"{what} must be 3-32 characters of a-z, 0-9, '.', '_' or '-'")
    return value


def _check_password(password):
    if len(password) < MIN_PASSWORD_LENGTH:
        raise VaultError(f"master password must be at least {MIN_PASSWORD_LENGTH} characters")


def _check_role(role):
    if role not in ROLES:
        raise VaultError(f"unknown role '{role}', expected one of: {', '.join(ROLES)}")


class Vaultkeep:
    def __init__(self, store, kdf_params=None):
        self.store = store
        self.kdf_params = kdf_params or crypto.DEFAULT_KDF
        self._hasher = crypto.password_hasher(self.kdf_params)
        self._dummy_hash = None

    def register(self, username, password):
        username = _check_name(username, "username")
        _check_password(password)
        if self.store.get_user(username):
            raise VaultError(f"user '{username}' already exists")
        salt = crypto.random_bytes(crypto.SALT_SIZE)
        master_key = crypto.derive_key(password, salt, self.kdf_params)
        private_key, public_key = crypto.generate_keypair()
        with self.store.transaction():
            self.store.add_user(
                username,
                self._hasher.hash(password),
                salt,
                self.kdf_params.to_json(),
                public_key,
                crypto.encrypt(master_key, private_key, _user_aad(username)),
            )
        return username

    def login(self, username, password):
        username = username.strip().lower()
        user = self.store.get_user(username)
        if user is None:
            if self._dummy_hash is None:
                self._dummy_hash = self._hasher.hash(crypto.random_bytes(16).hex())
            crypto.verify_password(self._dummy_hash, password)
            raise AuthError("invalid username or password")
        if not crypto.verify_password(user["password_hash"], password):
            raise AuthError("invalid username or password")
        params = crypto.KdfParams.from_json(user["kdf_params"])
        master_key = crypto.derive_key(password, user["kdf_salt"], params)
        try:
            private_key = crypto.decrypt(master_key, user["private_key"], _user_aad(username))
        except IntegrityError:
            raise AuthError("account key could not be decrypted") from None
        return Session(user["id"], username, user["public_key"], private_key)

    def change_password(self, session, old_password, new_password):
        self.login(session.username, old_password)
        _check_password(new_password)
        salt = crypto.random_bytes(crypto.SALT_SIZE)
        master_key = crypto.derive_key(new_password, salt, self.kdf_params)
        with self.store.transaction():
            self.store.update_credentials(
                session.user_id,
                self._hasher.hash(new_password),
                salt,
                self.kdf_params.to_json(),
                crypto.encrypt(master_key, session.private_key, _user_aad(session.username)),
            )

    def _access(self, session, vault_name, needed):
        vault = self.store.get_vault(vault_name.strip().lower())
        member = vault and self.store.get_member(vault["id"], session.user_id)
        if not member:
            raise NotFound(f"vault '{vault_name}' not found")
        if ROLES[member["role"]] < ROLES[needed]:
            raise PermissionDenied(
                f"this needs the {needed} role on '{vault['name']}', you are {member['role']}"
            )
        key = crypto.unwrap_key(
            session.private_key,
            member["wrapped_key"],
            _member_aad(vault["id"], session.user_id, vault["key_version"]),
        )
        return Access(vault["id"], vault["name"], vault["key_version"], member["role"], key)

    def _audit(self, access, session, action, target=""):
        at = now()
        prev_hash = self.store.last_audit_hash(access.vault_id) or GENESIS
        digest = _chain_hash(prev_hash, access.vault_id, session.username, action, target, at)
        self.store.append_audit(access.vault_id, session.username, action, target, at, prev_hash, digest)

    def _seal(self, access, entry_id, kind, data):
        return crypto.encrypt(access.key, data, _entry_aad(access.vault_id, entry_id, kind, access.version))

    def _open(self, access, entry):
        return crypto.decrypt(
            access.key,
            entry["payload"],
            _entry_aad(access.vault_id, entry["id"], entry["kind"], access.version),
        )

    def _entry(self, access, kind, name):
        entry = self.store.get_entry(access.vault_id, kind, name)
        if entry is None:
            raise NotFound(f"no {kind} named '{name}' in '{access.name}'")
        return entry

    def _target_user(self, username):
        user = self.store.get_user(username.strip().lower())
        if user is None:
            raise NotFound(f"user '{username}' not found")
        return user

    def create_vault(self, session, name):
        name = _check_name(name, "vault name")
        if self.store.get_vault(name):
            raise VaultError(f"vault '{name}' already exists")
        vault_id = uuid.uuid4().hex
        key = crypto.new_key()
        with self.store.transaction():
            self.store.create_vault(vault_id, name)
            self.store.add_member(
                vault_id,
                session.user_id,
                "owner",
                crypto.wrap_key(session.public_key, key, _member_aad(vault_id, session.user_id, 1)),
            )
            self._audit(Access(vault_id, name, 1, "owner", key), session, "create")
        return name

    def delete_vault(self, session, vault):
        access = self._access(session, vault, "owner")
        with self.store.transaction():
            self._audit(access, session, "delete-vault")
            self.store.delete_vault(access.vault_id)

    def vaults(self, session):
        return self.store.user_vaults(session.user_id)

    def members(self, session, vault):
        access = self._access(session, vault, "viewer")
        return [(m["username"], m["role"]) for m in self.store.members(access.vault_id)]

    def _put(self, session, vault, kind, name, data, overwrite):
        access = self._access(session, vault, "editor")
        with self.store.transaction():
            existing = self.store.get_entry(access.vault_id, kind, name)
            if existing:
                if not overwrite:
                    raise VaultError(f"{kind} '{name}' already exists in '{access.name}'")
                self.store.update_entry(
                    existing["id"], self._seal(access, existing["id"], kind, data), session.user_id
                )
                self._audit(access, session, "update", f"{kind}:{name}")
            else:
                entry_id = uuid.uuid4().hex
                self.store.add_entry(
                    entry_id, access.vault_id, name, kind, self._seal(access, entry_id, kind, data), session.user_id
                )
                self._audit(access, session, "add", f"{kind}:{name}")

    def add_secret(self, session, vault, name, password, username="", url="", notes="", overwrite=False):
        name = name.strip()
        if not name:
            raise VaultError("entry name cannot be empty")
        data = json.dumps({"username": username, "password": password, "url": url, "notes": notes})
        self._put(session, vault, "secret", name, data.encode(), overwrite)

    def get_secret(self, session, vault, name):
        access = self._access(session, vault, "viewer")
        entry = self._entry(access, "secret", name)
        secret = json.loads(self._open(access, entry))
        with self.store.transaction():
            self._audit(access, session, "read", f"secret:{name}")
        return secret

    def put_file(self, session, vault, path, name=None, overwrite=False):
        path = Path(path)
        if not path.is_file():
            raise NotFound(f"file '{path}' not found")
        if path.stat().st_size > MAX_FILE_SIZE:
            raise VaultError(f"file is larger than {MAX_FILE_SIZE // (1024 * 1024)} MB")
        name = name or path.name
        self._put(session, vault, "file", name, path.read_bytes(), overwrite)
        return name

    def get_file(self, session, vault, name):
        access = self._access(session, vault, "viewer")
        data = self._open(access, self._entry(access, "file", name))
        with self.store.transaction():
            self._audit(access, session, "read", f"file:{name}")
        return data

    def entries(self, session, vault):
        access = self._access(session, vault, "viewer")
        return self.store.entries(access.vault_id)

    def remove(self, session, vault, name, kind="secret"):
        access = self._access(session, vault, "editor")
        entry = self._entry(access, kind, name)
        with self.store.transaction():
            self.store.delete_entry(entry["id"])
            self._audit(access, session, "remove", f"{kind}:{name}")

    def share(self, session, vault, username, role="viewer"):
        _check_role(role)
        access = self._access(session, vault, "owner")
        user = self._target_user(username)
        if self.store.get_member(access.vault_id, user["id"]):
            raise VaultError(f"'{user['username']}' is already a member of '{access.name}'")
        wrapped = crypto.wrap_key(user["public_key"], access.key, _member_aad(access.vault_id, user["id"], access.version))
        with self.store.transaction():
            self.store.add_member(access.vault_id, user["id"], role, wrapped)
            self._audit(access, session, "share", f"{user['username']}:{role}")

    def _owners(self, vault_id):
        return [m for m in self.store.members(vault_id) if m["role"] == "owner"]

    def set_role(self, session, vault, username, role):
        _check_role(role)
        access = self._access(session, vault, "owner")
        user = self._target_user(username)
        member = self.store.get_member(access.vault_id, user["id"])
        if member is None:
            raise NotFound(f"'{user['username']}' is not a member of '{access.name}'")
        if member["role"] == "owner" and role != "owner" and len(self._owners(access.vault_id)) == 1:
            raise VaultError("a vault needs at least one owner")
        with self.store.transaction():
            self.store.set_role(access.vault_id, user["id"], role)
            self._audit(access, session, "role", f"{user['username']}:{member['role']}->{role}")

    def revoke(self, session, vault, username):
        access = self._access(session, vault, "owner")
        user = self._target_user(username)
        member = self.store.get_member(access.vault_id, user["id"])
        if member is None:
            raise NotFound(f"'{user['username']}' is not a member of '{access.name}'")
        if member["role"] == "owner" and len(self._owners(access.vault_id)) == 1:
            raise VaultError("cannot remove the last owner of a vault")
        with self.store.transaction():
            self.store.remove_member(access.vault_id, user["id"])
            self._audit(access, session, "revoke", user["username"])
            version = self._rotate(access)
            self._audit(access, session, "rotate", f"v{version}")

    def rotate(self, session, vault):
        access = self._access(session, vault, "owner")
        with self.store.transaction():
            version = self._rotate(access)
            self._audit(access, session, "rotate", f"v{version}")
        return version

    def _rotate(self, access):
        new_key = crypto.new_key()
        version = access.version + 1
        for entry in self.store.entries(access.vault_id):
            data = self._open(access, entry)
            payload = crypto.encrypt(new_key, data, _entry_aad(access.vault_id, entry["id"], entry["kind"], version))
            self.store.rekey_entry(entry["id"], payload)
        for member in self.store.members(access.vault_id):
            wrapped = crypto.wrap_key(member["public_key"], new_key, _member_aad(access.vault_id, member["user_id"], version))
            self.store.set_wrapped_key(access.vault_id, member["user_id"], wrapped)
        self.store.set_key_version(access.vault_id, version)
        return version

    def verify(self, session, vault):
        access = self._access(session, vault, "viewer")
        ok, broken = 0, []
        for entry in self.store.entries(access.vault_id):
            try:
                self._open(access, entry)
                ok += 1
            except IntegrityError:
                broken.append(f"{entry['kind']}:{entry['name']}")
        return ok, broken

    def audit_log(self, session, vault):
        access = self._access(session, vault, "owner")
        rows = self.store.audit_rows(access.vault_id)
        return rows, verify_chain(rows)


def verify_chain(rows):
    prev_hash = GENESIS
    for row in rows:
        expected = _chain_hash(prev_hash, row["vault_id"], row["username"], row["action"], row["target"], row["at"])
        if row["prev_hash"] != prev_hash or row["hash"] != expected:
            return row["id"]
        prev_hash = row["hash"]
    return None
