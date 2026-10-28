import pytest

from vaultkeep.errors import AuthError, NotFound, PermissionDenied, VaultError
from vaultkeep.service import Vaultkeep

from .conftest import PASSWORD


def test_register_and_login(app):
    app.register("Faiz", PASSWORD)
    session = app.login("faiz", PASSWORD)
    assert session.username == "faiz"


def test_password_never_stored(app, store):
    app.register("faiz", PASSWORD)
    row = store.get_user("faiz")
    dumped = b"".join(v if isinstance(v, bytes) else str(v).encode() for v in tuple(row))
    assert PASSWORD.encode() not in dumped


def test_bad_logins(app):
    app.register("faiz", PASSWORD)
    with pytest.raises(AuthError):
        app.login("faiz", "wrong password!!")
    with pytest.raises(AuthError):
        app.login("nobody", PASSWORD)


def test_registration_rules(app):
    with pytest.raises(VaultError):
        app.register("faiz", "short")
    with pytest.raises(VaultError):
        app.register("a", PASSWORD)
    app.register("faiz", PASSWORD)
    with pytest.raises(VaultError):
        app.register("faiz", PASSWORD)


def test_change_password(app, users):
    app.change_password(users["faiz"], PASSWORD, "a brand new passphrase")
    with pytest.raises(AuthError):
        app.login("faiz", PASSWORD)
    app.login("faiz", "a brand new passphrase")


def test_change_password_keeps_vault_access(app, users):
    app.create_vault(users["faiz"], "work")
    app.add_secret(users["faiz"], "work", "github", "gh-pass")
    app.change_password(users["faiz"], PASSWORD, "a brand new passphrase")
    session = app.login("faiz", "a brand new passphrase")
    assert app.get_secret(session, "work", "github")["password"] == "gh-pass"


def test_secret_round_trip(app, users):
    faiz = users["faiz"]
    app.create_vault(faiz, "work")
    app.add_secret(faiz, "work", "github", "s3cret", username="faiz", url="https://github.com")
    secret = app.get_secret(faiz, "work", "github")
    assert secret == {"username": "faiz", "password": "s3cret", "url": "https://github.com", "notes": ""}


def test_secret_is_encrypted_at_rest(app, users, store):
    app.create_vault(users["faiz"], "work")
    app.add_secret(users["faiz"], "work", "github", "very-unique-password")
    raw = store.conn.execute("SELECT payload FROM entries").fetchone()[0]
    assert b"very-unique-password" not in raw


def test_duplicate_and_overwrite(app, users):
    faiz = users["faiz"]
    app.create_vault(faiz, "work")
    app.add_secret(faiz, "work", "github", "one")
    with pytest.raises(VaultError):
        app.add_secret(faiz, "work", "github", "two")
    app.add_secret(faiz, "work", "github", "two", overwrite=True)
    assert app.get_secret(faiz, "work", "github")["password"] == "two"


def test_file_round_trip(app, users, tmp_path):
    faiz = users["faiz"]
    app.create_vault(faiz, "work")
    source = tmp_path / "contract.pdf"
    source.write_bytes(b"%PDF-1.7 fake contents" * 100)
    assert app.put_file(faiz, "work", source) == "contract.pdf"
    assert app.get_file(faiz, "work", "contract.pdf") == source.read_bytes()


def test_remove(app, users):
    faiz = users["faiz"]
    app.create_vault(faiz, "work")
    app.add_secret(faiz, "work", "github", "x")
    app.remove(faiz, "work", "github")
    with pytest.raises(NotFound):
        app.get_secret(faiz, "work", "github")


def test_non_members_cannot_see_vault(app, users):
    app.create_vault(users["faiz"], "work")
    with pytest.raises(NotFound):
        app.entries(users["ali"], "work")


def test_viewer_permissions(app, users):
    faiz, ali = users["faiz"], users["ali"]
    app.create_vault(faiz, "work")
    app.add_secret(faiz, "work", "github", "x")
    app.share(faiz, "work", "ali", "viewer")
    assert app.get_secret(ali, "work", "github")["password"] == "x"
    with pytest.raises(PermissionDenied):
        app.add_secret(ali, "work", "aws", "y")
    with pytest.raises(PermissionDenied):
        app.remove(ali, "work", "github")
    with pytest.raises(PermissionDenied):
        app.share(ali, "work", "sara")


def test_editor_permissions(app, users):
    faiz, ali = users["faiz"], users["ali"]
    app.create_vault(faiz, "work")
    app.share(faiz, "work", "ali", "editor")
    app.add_secret(ali, "work", "aws", "y")
    assert app.get_secret(faiz, "work", "aws")["password"] == "y"
    with pytest.raises(PermissionDenied):
        app.share(ali, "work", "sara")
    with pytest.raises(PermissionDenied):
        app.revoke(ali, "work", "faiz")
    with pytest.raises(PermissionDenied):
        app.audit_log(ali, "work")


def test_role_change(app, users):
    faiz, ali = users["faiz"], users["ali"]
    app.create_vault(faiz, "work")
    app.share(faiz, "work", "ali", "viewer")
    app.set_role(faiz, "work", "ali", "editor")
    app.add_secret(ali, "work", "aws", "y")


def test_last_owner_is_protected(app, users):
    faiz = users["faiz"]
    app.create_vault(faiz, "work")
    with pytest.raises(VaultError):
        app.set_role(faiz, "work", "faiz", "viewer")
    with pytest.raises(VaultError):
        app.revoke(faiz, "work", "faiz")
    app.share(faiz, "work", "ali", "owner")
    app.set_role(faiz, "work", "faiz", "viewer")


def test_revoke_rotates_key(app, users, store):
    faiz, ali = users["faiz"], users["ali"]
    app.create_vault(faiz, "work")
    app.add_secret(faiz, "work", "github", "x")
    app.share(faiz, "work", "ali", "editor")
    app.share(faiz, "work", "sara", "viewer")

    old_key = app._access(ali, "work", "viewer").key
    app.revoke(faiz, "work", "ali")

    with pytest.raises(NotFound):
        app.get_secret(ali, "work", "github")
    new_access = app._access(faiz, "work", "owner")
    assert new_access.version == 2
    assert new_access.key != old_key
    assert app.get_secret(users["sara"], "work", "github")["password"] == "x"
    assert app.verify(faiz, "work") == (1, [])


def test_rotate(app, users, tmp_path):
    faiz = users["faiz"]
    app.create_vault(faiz, "work")
    app.add_secret(faiz, "work", "github", "x")
    f = tmp_path / "notes.txt"
    f.write_text("hello")
    app.put_file(faiz, "work", f)
    assert app.rotate(faiz, "work") == 2
    assert app.get_secret(faiz, "work", "github")["password"] == "x"
    assert app.get_file(faiz, "work", "notes.txt") == b"hello"


def test_tampered_entry_detected(app, users, store):
    faiz = users["faiz"]
    app.create_vault(faiz, "work")
    app.add_secret(faiz, "work", "github", "x")
    app.add_secret(faiz, "work", "aws", "y")
    payload = bytearray(store.conn.execute("SELECT payload FROM entries WHERE name = 'aws'").fetchone()[0])
    payload[-5] ^= 0xFF
    store.conn.execute("UPDATE entries SET payload = ? WHERE name = 'aws'", (bytes(payload),))
    store.conn.commit()
    assert app.verify(faiz, "work") == (1, ["secret:aws"])


def test_swapped_entries_detected(app, users, store):
    faiz = users["faiz"]
    app.create_vault(faiz, "work")
    app.add_secret(faiz, "work", "github", "x")
    app.add_secret(faiz, "work", "aws", "y")
    rows = dict(store.conn.execute("SELECT name, payload FROM entries").fetchall())
    store.conn.execute("UPDATE entries SET payload = ? WHERE name = 'github'", (rows["aws"],))
    store.conn.commit()
    assert app.verify(faiz, "work") == (1, ["secret:github"])


def test_audit_chain(app, users, store):
    faiz = users["faiz"]
    app.create_vault(faiz, "work")
    app.add_secret(faiz, "work", "github", "x")
    app.get_secret(faiz, "work", "github")
    app.share(faiz, "work", "ali", "viewer")
    rows, broken = app.audit_log(faiz, "work")
    assert [r["action"] for r in rows] == ["create", "add", "read", "share"]
    assert broken is None

    store.conn.execute("UPDATE audit SET username = 'mallory' WHERE action = 'read'")
    store.conn.commit()
    _, broken = app.audit_log(faiz, "work")
    assert broken == rows[2]["id"]


def test_delete_vault(app, users):
    faiz = users["faiz"]
    app.create_vault(faiz, "work")
    app.delete_vault(faiz, "work")
    assert app.vaults(faiz) == []
    app.create_vault(faiz, "work")


def test_kdf_params_stored_per_user(store, users):
    from vaultkeep import crypto

    stronger = crypto.KdfParams(time_cost=2, memory_cost=16 * 1024, parallelism=1)
    Vaultkeep(store, stronger).register("newbie", PASSWORD)
    app = Vaultkeep(store)
    assert app.login("newbie", PASSWORD).username == "newbie"
