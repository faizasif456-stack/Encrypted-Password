import pytest

from vaultkeep import crypto
from vaultkeep.service import Vaultkeep
from vaultkeep.store import Store

FAST_KDF = crypto.KdfParams(time_cost=1, memory_cost=8 * 1024, parallelism=1)
PASSWORD = "correct horse battery"


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch):
    monkeypatch.setattr(crypto, "DEFAULT_KDF", FAST_KDF)


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "vault.db")
    yield s
    s.close()


@pytest.fixture
def app(store):
    return Vaultkeep(store)


@pytest.fixture
def users(app):
    sessions = {}
    for name in ("faiz", "ali", "sara"):
        app.register(name, PASSWORD)
        sessions[name] = app.login(name, PASSWORD)
    return sessions
