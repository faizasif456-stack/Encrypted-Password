import pytest
from click.testing import CliRunner

from vaultkeep.cli import cli

from .conftest import PASSWORD


@pytest.fixture
def run(tmp_path, monkeypatch):
    runner = CliRunner()
    monkeypatch.setenv("VAULTKEEP_DB", str(tmp_path / "vault.db"))
    monkeypatch.chdir(tmp_path)

    def invoke(*args, user=None, input=None):
        env = {"VAULTKEEP_PASSWORD": PASSWORD}
        if user:
            env["VAULTKEEP_USER"] = user
        return runner.invoke(cli, list(args), env=env, input=input)

    for name in ("faiz", "ali"):
        result = runner.invoke(cli, ["register", name], env={"VAULTKEEP_NEW_PASSWORD": PASSWORD})
        assert result.exit_code == 0, result.output
    return invoke


def test_full_flow(run, tmp_path):
    assert run("vault", "create", "work", user="faiz").exit_code == 0

    result = run("add", "work", "github", "--username", "faiz", "-g", user="faiz")
    assert "generated 20-character password" in result.output

    result = run("get", "work", "github", user="faiz")
    assert "username: faiz" in result.output
    assert "************" in result.output

    password = run("get", "work", "github", "--field", "password", user="faiz").output.strip()
    assert len(password) == 20

    (tmp_path / "id.txt").write_text("passport scan")
    assert run("file", "put", "work", "id.txt", user="faiz").exit_code == 0
    result = run("file", "get", "work", "id.txt", "-o", "out.txt", user="faiz")
    assert result.exit_code == 0
    assert (tmp_path / "out.txt").read_text() == "passport scan"

    result = run("list", "work", user="faiz")
    assert "github" in result.output and "id.txt" in result.output

    assert run("share", "work", "ali", user="faiz").exit_code == 0
    result = run("add", "work", "aws", "-g", user="ali")
    assert result.exit_code == 1
    assert "needs the editor role" in result.output

    result = run("revoke", "work", "ali", user="faiz")
    assert "rotated" in result.output
    assert "not found" in run("list", "work", user="ali").output

    result = run("audit", "work", user="faiz")
    assert "Audit chain intact" in result.output
    assert "revoke" in result.output

    assert "2 entries passed" in run("verify", "work", user="faiz").output


def test_manual_password_prompt(run):
    run("vault", "create", "home", user="faiz")
    result = run("add", "home", "wifi", user="faiz", input="hunter2hunter2\nhunter2hunter2\n")
    assert result.exit_code == 0, result.output
    assert run("get", "home", "wifi", "--field", "password", user="faiz").output.strip() == "hunter2hunter2"


def test_wrong_password(run):
    result = CliRunner().invoke(cli, ["vault", "list"], env={"VAULTKEEP_USER": "faiz", "VAULTKEEP_PASSWORD": "nope nope nope"})
    assert result.exit_code == 1
    assert "invalid username or password" in result.output


def test_missing_user(run):
    result = run("vault", "list")
    assert result.exit_code == 2
    assert "no user given" in result.output


def test_generate():
    result = CliRunner().invoke(cli, ["generate", "--length", "32"])
    assert len(result.output.strip()) == 32
