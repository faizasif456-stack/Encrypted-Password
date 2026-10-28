import os
from datetime import datetime
from pathlib import Path

import click

from . import __version__, crypto
from .errors import VaultError
from .passwords import generate
from .service import ROLES, Vaultkeep
from .store import Store

DEFAULT_DB = Path.home() / ".vaultkeep" / "vault.db"


class Group(click.Group):
    def invoke(self, ctx):
        try:
            return super().invoke(ctx)
        except VaultError as e:
            raise click.ClickException(str(e)) from None


class Context:
    def __init__(self, db, user):
        self.db = db
        self.user = user
        self._app = None

    @property
    def app(self):
        if self._app is None:
            self._app = Vaultkeep(Store(self.db))
        return self._app

    def session(self):
        if not self.user:
            raise click.UsageError("no user given, pass --user or set VAULTKEEP_USER")
        password = os.environ.get("VAULTKEEP_PASSWORD") or click.prompt(
            f"Master password for {self.user}", hide_input=True
        )
        return self.app.login(self.user, password)


pass_ctx = click.make_pass_decorator(Context)


def fmt_time(ts):
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


def fmt_size(size):
    for unit in ("B", "KB", "MB"):
        if size < 1024:
            return f"{size:.0f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


def new_password(prompt):
    return os.environ.get("VAULTKEEP_NEW_PASSWORD") or click.prompt(
        prompt, hide_input=True, confirmation_prompt=True
    )


@click.group(cls=Group)
@click.option("--db", type=click.Path(path_type=Path), envvar="VAULTKEEP_DB", default=DEFAULT_DB, show_default=True)
@click.option("-u", "--user", envvar="VAULTKEEP_USER", help="Account to act as.")
@click.version_option(__version__, prog_name="vaultkeep")
@click.pass_context
def cli(ctx, db, user):
    ctx.obj = Context(db, user)


@cli.command()
@click.argument("username")
@pass_ctx
def register(c, username):
    """Create a new account."""
    name = c.app.register(username, new_password("Choose a master password"))
    click.echo(f"Account '{name}' created.")


@cli.command()
@pass_ctx
def passwd(c):
    """Change your master password."""
    session = c.session()
    old = os.environ.get("VAULTKEEP_PASSWORD") or click.prompt("Current master password", hide_input=True)
    c.app.change_password(session, old, new_password("New master password"))
    click.echo("Master password changed.")


@cli.group()
def vault():
    """Create, list and delete vaults."""


@vault.command("create")
@click.argument("name")
@pass_ctx
def vault_create(c, name):
    """Create a vault you own."""
    name = c.app.create_vault(c.session(), name)
    click.echo(f"Vault '{name}' created.")


@vault.command("list")
@pass_ctx
def vault_list(c):
    """List vaults you can access."""
    rows = c.app.vaults(c.session())
    if not rows:
        click.echo("No vaults yet. Create one with: vaultkeep vault create <name>")
        return
    for row in rows:
        click.echo(f"{row['name']:<24} {row['role']:<8} {row['entry_count']} entries")


@vault.command("members")
@click.argument("name")
@pass_ctx
def vault_members(c, name):
    """Show who has access to a vault."""
    for username, role in c.app.members(c.session(), name):
        click.echo(f"{username:<24} {role}")


@vault.command("delete")
@click.argument("name")
@click.confirmation_option(prompt="This permanently deletes the vault and everything in it. Continue?")
@pass_ctx
def vault_delete(c, name):
    """Delete a vault and all its entries."""
    c.app.delete_vault(c.session(), name)
    click.echo(f"Vault '{name}' deleted.")


@cli.command()
@click.argument("vault")
@click.argument("name")
@click.option("--username", default="", help="Login name stored with the secret.")
@click.option("--url", default="")
@click.option("--notes", default="")
@click.option("-g", "--generate", "gen", is_flag=True, help="Generate a random password.")
@click.option("--length", default=20, show_default=True)
@click.option("--no-symbols", is_flag=True)
@click.option("--overwrite", is_flag=True, help="Replace an existing entry.")
@pass_ctx
def add(c, vault, name, username, url, notes, gen, length, no_symbols, overwrite):
    """Store a password in a vault."""
    session = c.session()
    if gen:
        secret = generate(length, symbols=not no_symbols)
    else:
        secret = click.prompt(f"Password for {name}", hide_input=True, confirmation_prompt=True)
    c.app.add_secret(session, vault, name, secret, username=username, url=url, notes=notes, overwrite=overwrite)
    suffix = f" with a generated {length}-character password" if gen else ""
    click.echo(f"Saved '{name}' in '{vault}'{suffix}.")


@cli.command()
@click.argument("vault")
@click.argument("name")
@click.option("--show", is_flag=True, help="Print the password instead of masking it.")
@click.option("--field", type=click.Choice(["username", "password", "url", "notes"]), help="Print a single field only.")
@pass_ctx
def get(c, vault, name, show, field):
    """Read a password from a vault."""
    secret = c.app.get_secret(c.session(), vault, name)
    if field:
        click.echo(secret[field])
        return
    click.echo(f"name:     {name}")
    for key in ("username", "url", "notes"):
        if secret[key]:
            click.echo(f"{key + ':':<9} {secret[key]}")
    click.echo(f"password: {secret['password'] if show else '*' * 12}")


@cli.command("list")
@click.argument("vault")
@pass_ctx
def list_entries(c, vault):
    """List entries in a vault."""
    rows = c.app.entries(c.session(), vault)
    if not rows:
        click.echo(f"'{vault}' is empty.")
        return
    for row in rows:
        size = fmt_size(row["size"] - crypto.NONCE_SIZE - crypto.TAG_SIZE) if row["kind"] == "file" else ""
        who = row["updated_by_name"] or "-"
        click.echo(f"{row['kind']:<7} {row['name']:<28} {size:>8}  {fmt_time(row['updated_at'])}  {who}")


@cli.command()
@click.argument("vault")
@click.argument("name")
@click.option("--file", "is_file", is_flag=True, help="Remove a stored file instead of a password.")
@pass_ctx
def rm(c, vault, name, is_file):
    """Remove an entry from a vault."""
    kind = "file" if is_file else "secret"
    c.app.remove(c.session(), vault, name, kind)
    click.echo(f"Removed {kind} '{name}' from '{vault}'.")


@cli.group("file")
def file_group():
    """Store and retrieve encrypted files."""


@file_group.command("put")
@click.argument("vault")
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--name", help="Name to store it under (defaults to the file name).")
@click.option("--overwrite", is_flag=True)
@pass_ctx
def file_put(c, vault, path, name, overwrite):
    """Encrypt a file into a vault."""
    stored = c.app.put_file(c.session(), vault, path, name=name, overwrite=overwrite)
    click.echo(f"Stored '{stored}' in '{vault}'.")


@file_group.command("get")
@click.argument("vault")
@click.argument("name")
@click.option("-o", "--output", type=click.Path(dir_okay=False, path_type=Path))
@click.option("--force", is_flag=True, help="Overwrite the output file if it exists.")
@pass_ctx
def file_get(c, vault, name, output, force):
    """Decrypt a file out of a vault."""
    output = output or Path(name)
    if output.exists() and not force:
        raise click.ClickException(f"'{output}' already exists, use --force to overwrite")
    data = c.app.get_file(c.session(), vault, name)
    output.write_bytes(data)
    os.chmod(output, 0o600)
    click.echo(f"Wrote {fmt_size(len(data))} to {output}.")


@cli.command()
@click.argument("vault")
@click.argument("username")
@click.option("--role", type=click.Choice(list(ROLES)), default="viewer", show_default=True)
@pass_ctx
def share(c, vault, username, role):
    """Give another user access to a vault."""
    c.app.share(c.session(), vault, username, role)
    click.echo(f"Shared '{vault}' with {username} as {role}.")


@cli.command()
@click.argument("vault")
@click.argument("username")
@click.argument("role", type=click.Choice(list(ROLES)))
@pass_ctx
def role(c, vault, username, role):
    """Change a member's role."""
    c.app.set_role(c.session(), vault, username, role)
    click.echo(f"{username} is now {role} on '{vault}'.")


@cli.command()
@click.argument("vault")
@click.argument("username")
@pass_ctx
def revoke(c, vault, username):
    """Remove a member and rotate the vault key."""
    c.app.revoke(c.session(), vault, username)
    click.echo(f"Removed {username} from '{vault}' and rotated the vault key.")


@cli.command()
@click.argument("vault")
@pass_ctx
def rotate(c, vault):
    """Re-encrypt a vault under a fresh key."""
    version = c.app.rotate(c.session(), vault)
    click.echo(f"'{vault}' is now on key version {version}.")


@cli.command()
@click.argument("vault")
@pass_ctx
def verify(c, vault):
    """Check every entry decrypts and authenticates."""
    ok, broken = c.app.verify(c.session(), vault)
    click.echo(f"{ok} entries passed authentication.")
    if broken:
        for name in broken:
            click.echo(f"FAILED  {name}", err=True)
        raise SystemExit(1)


@cli.command()
@click.argument("vault")
@pass_ctx
def audit(c, vault):
    """Show the vault's audit log."""
    rows, broken_at = c.app.audit_log(c.session(), vault)
    for row in rows:
        click.echo(f"{fmt_time(row['at'])}  {row['username']:<16} {row['action']:<13} {row['target']}")
    if broken_at is None:
        click.echo(f"\nAudit chain intact ({len(rows)} records).")
    else:
        click.echo(f"\nAudit chain broken at record {broken_at}.", err=True)
        raise SystemExit(1)


@cli.command("generate")
@click.option("--length", default=20, show_default=True)
@click.option("--no-symbols", is_flag=True)
def generate_cmd(length, no_symbols):
    """Print a random password."""
    try:
        click.echo(generate(length, symbols=not no_symbols))
    except ValueError as e:
        raise click.BadParameter(str(e), param_hint="--length") from None
