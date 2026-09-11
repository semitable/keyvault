"""Command line entry point."""

import json
import logging
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Annotated

import typer

from . import gpg as gpg_keys
from . import secrets, ssh
from .errors import KeyvaultError
from .paths import flatten, merge
from .vault import Vault, lock_session, open_session

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help="Bitwarden-backed secrets, GPG and SSH key management.",
)
ssh_app = typer.Typer(no_args_is_help=True, help="SSH keys.")
app.add_typer(ssh_app, name="ssh")
secrets_app = typer.Typer(no_args_is_help=True, help="Environment secrets.")
app.add_typer(secrets_app, name="secrets")
gpg_app = typer.Typer(no_args_is_help=True, help="The personal GPG key.")
app.add_typer(gpg_app, name="gpg")


# Without a callback, typer folds a lone command into the root and `keyvault
# dump` stops being a subcommand.
@app.callback()
def root() -> None:
    pass


@app.command()
def unlock() -> None:
    """Print a shell command that exports a Bitwarden session key.

    Use it as `eval "$(keyvault unlock)"`.

    The key has no expiry. It stays valid until `bw lock` or `bw logout`, it
    keeps working in other terminals if copied there, and every process
    started from the exporting shell inherits it.
    """
    typer.echo(f"export BW_SESSION={shlex.quote(open_session())}")


@app.command()
def lock() -> None:
    """Invalidate the Bitwarden session.

    Use it as `eval "$(keyvault lock)"`. The key is dead either way, but a
    stale BW_SESSION left in the shell makes every later command report a
    locked vault without saying why.
    """
    lock_session()
    typer.echo("unset BW_SESSION")


@app.command()
def init() -> None:
    """Create the vault item, if it does not exist yet."""
    vault = Vault()
    vault.sync()
    vault.create()
    typer.echo(f"created {vault.item_name!r}")


@app.command()
def dump() -> None:
    """Print the whole vault document as JSON.

    Writes every secret to stdout, so mind the scrollback.
    """
    _, fields = _open()
    json.dump(merge(fields), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


@app.command()
def edit() -> None:
    """Open the whole vault document in $EDITOR and save any changes.

    The document goes to a private temporary file for the editor to open.
    That is the one place keyvault writes secrets it was not asked to write;
    the file is removed when the editor exits.
    """
    vault, fields = _open()
    before = json.dumps(merge(fields), indent=2, sort_keys=True)
    after = _through_editor(before)
    if after.strip() == before.strip():
        typer.echo("unchanged")
        return
    try:
        doc = json.loads(after)
    except json.JSONDecodeError as exc:
        raise KeyvaultError(f"not valid JSON, nothing written: {exc}") from exc
    after_fields = flatten(doc)
    removed, added, changed = _changes(fields, after_fields)
    for label, paths in (("remove", removed), ("change", changed), ("add", added)):
        for path in paths:
            typer.echo(f"  {label:<7} {path}")
    # Only losing data needs a confirmation. Bitwarden keeps no history for
    # custom fields, so an overwritten value has nowhere to come back from.
    if removed or changed:
        typer.confirm("apply", abort=True)
    vault.write_fields(after_fields)
    typer.echo("saved")


@ssh_app.command("new")
def ssh_new(name: Annotated[str, typer.Argument()] = "") -> None:
    """Generate a key on this machine and store it in the vault.

    The key is written to ~/.ssh/id_<name>, which is where it lives from then
    on; the vault gets a copy so another machine can retrieve it.
    """
    vault, fields = _open()
    name = name or ssh.default_name()
    if f"ssh.{name}" in fields:
        raise KeyvaultError(f"the vault already holds a key named {name!r}")

    private = ssh.generate(name, ssh.key_path(name))
    vault.write_fields(fields | {f"ssh.{name}": private})
    typer.echo(f"{ssh.key_path(name)}\n{ssh.public_key(private)}")


@ssh_app.command("store")
def ssh_store(name: str, path: Path, force: bool = False) -> None:
    """Store a key that already exists on disk in the vault.

    For adopting a machine's existing key, where the filename does not follow
    the id_<name> convention:

        keyvault ssh store oxygen ~/.ssh/id_ed25519
    """
    vault, fields = _open()
    if f"ssh.{name}" in fields and not force:
        raise KeyvaultError(
            f"the vault already holds a key named {name!r}; pass --force to replace it"
        )
    private = ssh.read_key(path)
    if (twin := ssh.find_duplicate(fields, private, ignore=name)) and not force:
        raise KeyvaultError(
            f"that key is already in the vault as {twin!r}; "
            "pass --force to store it under a second name"
        )
    vault.write_fields(fields | {f"ssh.{name}": private})
    typer.echo(f"stored {name!r}: {ssh.fingerprint(private)}")


@ssh_app.command("load")
def ssh_load(name: str, master: bool = False) -> None:
    """Load a key from the vault into ssh-agent, without touching disk."""
    _, fields = _open()
    ssh.add_to_agent(_private_key(fields, name, master=master))
    typer.echo(f"loaded {name!r}")


@ssh_app.command("install")
def ssh_install(name: str, force: bool = False, master: bool = False) -> None:
    """Write a key from the vault to ~/.ssh/id_<name>.

    Prefer `load` unless something needs a file: an unattended job, or a tool
    that ignores ssh-agent.
    """
    _, fields = _open()
    private = _private_key(fields, name, master=master)
    typer.echo(str(ssh.write(name, private, force=force)))


@ssh_app.command("list")
def ssh_list() -> None:
    """Show the keys in the vault."""
    _, fields = _open()
    if not (stored := ssh.names(fields)):
        typer.echo("no keys in the vault")
        return
    for name in stored:
        typer.echo(f"{name:<16} {ssh.fingerprint(fields[f'ssh.{name}'])}")


@gpg_app.command("show")
def gpg_show(name: Annotated[str, typer.Argument()] = "") -> None:
    """Print the armored private key.

    For piping the key somewhere other than the local keyring:

        keyvault gpg show | gpg --import

    Prefer `gpg install` for the local keyring: a pipe cannot set ownertrust,
    and gpg refuses to encrypt to a key it has none for.
    """
    _, fields = _open()
    sys.stdout.write(gpg_keys.private_key(fields, gpg_keys.resolve(fields, name)))


@gpg_app.command("store")
def gpg_store(name: str, fingerprint: str, force: bool = False) -> None:
    """Store a key from the local keyring in the vault.

        keyvault gpg store personal E2464A53...

    Sourced from the keyring rather than a file, so the private key never has
    to be exported to disk first. The revocation certificate goes in too, if
    gpg kept one for this key.
    """
    vault, fields = _open()
    if f"gpg.{name}.private" in fields and not force:
        raise KeyvaultError(
            f"the vault already holds gpg.{name}; pass --force to replace it"
        )
    wanted = fingerprint.replace(" ", "").upper()
    if (twin := gpg_keys.find_duplicate(fields, wanted, ignore=name)) and not force:
        raise KeyvaultError(
            f"that key is already in the vault as {twin!r}; "
            "pass --force to store it under a second name"
        )
    entry = {f"gpg.{name}.private": gpg_keys.export_secret(wanted)}
    if revocation := gpg_keys.revocation_certificate(wanted):
        entry[f"gpg.{name}.revocation-cert"] = revocation
    vault.write_fields(fields | entry)
    parts = ", ".join(sorted(path.split(".", 2)[2] for path in entry))
    typer.echo(f"stored {name!r} as {wanted} [{parts}]")


@gpg_app.command("install")
def gpg_install(name: Annotated[str, typer.Argument()] = "") -> None:
    """Import a GPG key from the vault into the local keyring.

    Also marks it ultimately trusted, without which gpg refuses to encrypt to
    it -- so `git-crypt add-gpg-user` would fail even though the key is there.

    The key carries no passphrase, so nothing prompts on use afterwards: any
    process running as you can decrypt what it protects. Undo with
    `gpg --delete-secret-keys <fingerprint>`.
    """
    _, fields = _open()
    key = gpg_keys.resolve(fields, name)
    fingerprint = gpg_keys.install(gpg_keys.private_key(fields, key))
    typer.echo(f"imported {key!r} as {fingerprint}, trusted ultimately")


@gpg_app.command("check")
def gpg_check() -> None:
    """Report what the vault holds and whether each key is installed.

    Reads fingerprints off the stored keys without importing anything, and
    prints lengths rather than values.
    """
    _, fields = _open()
    if not (keys := gpg_keys.names(fields)):
        typer.echo("no gpg keys in the vault")
        return
    for key in keys:
        fingerprint = gpg_keys.fingerprint(gpg_keys.private_key(fields, key))
        state = "in keyring" if gpg_keys.in_keyring(fingerprint) else "not imported"
        typer.echo(f"{key:<12} {fingerprint} {state}")
        for path in sorted(p for p in fields if p.startswith(f"gpg.{key}.")):
            typer.echo(f"  {path.split('.', 2)[2]:<20} {len(fields[path])} chars")


@secrets_app.command("show")
def secrets_show(name: Annotated[str, typer.Argument()] = "") -> None:
    """Print export lines for the stored secrets.

    Use them however you like:

        eval "$(keyvault secrets show)"
        keyvault secrets show > ~/.zshenv.secrets

    Redirecting onto an existing file keeps that file's permissions; creating
    one fresh does not, so `umask 077` first or chmod it afterwards.
    """
    _, fields = _open()
    values = secrets.values(fields)
    if name:
        secrets.check_name(name)
        if name not in values:
            raise KeyvaultError(f"the vault holds no secret named {name!r}")
        values = {name: values[name]}
    sys.stdout.write(secrets.render(values))


@secrets_app.command("store")
def secrets_store(name: str, force: bool = False) -> None:
    """Prompt for a secret and store it in the vault as env.<NAME>."""
    secrets.check_name(name)
    vault, fields = _open()
    if f"env.{name}" in fields and not force:
        raise KeyvaultError(f"env.{name} already exists; pass --force to replace it")
    value = typer.prompt(f"value for {name}", hide_input=True)
    if not value:
        raise KeyvaultError("empty value")
    # Enough to catch a truncated paste, not enough to expose the secret.
    typer.echo(f"{len(value)} characters ending {value[-4:]!r}")
    vault.write_fields(fields | {f"env.{name}": value})
    typer.echo(f"stored env.{name}; run 'keyvault secrets show' to export it")


@secrets_app.command("list")
def secrets_list() -> None:
    """Show the stored secrets by name and length, never by value."""
    _, fields = _open()
    if not (values := secrets.values(fields)):
        typer.echo("no secrets in the vault")
        return
    for name, value in sorted(values.items()):
        typer.echo(f"{name:<28} {len(value)} chars")


def _through_editor(text: str) -> str:
    editor = os.environ.get("VISUAL") or os.environ.get("EDITOR") or "vi"
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "keyvault.json"
        path.write_text(text)
        path.chmod(0o600)
        subprocess.run([*shlex.split(editor), str(path)], check=True)
        return path.read_text()


def _changes(
    before: dict[str, str], after: dict[str, str]
) -> tuple[list[str], list[str], list[str]]:
    """Field paths removed, added and changed. Never returns values."""
    return (
        sorted(before.keys() - after.keys()),
        sorted(after.keys() - before.keys()),
        sorted(
            path for path in before.keys() & after.keys() if before[path] != after[path]
        ),
    )


def _open() -> tuple[Vault, dict[str, str]]:
    """Unlock, sync and read once. bw costs about a second per call."""
    vault = Vault()
    vault.sync()
    return vault, vault.read_fields()


def _private_key(fields: dict[str, str], name: str, *, master: bool) -> str:
    if name == ssh.MASTER and not master:
        raise KeyvaultError(
            "the master key is for recovery; pass --master to use it anyway"
        )
    return ssh.private_key(fields, name)


def main() -> None:
    logging.basicConfig(format="keyvault: %(message)s", level=logging.WARNING)
    try:
        app()
    except KeyvaultError as exc:
        raise SystemExit(f"keyvault: {exc}") from exc
