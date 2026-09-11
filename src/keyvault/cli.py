"""Command line entry point."""

import json
import logging
import shlex
import sys

import typer

from .errors import KeyvaultError
from .vault import Vault, lock_session, open_session

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help="Bitwarden-backed secrets, GPG and SSH key management.",
)


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
    vault = Vault()
    vault.sync()
    json.dump(vault.read(), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


def main() -> None:
    logging.basicConfig(format="keyvault: %(message)s", level=logging.WARNING)
    try:
        app()
    except KeyvaultError as exc:
        raise SystemExit(f"keyvault: {exc}") from exc
