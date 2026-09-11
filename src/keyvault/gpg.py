"""GPG keys.

`gpg.<name>.private` holds the armored private key; `gpg.<name>.revocation-cert`
holds its revocation certificate, if there is one. Two levels because a GPG key
has more than one thing worth keeping, unlike an SSH key.

Fingerprints are not stored. They are read off the armored key without
importing it, so `list` can report what the vault holds without touching the
local keyring.

`install` reads only `.private`. Importing a revocation certificate revokes the
key, so nothing here looks that field up.
"""

import os
import subprocess
from pathlib import Path

from .errors import KeyvaultError
from .paths import groups

PRIVATE_ARMOR = "-----BEGIN PGP PRIVATE KEY BLOCK-----"

# gpg --export-ownertrust scale. 6 is ultimate: "this key is mine, treat its
# self-signature as authoritative". An imported key arrives with none, and gpg
# then refuses to encrypt to it -- which is what git-crypt needs to do.
TRUST_ULTIMATE = 6


def names(fields: dict[str, str]) -> list[str]:
    return sorted(groups(fields, "gpg"))


def resolve(fields: dict[str, str], name: str) -> str:
    """The key to act on: the named one, or the only one if there is just one."""
    if name:
        return name
    match names(fields):
        case [only]:
            return only
        case []:
            raise KeyvaultError("the vault holds no gpg keys")
        case several:
            raise KeyvaultError(f"name one of: {', '.join(several)}")


def private_key(fields: dict[str, str], name: str) -> str:
    if not (private := fields.get(f"gpg.{name}.private")):
        raise KeyvaultError(f"the vault holds no gpg.{name}.private")
    if not private.lstrip().startswith(PRIVATE_ARMOR):
        raise KeyvaultError(
            f"gpg.{name}.private is not a PGP PRIVATE KEY BLOCK; refusing to use it"
        )
    return private


def fingerprint(private: str) -> str:
    """Read the fingerprint off an armored key, importing nothing."""
    listing = _gpg("--show-keys", "--with-colons", stdin=private) or ""
    for line in listing.splitlines():
        if line.startswith("fpr:"):
            return line.split(":")[9]
    raise KeyvaultError("gpg could not read a fingerprint from the stored key")


def uid(private: str) -> str:
    """The key's primary user ID, read off the armored key.

    A key can carry several; the first is the one gpg treats as primary.
    """
    listing = _gpg("--show-keys", "--with-colons", stdin=private) or ""
    for line in listing.splitlines():
        if line.startswith("uid:"):
            return line.split(":")[9]
    return "(no user id)"


def in_keyring(fingerprint: str) -> bool:
    return fingerprint in installed_fingerprints()


def installed_fingerprints() -> set[str]:
    listing = _gpg("--list-secret-keys", "--with-colons", check=False) or ""
    return {
        line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")
    }


def install(private: str) -> str:
    """Import the key, trust it ultimately, and return its fingerprint.

    Asserts the key gpg actually imported is the one the vault holds, by
    comparing the keyring before and after -- membership alone would pass on a
    fingerprint that happened to be present already.
    """
    expected = fingerprint(private)
    before = installed_fingerprints()
    _gpg("--batch", "--quiet", "--import", stdin=private)
    added = installed_fingerprints() - before
    if added and expected not in added:
        raise KeyvaultError(f"gpg imported {', '.join(sorted(added))}, not {expected}")
    if expected not in installed_fingerprints():
        raise KeyvaultError(f"imported, but {expected} is not in the keyring")
    _gpg("--import-ownertrust", stdin=f"{expected}:{TRUST_ULTIMATE}:\n")
    return expected


def export_secret(fingerprint: str) -> str:
    """Export an armored private key from the local keyring.

    Prompts for the passphrase if the key has one. Storing a key in the vault
    is an interactive operation, so a prompt here is fine.
    """
    if fingerprint not in installed_fingerprints():
        raise KeyvaultError(f"{fingerprint} is not a secret key in this keyring")
    armored = _gpg("--armor", "--export-secret-keys", fingerprint) or ""
    if not armored.lstrip().startswith(PRIVATE_ARMOR):
        raise KeyvaultError(f"gpg did not export a private key for {fingerprint}")
    return armored


def revocation_certificate(fingerprint: str) -> str | None:
    """The revocation certificate gpg wrote when the key was generated."""
    home = os.environ.get("GNUPGHOME") or str(Path.home() / ".gnupg")
    path = Path(home) / "openpgp-revocs.d" / f"{fingerprint}.rev"
    return path.read_text() if path.exists() else None


def find_duplicate(fields: dict[str, str], wanted: str, *, ignore: str) -> str | None:
    """The name a key with this fingerprint is already stored under."""
    for name in names(fields):
        stored = fields.get(f"gpg.{name}.private")
        if name != ignore and stored and fingerprint(stored) == wanted:
            return name
    return None


def _gpg(*args: str, stdin: str | None = None, check: bool = True) -> str | None:
    proc = subprocess.run(
        ["gpg", *args], input=stdin, capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        if check:
            raise KeyvaultError(f"gpg {args[0]} failed: {proc.stderr.strip()}")
        return None
    return proc.stdout
