"""GPG key import.

The vault holds `gpg.fingerprint` and `gpg.private`. The public key is not
stored: importing the private block yields it, because a secret key packet
carries the public material.

`gpg.revocation-cert` is never read here. Importing it revokes the key, and
that is irreversible once the revoked key reaches a keyserver, so the only
protection worth having is that no routine code path can reach it.
"""

import subprocess

from .errors import KeyvaultError

PRIVATE_ARMOR = "-----BEGIN PGP PRIVATE KEY BLOCK-----"


def fingerprint(fields: dict[str, str]) -> str:
    if not (value := fields.get("gpg.fingerprint")):
        raise KeyvaultError("the vault holds no gpg.fingerprint")
    return value.replace(" ", "").upper()


def private_key(fields: dict[str, str]) -> str:
    if not (private := fields.get("gpg.private")):
        raise KeyvaultError("the vault holds no gpg.private")
    if not private.lstrip().startswith(PRIVATE_ARMOR):
        raise KeyvaultError(
            "gpg.private is not a PGP PRIVATE KEY BLOCK; refusing to import it"
        )
    return private


def in_keyring(fingerprint: str) -> bool:
    return _gpg("--list-secret-keys", fingerprint, check=False) is not None


def install(private: str, fingerprint: str) -> None:
    """Import the key and mark it ultimately trusted.

    Without ultimate trust, gpg and git-crypt warn on every use that there is
    no assurance the key belongs to its owner.
    """
    _gpg("--batch", "--quiet", "--import", stdin=private)
    _gpg("--import-ownertrust", stdin=f"{fingerprint}:6:\n")
    if fingerprint not in installed_fingerprints():
        raise KeyvaultError(
            f"imported, but {fingerprint} is not in the keyring; check the vault item"
        )


def installed_fingerprints() -> set[str]:
    listing = _gpg("--list-secret-keys", "--with-colons", check=False) or ""
    return {
        line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")
    }


def _gpg(*args: str, stdin: str | None = None, check: bool = True) -> str | None:
    proc = subprocess.run(
        ["gpg", *args],
        input=stdin,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        if check:
            raise KeyvaultError(f"gpg {args[0]} failed: {proc.stderr.strip()}")
        return None
    return proc.stdout
