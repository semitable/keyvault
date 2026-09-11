"""Exception types.

One base class so the CLI can turn any expected failure into a clean message
and a non-zero exit, while an unexpected exception still gets a traceback.
"""


class KeyvaultError(Exception):
    """Base for every expected failure."""


class SchemaError(KeyvaultError):
    """The vault item does not match the dotted-path schema."""


class VaultError(KeyvaultError):
    """Bitwarden is unusable: not logged in, locked, or unreachable."""
