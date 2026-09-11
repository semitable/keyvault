"""Environment secrets.

`env.<VAR>` in the vault becomes an `export VAR=...` line. Printing those
rather than managing a file lets the caller choose: `eval` them into the
current shell, or redirect them into a file the shell sources at startup.

There is no map from variable names to vault items: the `env` section is the
set. That is the point of storing everything under one item -- there is
nothing to keep in sync and nothing to leave behind.
"""

import re
import shlex

from .errors import KeyvaultError
from .paths import section

# POSIX environment variable names. Narrower than a path segment, which also
# allows "-", so a storable path is not necessarily an exportable name.
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def values(fields: dict[str, str]) -> dict[str, str]:
    """The env section, rejecting names a shell could not export."""
    found = section(fields, "env")
    if bad := sorted(name for name in found if not ENV_NAME_RE.match(name)):
        raise KeyvaultError(
            f"not usable as environment variable names: {', '.join(bad)}"
        )
    return found


def render(values: dict[str, str]) -> str:
    """Shell-quoted export lines, sorted so a redirected file does not churn."""
    return "".join(
        f"export {name}={shlex.quote(value)}\n"
        for name, value in sorted(values.items())
    )


def check_name(name: str) -> None:
    if not ENV_NAME_RE.match(name):
        raise KeyvaultError(
            f"{name!r} is not a usable environment variable name "
            "([A-Za-z_][A-Za-z0-9_]*)"
        )
