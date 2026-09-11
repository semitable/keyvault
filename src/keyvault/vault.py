"""Bitwarden CLI client for a single item.

`bw` costs about a second per invocation, so a Vault holds its session and the
fetched item for its lifetime; reuse one instance rather than constructing
several.

The session key is passed to each subprocess through the environment and never
appears in argv, which is readable by any process via `ps`. Field values go to
`bw edit` on stdin for the same reason.
"""

import base64
import json
import logging
import os
import subprocess
from typing import Any

from .errors import VaultError
from .paths import Document, flatten, merge

logger = logging.getLogger(__name__)

DEFAULT_ITEM = "keyvault"
ITEM_ENV_VAR = "KEYVAULT_ITEM"

# Bitwarden custom field types; hidden values are masked in the clients.
FIELD_HIDDEN = 1

# Bitwarden item types. A secure note carries custom fields without pretending
# to be a login.
ITEM_SECURE_NOTE = 2
SECURE_NOTE_GENERIC = 0

type Item = dict[str, Any]


class Vault:
    """One Bitwarden item, read and written as a nested document."""

    def __init__(self, item_name: str | None = None) -> None:
        self.item_name = item_name or os.environ.get(ITEM_ENV_VAR, DEFAULT_ITEM)
        self._session = open_session()
        self._item: Item | None = None
        self._read_revision: str | None = None

    def sync(self) -> None:
        """Refresh the local vault cache.

        A failure is logged rather than raised: a stale cache still lets an
        offline machine read its keys.
        """
        try:
            self._run("sync")
        except VaultError as exc:
            logger.warning("vault sync failed, using the local cache: %s", exc)

    def read(self) -> Document:
        item = self._fetch()
        self._read_revision = item["revisionDate"]
        fields = item.get("fields") or []
        return merge({field["name"]: field["value"] for field in fields})

    def write(self, doc: Document) -> None:
        """Replace the item's fields with `doc`.

        Refuses if the item changed since `read`, so two machines editing
        concurrently cannot silently lose one side's work.
        """
        assert self._read_revision is not None, "read() before write()"
        fields = flatten(doc)
        item = self._fetch(refresh=True)
        if item["revisionDate"] != self._read_revision:
            raise VaultError(
                f"{self.item_name!r} changed in the vault since it was read; "
                "re-read and re-apply"
            )
        # Keep the type of fields that already exist so an edit cannot turn a
        # hidden value into a visible one.
        types = {f["name"]: f["type"] for f in item.get("fields") or []}
        item["fields"] = [
            {
                "name": name,
                "value": value,
                "type": types.get(name, FIELD_HIDDEN),
            }
            for name, value in sorted(fields.items())
        ]
        payload = base64.b64encode(json.dumps(item).encode()).decode()
        self._run("edit", "item", item["id"], stdin=payload)
        self._item = None

    def create(self) -> None:
        """Create the item as an empty secure note."""
        if self._search():
            raise VaultError(f"{self.item_name!r} already exists")
        item = {
            "type": ITEM_SECURE_NOTE,
            "name": self.item_name,
            "notes": None,
            "favorite": False,
            "fields": [],
            "secureNote": {"type": SECURE_NOTE_GENERIC},
        }
        payload = base64.b64encode(json.dumps(item).encode()).decode()
        self._run("create", "item", stdin=payload)

    def _fetch(self, *, refresh: bool = False) -> Item:
        if self._item is None or refresh:
            matches = self._search()
            if not matches:
                raise VaultError(f"no vault item named {self.item_name!r}")
            if len(matches) > 1:
                raise VaultError(
                    f"{len(matches)} vault items are named {self.item_name!r}"
                )
            self._item = matches[0]
        return self._item

    def _search(self) -> list[Item]:
        found = json.loads(self._run("list", "items", "--search", self.item_name))
        return [item for item in found if item["name"] == self.item_name]

    def _run(self, *args: str, stdin: str | None = None) -> str:
        env = os.environ | {"BW_SESSION": self._session}
        return _bw(*args, stdin=stdin, env=env)


def open_session() -> str:
    """Return an unlocked session key, prompting for the password if needed.

    Reuses BW_SESSION when the vault is already unlocked, so callers do not
    prompt again for a session the shell already holds.

    Reports the three `bw` states separately: "authentication failed" sends you
    looking in the wrong place when the real problem is a locked vault.
    """
    status = json.loads(_bw("status"))["status"]
    match status:
        case "unlocked":
            if session := os.environ.get("BW_SESSION"):
                return session
            raise VaultError("bw reports an unlocked vault but BW_SESSION is unset")
        case "locked":
            return _bw_interactive("unlock", "--raw").strip()
        case "unauthenticated":
            raise VaultError("bw is not logged in; run: bw login <email>")
        case other:
            raise VaultError(f"unexpected bw status {other!r}")


def lock_session() -> None:
    """Invalidate the current session key.

    Needs no session of its own: locking discards local vault state, so it
    works whatever BW_SESSION the caller holds.
    """
    _bw("lock")


def _bw(*args: str, stdin: str | None = None, env: dict[str, str] | None = None) -> str:
    proc = subprocess.run(
        ["bw", *args],
        input=stdin,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    if proc.returncode != 0:
        raise VaultError(f"bw {args[0]} failed: {proc.stderr.strip()}")
    return proc.stdout


def _bw_interactive(*args: str) -> str:
    """Run `bw` with its prompts on the terminal, capturing only stdout."""
    proc = subprocess.run(
        ["bw", *args],
        stdout=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise VaultError(f"bw {args[0]} failed")
    return proc.stdout
