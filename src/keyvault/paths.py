"""Dotted-path field names to nested documents.

Each value lives in a vault field whose name is a dotted path and whose value
is a leaf string, so `ssh.laptop.private` reads back as
`{"ssh": {"laptop": {"private": ...}}}`.

Field names come from the vault or a hand-edited document, so both directions
validate. A path is either a leaf or a branch, never both: merging the two
would mean guessing which was meant. Segments are restricted so that `.` is
unambiguous and no value ever needs escaping.
"""

import re

from .errors import SchemaError

type Document = dict[str, str | Document]

SEGMENT_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def merge(fields: dict[str, str]) -> Document:
    """Build a nested document from flat path-to-value fields.

    Walks fields in sorted order so a conflicting item reports the same pair of
    paths whatever order the vault returned them in.
    """
    doc: Document = {}
    leaf_paths: dict[tuple[str, ...], str] = {}
    for path in sorted(fields):
        segments = split_path(path)
        cursor = doc
        for depth, segment in enumerate(segments[:-1], start=1):
            match cursor.get(segment):
                case str():
                    prefix = ".".join(segments[:depth])
                    owner = leaf_paths[tuple(segments[:depth])]
                    raise SchemaError(
                        f"{path!r} needs {prefix!r} to be a branch, "
                        f"but {owner!r} stores a value there"
                    )
                case dict() as branch:
                    cursor = branch
                case _:
                    branch = {}
                    cursor[segment] = branch
                    cursor = branch
        last = segments[-1]
        if isinstance(cursor.get(last), dict):
            raise SchemaError(
                f"{path!r} stores a value where another field needs a branch"
            )
        cursor[last] = fields[path]
        leaf_paths[tuple(segments)] = path
    return doc


def flatten(doc: Document, prefix: str = "") -> dict[str, str]:
    """Flatten a nested document into path-to-value fields.

    Inverse of `merge`. An empty branch is rejected rather than dropped: the
    schema cannot represent it, so writing one would lose it on the next read.
    """
    out: dict[str, str] = {}
    for key, value in doc.items():
        if not SEGMENT_RE.match(key):
            raise SchemaError(f"key {key!r} has characters outside [A-Za-z0-9_-]")
        path = f"{prefix}{key}"
        match value:
            case str():
                out[path] = value
            case dict() if not value:
                raise SchemaError(f"{path!r} is an empty branch and cannot be stored")
            case dict():
                out |= flatten(value, f"{path}.")
            case _:
                raise SchemaError(
                    f"{path!r} holds {type(value).__name__}; "
                    "only strings and nested objects are storable"
                )
    return out


def split_path(path: str) -> list[str]:
    """Split a field name into validated segments."""
    if not path:
        raise SchemaError("empty field name")
    segments = path.split(".")
    for segment in segments:
        if not segment:
            raise SchemaError(f"{path!r}: empty path segment")
        if not SEGMENT_RE.match(segment):
            raise SchemaError(
                f"{path!r}: segment {segment!r} has characters outside [A-Za-z0-9_-]"
            )
    return segments
