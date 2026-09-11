import pytest

from keyvault.errors import SchemaError
from keyvault.paths import flatten, merge, split_path


@pytest.mark.parametrize(
    "bad",
    [
        "",
        ".",
        ".env",
        "env.",
        "env..KEY",
        "env.MY KEY",
        "env.MY/KEY",
        "env.MY:KEY",
    ],
)
def test_split_path_rejects_ambiguous(bad: str) -> None:
    with pytest.raises(SchemaError):
        split_path(bad)


@pytest.mark.parametrize(
    "fields",
    [
        {},
        {"a": "1"},
        {"a.b.c.d.e": "1"},
        {"env.A": "1", "env.B": "2", "gpg.private": "x"},
        {"ssh.a.private": "1", "ssh.a.public": "2", "ssh.b.public": "3"},
        {"x-1.y_2": "v"},
        # env.* is one level deep while ssh.*.* is two; the schema constrains
        # paths, not uniform depth.
        {"env.A": "1", "ssh.laptop.public": "P"},
    ],
)
def test_round_trip(fields: dict[str, str]) -> None:
    assert flatten(merge(fields)) == fields


def test_merge_nests() -> None:
    assert merge({"ssh.a.private": "p", "ssh.a.public": "P"}) == {
        "ssh": {"a": {"private": "p", "public": "P"}}
    }


@pytest.mark.parametrize(
    "fields",
    [
        {"ssh.a": "key", "ssh.a.private": "p"},
        {"ssh.a.private": "p", "ssh.a": "key"},
    ],
)
def test_merge_rejects_leaf_and_branch_at_one_path(fields: dict[str, str]) -> None:
    with pytest.raises(SchemaError):
        merge(fields)


def test_merge_conflict_message_is_order_independent() -> None:
    with pytest.raises(SchemaError) as first:
        merge({"ssh.a": "k", "ssh.a.private": "p"})
    with pytest.raises(SchemaError) as second:
        merge({"ssh.a.private": "p", "ssh.a": "k"})
    assert str(first.value) == str(second.value)


def test_flatten_rejects_empty_branch() -> None:
    with pytest.raises(SchemaError, match="empty branch"):
        flatten({"ssh": {}})


def test_flatten_rejects_non_string_leaf() -> None:
    with pytest.raises(SchemaError, match="int"):
        flatten({"env": {"A": 1}})  # type: ignore[dict-item]


def test_flatten_preserves_multiline_values() -> None:
    key = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\ndef\n-----END-----\n"
    assert flatten(merge({"ssh.a.private": key}))["ssh.a.private"] == key
