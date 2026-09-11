import pytest

from keyvault import gpg
from keyvault.errors import KeyvaultError

ARMOR = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nabc\n-----END-----\n"


def test_fingerprint_normalises_spacing_and_case() -> None:
    assert gpg.fingerprint({"gpg.fingerprint": "abcd ef01 2345"}) == "ABCDEF012345"


def test_fingerprint_reports_a_missing_field() -> None:
    with pytest.raises(KeyvaultError, match=r"no gpg\.fingerprint"):
        gpg.fingerprint({})


def test_private_key_accepts_a_private_block() -> None:
    assert gpg.private_key({"gpg.private": ARMOR}) == ARMOR


@pytest.mark.parametrize(
    "value",
    [
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\nabc\n",
        "not armored at all",
    ],
)
def test_private_key_refuses_anything_but_a_private_block(value: str) -> None:
    # A revocation certificate is an armored PUBLIC KEY BLOCK, and importing
    # one revokes the key. This guard is what stops a mis-edited item doing it.
    with pytest.raises(KeyvaultError, match="refusing to import"):
        gpg.private_key({"gpg.private": value})
