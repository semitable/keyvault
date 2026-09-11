import pytest

from keyvault import secrets
from keyvault.errors import KeyvaultError


def test_values_takes_only_the_env_section() -> None:
    assert secrets.values({"env.A": "1", "ssh.laptop": "k", "gpg.private": "p"}) == {
        "A": "1"
    }


def test_values_rejects_a_name_a_shell_cannot_export() -> None:
    # SEGMENT_RE allows "-", so this path is storable but not exportable.
    with pytest.raises(KeyvaultError, match="MY-VAR"):
        secrets.values({"env.MY-VAR": "1"})


def test_render_quotes_values_that_would_otherwise_run_as_shell() -> None:
    text = secrets.render({"A": "it's a $PATH; rm -rf /"})
    assert text == "export A='it'\"'\"'s a $PATH; rm -rf /'\n"


def test_render_is_sorted_so_a_redirected_file_does_not_churn() -> None:
    assert secrets.render({"B": "2", "A": "1"}) == "export A=1\nexport B=2\n"


def test_check_name_rejects_a_leading_digit() -> None:
    with pytest.raises(KeyvaultError, match="not a usable"):
        secrets.check_name("1ABC")
