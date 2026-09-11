from pathlib import Path

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


def test_render_quotes_values_that_would_break_a_shell() -> None:
    text = secrets.render({"A": "it's a $PATH; rm -rf /"})
    assert "export A='it'\"'\"'s a $PATH; rm -rf /'" in text


def test_render_is_sorted_so_the_file_does_not_churn() -> None:
    assert secrets.render({"B": "2", "A": "1"}).index("export A") < secrets.render(
        {"B": "2", "A": "1"}
    ).index("export B")


def test_write_is_atomic_and_private(tmp_path: Path) -> None:
    target = tmp_path / ".zshenv.secrets"
    secrets.write("first\n", target)
    secrets.write("second\n", target)
    assert target.read_text() == "second\n"
    assert target.stat().st_mode & 0o777 == 0o600
    assert not list(tmp_path.glob(".keyvault-*"))


def test_write_leaves_no_temp_file_when_it_fails(tmp_path: Path) -> None:
    target = tmp_path / "sub" / "out"
    with pytest.raises(TypeError):
        secrets.write(None, target)  # type: ignore[arg-type]
    assert not list(target.parent.glob(".keyvault-*"))
