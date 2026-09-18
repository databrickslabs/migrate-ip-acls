"""The `--version` flag prints the tool version and exits cleanly, before any command or auth runs."""

from __future__ import annotations

from typer.testing import CliRunner

from dbx_migrate_ip_acls import __version__, cli

runner = CliRunner()


def test_version_flag_prints_version_and_exits():
    result = runner.invoke(cli.app, ["--version"])
    assert result.exit_code == 0
    assert "dbx-migrate-ip-acls" in result.output
    assert __version__ in result.output


def test_version_is_a_nonempty_string():
    assert isinstance(__version__, str)
    assert __version__
