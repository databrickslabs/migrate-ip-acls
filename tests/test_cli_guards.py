"""Tests for the CLI's interactive gates, pre-checks, guards, and exports.

All offline: SDK clients and workspace/account reads are faked or monkeypatched. The single command
is the app callback, so it's invoked without a subcommand name (e.g. `[--profile, test, ...]`)."""

from __future__ import annotations

import re

import pytest
from typer.testing import CliRunner

from dbx_migrate_ip_acls import cli

runner = CliRunner()

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _squash(output: str) -> str:
    """Strip ANSI codes, Rich panel borders, and all whitespace from CLI output. Typer renders
    errors in a Rich panel whose width depends on the environment (CI has no TTY → 80 cols → it can
    wrap and even hyphen-break a long `--flag` across lines). Squashing lets substring assertions on
    error text stay stable regardless of wrapping."""
    return re.sub(r"[\s│|╭╮╰╯─]+", "", _ANSI_RE.sub("", output))


def _err_text(result) -> str:
    """Squashed CLI error text, drawn from stdout AND stderr — Typer renders errors to a Rich
    console on stderr, which newer Click keeps separate from `result.output`."""
    text = result.output or ""
    try:
        text += result.stderr or ""
    except ValueError:
        pass  # this runner merged stderr into stdout — already covered by result.output
    return _squash(text)


def test_resolve_profile_passthrough():
    assert cli._resolve_profile("myprofile") == "myprofile"


def test_resolve_profile_respects_env_auth(monkeypatch):
    monkeypatch.setenv("DATABRICKS_HOST", "https://x.cloud.databricks.com")
    assert cli._resolve_profile(None) is None


def test_resolve_profile_none_and_no_profiles_errors(monkeypatch):
    import typer

    monkeypatch.delenv("DATABRICKS_HOST", raising=False)
    monkeypatch.setattr(cli, "_available_profiles", lambda: [])
    with pytest.raises(typer.BadParameter):
        cli._resolve_profile(None)


def test_resolve_profile_none_noninteractive_errors(monkeypatch):
    import typer

    monkeypatch.delenv("DATABRICKS_HOST", raising=False)
    monkeypatch.setattr(cli, "_available_profiles", lambda: ["a", "b"])
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    with pytest.raises(typer.BadParameter):
        cli._resolve_profile(None)


def test_confirm_params_yes_skips(monkeypatch):
    # --yes must not prompt and must not raise.
    called = {"n": 0}
    monkeypatch.setattr("typer.confirm", lambda *a, **k: called.__setitem__("n", called["n"] + 1))
    cli._confirm_params(yes=True)
    assert called["n"] == 0


def test_confirm_params_noninteractive_skips(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    monkeypatch.setattr(
        "typer.confirm",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not prompt non-interactively")),
    )
    cli._confirm_params(yes=False)


def test_confirm_params_decline_aborts(monkeypatch):
    import typer

    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: False)
    with pytest.raises(typer.Exit) as exc:
        cli._confirm_params(yes=False)
    assert exc.value.exit_code == 0  # user chose to abort — a clean exit, not an error


def test_confirm_params_accept_proceeds(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: True)
    cli._confirm_params(yes=False)  # must not raise


def test_checkpoint_yes_skips_prompt(monkeypatch):
    monkeypatch.setattr(
        "typer.confirm", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not prompt with --yes"))
    )
    cli._checkpoint(yes=True)  # must not raise


def test_checkpoint_noninteractive_skips_prompt(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    monkeypatch.setattr(
        "typer.confirm",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not prompt non-interactively")),
    )
    cli._checkpoint(yes=False)  # must not raise


def test_checkpoint_continue_proceeds(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: True)
    cli._checkpoint(yes=False)  # must not raise


def test_checkpoint_decline_aborts_cleanly(monkeypatch):
    import typer

    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: False)
    with pytest.raises(typer.Exit) as exc:
        cli._checkpoint(yes=False)
    assert exc.value.exit_code == 0  # 'n' -> clean abort


def test_confirm_write_yes_proceeds():
    assert cli._confirm_write(yes=True) is True


def test_confirm_write_interactive_decline(monkeypatch):
    monkeypatch.setattr("typer.confirm", lambda *a, **k: False)
    assert cli._confirm_write(yes=False) is False


def test_responsibility_warning_shown(capsys):
    from dbx_migrate_ip_acls import console

    console.responsibility_warning()
    out = capsys.readouterr().out
    assert "responsib" in out.lower()
    assert "security-enforcing" in out.lower()
    # mentions the reuse-the-JSON case, not just create-here
    assert "copy this JSON" in out or "copy" in out.lower()


def test_ensure_account_id_passthrough_when_set():
    from dbx_migrate_ip_acls.config import Connection

    conn = Connection(account_id="already-set")
    cli._ensure_account_id(conn, "Creating a policy")  # no prompt, no raise
    assert conn.account_id == "already-set"


def test_ensure_account_id_noninteractive_errors(monkeypatch):
    import typer

    from dbx_migrate_ip_acls.config import Connection

    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    with pytest.raises(typer.BadParameter):
        cli._ensure_account_id(Connection(account_id=""), "Creating a policy")


def test_ensure_account_id_prompts_interactive(monkeypatch):
    from dbx_migrate_ip_acls.config import Connection

    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    class _Q:
        def ask(self):
            return "  1234567890  "

    monkeypatch.setattr("questionary.text", lambda *a, **k: _Q())
    conn = Connection(account_id="")
    cli._ensure_account_id(conn, "Creating a policy")
    assert conn.account_id == "1234567890"


def test_maybe_disable_ip_acls_noop_when_flag_false():
    class _WS:
        @property
        def workspace_conf(self):
            raise AssertionError("must not touch the workspace when the flag is off")

    cli._maybe_disable_ip_acls(False, [{"assigned": 42}], _WS())  # must not raise


def test_maybe_disable_ip_acls_skips_when_nothing_assigned():
    # apply errored / assigned nothing -> we must NOT strip the workspace's IP-ACL protection.
    class _WS:
        @property
        def workspace_conf(self):
            raise AssertionError("must not disable ACLs when no policy was assigned")

    cli._maybe_disable_ip_acls(True, [{"target": "x", "error": "boom"}], _WS())  # must not raise


def test_maybe_disable_ip_acls_runs_when_assigned():
    seen = {}

    class _Conf:
        def get_status(self, keys):
            return {"enableIpAccessLists": "true"}

        def set_status(self, contents):
            seen["set"] = contents

    class _WS:
        workspace_conf = _Conf()

    cli._maybe_disable_ip_acls(True, [{"assigned": 42, "policy_id": "p"}], _WS())
    assert seen["set"] == {"enableIpAccessLists": "false"}


def test_maybe_disable_ip_acls_warns_on_sdk_failure(capsys):
    # if disabling raises (e.g. no workspace-admin rights), the run must NOT crash — the policy is
    # already applied and assigned, so we warn and continue.
    class _Conf:
        def get_status(self, keys):
            raise RuntimeError("permission denied")

    class _WS:
        workspace_conf = _Conf()

    cli._maybe_disable_ip_acls(True, [{"assigned": 42, "policy_id": "p"}], _WS())  # must not raise
    out = capsys.readouterr().out
    assert "manually" in out.lower()


def test_verify_account_access_returns_account_and_ws_on_success():
    from dbx_migrate_ip_acls.config import Connection

    conn = Connection(account_id="acc", account_profile="acct-prof")
    ws_obj = object()

    class _OK:
        def get(self, workspace_id):
            return ws_obj

    account = type("Acct", (), {"workspaces": _OK()})()
    got_account, got_ws = cli._verify_account_access_or_exit(conn, account, 42)
    assert got_account is account
    assert got_ws is ws_obj


def test_verify_account_access_exits_cleanly_on_rejection(capsys):
    # a wrong-tenant / wrong-account / not-admin rejection must become a clean exit(1) with an
    # actionable message — not a raw SDK traceback swallowed and surfaced later.
    import typer

    from dbx_migrate_ip_acls.config import Connection

    conn = Connection(account_id="acc-123", account_host="https://accounts.azuredatabricks.net")

    class _Bad:
        def get(self, workspace_id):
            raise RuntimeError("IncorrectClaimException: Expected iss claim to be ...")

    account = type("Acct", (), {"workspaces": _Bad()})()
    with pytest.raises(typer.Exit) as exc:
        cli._verify_account_access_or_exit(conn, account, 42)
    assert exc.value.exit_code == 1
    out = _squash(capsys.readouterr().out)
    # names the account it tried and points at the fix
    assert "acc-123" in out
    assert "--account-profile" in out


def test_verify_account_access_message_flags_missing_account_profile(capsys):
    import typer

    from dbx_migrate_ip_acls.config import Connection

    # no --account-profile -> the message must call out that creds came from ambient unified auth
    conn = Connection(account_id="acc-9", profile="ws-prof")

    class _Bad:
        def get(self, workspace_id):
            raise RuntimeError("boom")

    with pytest.raises(typer.Exit):
        cli._verify_account_access_or_exit(conn, type("Acct", (), {"workspaces": _Bad()})(), 42)
    out = _squash(capsys.readouterr().out).lower()
    assert "unifiedauth" in out  # "...resolved by unified auth..." (whitespace squashed)


def test_verify_account_access_offers_reauth_then_retries(monkeypatch):
    # expired account creds -> offer re-auth; on success, rebuild the client and retry the probe once.
    from dbx_migrate_ip_acls import auth
    from dbx_migrate_ip_acls.config import Connection

    conn = Connection(account_id="acc", account_profile="acct-prof")
    ws_obj = object()
    calls = {"n": 0}

    class _Expired:
        def get(self, workspace_id):
            calls["n"] += 1
            raise ValueError("Cannot get access token; run: databricks auth login --profile acct-prof")

    class _OK:
        def get(self, workspace_id):
            return ws_obj

    monkeypatch.setattr(cli, "_reauthenticate", lambda profile: True)
    monkeypatch.setattr(auth, "account_client", lambda conn: type("Acct", (), {"workspaces": _OK()})())

    got_account, got_ws = cli._verify_account_access_or_exit(
        conn, type("Acct", (), {"workspaces": _Expired()})(), 42
    )
    assert got_ws is ws_obj  # retry with the rebuilt client succeeded
    assert calls["n"] == 1  # original client tried exactly once before re-auth


def test_disable_without_create_is_rejected():
    # --disable-existing-ip-acls without a create+assign must fail up front (before any SDK call),
    # so the workspace can't be left unprotected. (create-policy defaults on, so force it off here.)
    result = runner.invoke(
        cli.app, ["--profile", "test", "--no-create-policy", "--no-auto-assign", "--disable-existing-ip-acls"]
    )
    assert result.exit_code == 2
    assert "disable-existing-ip-acls" in _err_text(result)


def test_assign_without_create_is_rejected():
    # auto-assign with --no-create-policy is nonsensical (nothing to bind) -> rejected up front.
    result = runner.invoke(cli.app, ["--profile", "test", "--no-create-policy"])
    assert result.exit_code == 2
    assert "auto-assign" in _err_text(result)


def test_dry_run_disable_is_rejected():
    # disabling the old ACLs while the new policy only logs (dry_run) would leave no enforced
    # ingress control -> rejected up front.
    result = runner.invoke(
        cli.app, ["--profile", "test", "--policy-mode", "dry_run", "--disable-existing-ip-acls"]
    )
    assert result.exit_code == 2
    text = _err_text(result)
    assert "dry_run" in text or "dry-run" in text


def test_invalid_flags_rejected_before_profile_prompt():
    # Flag-combination errors depend only on the flags, so they must fire FIRST — before profile
    # resolution. With no --profile given (which would otherwise prompt, or error asking for one),
    # the flag-combination error is what surfaces, not a request to pick a profile.
    result = runner.invoke(cli.app, ["--no-create-policy"])
    assert result.exit_code == 2
    text = _err_text(result)
    assert "auto-assign" in text  # the flag-combination error
    assert "profile" not in text.lower()  # we never reached profile resolution


class _FakeWsClient:
    class _Cfg:
        host = "https://ws.cloud.databricks.com"

    config = _Cfg()

    def get_workspace_id(self):
        return 12345


def test_confirm_workspace_yes_displays_and_does_not_prompt(monkeypatch, capsys):
    import dbx_migrate_ip_acls.auth as auth
    from dbx_migrate_ip_acls.config import Connection

    monkeypatch.setattr(auth, "workspace_client", lambda conn: _FakeWsClient())
    monkeypatch.setattr(
        "typer.confirm", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not prompt with --yes"))
    )
    wc = cli._confirm_workspace(Connection(profile="myprof"), yes=True)
    assert isinstance(wc, _FakeWsClient)
    out = capsys.readouterr().out
    # the panel must surface all three so the target is unmistakable
    assert "12345" in out and "ws.cloud.databricks.com" in out and "myprof" in out


def test_confirm_workspace_decline_aborts(monkeypatch):
    import typer

    import dbx_migrate_ip_acls.auth as auth
    from dbx_migrate_ip_acls.config import Connection

    monkeypatch.setattr(auth, "workspace_client", lambda conn: _FakeWsClient())
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: False)
    with pytest.raises(typer.Exit) as exc:
        cli._confirm_workspace(Connection(profile="p"), yes=False)
    assert exc.value.exit_code == 0  # declining the wrong workspace is a clean abort


def test_confirm_workspace_bad_profile_exits_cleanly(monkeypatch, capsys):
    # A mistyped --profile must produce a clean, actionable message (not a raw SDK traceback).
    import typer

    import dbx_migrate_ip_acls.auth as auth
    from dbx_migrate_ip_acls.config import Connection

    monkeypatch.setattr(
        auth,
        "workspace_client",
        lambda conn: (_ for _ in ()).throw(
            ValueError("resolve: /Users/x/.databrickscfg has no sfe-cloud profile configured")
        ),
    )
    monkeypatch.setattr(cli, "_available_profiles", lambda: ["sfe-foghorn", "e2-dogfood"])
    with pytest.raises(typer.Exit) as exc:
        cli._confirm_workspace(Connection(profile="sfe-cloud"), yes=True)
    assert exc.value.exit_code == 1
    out = capsys.readouterr().out
    assert "sfe-cloud" in out and "sfe-foghorn" in out  # names the bad profile + lists available


def test_account_client_bad_profile_exits_cleanly(monkeypatch, capsys):
    import typer

    import dbx_migrate_ip_acls.auth as auth
    from dbx_migrate_ip_acls.config import Connection

    monkeypatch.setattr(
        auth,
        "account_client",
        lambda conn: (_ for _ in ()).throw(
            ValueError("resolve: /Users/x/.databrickscfg has no acct profile configured")
        ),
    )
    monkeypatch.setattr(cli, "_available_profiles", lambda: ["acct-admin"])
    with pytest.raises(typer.Exit) as exc:
        cli._account_client_or_exit(Connection(account_profile="acct"))
    assert exc.value.exit_code == 1
    out = capsys.readouterr().out
    assert "--account-profile" in out and "acct" in out


def test_workspace_client_other_valueerror_still_clean(monkeypatch, capsys):
    # A non-profile config error should also exit cleanly rather than traceback.
    import typer

    import dbx_migrate_ip_acls.auth as auth
    from dbx_migrate_ip_acls.config import Connection

    monkeypatch.setattr(
        auth,
        "workspace_client",
        lambda conn: (_ for _ in ()).throw(ValueError("default auth: cannot configure default credentials")),
    )
    with pytest.raises(typer.Exit) as exc:
        cli._confirm_workspace(Connection(profile=None), yes=True)
    assert exc.value.exit_code == 1
    assert "Databricks client" in capsys.readouterr().out


def _acl_analysis(enabled=1, disabled=0):
    import types

    ip_acls = [
        {"label": f"a{i}", "list_type": "ALLOW", "ip_addresses": ["8.8.8.8/32"]} for i in range(enabled)
    ]
    dis = [{"label": f"d{i}", "list_type": "ALLOW", "ip_addresses": ["1.1.1.1/32"]} for i in range(disabled)]
    return types.SimpleNamespace(workspace_id=42, ip_acls=ip_acls, disabled_acls=dis)


def test_acl_ip_gate_proceeds_when_enabled_with_rules(monkeypatch):
    monkeypatch.setattr("dbx_migrate_ip_acls.acl.ip_acl_enforcement_state", lambda wc: True)
    cli._acl_ip_gate(_acl_analysis(enabled=1), object(), yes=True)  # must not raise


def test_acl_ip_gate_enabled_no_rules_exits(monkeypatch, capsys):
    import typer

    monkeypatch.setattr("dbx_migrate_ip_acls.acl.ip_acl_enforcement_state", lambda wc: True)
    with pytest.raises(typer.Exit) as e:
        cli._acl_ip_gate(_acl_analysis(enabled=0), object(), yes=True)
    assert e.value.exit_code == 0
    assert "no rules" in capsys.readouterr().out.lower()


def test_acl_ip_gate_disabled_no_rules_exits(monkeypatch, capsys):
    import typer

    monkeypatch.setattr("dbx_migrate_ip_acls.acl.ip_acl_enforcement_state", lambda wc: False)
    with pytest.raises(typer.Exit) as e:
        cli._acl_ip_gate(_acl_analysis(enabled=0), object(), yes=True)
    assert e.value.exit_code == 0
    out = capsys.readouterr().out.lower()
    assert "disabled" in out and "no rules" in out


def test_acl_ip_gate_disabled_with_rules_noninteractive_aborts(monkeypatch):
    import typer

    monkeypatch.setattr("dbx_migrate_ip_acls.acl.ip_acl_enforcement_state", lambda wc: False)
    with pytest.raises(typer.Exit) as e:
        cli._acl_ip_gate(_acl_analysis(enabled=1), object(), yes=True)  # --yes: no auto re-enable
    assert e.value.exit_code == 0


def test_acl_ip_gate_disabled_with_rules_decline_reenable(monkeypatch):
    import typer

    monkeypatch.setattr("dbx_migrate_ip_acls.acl.ip_acl_enforcement_state", lambda wc: False)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: False)
    called = {"n": 0}
    monkeypatch.setattr(
        "dbx_migrate_ip_acls.acl.enable_ip_access_lists",
        lambda *a, **k: called.__setitem__("n", called["n"] + 1),
    )
    with pytest.raises(typer.Exit) as e:
        cli._acl_ip_gate(_acl_analysis(enabled=1), object(), yes=False)
    assert e.value.exit_code == 0
    assert called["n"] == 0  # declined -> must NOT re-enable


def test_acl_ip_gate_disabled_with_rules_accept_reenable_and_continues(monkeypatch, capsys):
    monkeypatch.setattr("dbx_migrate_ip_acls.acl.ip_acl_enforcement_state", lambda wc: False)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: True)
    called = {"n": 0}
    monkeypatch.setattr(
        "dbx_migrate_ip_acls.acl.enable_ip_access_lists",
        lambda *a, **k: called.__setitem__("n", called["n"] + 1),
    )
    # accept -> re-enable, then CONTINUE the run (must not raise).
    cli._acl_ip_gate(_acl_analysis(enabled=1), object(), yes=False)
    assert called["n"] == 1
    assert "continuing" in capsys.readouterr().out.lower()


def test_ensure_acl_policy_name_unique_reprompts_then_accepts(monkeypatch):
    from dbx_migrate_ip_acls.config import AclConfig

    seen = iter([True, False])  # first name exists, second is free
    monkeypatch.setattr("dbx_migrate_ip_acls.acl.policy_exists", lambda a, pid: next(seen))
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    class _Q:
        def ask(self):
            return "fresh-name"

    monkeypatch.setattr("questionary.text", lambda *a, **k: _Q())
    cfg = AclConfig(policy_name="taken")
    cli._ensure_acl_policy_name_unique(cfg, object(), 42, yes=False)
    assert cfg.policy_name == "fresh-name"


def test_ensure_acl_policy_name_unique_noninteractive_aborts(monkeypatch):
    import typer

    from dbx_migrate_ip_acls.config import AclConfig

    monkeypatch.setattr("dbx_migrate_ip_acls.acl.policy_exists", lambda a, pid: True)
    cfg = AclConfig(policy_name="taken")
    with pytest.raises(typer.Exit) as e:
        cli._ensure_acl_policy_name_unique(cfg, object(), 42, yes=True)
    assert e.value.exit_code == 1


def test_note_policy_name_shows_normalized_id(capsys):
    cli._note_policy_name("My Policy")
    assert "my-policy" in capsys.readouterr().out


def test_note_policy_name_silent_when_clean_or_blank(capsys):
    cli._note_policy_name("clean-name")  # already normalised -> no notice
    cli._note_policy_name("")  # not set -> no notice
    assert capsys.readouterr().out == ""


def test_resolve_policy_name_keeps_explicit():
    from dbx_migrate_ip_acls.config import AclConfig, Connection

    cfg = AclConfig(policy_name="chosen")
    cli._resolve_policy_name(cfg, Connection(profile="p"), object(), yes=True)
    assert cfg.policy_name == "chosen"


def test_resolve_policy_name_uses_profile_when_blank_and_noninteractive():
    from dbx_migrate_ip_acls.config import AclConfig, Connection

    class _WC:
        def get_workspace_id(self):
            return 42

    cfg = AclConfig()
    cli._resolve_policy_name(cfg, Connection(profile="myprof"), _WC(), yes=True)
    assert cfg.policy_name == "myprof"  # blank -> profile name (no prompt under --yes)


class _AclWorkspace:
    class _Cfg:
        host = "https://ws.cloud.databricks.com"

    config = _Cfg()

    def get_workspace_id(self):
        return 42

    class _Acls:
        def list(self):
            lt = type("LT", (), {"value": "ALLOW"})()
            return [
                type(
                    "A",
                    (),
                    {"label": "office", "enabled": True, "list_type": lt, "ip_addresses": ["8.8.8.8/32"]},
                )()
            ]

    ip_access_lists = _Acls()

    class _Conf:
        def get_status(self, keys):
            return {"enableIpAccessLists": "true"}

    workspace_conf = _Conf()


class _CleanAclAccount:
    """Account client that passes the migration preflight: no PAS, no VPC endpoints, no assigned
    network policy, and the chosen policy name is free (create-only uniqueness check)."""

    class _WS:
        def get(self, workspace_id):
            return type("W", (), {"private_access_settings_id": None, "network_id": None})()

    class _WNC:
        def get_workspace_network_option_rpc(self, workspace_id):
            return type("O", (), {"network_policy_id": None})()

    class _NP:
        def get_network_policy_rpc(self, network_policy_id):
            from databricks.sdk.errors import NotFound

            raise NotFound("no such policy")

    workspaces = _WS()
    workspace_network_configuration = _WNC()
    network_policies = _NP()


def test_export_writes_json_and_terraform(monkeypatch, tmp_path):
    import json

    import dbx_migrate_ip_acls.auth as auth

    monkeypatch.setattr(auth, "workspace_client", lambda conn: _AclWorkspace())
    monkeypatch.setattr(auth, "account_client", lambda conn: _CleanAclAccount())
    out = tmp_path / "policy.json"
    # propose-only (--no-create-policy --no-auto-assign) + --yes; the migration needs --account-id for
    # its PAS / VPC-endpoint / existing-policy pre-checks, but --export must still write the JSON.
    result = runner.invoke(
        cli.app,
        [
            "--profile",
            "test",
            "--account-id",
            "acc-1",
            "--export",
            str(out),
            "--no-create-policy",
            "--no-auto-assign",
            "--yes",
        ],
    )
    assert result.exit_code == 0, result.output
    data = json.loads(out.read_text())
    assert data["network_policy_id"] == "test"  # blank name -> profile name ("test")
    assert data["account_id"] == "acc-1"
    assert "egress" in data and "ingress" in data  # enforce default -> ingress block present
    # --export also writes a sibling Terraform config.
    tf = out.with_suffix(".tf")
    assert tf.exists()
    assert 'resource "databricks_account_network_policy"' in tf.read_text()


def test_write_tf_export_into_directory(tmp_path):
    payload = {"network_policy_id": "pol-x", "ingress": {"public_access": {"restriction_mode": "X"}}}
    dest = cli._write_tf_export(str(tmp_path), payload)
    assert dest.endswith("pol-x.tf")
    assert 'resource "databricks_account_network_policy" "pol_x"' in (
        (tmp_path / "pol-x.tf").read_text(encoding="utf-8")
    )


def test_export_writes_utf8_non_ascii_labels(tmp_path):
    # A non-ASCII rule label must write cleanly on any platform — Windows' default cp1252 would
    # otherwise raise UnicodeEncodeError, so both writers pin UTF-8.
    import json
    from pathlib import Path

    payload = {
        "network_policy_id": "pol",
        "ingress": {
            "public_access": {
                "restriction_mode": "RESTRICTED_ACCESS",
                "allow_rules": [{"label": "café-café", "destination": {"all_destinations": True}}],
            }
        },
    }
    tf = cli._write_tf_export(str(tmp_path), payload)
    js = cli._write_json_export(str(tmp_path), payload)
    assert "café-café" in Path(tf).read_text(encoding="utf-8")
    loaded = json.loads(Path(js).read_text(encoding="utf-8"))
    assert loaded["ingress"]["public_access"]["allow_rules"][0]["label"] == "café-café"


def test_acl_preflight_aborts_on_pas(monkeypatch):
    import typer

    monkeypatch.setattr("dbx_migrate_ip_acls.acl.workspace_pas_attached", lambda a, w: True)
    with pytest.raises(typer.Exit) as e:
        cli._acl_preflight(object(), 42, will_assign=True, yes=True)
    assert e.value.exit_code == 1


def test_acl_preflight_aborts_on_account_registered_endpoints(monkeypatch, capsys):
    # ANY registered VPC endpoint in the account aborts (AWS), even though this workspace has no PAS.
    import typer

    monkeypatch.setattr("dbx_migrate_ip_acls.acl.workspace_pas_attached", lambda a, w: False)
    monkeypatch.setattr("dbx_migrate_ip_acls.acl.account_registered_endpoint_count", lambda a: 2)
    with pytest.raises(typer.Exit) as e:
        cli._acl_preflight(object(), 42, will_assign=True, yes=True)
    assert e.value.exit_code == 1
    assert "account has 2 registered" in capsys.readouterr().out.lower()


def test_acl_preflight_aborts_on_existing_enforced_policy_when_assigning(monkeypatch):
    import typer

    monkeypatch.setattr("dbx_migrate_ip_acls.acl.workspace_pas_attached", lambda a, w: False)
    monkeypatch.setattr("dbx_migrate_ip_acls.acl.account_registered_endpoint_count", lambda a: 0)
    monkeypatch.setattr("dbx_migrate_ip_acls.acl.assigned_ingress_state", lambda a, w: ("p1", "enforced"))
    with pytest.raises(typer.Exit) as e:
        cli._acl_preflight(object(), 42, will_assign=True, yes=True)
    assert e.value.exit_code == 1


def test_acl_preflight_enforced_warns_and_proceeds_when_not_assigning(monkeypatch, capsys):
    # not assigning -> existing enforced policy stays put; warn and continue (no abort).
    monkeypatch.setattr("dbx_migrate_ip_acls.acl.workspace_pas_attached", lambda a, w: False)
    monkeypatch.setattr("dbx_migrate_ip_acls.acl.account_registered_endpoint_count", lambda a: 0)
    monkeypatch.setattr("dbx_migrate_ip_acls.acl.assigned_ingress_state", lambda a, w: ("p1", "enforced"))
    cli._acl_preflight(object(), 42, will_assign=False, yes=True)  # must not raise
    assert "isn't assigning" in capsys.readouterr().out


def test_acl_preflight_dry_run_cancels_without_promote_noninteractive(monkeypatch):
    import typer

    monkeypatch.setattr("dbx_migrate_ip_acls.acl.workspace_pas_attached", lambda a, w: False)
    monkeypatch.setattr("dbx_migrate_ip_acls.acl.account_registered_endpoint_count", lambda a: 0)
    monkeypatch.setattr("dbx_migrate_ip_acls.acl.assigned_ingress_state", lambda a, w: ("p1", "dry_run"))
    promoted = {"n": 0}
    monkeypatch.setattr(
        "dbx_migrate_ip_acls.acl.promote_dry_run_to_enforced",
        lambda *a, **k: promoted.__setitem__("n", promoted["n"] + 1),
    )
    with pytest.raises(typer.Exit) as e:
        cli._acl_preflight(object(), 42, will_assign=True, yes=True)  # --yes -> no prompt/promotion
    assert e.value.exit_code == 0 and promoted["n"] == 0


def test_acl_preflight_dry_run_promotes_when_confirmed(monkeypatch):
    import typer

    monkeypatch.setattr("dbx_migrate_ip_acls.acl.workspace_pas_attached", lambda a, w: False)
    monkeypatch.setattr("dbx_migrate_ip_acls.acl.account_registered_endpoint_count", lambda a: 0)
    monkeypatch.setattr("dbx_migrate_ip_acls.acl.assigned_ingress_state", lambda a, w: ("p1", "dry_run"))
    promoted = {"n": 0}
    monkeypatch.setattr(
        "dbx_migrate_ip_acls.acl.promote_dry_run_to_enforced",
        lambda *a, **k: promoted.__setitem__("n", promoted["n"] + 1),
    )
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: True)
    with pytest.raises(typer.Exit) as e:
        cli._acl_preflight(object(), 42, will_assign=True, yes=False)
    assert e.value.exit_code == 0 and promoted["n"] == 1  # promoted, then migration cancelled


def test_acl_preflight_passes_when_clean(monkeypatch):
    monkeypatch.setattr("dbx_migrate_ip_acls.acl.workspace_pas_attached", lambda a, w: False)
    monkeypatch.setattr("dbx_migrate_ip_acls.acl.account_registered_endpoint_count", lambda a: 0)
    monkeypatch.setattr("dbx_migrate_ip_acls.acl.assigned_ingress_state", lambda a, w: (None, None))
    cli._acl_preflight(object(), 42, will_assign=True, yes=True)  # must not raise


def test_acl_preflight_warns_but_proceeds_when_pas_unknown(monkeypatch, capsys):
    monkeypatch.setattr("dbx_migrate_ip_acls.acl.workspace_pas_attached", lambda a, w: None)
    monkeypatch.setattr("dbx_migrate_ip_acls.acl.account_registered_endpoint_count", lambda a: 0)
    monkeypatch.setattr("dbx_migrate_ip_acls.acl.assigned_ingress_state", lambda a, w: (None, None))
    cli._acl_preflight(object(), 42, will_assign=True, yes=True)  # must not raise
    assert "couldn't verify" in capsys.readouterr().out.lower()


def test_acl_preflight_skips_both_privatelink_checks_on_azure(monkeypatch, capsys):
    # Azure has no PAS and no account VPC endpoints — neither PrivateLink check should even be
    # consulted, and a would-be-aborting endpoint count must NOT abort.
    called = {"pas": 0, "endpoints": 0}
    monkeypatch.setattr(
        "dbx_migrate_ip_acls.acl.workspace_pas_attached",
        lambda a, w: called.__setitem__("pas", called["pas"] + 1) or True,
    )
    monkeypatch.setattr(
        "dbx_migrate_ip_acls.acl.account_registered_endpoint_count",
        lambda a: called.__setitem__("endpoints", called["endpoints"] + 1) or 5,
    )
    monkeypatch.setattr("dbx_migrate_ip_acls.acl.assigned_ingress_state", lambda a, w: (None, None))
    cli._acl_preflight(object(), 42, will_assign=True, yes=True, is_azure=True)  # must not raise
    assert called == {"pas": 0, "endpoints": 0}  # neither PrivateLink helper was called
    assert "azure" in capsys.readouterr().out.lower()


def _wc_host(host):
    return type("WC", (), {"config": type("Cfg", (), {"host": host})()})()


def test_resolve_account_host_derives_from_workspace_when_not_pinned(capsys):
    from dbx_migrate_ip_acls.config import Connection

    # staging workspace, --account-host not pinned -> switch to the staging account console
    conn = Connection(account_host_explicit=False)
    cli._resolve_account_host(conn, _wc_host("https://dbc-x.staging.cloud.databricks.com"))
    assert conn.account_host == "https://accounts.staging.cloud.databricks.com"
    assert "accounts.staging.cloud.databricks.com" in capsys.readouterr().out


def test_resolve_account_host_respects_explicit(capsys):
    from dbx_migrate_ip_acls.config import Connection

    conn = Connection(account_host="https://accounts.cloud.databricks.com", account_host_explicit=True)
    cli._resolve_account_host(conn, _wc_host("https://dbc-x.staging.cloud.databricks.com"))
    assert conn.account_host == "https://accounts.cloud.databricks.com"  # unchanged
    assert capsys.readouterr().out == ""  # no announcement


def test_resolve_account_host_noop_for_prod_or_unknown(capsys):
    from dbx_migrate_ip_acls.config import Connection

    # prod workspace -> derived host equals the default, so no change/announcement
    conn = Connection(account_host_explicit=False)
    cli._resolve_account_host(conn, _wc_host("https://dbc-x.cloud.databricks.com"))
    assert conn.account_host == "https://accounts.cloud.databricks.com"
    # unrecognised host -> keep the default
    conn2 = Connection(account_host_explicit=False)
    cli._resolve_account_host(conn2, _wc_host(None))
    assert conn2.account_host == "https://accounts.cloud.databricks.com"


def test_acl_preflight_azure_still_runs_assigned_policy_check(monkeypatch):
    # Skipping PrivateLink doesn't skip the existing-assigned-policy guard.
    import typer

    monkeypatch.setattr("dbx_migrate_ip_acls.acl.assigned_ingress_state", lambda a, w: ("p1", "enforced"))
    with pytest.raises(typer.Exit) as e:
        cli._acl_preflight(object(), 42, will_assign=True, yes=True, is_azure=True)
    assert e.value.exit_code == 1


def test_write_json_export_to_directory_uses_policy_id_filename(tmp_path):
    import json
    from pathlib import Path

    dest = cli._write_json_export(str(tmp_path), {"network_policy_id": "my-acl", "egress": {}})
    assert dest == str(tmp_path / "my-acl.json")
    assert json.loads(Path(dest).read_text())["network_policy_id"] == "my-acl"


def test_write_json_export_creates_missing_parent_dirs(tmp_path):
    from pathlib import Path

    target = tmp_path / "nested" / "sub" / "policy.json"
    dest = cli._write_json_export(str(target), {"network_policy_id": "p"})
    assert dest == str(target) and Path(target).exists()


def test_write_json_export_bad_path_errors_cleanly(tmp_path):
    import typer

    # a path whose parent is a *file* can't be created -> clean Exit, not a traceback
    afile = tmp_path / "afile"
    afile.write_text("x")
    with pytest.raises(typer.Exit) as e:
        cli._write_json_export(str(afile / "policy.json"), {"network_policy_id": "p"})
    assert e.value.exit_code == 1


# --- expired-credentials detection + offer-to-reauthenticate -----------------------------------

_EXPIRED = (
    "default auth: databricks-cli: cannot get access token: Error: A new access token could "
    "not be retrieved because the refresh token is invalid. To reauthenticate, run the "
    "following command:\n  $ databricks auth login --profile p"
)


def test_is_expired_auth_detects_and_ignores():
    assert cli._is_expired_auth(_EXPIRED)
    assert cli._is_expired_auth("databricks-cli: cannot get access token")
    # not expiry — a mistyped profile or missing config must NOT be treated as re-auth
    assert not cli._is_expired_auth("default auth: cannot configure default credentials")
    assert not cli._is_expired_auth("resolve: /x/.databrickscfg has no p profile configured")


def test_workspace_client_expired_offers_reauth_and_retries(monkeypatch):
    import subprocess

    import dbx_migrate_ip_acls.auth as auth
    from dbx_migrate_ip_acls.config import Connection

    calls = {"n": 0}
    sentinel = object()

    def _build(conn):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ValueError(_EXPIRED)
        return sentinel

    monkeypatch.setattr(auth, "workspace_client", _build)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: True)
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/databricks")
    ran = {}

    def _run(argv, *a, **k):
        ran["argv"] = argv
        return type("R", (), {"returncode": 0})()

    monkeypatch.setattr(subprocess, "run", _run)

    wc = cli._workspace_client_or_exit(Connection(profile="p"))
    assert wc is sentinel  # retried build returned the client
    assert calls["n"] == 2  # built again after re-auth
    assert ran["argv"] == ["databricks", "auth", "login", "--profile", "p"]


def test_expired_decline_exits_with_command(monkeypatch, capsys):
    import typer

    import dbx_migrate_ip_acls.auth as auth
    from dbx_migrate_ip_acls.config import Connection

    monkeypatch.setattr(auth, "workspace_client", lambda conn: (_ for _ in ()).throw(ValueError(_EXPIRED)))
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: False)  # user declines
    with pytest.raises(typer.Exit) as e:
        cli._workspace_client_or_exit(Connection(profile="p"))
    assert e.value.exit_code == 1
    assert "databricks auth login --profile p" in capsys.readouterr().out


def test_expired_noninteractive_prints_command_and_exits(monkeypatch, capsys):
    import typer

    import dbx_migrate_ip_acls.auth as auth
    from dbx_migrate_ip_acls.config import Connection

    monkeypatch.setattr(auth, "workspace_client", lambda conn: (_ for _ in ()).throw(ValueError(_EXPIRED)))
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)  # non-interactive: never launch a browser
    monkeypatch.setattr(
        "typer.confirm",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not prompt non-interactively")),
    )
    with pytest.raises(typer.Exit) as e:
        cli._workspace_client_or_exit(Connection(profile="p"))
    assert e.value.exit_code == 1
    assert "databricks auth login --profile p" in capsys.readouterr().out


def test_expired_databricks_cli_not_on_path_exits(monkeypatch, capsys):
    import typer

    import dbx_migrate_ip_acls.auth as auth
    from dbx_migrate_ip_acls.config import Connection

    monkeypatch.setattr(auth, "workspace_client", lambda conn: (_ for _ in ()).throw(ValueError(_EXPIRED)))
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: True)
    monkeypatch.setattr("shutil.which", lambda name: None)  # databricks CLI missing
    with pytest.raises(typer.Exit) as e:
        cli._workspace_client_or_exit(Connection(profile="p"))
    assert e.value.exit_code == 1
    assert "PATH" in capsys.readouterr().out


def test_reauth_profile_parsed_from_error_message():
    # the SDK error names the exact profile to re-auth; prefer it over the assumed one.
    assert cli._reauth_profile(_EXPIRED, "assumed") == "p"
    acct = (
        "... To reauthenticate, run:\n  $ databricks auth login --profile sfe-account. "
        "Config: host=https://accounts.cloud.databricks.com"
    )
    assert cli._reauth_profile(acct, "sfe-foghorn") == "sfe-account"  # not the assumed workspace one
    # no profile named -> fall back to what we asked for
    assert cli._reauth_profile("some unrelated error", "fallback") == "fallback"


def test_expired_reauths_profile_named_in_error_not_assumed(monkeypatch):
    # The real bug: account access resolves to a *different* auto-discovered profile (sfe-account)
    # than --profile (sfe-foghorn). Re-auth must target the profile the SDK error names.
    import subprocess

    import dbx_migrate_ip_acls.auth as auth
    from dbx_migrate_ip_acls.config import Connection

    acct_expired = (
        "default auth: databricks-cli: cannot get access token: the refresh token is "
        "invalid. To reauthenticate, run:\n  $ databricks auth login --profile "
        "sfe-account. Config: host=https://accounts.cloud.databricks.com"
    )
    calls = {"n": 0}
    sentinel = object()

    def _build(conn):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ValueError(acct_expired)
        return sentinel

    monkeypatch.setattr(auth, "account_client", _build)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: True)
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/databricks")
    ran = {}

    def _run(argv, *a, **k):
        ran["argv"] = argv
        return type("R", (), {"returncode": 0})()

    monkeypatch.setattr(subprocess, "run", _run)
    # workspace profile is sfe-foghorn, but the account error names sfe-account -> re-auth that one
    acc = cli._account_client_or_exit(Connection(profile="sfe-foghorn"))
    assert acc is sentinel
    assert ran["argv"] == ["databricks", "auth", "login", "--profile", "sfe-account"]


# --- --export overwrite guard ------------------------------------------------------------------


def test_write_json_export_confirm_declined_keeps_existing_file(monkeypatch, tmp_path):
    dest = tmp_path / "p.json"
    dest.write_text("ORIGINAL", encoding="utf-8")
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: False)  # decline overwrite
    result = cli._write_json_export(str(dest), {"network_policy_id": "p"}, yes=False)
    assert result is None
    assert dest.read_text(encoding="utf-8") == "ORIGINAL"  # untouched


def test_write_json_export_confirm_accepted_overwrites(monkeypatch, tmp_path):
    import json

    dest = tmp_path / "p.json"
    dest.write_text("ORIGINAL", encoding="utf-8")
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: True)  # accept overwrite
    result = cli._write_json_export(str(dest), {"network_policy_id": "p"}, yes=False)
    assert result == str(dest)
    assert json.loads(dest.read_text(encoding="utf-8"))["network_policy_id"] == "p"


def test_write_json_export_yes_overwrites_without_prompt(monkeypatch, tmp_path):
    dest = tmp_path / "p.json"
    dest.write_text("ORIGINAL", encoding="utf-8")
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(
        "typer.confirm",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not prompt with --yes")),
    )
    assert cli._write_json_export(str(dest), {"network_policy_id": "p"}, yes=True) == str(dest)


def test_write_tf_export_confirm_declined_keeps_existing_file(monkeypatch, tmp_path):
    dest = tmp_path / "p.tf"
    dest.write_text("ORIGINAL", encoding="utf-8")
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: False)
    # pass the .tf path (writer applies .with_suffix('.tf') -> same file)
    result = cli._write_tf_export(str(dest), {"network_policy_id": "p"}, yes=False)
    assert result is None
    assert dest.read_text(encoding="utf-8") == "ORIGINAL"


def test_write_export_noninteractive_overwrites_silently(monkeypatch, tmp_path):
    # non-interactive (no TTY) must overwrite without prompting, for scripted runs.
    dest = tmp_path / "p.json"
    dest.write_text("ORIGINAL", encoding="utf-8")
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    monkeypatch.setattr(
        "typer.confirm",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not prompt non-interactively")),
    )
    assert cli._write_json_export(str(dest), {"network_policy_id": "p"}, yes=False) == str(dest)


# --- _reconcile_disabled_lists (offer to re-enable + include disabled lists) --------------------


def test_reconcile_no_disabled_returns_unchanged():
    import types

    from dbx_migrate_ip_acls.config import AclConfig

    a = types.SimpleNamespace(disabled_acls=[])
    assert cli._reconcile_disabled_lists(a, AclConfig(), object(), yes=True) is a


def test_reconcile_noninteractive_flags_but_never_enables(monkeypatch, capsys):
    import types

    from dbx_migrate_ip_acls.config import AclConfig

    monkeypatch.setattr(
        "dbx_migrate_ip_acls.acl.enable_disabled_lists",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not enable non-interactively")),
    )
    a = types.SimpleNamespace(disabled_acls=[{"label": "corp-vpn"}])
    out = cli._reconcile_disabled_lists(a, AclConfig(create_policy=True), object(), yes=True)
    assert out is a
    assert "WILL NOT be migrated" in capsys.readouterr().out


def _fake_checkbox(selection):
    """A stand-in for questionary.checkbox(...) whose .ask() returns `selection`."""
    return type("CB", (), {"ask": lambda self: selection})()


def test_reconcile_select_none_does_not_enable(monkeypatch):
    import types

    from dbx_migrate_ip_acls.config import AclConfig

    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("questionary.checkbox", lambda *a, **k: _fake_checkbox([]))  # select none
    monkeypatch.setattr(
        "dbx_migrate_ip_acls.acl.enable_disabled_lists",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("none selected -> must not enable")),
    )
    a = types.SimpleNamespace(disabled_acls=[{"label": "corp-vpn"}])
    assert cli._reconcile_disabled_lists(a, AclConfig(create_policy=True), object(), yes=False) is a


def test_reconcile_enables_only_the_selected_subset_and_reanalyzes(monkeypatch):
    import types

    from dbx_migrate_ip_acls.config import AclConfig

    fresh = types.SimpleNamespace(disabled_acls=[], allow_specs=[{"cidrs": ["8.8.8.8/32"]}])
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    # user ticks only "corp-vpn" out of the two disabled lists
    monkeypatch.setattr("questionary.checkbox", lambda *a, **k: _fake_checkbox(["corp-vpn"]))
    seen = {}
    monkeypatch.setattr(
        "dbx_migrate_ip_acls.acl.enable_disabled_lists",
        lambda wc, labels: (seen.update(labels=labels) or (len(labels), [])),
    )
    monkeypatch.setattr("dbx_migrate_ip_acls.acl.analyze", lambda cfg, wc: fresh)
    a = types.SimpleNamespace(disabled_acls=[{"label": "corp-vpn"}, {"label": "office"}])
    out = cli._reconcile_disabled_lists(a, AclConfig(create_policy=True), object(), yes=False)
    assert out is fresh  # re-read analysis folds in the selected list
    assert seen["labels"] == ["corp-vpn"]  # only the ticked subset is enabled, not all


# --- propose-only runs must not offer/perform re-enables (no writes) ---------------------------


def test_acl_ip_gate_disabled_propose_only_skips_reenable(monkeypatch, capsys):
    # toggle OFF + rules + --no-create-policy: must NOT prompt or enable enforcement; proceeds.
    monkeypatch.setattr("dbx_migrate_ip_acls.acl.ip_acl_enforcement_state", lambda wc: False)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(
        "typer.confirm",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("propose-only must not prompt")),
    )
    monkeypatch.setattr(
        "dbx_migrate_ip_acls.acl.enable_ip_access_lists",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("propose-only must not enable")),
    )
    cli._acl_ip_gate(_acl_analysis(enabled=1), object(), yes=False, create_policy=False)  # no raise
    assert "propose-only" in capsys.readouterr().out.lower()


def test_reconcile_propose_only_flags_but_does_not_offer(monkeypatch, capsys):
    import types

    from dbx_migrate_ip_acls.config import AclConfig

    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(
        "typer.confirm",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("propose-only must not prompt")),
    )
    monkeypatch.setattr(
        "dbx_migrate_ip_acls.acl.enable_disabled_lists",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("propose-only must not enable")),
    )
    a = types.SimpleNamespace(disabled_acls=[{"label": "corp-vpn"}])
    out = cli._reconcile_disabled_lists(a, AclConfig(create_policy=False), object(), yes=False)
    assert out is a
    o = capsys.readouterr().out.lower()
    assert "will not be migrated" in o and "propose-only" in o
