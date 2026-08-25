"""Tests for the render-layer display helpers: ACL tables, decisions panel, apply results, URL."""

from __future__ import annotations

import types

from dbx_migrate_ip_acls import console, render


def _acl_analysis_obj(disabled=True):
    return types.SimpleNamespace(
        workspace_id=42,
        ip_acls=[{"label": "office", "list_type": "ALLOW", "ip_addresses": ["8.8.8.8/32"]}],
        disabled_acls=(
            [{"label": "old-vpn", "list_type": "ALLOW", "ip_addresses": ["1.2.3.4/32"]}] if disabled else []
        ),
        allow_specs=[{"label": "office", "cidrs": ["8.8.8.8/32"]}],  # office (enabled) is migrated
        deny_specs=[],
    )


def _squash(out: str) -> str:
    """Strip ANSI + panel borders + whitespace so wrapped/folded table cells stay matchable."""
    import re

    return re.sub(r"[\s│|╭╮╰╯─┃┏┓┗┛┡┩╇━┳┻┼╈]+", "", re.sub(r"\x1b\[[0-9;]*m", "", out))


def test_acl_disabled_notice_flags_disabled_rules(capsys):
    render.acl_disabled_notice(_acl_analysis_obj(disabled=True))
    out = capsys.readouterr().out
    assert "old-vpn" in out and "will not be migrated" in out.lower() and "review" in out.lower()


def test_acl_disabled_notice_silent_when_none(capsys):
    render.acl_disabled_notice(_acl_analysis_obj(disabled=False))
    assert capsys.readouterr().out == ""


def test_acl_current_config_shows_enabled_and_disabled(capsys):
    render.acl_current_config(_acl_analysis_obj(disabled=True))
    out = capsys.readouterr().out
    assert "office" in out and "old-vpn" in out  # both enabled + disabled lists shown
    assert "(DISABLED)" in out  # header reflects workspace enforcement state (default off)


def test_acl_current_config_has_will_be_migrated_column(capsys, monkeypatch):
    # widen the console so the extra column's header/cells don't fold, keeping assertions stable
    monkeypatch.setattr(console.console, "_width", 240)
    render.acl_current_config(_acl_analysis_obj(disabled=True))
    out = _squash(capsys.readouterr().out)
    assert "will_be_migrated" in out  # the new column is present


def test_acl_current_config_header_reflects_enabled_state(capsys):
    render.acl_current_config(_acl_analysis_obj(disabled=False), workspace_enabled=True)
    assert "(ENABLED)" in capsys.readouterr().out


def test_acl_preview_shows_egress_block_and_full_access_warning(capsys):
    from dbx_migrate_ip_acls.config import AclConfig

    preview = {
        "ingress": {"public_access": {"restriction_mode": "RESTRICTED_ACCESS"}},
        "egress": {"network_access": {"restriction_mode": "FULL_ACCESS"}},
    }
    render.acl_preview(preview, AclConfig(policy_mode="enforce"))
    out = capsys.readouterr().out.lower()
    assert "restricted_access" in out  # ingress block shown
    assert "full_access" in out  # egress block shown
    assert "unrestricted" in out and "egress" in out  # the FULL_ACCESS warning is present


def test_acl_preview_reports_egress_copied_from_existing_policy(capsys):
    from dbx_migrate_ip_acls.config import AclConfig

    preview = {
        "ingress": {"public_access": {"restriction_mode": "RESTRICTED_ACCESS"}},
        "egress": {"network_access": {"restriction_mode": "RESTRICTED_ACCESS"}},
    }
    render.acl_preview(preview, AclConfig(policy_mode="enforce"), egress_source="default-policy")
    out = capsys.readouterr().out.lower()
    assert "copied" in out and "default-policy" in out  # names the source policy
    assert "unrestricted" not in out  # the FULL_ACCESS warning is suppressed when egress is copied


def test_acl_decisions_renders(capsys):
    from dbx_migrate_ip_acls.config import AclConfig

    render.acl_decisions(AclConfig(policy_name="my-acl"))
    out = capsys.readouterr().out
    assert "migration configuration" in out.lower()


def test_decisions_panel_renders_flag_dash_names(capsys):
    # settings must display in dash form so they match the CLI flags (copy-paste as `--<name>`).
    console.decisions_panel("cfg", [("auto_assign", True, "meaning")])
    out = capsys.readouterr().out
    assert "auto-assign" in out and "auto_assign" not in out


def test_apply_results_reports_id_and_url(capsys):
    render.apply_results(
        [{"target": "single", "action": "created", "policy_id": "np-helper"}],
        account_host="https://accounts.cloud.databricks.com",
        account_id="ACC",
    )
    out = capsys.readouterr().out
    assert "network policy id: np-helper" in out
    assert "network-access-policies/np-helper?account_id=ACC" in out


def test_apply_results_reports_id_without_url_when_no_account(capsys):
    render.apply_results([{"target": "single", "action": "updated", "policy_id": "np-helper"}])
    out = capsys.readouterr().out
    assert "network policy id: np-helper" in out
    assert "network-access-policies" not in out  # no URL without host/account_id


def test_apply_results_reports_errors(capsys):
    render.apply_results([{"target": 123, "error": "boom"}])
    out = capsys.readouterr().out
    assert "boom" in out


def test_policy_url_format():
    url = render.policy_url("https://accounts.cloud.databricks.com", "ACC123", "np-helper")
    assert url == (
        "https://accounts.cloud.databricks.com/security/networking/"
        "network-access-policies/np-helper?account_id=ACC123"
    )


def test_policy_url_strips_trailing_slash():
    url = render.policy_url("https://accounts.cloud.databricks.com/", "ACC", "p")
    assert "databricks.com/security" in url
    assert "//security" not in url
