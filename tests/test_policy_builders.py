"""Unit tests for the SDK policy-block builders + policy_name."""

from __future__ import annotations

from dbx_migrate_ip_acls import policy


def _allow(**kw):
    base = {
        "label": "r",
        "cidrs": ["1.2.3.4/32"],
        "destination": "all_destinations",
        "identity_type": "ALL_USERS",
        "identities": [],
    }
    base.update(kw)
    return base


def test_ingress_rule_ip_ranges_wrapped():
    rule = policy.build_ingress_rule(_allow(), "dry-run").as_dict()
    assert rule["origin"]["included_ip_ranges"]["ip_ranges"] == ["1.2.3.4/32"]
    assert rule["destination"]["all_destinations"] is True
    assert rule["label"].endswith("(dry-run)")


def test_ingress_rule_verbatim_label_when_no_mode():
    # the migration recreates labels exactly — mode_label=None -> no suffix.
    rule = policy.build_ingress_rule(_allow(label="office"), None).as_dict()
    assert rule["label"] == "office"


def test_ingress_rule_apps_and_lakebase_destinations():
    apps = policy.build_ingress_rule(_allow(destination="apps_runtime"), "dry-run").as_dict()
    assert apps["destination"]["apps_runtime"]["all_destinations"] is True
    lb = policy.build_ingress_rule(_allow(destination="lakebase_runtime"), "dry-run").as_dict()
    assert lb["destination"]["lakebase_runtime"]["all_destinations"] is True


def test_ingress_rule_selected_identities_auth_omitted_on_broad_destinations():
    # The CBI API rejects an authentication block on Apps / Lakebase / all_destinations rules, so
    # even with SELECTED_IDENTITIES the builder must omit it (otherwise apply 400s).
    ids = [
        {"principal_id": 42, "principal_type": "USER"},
        {"principal_id": 7, "principal_type": "SERVICE_PRINCIPAL"},
    ]
    for dest in ("all_destinations", "apps_runtime", "lakebase_runtime"):
        spec = _allow(destination=dest, identity_type="SELECTED_IDENTITIES", identities=ids)
        rule = policy.build_ingress_rule(spec, "enforced").as_dict()
        assert "authentication" not in rule, dest


def test_catch_all_origin():
    rule = policy.build_ingress_rule(_allow(catch_all=True), "dry-run").as_dict()
    assert rule["origin"]["all_ip_ranges"] is True
    assert "included_ip_ranges" not in rule["origin"]


def test_deny_rule_shape():
    rule = policy.build_deny_rule({"label": "d", "cidrs": ["9.9.9.0/24"]}, "enforced").as_dict()
    assert rule["origin"]["included_ip_ranges"]["ip_ranges"] == ["9.9.9.0/24"]
    assert rule["destination"]["all_destinations"] is True


def test_deny_without_allow_injects_catch_all():
    notes = []
    block = policy.build_ingress_block(
        allow=[],
        deny=[{"label": "np-deny", "cidrs": ["9.9.9.0/24"]}],
        mode_label="dry-run",
        note=notes.append,
    ).as_dict()
    pub = block["public_access"]
    assert pub["allow_rules"][0]["origin"]["all_ip_ranges"] is True
    assert pub["deny_rules"]
    assert any("catch-all" in n for n in notes)


def test_allow_with_deny_no_catch_all():
    notes = []
    block = policy.build_ingress_block(
        allow=[_allow()],
        deny=[{"label": "d", "cidrs": ["9.9.9.0/24"]}],
        mode_label="dry-run",
        note=notes.append,
    ).as_dict()
    pub = block["public_access"]
    assert len(pub["allow_rules"]) == 1
    assert pub["allow_rules"][0]["origin"].get("all_ip_ranges") is None
    assert not notes  # no catch-all note


def test_restriction_mode_always_restricted():
    block = policy.build_ingress_block([_allow()], [], "dry-run").as_dict()
    assert block["public_access"]["restriction_mode"] == "RESTRICTED_ACCESS"


def test_full_access_egress():
    egr = policy.build_full_access_egress().as_dict()
    assert egr["network_access"]["restriction_mode"] == "FULL_ACCESS"


def test_policy_name_single_truncates_prefix():
    assert policy.policy_name("np-helper") == "np-helper"
    long = policy.policy_name("x" * 50)
    assert len(long) == 30


def test_policy_name_per_workspace_keeps_full_id():
    name = policy.policy_name("np-helper", workspace_id=1657683783405196)
    # the full workspace id is always preserved, even if the prefix must be trimmed
    assert name.endswith("-ws-1657683783405196")


def test_policy_name_per_workspace_trims_long_prefix():
    name = policy.policy_name("really-long-prefix-name", workspace_id=1657683783405196)
    assert name.endswith("-ws-1657683783405196")
    assert not name.startswith("really-long-prefix-name")


def test_policy_name_current_workspace_uses_profile_suffix():
    assert policy.policy_name("np-helper", suffix="prod") == "np-helper-prod"


def test_policy_name_suffix_is_slugified():
    name = policy.policy_name("np", suffix="My Prod Workspace!")
    assert name == "np-my-prod-workspace"


def test_policy_name_explicit_overrides_and_slugifies():
    assert policy.policy_name("np", explicit="My Prod Policy!") == "my-prod-policy"
    assert policy.policy_name("np", workspace_id=42, explicit="chosen-name") == "chosen-name"


def test_policy_name_explicit_capped_to_limit():
    assert len(policy.policy_name("np", explicit="x" * 60)) == 30


def test_policy_name_explicit_empty_slug_falls_back_to_prefix():
    assert policy.policy_name("np-helper", explicit="!!!") == "np-helper"
