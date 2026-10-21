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


# --------------------------------------------------------------------- private access (front-end PL)
def test_private_access_allow_all_registered():
    blk = policy.build_private_access_block("ALLOW_ALL_REGISTERED_ENDPOINTS", [], "lbl").as_dict()
    assert blk["restriction_mode"] == "ALLOW_ALL_REGISTERED_ENDPOINTS"
    assert "allow_rules" not in blk  # no explicit rules for allow-all


def test_private_access_restricted_enumerates_endpoint_ids():
    blk = policy.build_private_access_block("RESTRICTED_ACCESS", ["el-1", "el-2"], "corp-pas").as_dict()
    assert blk["restriction_mode"] == "RESTRICTED_ACCESS"
    rule = blk["allow_rules"][0]
    assert rule["label"] == "corp-pas"
    assert rule["origin"]["endpoints"]["endpoint_ids"] == ["el-1", "el-2"]
    assert rule["destination"]["all_destinations"] is True


def test_private_access_restricted_without_ids_has_no_allow_rules():
    # an endpoint-scoped PAS that allows nothing -> RESTRICTED_ACCESS with no allow rules (deny-all).
    blk = policy.build_private_access_block("RESTRICTED_ACCESS", [], "lbl").as_dict()
    assert blk["restriction_mode"] == "RESTRICTED_ACCESS"
    assert "allow_rules" not in blk


class _Plan:
    def __init__(self, restriction_mode, endpoint_ids=None, label="pl"):
        self.restriction_mode = restriction_mode
        self.endpoint_ids = endpoint_ids or []
        self.label = label


def test_ingress_block_includes_private_access_when_plan_given():
    block = policy.build_ingress_block(
        [_allow()], [], None, private_plan=_Plan("ALLOW_ALL_REGISTERED_ENDPOINTS")
    ).as_dict()
    assert block["public_access"]["allow_rules"]  # public still built
    assert block["private_access"]["restriction_mode"] == "ALLOW_ALL_REGISTERED_ENDPOINTS"


def test_ingress_block_public_disabled_is_deny_all_and_drops_ip_acls():
    notes = []
    block = policy.build_ingress_block(
        [_allow()],
        [{"label": "d", "cidrs": ["9.9.9.0/24"]}],
        None,
        note=notes.append,
        public_enabled=False,
        private_plan=_Plan("RESTRICTED_ACCESS", ["el-1"]),
    ).as_dict()
    pub = block["public_access"]
    assert pub["restriction_mode"] == "RESTRICTED_ACCESS"
    assert "allow_rules" not in pub and "deny_rules" not in pub  # IP ACLs not recreated as public
    assert any("disabled" in n for n in notes)
    assert block["private_access"]["allow_rules"][0]["origin"]["endpoints"]["endpoint_ids"] == ["el-1"]


def test_ingress_block_public_disabled_no_ip_acls_emits_no_note():
    notes = []
    block = policy.build_ingress_block(
        [],
        [],
        None,
        note=notes.append,
        public_enabled=False,
        private_plan=_Plan("ALLOW_ALL_REGISTERED_ENDPOINTS"),
    ).as_dict()
    assert block["public_access"]["restriction_mode"] == "RESTRICTED_ACCESS"
    assert not notes  # nothing to warn about dropping when there were no IP ACLs


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
