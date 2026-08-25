"""Unit tests for the ACL migration engine: analyze, build/apply, the workspace/account state
queries, and the IP-ACL enforcement toggle."""

from __future__ import annotations

from dbx_migrate_ip_acls import acl as acl_core
from dbx_migrate_ip_acls.config import AclConfig


class _FakeAcl:
    def __init__(self, label, list_type, enabled, ips):
        self.label, self.enabled, self.ip_addresses = label, enabled, ips
        self.list_type = type("LT", (), {"value": list_type})()


class _FakeWs:
    def __init__(self, acls, ws_id=42):
        self.ip_access_lists = type("A", (), {"list": lambda self=None: acls})()
        self._id = ws_id

    def get_workspace_id(self):
        return self._id


def test_acl_analyze_splits_allow_deny_ipv4_only():
    ws = _FakeWs(
        [
            _FakeAcl("office", "ALLOW", True, ["8.8.8.8/32", "2001:db8::/32"]),
            _FakeAcl("bad", "BLOCK", True, ["9.9.9.0/24"]),
            _FakeAcl("off", "ALLOW", False, ["1.1.1.1"]),
        ]
    )
    a = acl_core.analyze(AclConfig(), ws)
    assert a.workspace_id == 42
    assert len(a.allow_specs) == 1 and a.allow_specs[0]["cidrs"] == ["8.8.8.8/32"]  # ipv6 dropped
    assert len(a.deny_specs) == 1 and a.deny_specs[0]["cidrs"] == ["9.9.9.0/24"]
    # labels are migrated verbatim — the original ACL label, no prefix and no mode suffix
    assert a.allow_specs[0]["label"] == "office"
    assert a.deny_specs[0]["label"] == "bad"
    # the disabled list is surfaced (flagged) but NOT migrated; only enabled lists become specs
    assert len(a.ip_acls) == 2
    assert [d["label"] for d in a.disabled_acls] == ["off"]


def test_acl_analyze_labels_have_no_mode_suffix():
    ws = _FakeWs([_FakeAcl("office", "ALLOW", True, ["8.8.8.8/32"])])
    cfg = AclConfig(policy_mode="enforce")
    prev = acl_core.preview_block(acl_core.analyze(cfg, ws), cfg)
    label = prev["ingress"]["public_access"]["allow_rules"][0]["label"]
    assert label == "office"


def test_acl_analyze_all_disabled_leaves_nothing_to_migrate():
    ws = _FakeWs([_FakeAcl("off", "ALLOW", False, ["1.1.1.1/32"])])
    a = acl_core.analyze(AclConfig(), ws)
    assert a.ip_acls == [] and a.allow_specs == [] and a.deny_specs == []
    assert [d["label"] for d in a.disabled_acls] == ["off"]


class _CreateCapturingAccount:
    """An account client that captures the network_policy_id sent to create (workspace has no
    existing policy)."""

    def __init__(self, captured):
        from databricks.sdk.errors import NotFound

        self._NotFound = NotFound
        self.captured = captured

        parent = self

        class _NP:
            def get_network_policy_rpc(self, network_policy_id):
                raise parent._NotFound("no such policy")

            def create_network_policy_rpc(self, network_policy):
                parent.captured["id"] = network_policy.network_policy_id
                parent.captured["policy"] = network_policy
                return network_policy

        self.network_policies = _NP()


def test_acl_apply_explicit_policy_name_is_slugified_and_capped():
    captured = {}
    ws = _FakeWs([_FakeAcl("office", "ALLOW", True, ["8.8.8.8/32"])], ws_id=42)
    cfg = AclConfig(policy_name="My Custom ACL Policy", create_policy=True, auto_assign=False)
    acl_core.apply(acl_core.analyze(cfg, ws), cfg, _CreateCapturingAccount(captured), account_id="a")
    assert captured["id"] == "my-custom-acl-policy"

    captured2 = {}
    cfg2 = AclConfig(policy_name="x" * 60, create_policy=True, auto_assign=False)
    acl_core.apply(acl_core.analyze(cfg2, ws), cfg2, _CreateCapturingAccount(captured2), account_id="a")
    assert len(captured2["id"]) == 30


def test_acl_apply_falls_back_to_workspace_id_when_no_name():
    # With no explicit/entered name (CLI resolves this, but defend the fallback), the id is the ws id.
    captured = {}
    ws = _FakeWs([_FakeAcl("office", "ALLOW", True, ["8.8.8.8/32"])], ws_id=42)
    cfg = AclConfig(create_policy=True, auto_assign=False)
    acl_core.apply(acl_core.analyze(cfg, ws), cfg, _CreateCapturingAccount(captured), account_id="a")
    assert captured["id"] == "42"


class _FakeWorkspaceConf:
    def __init__(self, initial="true"):
        self._val = initial
        self.set_calls = []

    def get_status(self, keys):
        assert keys == "enableIpAccessLists"
        return {"enableIpAccessLists": self._val}

    def set_status(self, contents):
        self.set_calls.append(contents)
        self._val = contents.get("enableIpAccessLists", self._val)


class _WsWithConf:
    def __init__(self, initial="true"):
        self.workspace_conf = _FakeWorkspaceConf(initial)


def test_enable_ip_access_lists_flips_toggle_on():
    ws = _WsWithConf(initial="false")
    assert acl_core.enable_ip_access_lists(ws) is True
    assert ws.workspace_conf.set_calls == [{"enableIpAccessLists": "true"}]


def test_enable_ip_access_lists_idempotent_when_already_on():
    ws = _WsWithConf(initial="true")
    assert acl_core.enable_ip_access_lists(ws) is False
    assert ws.workspace_conf.set_calls == []


def test_disable_ip_access_lists_flips_toggle_off():
    ws = _WsWithConf(initial="true")
    assert acl_core.disable_ip_access_lists(ws) is True
    assert ws.workspace_conf.set_calls == [{"enableIpAccessLists": "false"}]


def test_disable_ip_access_lists_idempotent_when_already_off():
    ws = _WsWithConf(initial="false")
    assert acl_core.disable_ip_access_lists(ws) is False
    assert ws.workspace_conf.set_calls == []


def test_disable_ip_access_lists_noop_when_never_configured():
    class _Conf:
        def __init__(self):
            self.set_calls = []

        def get_status(self, keys):
            return {}

        def set_status(self, contents):
            self.set_calls.append(contents)

    class _WS:
        def __init__(self):
            self.workspace_conf = _Conf()

    ws = _WS()
    assert acl_core.disable_ip_access_lists(ws) is False
    assert ws.workspace_conf.set_calls == []


def test_acl_preview_block_target():
    ws = _FakeWs([_FakeAcl("office", "ALLOW", True, ["8.8.8.8/32"])])
    cfg = AclConfig(policy_mode="dry_run")
    a = acl_core.analyze(cfg, ws)
    prev = acl_core.preview_block(a, cfg)
    assert "ingress_dry_run" in prev
    # the preview mirrors the full policy body, incl. the permissive FULL_ACCESS egress default
    assert prev["egress"]["network_access"]["restriction_mode"] == "FULL_ACCESS"


def test_ip_acl_enforcement_state_reads_toggle():
    assert acl_core.ip_acl_enforcement_state(_WsWithConf("false")) is False
    assert acl_core.ip_acl_enforcement_state(_WsWithConf("true")) is True
    # unreadable (no workspace_conf) -> None, not a crash
    assert acl_core.ip_acl_enforcement_state(_FakeWs([])) is None


def _pas_account(pas_id):
    class _WS:
        def get(self, workspace_id):
            return type("W", (), {"private_access_settings_id": pas_id})()

    return type("Acct", (), {"workspaces": _WS()})()


def _cloud_account(cloud, raise_=False):
    class _WS:
        def get(self, workspace_id):
            if raise_:
                raise RuntimeError("no perms")
            return type("W", (), {"cloud": cloud})()

    return type("Acct", (), {"workspaces": _WS()})()


def test_workspace_cloud_reads_api_field():
    # authoritative API field (not host-parsed), normalised to lower-case
    assert acl_core.workspace_cloud(_cloud_account("azure"), 42) == "azure"
    assert acl_core.workspace_cloud(_cloud_account("AWS"), 42) == "aws"
    assert acl_core.workspace_cloud(_cloud_account("gcp"), 42) == "gcp"
    # missing / unreadable -> None (caller defaults to non-Azure, so the PrivateLink checks stay on)
    assert acl_core.workspace_cloud(_cloud_account(None), 42) is None
    assert acl_core.workspace_cloud(_cloud_account("azure", raise_=True), 42) is None


def test_workspace_pas_attached_true_false():
    assert acl_core.workspace_pas_attached(_pas_account("pas-abc"), 42) is True
    assert acl_core.workspace_pas_attached(_pas_account(None), 42) is False


def test_workspace_pas_attached_none_on_error():
    class _WS:
        def get(self, workspace_id):
            raise RuntimeError("no perms")

    acct = type("Acct", (), {"workspaces": _WS()})()
    assert acl_core.workspace_pas_attached(acct, 42) is None


def _vpce_account(network_id, dataplane=None, rest_api=None):
    ve = type("VE", (), {"dataplane_relay": dataplane, "rest_api": rest_api})()

    class _WS:
        def get(self, workspace_id):
            return type("W", (), {"network_id": network_id})()

    class _NW:
        def get(self, network_id):
            return type("N", (), {"vpc_endpoints": ve})()

    return type("Acct", (), {"workspaces": _WS(), "networks": _NW()})()


def test_workspace_vpc_endpoint_count():
    # no network config -> 0 (no VPC endpoints for this workspace)
    assert acl_core.workspace_vpc_endpoint_count(_vpce_account(None), 42) == 0
    # back-end endpoints (dataplane_relay + rest_api) are counted
    acct = _vpce_account("net-1", dataplane=["vpce-a"], rest_api=["vpce-b", "vpce-c"])
    assert acl_core.workspace_vpc_endpoint_count(acct, 42) == 3
    # empty lists -> 0
    assert acl_core.workspace_vpc_endpoint_count(_vpce_account("net-1"), 42) == 0


def test_workspace_vpc_endpoint_count_none_on_error():
    class _WS:
        def get(self, workspace_id):
            raise RuntimeError("no perms")

    acct = type("Acct", (), {"workspaces": _WS()})()
    assert acl_core.workspace_vpc_endpoint_count(acct, 42) is None


def test_policy_exists_true_false():
    from databricks.sdk.errors import NotFound

    class _NPyes:
        def get_network_policy_rpc(self, network_policy_id):
            return object()

    class _NPno:
        def get_network_policy_rpc(self, network_policy_id):
            raise NotFound("nope")

    assert acl_core.policy_exists(type("A", (), {"network_policies": _NPyes()})(), "p") is True
    assert acl_core.policy_exists(type("A", (), {"network_policies": _NPno()})(), "p") is False


def _policy_account(assigned_policy_id, policy_obj):
    class _WNC:
        def get_workspace_network_option_rpc(self, workspace_id):
            return type("O", (), {"network_policy_id": assigned_policy_id})()

    class _NP:
        def get_network_policy_rpc(self, network_policy_id):
            return policy_obj

    return type("Acct", (), {"workspace_network_configuration": _WNC(), "network_policies": _NP()})()


def _ingress(
    public_mode="FULL_ACCESS", private_mode="ALLOW_ALL_REGISTERED_ENDPOINTS", xws_mode="LEGACY_MODE"
):
    def _blk(mode):
        return type("B", (), {"restriction_mode": mode, "allow_rules": None, "deny_rules": None})()

    return type(
        "Ing",
        (),
        {
            "public_access": _blk(public_mode),
            "private_access": _blk(private_mode),
            "cross_workspace_access": _blk(xws_mode),
        },
    )()


def test_ingress_restrictive_matches_allow_all_vs_rules():
    # mirrors the real default-policy: all sub-blocks permissive, no rules -> not restrictive
    assert acl_core._ingress_restrictive(_ingress()) is False
    assert acl_core._ingress_restrictive(None) is False
    # any sub-block in RESTRICTED_ACCESS -> restrictive
    assert acl_core._ingress_restrictive(_ingress(public_mode="RESTRICTED_ACCESS")) is True
    assert acl_core._ingress_restrictive(_ingress(private_mode="RESTRICTED_ACCESS")) is True


def test_public_vs_private_restrictive_helpers():
    assert acl_core.public_restrictive(_ingress(public_mode="RESTRICTED_ACCESS")) is True
    assert acl_core.public_restrictive(_ingress()) is False
    # private / cross-workspace restrictiveness is independent of public
    assert acl_core.private_or_xws_restrictive(_ingress(private_mode="RESTRICTED_ACCESS")) is True
    assert acl_core.private_or_xws_restrictive(_ingress(xws_mode="RESTRICTED_ACCESS")) is True
    assert acl_core.private_or_xws_restrictive(_ingress()) is False
    assert acl_core.private_or_xws_restrictive(_ingress(public_mode="RESTRICTED_ACCESS")) is False


def _egress(restricted=True, enforced=True, internet=None, storage=None):
    import types

    na = types.SimpleNamespace(
        restriction_mode="RESTRICTED_ACCESS" if restricted else "FULL_ACCESS",
        allowed_internet_destinations=internet,
        allowed_storage_destinations=storage,
        blocked_internet_destinations=None,
        policy_enforcement=types.SimpleNamespace(enforcement_mode="ENFORCED" if enforced else "DRY_RUN"),
    )
    return types.SimpleNamespace(network_access=na)


def test_egress_restrictive_matches_restricted_mode_and_dest_lists():
    assert acl_core.egress_restrictive(None) is False
    assert acl_core.egress_restrictive(_egress(restricted=False)) is False  # FULL_ACCESS
    assert acl_core.egress_restrictive(_egress(restricted=True)) is True  # RESTRICTED_ACCESS
    # FULL_ACCESS but with an allow list present -> still restrictive
    assert acl_core.egress_restrictive(_egress(restricted=False, internet=["x"])) is True


def test_egress_enforced_reads_enforcement_mode():
    assert acl_core.egress_enforced(_egress(enforced=True)) is True
    assert acl_core.egress_enforced(_egress(enforced=False)) is False  # DRY_RUN
    assert acl_core.egress_enforced(None) is False


def test_assigned_policy_returns_id_and_object():
    pol = object()
    assert acl_core.assigned_policy(_policy_account("p1", pol), 42) == ("p1", pol)
    assert acl_core.assigned_policy(_policy_account(None, None), 42) == (None, None)


def test_assigned_ingress_state_none_when_unassigned():
    assert acl_core.assigned_ingress_state(_policy_account(None, None), 42) == (None, None)


def test_assigned_ingress_state_ignores_allow_all_policy():
    # temp / default-policy: dry-run block present but fully permissive -> no blocker (state None)
    allow_all = type("P", (), {"ingress": None, "ingress_dry_run": _ingress()})()
    assert acl_core.assigned_ingress_state(_policy_account("default-policy", allow_all), 42) == (
        "default-policy",
        None,
    )


def test_assigned_ingress_state_enforced_dry_run_when_restrictive():
    enforced = type(
        "P", (), {"ingress": _ingress(public_mode="RESTRICTED_ACCESS"), "ingress_dry_run": None}
    )()
    assert acl_core.assigned_ingress_state(_policy_account("p1", enforced), 42) == ("p1", "enforced")
    dry = type("P", (), {"ingress": None, "ingress_dry_run": _ingress(public_mode="RESTRICTED_ACCESS")})()
    assert acl_core.assigned_ingress_state(_policy_account("p2", dry), 42) == ("p2", "dry_run")


def test_promote_dry_run_to_enforced_moves_block():
    sent = {}
    dry_block = object()
    pol = type("P", (), {"ingress": None, "ingress_dry_run": dry_block})()

    class _NP:
        def get_network_policy_rpc(self, network_policy_id):
            return pol

        def update_network_policy_rpc(self, network_policy_id, network_policy):
            sent["id"] = network_policy_id
            sent["pol"] = network_policy

    acct = type("Acct", (), {"network_policies": _NP()})()
    acl_core.promote_dry_run_to_enforced(acct, "p1")
    assert sent["id"] == "p1"
    assert sent["pol"].ingress is dry_block and sent["pol"].ingress_dry_run is None


def test_acl_policy_payload_is_curl_ready():
    # --export builds the full AccountNetworkPolicy (ingress mode block + a FULL_ACCESS egress by
    # default, when no egress is carried over) as a dict.
    ws = _FakeWs([_FakeAcl("office", "ALLOW", True, ["8.8.8.8/32"])], ws_id=42)
    cfg = AclConfig(policy_mode="enforce", policy_name="my-acl")
    a = acl_core.analyze(cfg, ws)
    payload = acl_core.policy_payload(a, cfg, account_id="acc-123")
    assert payload["network_policy_id"] == "my-acl"
    assert payload["account_id"] == "acc-123"
    assert "ingress" in payload  # enforce -> ingress (not ingress_dry_run)
    assert payload["egress"]["network_access"]["restriction_mode"] == "FULL_ACCESS"


# --- egress carry-over (copy the assigned policy's egress into the new policy) -----------------


def _restricted_egress():
    """A real (SDK) RESTRICTED_ACCESS egress block, so .as_dict() round-trips like the API's."""
    from databricks.sdk.service.settings import (  # noqa: I001
        EgressNetworkPolicyNetworkAccessPolicy as EA,
        EgressNetworkPolicyNetworkAccessPolicyRestrictionMode as RM,
        NetworkPolicyEgress,
    )

    return NetworkPolicyEgress(network_access=EA(restriction_mode=RM.RESTRICTED_ACCESS))


def _egr_policy(egress):
    return type("P", (), {"ingress": None, "ingress_dry_run": None, "egress": egress})()


def test_assigned_egress_copies_the_assigned_policys_egress():
    egr = _restricted_egress()
    src, out = acl_core.assigned_egress(_policy_account("custom-policy", _egr_policy(egr)), 42)
    assert src == "custom-policy"
    assert out is not None and out is not egr  # deep-copied (independent object)
    assert out.network_access.restriction_mode.value == "RESTRICTED_ACCESS"


def test_assigned_egress_falls_back_to_default_policy_when_unassigned():
    # Nothing explicitly assigned -> the account default-policy governs the workspace; copy ITS egress.
    egr = _restricted_egress()

    class _WNC:
        def get_workspace_network_option_rpc(self, workspace_id):
            return type("O", (), {"network_policy_id": None})()

    class _NP:
        def get_network_policy_rpc(self, network_policy_id):
            assert network_policy_id == "default-policy"
            return _egr_policy(egr)

    acct = type("Acct", (), {"workspace_network_configuration": _WNC(), "network_policies": _NP()})()
    src, out = acl_core.assigned_egress(acct, 42)
    assert src == "default-policy"
    assert out.network_access.restriction_mode.value == "RESTRICTED_ACCESS"


def test_assigned_egress_none_when_default_policy_unreadable():
    from databricks.sdk.errors import NotFound

    class _WNC:
        def get_workspace_network_option_rpc(self, workspace_id):
            return type("O", (), {"network_policy_id": None})()

    class _NP:
        def get_network_policy_rpc(self, network_policy_id):
            raise NotFound("no default-policy")

    acct = type("Acct", (), {"workspace_network_configuration": _WNC(), "network_policies": _NP()})()
    assert acl_core.assigned_egress(acct, 42) == (None, None)


def test_preview_and_payload_carry_supplied_egress():
    ws = _FakeWs([_FakeAcl("office", "ALLOW", True, ["8.8.8.8/32"])], ws_id=42)
    cfg = AclConfig(policy_mode="enforce", policy_name="my-acl")
    a = acl_core.analyze(cfg, ws)
    prev = acl_core.preview_block(a, cfg, egress=_restricted_egress())
    assert prev["egress"]["network_access"]["restriction_mode"] == "RESTRICTED_ACCESS"
    payload = acl_core.policy_payload(a, cfg, account_id="acc", egress=_restricted_egress())
    assert payload["egress"]["network_access"]["restriction_mode"] == "RESTRICTED_ACCESS"


def test_apply_sends_the_supplied_egress():
    captured = {}
    ws = _FakeWs([_FakeAcl("office", "ALLOW", True, ["8.8.8.8/32"])], ws_id=42)
    cfg = AclConfig(policy_name="p", create_policy=True, auto_assign=False)
    acl_core.apply(
        acl_core.analyze(cfg, ws),
        cfg,
        _CreateCapturingAccount(captured),
        account_id="a",
        egress=_restricted_egress(),
    )
    assert captured["policy"].egress.network_access.restriction_mode.value == "RESTRICTED_ACCESS"


# --- enable_disabled_lists (re-enable individually-disabled lists) -----------------------------


class _EnableAcl:
    def __init__(self, list_id, label, enabled):
        self.list_id, self.label, self.enabled = list_id, label, enabled
        self.ip_addresses = ["8.8.8.8/32"]
        self.list_type = type("LT", (), {"value": "ALLOW"})()


def _enable_ws(acls, updater):
    api = type("Api", (), {"list": lambda self: acls, "update": updater})()
    return type("WS", (), {"ip_access_lists": api})()


def test_enable_disabled_lists_enables_only_matching_disabled():
    acls = [
        _EnableAcl("1", "office", True),
        _EnableAcl("2", "vpn", False),
        _EnableAcl("3", "corp-vpn", False),
    ]
    seen = []

    def _update(self, ip_access_list_id, label, list_type, ip_addresses, enabled):
        seen.append((label, enabled))

    n, failures = acl_core.enable_disabled_lists(_enable_ws(acls, _update), ["vpn", "corp-vpn", "not-there"])
    assert n == 2 and failures == []
    # office is already enabled and "not-there" doesn't exist -> only the two disabled ones updated
    assert sorted(label for label, _ in seen) == ["corp-vpn", "vpn"]
    assert all(enabled is True for _, enabled in seen)


def test_enable_disabled_lists_captures_per_list_failures():
    acls = [_EnableAcl("2", "vpn", False)]

    def _update(self, **kwargs):
        raise RuntimeError("current IP will not be allowed")  # e.g. self-lockout guard on a BLOCK list

    n, failures = acl_core.enable_disabled_lists(_enable_ws(acls, _update), ["vpn"])
    assert n == 0 and len(failures) == 1 and failures[0].startswith("vpn:")
