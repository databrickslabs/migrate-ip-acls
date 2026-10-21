"""SDK dataclass builders for the CBI account network policy.

The build_* functions turn plain rule-spec dicts into the `CustomerFacingIngressNetworkPolicy*` /
`NetworkPolicyEgress` dataclasses so the JSON you preview is exactly what gets sent. policy_name()
produces the deterministic, length-capped policy id.
"""

from __future__ import annotations

from collections.abc import Callable

from .config import MAX_POLICY_ID_LEN

Note = Callable[[str], None]

# Destinations the CBI API forbids an authentication block on — they implicitly allow all users +
# service principals, so a SELECTED_IDENTITIES block is rejected. These are the only destination
# shapes this tool emits, so per-identity auth is effectively unsupported (the verbatim IP-ACL
# migration never sets it anyway).
_DESTINATIONS_WITHOUT_AUTH = {None, "all_destinations", "apps_runtime", "lakebase_runtime"}


# --------------------------------------------------------------------------- ingress block builders
def _rule_label(spec: dict, mode_label: str | None) -> str:
    """The rule label. With a mode_label it's suffixed `<label> (<mode>)`; with mode_label=None the
    label is verbatim (the IP-ACL migration recreates the lists exactly)."""
    return f"{spec['label']} ({mode_label})" if mode_label else spec["label"]


def build_ingress_rule(spec: dict, mode_label: str | None):
    from databricks.sdk.service.settings import (  # noqa: I001
        CustomerFacingIngressNetworkPolicyAppsRuntimeDestination as AppsDest,
        CustomerFacingIngressNetworkPolicyAuthentication as Auth,
        CustomerFacingIngressNetworkPolicyAuthenticationIdentity as Identity,
        CustomerFacingIngressNetworkPolicyAuthenticationIdentityPrincipalType as PrincipalType,
        CustomerFacingIngressNetworkPolicyAuthenticationIdentityType as IdentityType,
        CustomerFacingIngressNetworkPolicyIpRanges as IpRanges,
        CustomerFacingIngressNetworkPolicyLakebaseRuntimeDestination as LakebaseDest,
        CustomerFacingIngressNetworkPolicyPublicIngressRule as Rule,
        CustomerFacingIngressNetworkPolicyPublicRequestOrigin as Origin,
        CustomerFacingIngressNetworkPolicyRequestDestination as Destination,
    )

    origin = (
        Origin(all_ip_ranges=True)
        if spec.get("catch_all")
        else Origin(included_ip_ranges=IpRanges(ip_ranges=list(spec["cidrs"])))
    )

    if spec.get("destination") == "apps_runtime":
        destination = Destination(apps_runtime=AppsDest(all_destinations=True))
    elif spec.get("destination") == "lakebase_runtime":
        destination = Destination(lakebase_runtime=LakebaseDest(all_destinations=True))
    else:
        destination = Destination(all_destinations=True)

    # The CBI API rejects an authentication block on the broad "runtime"/"all" destinations
    # (Apps / Lakebase / all_destinations support only all users + service principals). Only attach
    # per-identity authentication where the destination can carry it.
    authentication = None
    if (
        spec.get("destination") not in _DESTINATIONS_WITHOUT_AUTH
        and spec.get("identity_type") == "SELECTED_IDENTITIES"
        and spec.get("identities")
    ):
        identities = [
            Identity(
                principal_id=i["principal_id"],
                principal_type=(
                    PrincipalType.PRINCIPAL_TYPE_USER
                    if i["principal_type"] == "USER"
                    else PrincipalType.PRINCIPAL_TYPE_SERVICE_PRINCIPAL
                ),
            )
            for i in spec["identities"]
        ]
        authentication = Auth(
            identity_type=IdentityType.IDENTITY_TYPE_SELECTED_IDENTITIES, identities=identities
        )

    return Rule(
        label=_rule_label(spec, mode_label),
        origin=origin,
        destination=destination,
        authentication=authentication,
    )


def build_deny_rule(spec: dict, mode_label: str | None):
    from databricks.sdk.service.settings import (  # noqa: I001
        CustomerFacingIngressNetworkPolicyIpRanges as IpRanges,
        CustomerFacingIngressNetworkPolicyPublicIngressRule as Rule,
        CustomerFacingIngressNetworkPolicyPublicRequestOrigin as Origin,
        CustomerFacingIngressNetworkPolicyRequestDestination as Destination,
    )

    return Rule(
        label=_rule_label(spec, mode_label),
        origin=Origin(included_ip_ranges=IpRanges(ip_ranges=list(spec["cidrs"]))),
        destination=Destination(all_destinations=True),
    )


def build_private_access_block(restriction_mode: str, endpoint_ids: list[str], label: str):
    """A CustomerFacingIngressNetworkPolicyPrivateAccess from a PrivateAccessPlan's fields.

    * ALLOW_ALL_REGISTERED_ENDPOINTS → the mode alone (any registered endpoint; no explicit rules).
    * RESTRICTED_ACCESS → one allow rule whose origin lists the registered endpoint ids. With no ids
      (an endpoint-scoped PAS that allows nothing) the block is RESTRICTED_ACCESS with no allow
      rules — faithfully, no private endpoint is permitted."""
    from databricks.sdk.service.settings import (  # noqa: I001
        CustomerFacingIngressNetworkPolicyEndpoints as Endpoints,
        CustomerFacingIngressNetworkPolicyPrivateAccess as PrivateAccess,
        CustomerFacingIngressNetworkPolicyPrivateAccessRestrictionMode as RestrictionMode,
        CustomerFacingIngressNetworkPolicyPrivateIngressRule as Rule,
        CustomerFacingIngressNetworkPolicyPrivateRequestOrigin as Origin,
        CustomerFacingIngressNetworkPolicyRequestDestination as Destination,
    )

    if restriction_mode == "ALLOW_ALL_REGISTERED_ENDPOINTS":
        return PrivateAccess(restriction_mode=RestrictionMode.ALLOW_ALL_REGISTERED_ENDPOINTS)
    rules = (
        [
            Rule(
                label=label,
                origin=Origin(endpoints=Endpoints(endpoint_ids=list(endpoint_ids))),
                destination=Destination(all_destinations=True),
            )
        ]
        if endpoint_ids
        else None
    )
    return PrivateAccess(restriction_mode=RestrictionMode.RESTRICTED_ACCESS, allow_rules=rules)


def build_public_access_block(
    allow: list[dict],
    deny: list[dict],
    mode_label: str | None,
    note: Note = lambda _m: None,
    public_enabled: bool = True,
):
    """The ingress public_access (source-IP) block from allow specs (+ optional deny specs).

    RESTRICTED_ACCESS is default-DENY; if a policy ends up with deny rules but no allow rules,
    everything would be blocked — add a catch-all allow (all public IPs) to preserve
    "block these, allow the rest".

    When `public_enabled` is False the workspace has public internet access disabled (a
    PrivateLink-only workspace); the IP access lists are not in effect, so the public block is an
    explicit deny-all (RESTRICTED_ACCESS with no allow rules) rather than recreating them — public
    ingress stays closed in CBI even if the workspace's public toggle is later flipped back on."""
    from databricks.sdk.service.settings import (  # noqa: I001
        CustomerFacingIngressNetworkPolicyPublicAccess as PublicAccess,
        CustomerFacingIngressNetworkPolicyPublicAccessRestrictionMode as RestrictionMode,
    )

    if not public_enabled:
        if allow or deny:
            note(
                "Public network access is disabled on this workspace, so its IP access lists are not "
                "in effect — the generated policy denies all public ingress (RESTRICTED_ACCESS with "
                "no allow rules) rather than recreating them as public rules."
            )
        return PublicAccess(restriction_mode=RestrictionMode.RESTRICTED_ACCESS)

    allow = list(allow)
    if (deny or []) and not allow:
        allow = [
            {
                "label": "allow-all",
                "catch_all": True,
                "destination": "all_destinations",
                "identity_type": "ALL_USERS",
                "identities": [],
            }
        ]
        note(
            "Policy has deny rules but no allow rules — added a catch-all allow (all public IPs) "
            "so non-denied traffic is still permitted (default-allow-except-blocked)."
        )

    return PublicAccess(
        restriction_mode=RestrictionMode.RESTRICTED_ACCESS,
        allow_rules=[build_ingress_rule(s, mode_label) for s in allow],
        deny_rules=[build_deny_rule(s, mode_label) for s in (deny or [])] or None,
    )


def assemble_ingress(public_access=None, private_access=None, cross_workspace_access=None):
    """Assemble a CustomerFacingIngressNetworkPolicy from independently-built (or preserved)
    sub-blocks. Any of them may be None (omitted)."""
    from databricks.sdk.service.settings import CustomerFacingIngressNetworkPolicy as IngressPolicy

    return IngressPolicy(
        public_access=public_access,
        private_access=private_access,
        cross_workspace_access=cross_workspace_access,
    )


def build_ingress_block(
    allow: list[dict],
    deny: list[dict],
    mode_label: str | None,
    note: Note = lambda _m: None,
    public_enabled: bool = True,
    private_plan: object | None = None,
):
    """Build a full ingress block from scratch (public + optional private) — the "migrate both
    dimensions" path. The engine's per-dimension migrate-vs-preserve logic composes
    build_public_access_block / build_private_access_block via assemble_ingress directly."""
    public = build_public_access_block(allow, deny, mode_label, note, public_enabled)
    private = (
        build_private_access_block(
            private_plan.restriction_mode, private_plan.endpoint_ids, private_plan.label
        )
        if private_plan is not None
        else None
    )
    return assemble_ingress(public, private)


def build_full_access_egress():
    """A permissive (FULL_ACCESS) egress block — the migration only recreates IP ACLs (ingress), but
    the API requires an egress block on create, so serverless egress is left unrestricted."""
    from databricks.sdk.service.settings import (  # noqa: I001
        EgressNetworkPolicyNetworkAccessPolicy as EgressAccess,
        EgressNetworkPolicyNetworkAccessPolicyRestrictionMode as EgressRestriction,
        NetworkPolicyEgress,
    )

    return NetworkPolicyEgress(network_access=EgressAccess(restriction_mode=EgressRestriction.FULL_ACCESS))


# --------------------------------------------------------------------------------- policy id naming
def _slug(text: str) -> str:
    """Normalise a free-form label (e.g. a profile name) into a policy-id-safe slug."""
    import re

    return re.sub(r"[^a-z0-9-]+", "-", (text or "").lower()).strip("-")


def policy_name(
    name_prefix: str, workspace_id: int | None = None, suffix: str | None = None, explicit: str | None = None
) -> str:
    """Deterministic policy id, truncated to the id length limit while preserving the suffix:
      all_workspaces   -> <prefix>
      per_workspace    -> <prefix>-ws-<id>       (workspace_id given)
      current_workspace-> <prefix>-<profile>     (suffix given)
    The suffix (workspace id or profile slug) is kept whole; the prefix is trimmed to fit.
    An `explicit` name (the user's --policy-name) overrides all of the above: it's slugified to an
    id-safe form and capped, falling back to the prefix if it slugs away to nothing."""
    if explicit:
        return (_slug(explicit) or _slug(name_prefix) or "policy")[:MAX_POLICY_ID_LEN]
    prefix = _slug(name_prefix) or "policy"
    if workspace_id is not None:
        tail = f"-ws-{workspace_id}"
    elif suffix:
        tail = f"-{_slug(suffix)}"
    else:
        return prefix[:MAX_POLICY_ID_LEN]
    room = MAX_POLICY_ID_LEN - len(tail)
    return f"{prefix[:max(room, 1)].rstrip('-')}{tail}"
