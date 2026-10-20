"""IP ACL → CBI verbatim migration engine.

Ported from `notebooks/ip_acl_migration.py`. Reads this workspace's enabled IP access lists and
recreates them as a CBI policy as-is (ALLOW → allow rules, BLOCK → deny rules), adding nothing but the
catch-all allow required when only BLOCK lists exist (CBI is default-deny).
"""

from __future__ import annotations

import copy
import ipaddress
from collections.abc import Callable
from dataclasses import dataclass, field

from . import policy
from .config import AclConfig

Note = Callable[[str], None]

# The account's baseline network policy. It governs any workspace that has no policy explicitly
# assigned, so its egress is what such a workspace effectively runs under; we replicate that egress
# (like any assigned policy's) so a workspace on an egress-restricted default keeps its posture.
DEFAULT_POLICY_ID = "default-policy"


@dataclass
class PrivateAccessPlan:
    """The workspace's front-end PrivateLink, recreated as-is in the CBI `private_access` block.

    Derived from the workspace's Private Access Settings (PAS):
    * `private_access_level=ACCOUNT`  → restriction_mode ALLOW_ALL_REGISTERED_ENDPOINTS (any
      registered endpoint; no explicit rules);
    * `private_access_level=ENDPOINT` → restriction_mode RESTRICTED_ACCESS with one allow rule
      listing the PAS's `allowed_vpc_endpoint_ids` (the Databricks-registered endpoint ids).
    The label is the PAS name (verbatim) when it has one, else a generic fallback."""

    restriction_mode: str  # "ALLOW_ALL_REGISTERED_ENDPOINTS" | "RESTRICTED_ACCESS"
    endpoint_ids: list[str] = field(default_factory=list)
    label: str = "registered-private-endpoints"
    source_pas_id: str | None = None


@dataclass
class AclAnalysis:
    workspace_id: int
    ip_acls: list[dict] = field(default_factory=list)  # enabled lists (migrated)
    allow_specs: list[dict] = field(default_factory=list)
    deny_specs: list[dict] = field(default_factory=list)
    # Individual IP access lists with enabled=false — surfaced to the user but NOT migrated (the tool
    # preserves inbound access exactly as it is, and a disabled list isn't in effect).
    disabled_acls: list[dict] = field(default_factory=list)
    # Front-end PrivateLink, read from the account (not the workspace client), so these are populated
    # by the CLI after analyze() rather than by analyze() itself:
    #   * public_access_enabled — the PAS public-internet toggle (default True = no PAS / public on).
    #     When False (PrivateLink-only), the generated public_access block is an explicit deny-all.
    #   * private_plan — the PAS mapped to a CBI private_access block, or None when there's no
    #     front-end PrivateLink to migrate.
    public_access_enabled: bool = True
    private_plan: PrivateAccessPlan | None = None


def _ipv4(cidrs):
    out = []
    for c in cidrs:
        v = c if "/" in c else f"{c}/32"
        try:
            if ipaddress.ip_network(v, strict=False).version == 4 and v not in out:
                out.append(v)
        except ValueError:
            pass
    return out


def ip_acl_enforcement_state(workspace_client) -> bool | None:
    """Read the workspace-wide `enableIpAccessLists` toggle. True/False, or None if unreadable."""
    try:
        status = workspace_client.workspace_conf.get_status(keys="enableIpAccessLists") or {}
        val = str(status.get("enableIpAccessLists", "")).lower()
        if val in ("true", "false"):
            return val == "true"
    except Exception:  # noqa: BLE001 - best-effort; absence just means "unknown"
        pass
    return None


def analyze(cfg: AclConfig, workspace_client) -> AclAnalysis:
    workspace_id = workspace_client.get_workspace_id()
    ip_acls, disabled_acls = [], []
    for acl in workspace_client.ip_access_lists.list():
        entry = {
            "label": acl.label,
            "list_type": acl.list_type.value if acl.list_type else None,
            "ip_addresses": list(acl.ip_addresses or []),
        }
        # A disabled list isn't in effect, so migrating it would change the posture — surface it but
        # don't migrate it (the tool preserves inbound access exactly as it is).
        (ip_acls if acl.enabled else disabled_acls).append(entry)

    allow_specs, deny_specs = [], []
    for a in ip_acls:
        cidrs = _ipv4(a["ip_addresses"])
        if not cidrs:
            continue
        # Recreate the rules verbatim — the original ACL label, no prefix or mode suffix.
        label = a["label"][:250]
        if a["list_type"] == "ALLOW":
            allow_specs.append({"label": label, "cidrs": cidrs})
        elif a["list_type"] == "BLOCK":
            deny_specs.append({"label": label, "cidrs": cidrs})

    return AclAnalysis(
        workspace_id=workspace_id,
        ip_acls=ip_acls,
        allow_specs=allow_specs,
        deny_specs=deny_specs,
        disabled_acls=disabled_acls,
    )


def cloud_from_host(host: str | None) -> str | None:
    """Infer the cloud — 'aws', 'azure', or 'gcp' — from a Databricks host URL by its domain. None if
    the host is empty or doesn't match a known Databricks domain. Used as a fallback when the account
    API doesn't populate the `cloud` field (it often doesn't)."""
    h = (host or "").lower()
    if not h:
        return None
    if "azuredatabricks.net" in h:
        return "azure"
    if "gcp.databricks.com" in h:
        return "gcp"
    if "cloud.databricks.com" in h:  # the AWS domain (also the account host accounts.cloud.databricks.com)
        return "aws"
    return None


def account_host_from_workspace_host(host: str | None) -> str | None:
    """Derive the account-console API host from a workspace host, so a workspace in a non-default
    environment (e.g. AWS staging, GCP) reaches the matching account API instead of the AWS prod
    default. None if it can't be derived from the host.

    Per cloud:
    * Azure — one fixed account host (accounts.azuredatabricks.net).
    * AWS — the workspace host is `<deployment>.[staging.]cloud.databricks.com`; the single leading
      label is workspace-specific, so replace it with 'accounts' —
      dbc-x.staging.cloud.databricks.com -> accounts.staging.cloud.databricks.com.
    * GCP — the workspace host is `<workspace-id>.<shard>.[staging.]gcp.databricks.com` with *two*
      workspace-specific leading labels (id + shard), which the account console drops entirely —
      1828…914.4.staging.gcp.databricks.com -> accounts.staging.gcp.databricks.com. So anchor on the
      shared base domain rather than stripping a fixed number of labels."""
    h = (host or "").strip().lower()
    h = h.split("://", 1)[-1]  # drop any scheme
    h = h.split("/", 1)[0]  # drop any path / trailing slash
    if not h:
        return None
    if "azuredatabricks.net" in h:
        return "https://accounts.azuredatabricks.net"
    if "gcp.databricks.com" in h:
        # Both leading labels (workspace id + shard) are workspace-specific; keep only the shared
        # environment base (with 'staging' when present).
        base = "staging.gcp.databricks.com" if ".staging.gcp.databricks.com" in h else "gcp.databricks.com"
        return f"https://accounts.{base}"
    if "cloud.databricks.com" in h:
        # AWS: the first label is workspace-specific (dbc-<id> or a vanity name); everything after it
        # is the environment domain shared with the account console.
        _first, _, rest = h.partition(".")
        if rest:
            return f"https://accounts.{rest}"
    return None


def verify_account_access(account, workspace_id):
    """Make one real account-API call up front (fetch this workspace via the account API) so a bad
    account credential fails FAST with a clear message. Every other account reader here
    (`workspace_cloud`, `read_workspace_pas`, `assigned_ingress_state`, `assigned_egress`) is
    deliberately best-effort — it swallows errors and
    degrades to a safe-ish default. That's right once we know the account client works, but if it
    *doesn't* (wrong account, wrong Azure AD tenant, missing account-admin rights) those swallows
    would silently produce wrong results — skipped PrivateLink checks, or a FULL_ACCESS egress
    instead of the copied one — and the failure would only surface much later as a raw SDK traceback
    from the first reader that happens not to catch it (`policy_exists`). Probing here converts all
    of that into one clean, early error. Returns the workspace object (callers reuse it for cloud
    detection + the PAS read); the underlying SDK error propagates on failure."""
    return account.workspaces.get(workspace_id=int(workspace_id))


def workspace_cloud(account, workspace_id, host: str | None = None, ws: object | None = None) -> str | None:
    """This workspace's cloud — 'aws', 'azure', or 'gcp'. Prefers the authoritative `cloud` field on
    the account workspaces API; when that's empty (it frequently is — e.g. AWS workspaces report no
    cloud), falls back to inferring it from the workspace `host` URL's domain. None if neither yields
    an answer. Used to drive per-cloud behaviour (today: skipping the PrivateLink pre-checks on
    Azure). Pass `ws` to reuse an already-fetched workspace object (e.g. from verify_account_access)
    instead of making a second account call. Best-effort — a read failure degrades to the host
    fallback rather than crashing."""
    try:
        if ws is None:
            ws = account.workspaces.get(workspace_id=int(workspace_id))
        cloud = (getattr(ws, "cloud", None) or "").strip().lower()
        if cloud:
            return cloud
    except Exception:  # noqa: BLE001 - couldn't read the API field; fall back to the host below
        pass
    return cloud_from_host(host)


def read_workspace_pas(account, workspace_id, ws: object | None = None) -> tuple[object | None, str]:
    """Fetch the workspace's Private Access Settings (PAS) object — the source of truth for AWS/GCP
    front-end PrivateLink. Returns (pas, status) where status is:
      * 'none'  — no PAS attached (the workspace has no front-end PrivateLink; migrate public only);
      * 'ok'    — PAS read (`pas` is the object to map into a private_access block);
      * 'error' — the account read failed (caller warns; PrivateLink can't be migrated).
    Separating 'none' from 'error' matters: a workspace with genuinely no PrivateLink must migrate
    cleanly, while an unreadable account must warn rather than silently drop a private rule. Pass `ws`
    to reuse an already-fetched workspace object (e.g. from verify_account_access). Best-effort."""
    try:
        if ws is None:
            ws = account.workspaces.get(workspace_id=int(workspace_id))
    except Exception:  # noqa: BLE001 - couldn't read the workspace; caller warns
        return None, "error"
    pas_id = getattr(ws, "private_access_settings_id", None)
    if not pas_id:
        return None, "none"
    try:
        return account.private_access.get(private_access_settings_id=pas_id), "ok"
    except Exception:  # noqa: BLE001 - PAS id present but unreadable; caller warns
        return None, "error"


def plan_from_pas(pas) -> tuple[bool, PrivateAccessPlan]:
    """Map a Private Access Settings object to (public_access_enabled, PrivateAccessPlan), recreating
    the workspace's front-end PrivateLink as-is. `public_access_enabled` is the PAS public-internet
    toggle; the plan is the private_access block (ACCOUNT → allow-all-registered, ENDPOINT → the
    enumerated allowed endpoint ids)."""
    public_enabled = bool(getattr(pas, "public_access_enabled", True))
    level = getattr(pas, "private_access_level", None)
    level_val = str(getattr(level, "value", level) or "").upper()
    pas_id = getattr(pas, "private_access_settings_id", None)
    # Keep the PAS name as the rule label verbatim (nothing added); fall back when it has none.
    label = getattr(pas, "private_access_settings_name", None) or "registered-private-endpoints"
    if level_val == "ENDPOINT":
        ids = list(getattr(pas, "allowed_vpc_endpoint_ids", None) or [])
        plan = PrivateAccessPlan(
            restriction_mode="RESTRICTED_ACCESS", endpoint_ids=ids, label=label, source_pas_id=pas_id
        )
    else:
        # ACCOUNT (or an unspecified level) means any endpoint registered in the account is accepted.
        plan = PrivateAccessPlan(
            restriction_mode="ALLOW_ALL_REGISTERED_ENDPOINTS", label=label, source_pas_id=pas_id
        )
    return public_enabled, plan


def policy_exists(account, policy_id: str) -> bool:
    """True if a network policy with this id already exists (migrate-acl only creates new ones)."""
    from databricks.sdk.errors import NotFound

    try:
        account.network_policies.get_network_policy_rpc(network_policy_id=policy_id)
        return True
    except NotFound:
        return False


def _block_restrictive(blk) -> bool:
    """True if a single access sub-block restricts traffic — RESTRICTED_ACCESS mode, or any
    allow/deny rules. Permissive defaults (FULL_ACCESS / ALLOW_ALL_REGISTERED_ENDPOINTS / LEGACY_MODE
    with no rules) return False."""
    if blk is None:
        return False
    rm = getattr(blk, "restriction_mode", None)
    if str(getattr(rm, "value", rm) or "") == "RESTRICTED_ACCESS":
        return True
    return bool(getattr(blk, "allow_rules", None) or getattr(blk, "deny_rules", None))


def public_restrictive(ingress) -> bool:
    """True if the ingress block's public_access (source-IP) sub-block is restrictive."""
    return ingress is not None and _block_restrictive(getattr(ingress, "public_access", None))


def private_or_xws_restrictive(ingress) -> bool:
    """True if the ingress block's private_access (PrivateLink) or cross_workspace_access sub-block
    is restrictive — the parts the public-IP helpers don't build and can't yet preserve."""
    if ingress is None:
        return False
    return _block_restrictive(getattr(ingress, "private_access", None)) or _block_restrictive(
        getattr(ingress, "cross_workspace_access", None)
    )


def _ingress_restrictive(ingress) -> bool:
    """True if an ingress block restricts traffic in any sub-block (public / private / cross-
    workspace). All-permissive blocks (the account's baseline `default-policy`) return False."""
    return public_restrictive(ingress) or private_or_xws_restrictive(ingress)


def egress_restrictive(egress) -> bool:
    """True if a policy's egress block restricts outbound traffic — RESTRICTED_ACCESS mode, or any
    allow/block destination lists. A FULL_ACCESS egress (the permissive default an ingress-only
    policy carries) — or None — returns False."""
    if egress is None:
        return False
    na = getattr(egress, "network_access", None)
    if na is None:
        return False
    rm = getattr(na, "restriction_mode", None)
    if str(getattr(rm, "value", rm) or "") == "RESTRICTED_ACCESS":
        return True
    return bool(
        getattr(na, "allowed_internet_destinations", None)
        or getattr(na, "allowed_storage_destinations", None)
        or getattr(na, "blocked_internet_destinations", None)
    )


def egress_enforced(egress) -> bool:
    """True if a restrictive egress block is ENFORCED (blocking). A DRY_RUN (or unset) enforcement
    mode is log-only. Only meaningful alongside egress_restrictive()."""
    na = getattr(egress, "network_access", None)
    pe = getattr(na, "policy_enforcement", None) if na is not None else None
    mode = getattr(pe, "enforcement_mode", None)
    return str(getattr(mode, "value", mode) or "") == "ENFORCED"


def assigned_policy(account, workspace_id) -> tuple[str | None, object | None]:
    """(assigned_policy_id, full policy object) for the workspace — (id, None) if the policy read
    failed, (None, None) if nothing is assigned. Best-effort."""
    try:
        opt = account.workspace_network_configuration.get_workspace_network_option_rpc(
            workspace_id=int(workspace_id)
        )
        policy_id = getattr(opt, "network_policy_id", None)
    except Exception:  # noqa: BLE001
        return None, None
    if not policy_id:
        return None, None
    try:
        return policy_id, account.network_policies.get_network_policy_rpc(network_policy_id=policy_id)
    except Exception:  # noqa: BLE001
        return policy_id, None


def assigned_ingress_state(account, workspace_id) -> tuple[str | None, str | None]:
    """Inspect the network policy currently assigned to the workspace. Returns
    (assigned_policy_id, ingress_state) where ingress_state is 'enforced' (a *restrictive* enforced
    ingress block), 'dry_run' (a *restrictive* dry-run ingress block), or None — no policy assigned,
    or the assigned policy is effectively allow-all (no restrictive rules to preserve, so migrating
    over it loses nothing). Best-effort."""
    policy_id, pol = assigned_policy(account, workspace_id)
    if pol is None:
        return policy_id, None
    if _ingress_restrictive(getattr(pol, "ingress", None)):
        return policy_id, "enforced"
    if _ingress_restrictive(getattr(pol, "ingress_dry_run", None)):
        return policy_id, "dry_run"
    return policy_id, None


def assigned_egress(account, workspace_id) -> tuple[str | None, object | None]:
    """The egress block to carry over verbatim to the new policy, so the migration preserves the
    workspace's current egress posture exactly — its enforcement mode, allowed internet (FQDN) and
    storage destinations, and blocked-internet lists. It's the egress of the policy currently
    assigned to the workspace or, when nothing is explicitly assigned, the account baseline
    `default-policy` that governs it by default (both cases replicated identically). Returns
    (source_policy_id, egress); (None, None) when neither is readable, so the caller falls back to a
    permissive FULL_ACCESS egress. Best-effort, and a deep copy independent of the fetched object."""
    policy_id, pol = assigned_policy(account, workspace_id)
    if policy_id:
        # A policy is explicitly assigned (possibly `default-policy` itself). If the policy read
        # failed (pol is None) we can't know its egress — return None so the caller uses FULL_ACCESS
        # rather than guessing.
        return policy_id, copy.deepcopy(getattr(pol, "egress", None))
    # Nothing explicitly assigned → the account default-policy is in effect; replicate its egress.
    try:
        default = account.network_policies.get_network_policy_rpc(network_policy_id=DEFAULT_POLICY_ID)
    except Exception:  # noqa: BLE001 - NotFound / read failure → caller uses FULL_ACCESS
        return None, None
    return DEFAULT_POLICY_ID, copy.deepcopy(getattr(default, "egress", None))


def disable_ip_access_lists(workspace_client, note: Note = lambda _m: None) -> bool:
    """Turn OFF workspace-wide IP access list enforcement via `enableIpAccessLists=false`.

    Disables enforcement of *all* the workspace's IP access lists at once; the lists themselves are
    preserved, so it's reversible by setting the flag back to true. Returns True if it changed state,
    False if enforcement was already off. The caller must ensure a replacement CBI policy has been
    created and assigned first (validate_disable_ip_acls enforces that invariant)."""
    status = workspace_client.workspace_conf.get_status(keys="enableIpAccessLists") or {}
    # Enforcement is only ON when the flag is explicitly "true"; anything else (missing key = never
    # configured, empty, or "false") means there's nothing to disable, so skip the write.
    if str(status.get("enableIpAccessLists", "")).lower() != "true":
        note(
            "Workspace IP access list enforcement is already off (never configured or already "
            "disabled) — no change needed."
        )
        return False
    workspace_client.workspace_conf.set_status({"enableIpAccessLists": "false"})
    note(
        "Disabled workspace IP access list enforcement (enableIpAccessLists=false). The lists "
        "themselves are preserved — set it back to true to re-enable."
    )
    return True


def enable_ip_access_lists(workspace_client, note: Note = lambda _m: None) -> bool:
    """Turn ON workspace-wide IP access list enforcement (`enableIpAccessLists=true`). Returns True
    if it changed state, False if it was already on. The mirror of disable_ip_access_lists()."""
    status = workspace_client.workspace_conf.get_status(keys="enableIpAccessLists") or {}
    if str(status.get("enableIpAccessLists", "")).lower() == "true":
        note("Workspace IP access list enforcement is already on — no change needed.")
        return False
    workspace_client.workspace_conf.set_status({"enableIpAccessLists": "true"})
    note("Re-enabled workspace IP access list enforcement (enableIpAccessLists=true).")
    return True


def enable_disabled_lists(workspace_client, labels) -> tuple[int, list[str]]:
    """Re-enable the individual IP access lists whose label is in `labels` and are currently
    disabled. Returns (enabled_count, failures) where each failure is "<label>: <reason>". Enabling
    an ALLOW list only *adds* allowed IPs so it can't lock the caller out; a BLOCK list containing
    the caller's IP can be rejected by the API's self-lockout guard, which is captured as a failure
    rather than crashing the run."""
    want = set(labels)
    enabled, failures = 0, []
    for acl in workspace_client.ip_access_lists.list():
        if acl.label not in want or acl.enabled:
            continue
        try:
            workspace_client.ip_access_lists.update(
                ip_access_list_id=acl.list_id,
                label=acl.label,
                list_type=acl.list_type,
                ip_addresses=list(acl.ip_addresses or []),
                enabled=True,
            )
            enabled += 1
        except Exception as e:  # noqa: BLE001 - report per-list; don't abort the whole migration
            failures.append(f"{acl.label}: {str(e)[:200]}")
    return enabled, failures


def resolve_policy_id(cfg: AclConfig, workspace_id) -> str:
    """The new policy's id: the explicit/entered name (--policy-name, resolved by the CLI to the
    profile name when left blank), falling back to the workspace id if nothing was set. Slugified
    and length-capped like every other command."""
    return policy.policy_name("", explicit=(cfg.policy_name or str(workspace_id)))


def build_block(analysis: AclAnalysis, cfg: AclConfig, note: Note = lambda _m: None):
    # mode_label=None → rule labels are migrated verbatim (no "(enforced)"/"(dry-run)" suffix).
    # public_access_enabled + private_plan carry the workspace's front-end PrivateLink posture
    # (populated by the CLI from the account PAS) into the ingress block as-is.
    return policy.build_ingress_block(
        analysis.allow_specs,
        analysis.deny_specs,
        None,
        note,
        public_enabled=analysis.public_access_enabled,
        private_plan=analysis.private_plan,
    )


def build_account_policy(
    analysis: AclAnalysis,
    cfg: AclConfig,
    account_id: str,
    policy_id: str,
    note: Note = lambda _m: None,
    egress=None,
):
    """The full AccountNetworkPolicy this migration would create. The migration only recreates the
    IP ACLs (ingress); the API requires an egress block on create, so it carries over the egress of
    the workspace's currently-assigned policy verbatim (`egress`), preserving its egress posture. When
    that isn't known (`egress` is None — nothing assigned / unreadable) it falls back to a permissive
    FULL_ACCESS egress. Used to create + to export."""
    from databricks.sdk.service.settings import AccountNetworkPolicy

    np = AccountNetworkPolicy(
        account_id=account_id,
        network_policy_id=policy_id,
        egress=egress if egress is not None else policy.build_full_access_egress(),
    )
    setattr(np, cfg.policy_mode_target, build_block(analysis, cfg, note))
    return np


def policy_payload(analysis: AclAnalysis, cfg: AclConfig, account_id: str, egress=None) -> dict:
    """The proposed network policy as a plain dict (for --export / a curl body)."""
    policy_id = resolve_policy_id(cfg, analysis.workspace_id)
    return build_account_policy(analysis, cfg, account_id, policy_id, egress=egress).as_dict()


def preview_block(analysis: AclAnalysis, cfg: AclConfig, egress=None, note: Note = lambda _m: None) -> dict:
    # Mirror the policy body that would be created: the ingress mode block + the egress carried over
    # from the workspace's currently-assigned policy (`egress`), falling back to the permissive
    # FULL_ACCESS default when that isn't known, so the preview surfaces the real egress too.
    block = build_block(analysis, cfg, note)
    egress = egress if egress is not None else policy.build_full_access_egress()
    return {
        cfg.policy_mode_target: block.as_dict(),
        "egress": egress.as_dict(),
    }


def apply(
    analysis: AclAnalysis,
    cfg: AclConfig,
    account,
    account_id: str,
    note: Note = lambda _m: None,
    egress=None,
) -> dict:
    """Create the named policy (migrate-acl only creates new policies — name uniqueness is checked
    up front) and optionally assign this workspace."""
    from databricks.sdk.service.settings import WorkspaceNetworkOption

    policy_id = resolve_policy_id(cfg, analysis.workspace_id)
    new_policy = build_account_policy(analysis, cfg, account_id, policy_id, note, egress=egress)
    result = account.network_policies.create_network_policy_rpc(network_policy=new_policy)
    effective_id = result.network_policy_id or policy_id

    out = {"action": "created", "policy_id": effective_id}
    if cfg.auto_assign:
        account.workspace_network_configuration.update_workspace_network_option_rpc(
            workspace_id=analysis.workspace_id,
            workspace_network_option=WorkspaceNetworkOption(
                workspace_id=analysis.workspace_id, network_policy_id=effective_id
            ),
        )
        out["assigned"] = analysis.workspace_id
    return out
