"""Presentation layer: turn engine results into Rich output.

Kept separate from the engine (pure logic) and cli.py (arg parsing / flow) so each function takes an
analysis/result object and prints.
"""

from __future__ import annotations

import pandas as pd

from . import acl, console
from .config import AclConfig


# ------------------------------------------------------------------------------------- decisions
def acl_decisions(cfg: AclConfig) -> None:
    console.decisions_panel(
        "IP ACL → CBI migration configuration",
        [
            ("policy_mode", cfg.policy_mode, "enforce (default) or dry_run."),
            ("policy_name", cfg.policy_name, "Policy id for the new policy (from --policy-name / prompt)."),
            ("auto_assign", cfg.auto_assign, "Bind this workspace to the new policy."),
            (
                "disable_existing_ip_acls",
                cfg.disable_existing_ip_acls,
                "After apply, turn off the workspace's IP access lists (needs create + assign).",
            ),
            (
                "export",
                cfg.export,
                "Path to write the proposed policy as JSON + Terraform (.tf); '.' = current directory.",
            ),
            ("create_policy", cfg.create_policy, "Master switch: nothing is written unless true."),
        ],
    )


# ---------------------------------------------------------------------------------- acl tables
def _acl_table(rows: list[dict], title: str) -> None:
    console.dataframe(
        pd.DataFrame([{**a, "ip_addresses": ", ".join(a["ip_addresses"])} for a in rows]), title
    )


def acl_current_config(analysis, workspace_enabled: bool = False) -> None:
    """The workspace's *current* IP access list configuration — all lists, enabled and disabled —
    shown when the workspace toggle is off so the user sees what they'd be enabling. The
    (ENABLED)/(DISABLED) suffix reflects the workspace-wide enforcement state."""
    state = "ENABLED" if workspace_enabled else "DISABLED"
    console.rule(f"Current IP access list configuration ({state})")
    # A list is migrated only if it's enabled AND produced a rule (has usable IPv4 CIDRs) — i.e. its
    # label appears in the built allow/deny specs. Disabled lists are never migrated. And when public
    # network access is disabled (PrivateLink-only), the IP access lists aren't in effect at all, so
    # none of them are migrated as public rules regardless of their individual state.
    if getattr(analysis, "public_access_enabled", True):
        migrated = {s["label"] for s in getattr(analysis, "allow_specs", [])} | {
            s["label"] for s in getattr(analysis, "deny_specs", [])
        }
    else:
        migrated = set()

    def _flag(ok: bool) -> str:
        # Colour the cell so the answer clearly stands out (red False / green True). Rich markup
        # renders in the terminal and is stripped in non-TTY/captured output (plain "True"/"False").
        return "[ok]True[/ok]" if ok else "[danger]False[/danger]"

    rows = [
        {**a, "enabled": _flag(True), "will_be_migrated": _flag(a["label"][:250] in migrated)}
        for a in analysis.ip_acls
    ] + [{**a, "enabled": _flag(False), "will_be_migrated": _flag(False)} for a in analysis.disabled_acls]
    if rows:
        _acl_table(rows, f"IP access lists on workspace {analysis.workspace_id}")


def acl_disabled_notice(analysis) -> None:
    """Flag any individually-disabled IP access lists that won't be migrated, so the operator can
    vet them (the CLI then offers to re-enable and include them)."""
    if not analysis.disabled_acls:
        return
    names = ", ".join(a["label"] for a in analysis.disabled_acls)
    console.banner(
        "warn",
        f"{len(analysis.disabled_acls)} rule(s) are disabled and WILL NOT be migrated: {names}. "
        "Make sure you review these rules carefully before proceeding.",
    )


def acl_private_access(analysis) -> None:
    """Show what the generated policy's private_access will be — the front-end PrivateLink migrated
    from the PAS, or the workspace's existing CBI private rules preserved verbatim. Nothing is shown
    when there's neither."""
    plan = getattr(analysis, "private_plan", None)
    existing_private = getattr(analysis, "existing_private", None)
    if plan is None:
        if existing_private is not None:
            console.rule("Private access")
            console.banner(
                "info",
                "The workspace's existing CBI private access rules are preserved verbatim in the new "
                "policy (this migration doesn't change private access on this workspace). Review them "
                "in the JSON preview below.",
            )
        return
    console.rule("Front-end PrivateLink → private access")
    if plan.restriction_mode == "ALLOW_ALL_REGISTERED_ENDPOINTS" and acl.block_restrictive(existing_private):
        console.banner(
            "info",
            "Front-end PrivateLink is account-level (all registered endpoints), but the workspace "
            "already has stricter CBI private access — the existing restrictive private rules are "
            "preserved rather than loosened. Review them in the JSON preview below.",
        )
        return
    if plan.restriction_mode == "ALLOW_ALL_REGISTERED_ENDPOINTS":
        detail = "all registered private endpoints (ALLOW_ALL_REGISTERED_ENDPOINTS)"
    elif plan.endpoint_ids:
        detail = f"RESTRICTED_ACCESS — selected endpoints: {', '.join(plan.endpoint_ids)}"
    else:
        detail = "RESTRICTED_ACCESS — no registered endpoints permitted"
    backend = getattr(plan, "backend_endpoint_ids", None)
    if backend:
        # The back-end data-plane endpoints aren't in the PAS; a RESTRICTED_ACCESS block gates all
        # private ingress, so they're added alongside the front-end endpoints (see acl.py).
        detail += (
            f"; plus {len(backend)} back-end PrivateLink endpoint(s) "
            f"(data-plane relay + REST): {', '.join(backend)}"
        )
    src = f" (from Private Access Settings '{plan.source_pas_id}')" if plan.source_pas_id else ""
    console.banner(
        "info",
        f"Front-end PrivateLink is migrated as-is into the policy's private access: {detail}{src}. "
        "Review it alongside the JSON preview below.",
    )


def acl_preview(preview: dict, cfg: AclConfig, egress_source: str | None = None) -> None:
    console.rule("Proposed policy — JSON preview")
    console.banner(
        "warn", "Please review the proposed context-based ingress policy carefully before applying."
    )
    console.json_panel(f"`{cfg.policy_mode_target}` block", preview.get(cfg.policy_mode_target))
    if "egress" in preview:
        console.json_panel("`egress` block", preview["egress"])
        if egress_source:
            # A restrictive egress was carried over from the workspace's current policy — say so
            # rather than warning about an unrestricted default.
            console.banner(
                "info",
                f"Egress copied verbatim from the policy the workspace currently runs under "
                f"('{egress_source}') — its enforcement mode, allowed internet (FQDN) + storage "
                "destinations and blocked-internet lists are preserved in the new policy.",
            )
        else:
            console.banner(
                "warn",
                "Serverless egress is left UNRESTRICTED (FULL_ACCESS) — this migration recreates "
                "ingress rules only. Please consider your egress requirements before auto-assigning "
                "this policy to a workspace.",
            )


# ------------------------------------------------------------------------------- apply results
def policy_url(account_host: str, account_id: str, policy_id: str) -> str:
    """The account-console URL for a network policy."""
    host = (account_host or "").rstrip("/")
    return f"{host}/security/networking/network-access-policies/{policy_id}?account_id={account_id}"


def apply_results(results: list[dict], account_host: str = "", account_id: str = "") -> None:
    console.rule("Apply results")
    for r in results:
        if "error" in r:
            console.banner("danger", f"target {r['target']}: {r['error']}")
            continue
        msg = f"{r['action']} network policy"
        if r.get("assigned") is not None:
            msg += f" and bound workspace {r['assigned']}"
        console.banner("success", msg)
        console.console.print(f"   [key]network policy id:[/key] {r['policy_id']}")
        if account_host and account_id:
            url = policy_url(account_host, account_id, r["policy_id"])
            # soft_wrap keeps the URL on one logical line (terminals still soft-wrap the display,
            # but it stays a single copy-pasteable string and isn't hard-broken mid-token).
            console.console.print(f"   [key]url:[/key] [info]{url}[/info]", soft_wrap=True)
