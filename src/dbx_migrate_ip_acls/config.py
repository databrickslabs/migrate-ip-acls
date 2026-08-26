"""Configuration dataclasses + input-combination validation.

The command builds an `AclConfig` from its CLI flags, and the engine reads only the dataclass — so
the flag surface and the migration logic never drift apart.
"""

from __future__ import annotations

from dataclasses import dataclass

DEFAULT_ACCOUNT_HOST = "https://accounts.cloud.databricks.com"
# Final fallback for a policy name when there's neither a --policy-name, a profile, nor a workspace id.
DEFAULT_NAME_PREFIX = "dbx-ip-acl"

# Generated policy ids have an empirical ~30-char limit.
MAX_POLICY_ID_LEN = 30


@dataclass
class Connection:
    """How the CLI reaches the workspace + account. Auth itself is resolved by the SDK's unified
    auth (profile / env / OAuth); this only carries the selectors."""

    profile: str | None = None
    account_id: str = ""
    account_host: str = DEFAULT_ACCOUNT_HOST
    # Whether --account-host was set explicitly. When False, the CLI derives the account host from the
    # workspace's environment (so a staging / GCP / Azure workspace reaches the matching account API
    # instead of the AWS prod default); an explicit host is always respected.
    account_host_explicit: bool = False
    # A workspace OAuth session can't call the account API, so the account client uses its own
    # profile when given. If unset, unified auth resolves account creds from env / matching profile.
    account_profile: str | None = None


@dataclass
class AclConfig:
    policy_mode: str = "enforce"
    # Policy id for the new policy. Explicit (--policy-name) or, when left blank, the CLI resolves it
    # to the profile name (falling back to the workspace id). Slugified + length-capped.
    policy_name: str = ""
    auto_assign: bool = True
    create_policy: bool = False
    # After creating AND assigning the new policy, turn off the workspace's existing IP access lists
    # (the CBI policy replaces them). Gated by validate_disable_ip_acls so it can't leave the
    # workspace unprotected.
    disable_existing_ip_acls: bool = False
    # Optional path to write the proposed network-policy JSON (for use with curl / the REST API).
    export: str = ""
    reviewed: bool = False

    @property
    def policy_mode_target(self) -> str:
        return {"dry_run": "ingress_dry_run", "enforce": "ingress"}[self.policy_mode]


def validate_disable_ip_acls(disable: bool, create_policy: bool, auto_assign: bool) -> None:
    """--disable-existing-ip-acls turns OFF the workspace's IP access list enforcement, which is a
    live ingress control. Only permit it when the run will both *create* AND *assign* the
    replacement CBI policy — otherwise disabling the ACL could leave the workspace with no ingress
    protection at all."""
    if not disable:
        return
    if not (create_policy and auto_assign):
        raise ValueError(
            "--disable-existing-ip-acls turns off the workspace's IP access lists, so it may only be "
            "used when the run also creates AND assigns the replacement policy (otherwise the "
            "workspace could be left with no ingress protection). Re-run with --create-policy and "
            "--auto-assign, or drop --disable-existing-ip-acls."
        )


def validate_acl_apply(
    create_policy: bool, auto_assign: bool, disable_existing_ip_acls: bool, policy_mode: str
) -> None:
    """Input-combination guards — reject nonsensical / unsafe flag combos up front."""
    # Can't assign a policy you're not creating.
    if auto_assign and not create_policy:
        raise ValueError(
            "--auto-assign can't be used with --no-create-policy — there's no new policy to bind. "
            "For a propose-only run pass --no-create-policy --no-auto-assign; otherwise keep "
            "--create-policy (the default)."
        )
    # Disabling the workspace's IP ACLs requires the replacement to be created AND assigned.
    validate_disable_ip_acls(disable_existing_ip_acls, create_policy, auto_assign)
    # A dry-run policy enforces nothing, so disabling the old ACLs would leave NO active ingress
    # control at all.
    if disable_existing_ip_acls and policy_mode == "dry_run":
        raise ValueError(
            "--disable-existing-ip-acls with --policy-mode dry_run would leave the workspace with no "
            "enforced ingress control (a dry-run policy blocks nothing). Use --policy-mode enforce, "
            "or drop --disable-existing-ip-acls."
        )
