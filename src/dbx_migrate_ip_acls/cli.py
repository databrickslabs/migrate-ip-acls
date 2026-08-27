"""dbx-migrate-ip-acls — the Typer CLI.

A single command: recreate this workspace's existing IP access list as a context-based ingress (CBI)
account network policy, verbatim (ALLOW → allow rules, BLOCK → deny rules). No traffic analysis, no
enrichment. Nothing is written unless --create-policy is set (on by default), and an interactive
review gate (or --yes) guards the write. Auth is the SDK's unified auth (a --profile, DATABRICKS_*
env, or OAuth); account-level pre-checks + create/assign need account-admin credentials.
"""

from __future__ import annotations

from enum import Enum

import typer

from . import console, render
from .config import (
    DEFAULT_ACCOUNT_HOST,
    DEFAULT_NAME_PREFIX,
    MAX_POLICY_ID_LEN,
    AclConfig,
    Connection,
    validate_acl_apply,
)

app = typer.Typer(
    add_completion=False,
    rich_markup_mode="rich",
    help="Migrate this workspace's IP access list into a context-based ingress (CBI) network policy.",
)


class Mode(str, Enum):
    dry_run = "dry_run"
    enforce = "enforce"  # noqa: E702


def _read_config_profiles() -> dict[str, dict[str, str]]:
    """Every profile in ~/.databrickscfg (or $DATABRICKS_CONFIG_FILE) as {name: {key: value}},
    including the DEFAULT section. Empty on a missing file or any read error."""
    import configparser
    import os

    path = os.path.expanduser(os.environ.get("DATABRICKS_CONFIG_FILE") or "~/.databrickscfg")
    if not os.path.exists(path):
        return {}
    cp = configparser.ConfigParser()
    try:
        cp.read(path)
    except configparser.Error:
        return {}
    out = {name: dict(cp[name]) for name in cp.sections()}
    # DEFAULT is a real, selectable profile in .databrickscfg; ConfigParser hides it in sections().
    if cp.defaults():
        out["DEFAULT"] = dict(cp.defaults())
    return out


def _available_profiles() -> list[str]:
    """Profile names configured in ~/.databrickscfg (or $DATABRICKS_CONFIG_FILE), DEFAULT first."""
    profiles = _read_config_profiles()
    names = [n for n in profiles if n != "DEFAULT"]
    if "DEFAULT" in profiles:
        names = ["DEFAULT", *names]
    return names


def _resolve_profile(profile: str | None) -> str | None:
    """Require an explicit profile choice rather than silently falling back to the first-configured
    one. If --profile is given, use it. If env-based auth is configured (DATABRICKS_HOST), allow it
    through. Otherwise prompt the user to pick from ~/.databrickscfg; error if none / non-interactive."""
    import os
    import sys

    if profile:
        return profile
    if os.environ.get("DATABRICKS_HOST"):
        return None  # explicit env auth — respect it

    profiles = _available_profiles()
    if not profiles:
        raise typer.BadParameter(
            "No --profile given and no profiles found in ~/.databrickscfg. Pass --profile <name> "
            "or run `databricks auth login` first."
        )
    if not sys.stdin.isatty():
        raise typer.BadParameter(
            "No --profile given (non-interactive). Pass --profile <name> explicitly — the CLI won't "
            f"guess. Available: {', '.join(profiles)}"
        )

    import questionary

    choice = questionary.select(
        "Which Databricks profile would you like to use? (pass --profile to skip this prompt)",
        choices=profiles,
        instruction="(Use the arrow keys to select)",
    ).ask()
    if not choice:
        raise typer.Abort()
    return choice


def _conn(profile, account_id, account_host, account_profile=None) -> Connection:
    profile = _resolve_profile(profile)
    return Connection(
        profile=profile,
        account_id=account_id or "",
        # None → not pinned: the CLI derives it from the workspace host (see _resolve_account_host).
        account_host=account_host or DEFAULT_ACCOUNT_HOST,
        account_host_explicit=account_host is not None,
        account_profile=account_profile,
    )


def _resolve_account_host(conn: Connection, wc) -> None:
    """When --account-host wasn't pinned, derive it from the workspace host so a workspace in a
    non-default environment (e.g. AWS staging) reaches the matching account API instead of the AWS
    prod default. An explicit --account-host is always respected. Mutates conn."""
    if conn.account_host_explicit:
        return
    from . import acl as acl_core

    ws_host = getattr(getattr(wc, "config", None), "host", None)
    derived = acl_core.account_host_from_workspace_host(ws_host)
    if derived and derived != conn.account_host:
        console.banner(
            "info",
            f"Using account host '{derived}', matched to the workspace's environment. "
            "Pass --account-host to override.",
        )
        conn.account_host = derived


def _norm_host(host: str | None) -> str:
    """Bare, comparable host: scheme + trailing slash stripped, lower-cased. So 'https://X/' and 'X'
    compare equal when matching a config profile's host against the account host."""
    if not host:
        return ""
    from urllib.parse import urlparse

    return urlparse(host if "://" in host else f"https://{host}").netloc.lower().rstrip("/")


def _matching_account_profiles(account_host: str, account_id: str) -> list[str]:
    """Profiles in the Databricks config whose host is `account_host` AND whose account_id is
    `account_id`. Matching on BOTH is deliberate: an account_id alone is ambiguous — the same id
    appears under several profiles, and the same id can exist across environments — so pairing it
    with the account-console host disambiguates."""
    if not account_host or not account_id:
        return []
    target = _norm_host(account_host)
    return [
        name
        for name, cfg in _read_config_profiles().items()
        if _norm_host(cfg.get("host")) == target and (cfg.get("account_id") or "") == account_id
    ]


def _default_account_id_from_workspace(conn: Connection, wc) -> None:
    """When --account-id wasn't given, default it from the workspace profile's own account_id (a
    workspace .databrickscfg profile usually carries it), so the user needn't retype it — and can't
    fat-finger a different account's id. Mutates conn."""
    if conn.account_id:
        return
    ws_account_id = getattr(getattr(wc, "config", None), "account_id", None)
    if ws_account_id:
        conn.account_id = str(ws_account_id)
        console.banner(
            "info",
            f"Using account id '{conn.account_id}' from the workspace profile. Pass --account-id to "
            "override.",
        )


def _resolve_account_profile(conn: Connection) -> None:
    """When no --account-profile was given, find a config profile matching the account host +
    account_id and use it, so account calls authenticate as that account admin rather than whatever
    ambient credential unified auth would otherwise resolve (a frequent source of wrong-tenant /
    wrong-account failures). Mutates conn. No-op when --account-profile was passed or nothing
    matches; on multiple matches it uses the first and says so."""
    if conn.account_profile:
        return
    matches = _matching_account_profiles(conn.account_host, conn.account_id)
    if not matches:
        return  # nothing matched → fall through; the account-access probe explains any failure
    if len(matches) > 1:
        console.banner(
            "info",
            f"Multiple config profiles match account '{conn.account_id}' at {conn.account_host} "
            f"({', '.join(matches)}); using '{matches[0]}'. Pass --account-profile to choose.",
        )
    else:
        console.banner(
            "info",
            f"Using account profile '{matches[0]}', matched to account '{conn.account_id}' at "
            f"{conn.account_host}. Pass --account-profile to override.",
        )
    conn.account_profile = matches[0]


def _ensure_account_id(conn: Connection, reason: str) -> None:
    """Ensure conn.account_id is set before account-level work begins, prompting for it up front
    rather than failing deep in the apply/pre-check step. `reason` explains why it's needed. Mutates
    conn. Prompts interactively; errors clearly when non-interactive."""
    import sys

    if conn.account_id:
        return
    if not sys.stdin.isatty():
        raise typer.BadParameter(
            f"{reason} needs a Databricks account_id. Pass --account-id <id> (non-interactive, so "
            "the CLI can't prompt)."
        )
    import questionary

    console.banner(
        "info",
        "Please enter a Databricks account_id. You can find it in the Account console top-right "
        "user menu, or in the account-console URL after 'account_id='.",
    )
    entered = (questionary.text("Databricks account_id:").ask() or "").strip()
    if not entered:
        raise typer.Abort()
    conn.account_id = entered


def _profile_config_error(e: Exception, profile: str | None, flag: str) -> None:
    """Turn an SDK client-construction ValueError (e.g. a mistyped profile that isn't in
    ~/.databrickscfg) into a clean, actionable message instead of a raw traceback. Always raises."""
    msg = str(e)
    if profile and "profile configured" in msg:
        available = ", ".join(_available_profiles()) or "(none found)"
        console.banner(
            "danger",
            f"{flag} '{profile}' isn't configured in your Databricks config "
            "(~/.databrickscfg or $DATABRICKS_CONFIG_FILE). Available profiles: "
            f"{available}. Fix the name or run `databricks auth login`.",
        )
    else:
        console.banner("danger", f"Couldn't initialise the Databricks client: {msg}")
    raise typer.Exit(code=1) from None


def _is_expired_auth(msg: str) -> bool:
    """True if an SDK auth error looks like expired / invalid Databricks-CLI credentials that a
    `databricks auth login` would fix — as opposed to a mistyped profile or missing config."""
    m = msg.lower()
    return (
        "reauthenticate" in m
        or "refresh token" in m
        or "cannot get access token" in m
        or "databricks auth login" in m
    )


def _reauth_profile(msg: str, fallback: str | None) -> str | None:
    """The profile that actually needs re-authenticating. The SDK error spells out the fix as
    `databricks auth login --profile <name>`, so prefer that exact profile — account access is often
    a different, auto-discovered profile than the workspace one (matched by account host + id), and
    re-authing the profile we *asked* for wouldn't fix it. Falls back to the passed profile when the
    message doesn't name one."""
    import re

    m = re.search(r"auth login --profile (\S+)", msg)
    return m.group(1).rstrip(".").strip("'\"") if m else fallback


def _reauthenticate(profile: str) -> bool:
    """Offer to run `databricks auth login --profile <profile>` and return True if it succeeded (so
    the caller can retry building the client). Returns False — after printing the command to run —
    when non-interactive, when the user declines, when the databricks CLI isn't on PATH, or when the
    login doesn't complete."""
    import shutil
    import subprocess
    import sys

    cmd = f"databricks auth login --profile {profile}"
    console.banner(
        "warn", f"The credentials for profile '{profile}' have expired (or its refresh " "token is invalid)."
    )
    if not sys.stdin.isatty():
        console.banner("info", f"Re-authenticate, then re-run: {cmd}")
        return False
    if not typer.confirm(
        typer.style(f"Re-authenticate now? This runs `{cmd}` and opens a browser.", fg="yellow"), default=True
    ):
        console.banner("info", f"Re-authenticate when ready, then re-run: {cmd}")
        return False
    if shutil.which("databricks") is None:
        console.banner(
            "danger",
            "The `databricks` CLI isn't on your PATH — install it "
            "(https://docs.databricks.com/dev-tools/cli/install), then run: "
            f"{cmd}",
        )
        return False
    console.banner("info", f"Running `{cmd}` …")
    try:
        result = subprocess.run(["databricks", "auth", "login", "--profile", profile])
    except OSError as e:  # noqa: BLE001 - surface a clean message, don't crash
        console.banner("danger", f"Couldn't launch the databricks CLI: {e}. Run manually: {cmd}")
        return False
    if result.returncode != 0:
        console.banner(
            "danger",
            f"Re-authentication didn't complete (exit {result.returncode}). "
            f"Run it manually, then re-run: {cmd}",
        )
        return False
    console.banner("success", "Re-authenticated — continuing.")
    return True


def _client_or_exit(build, profile: str | None, flag: str):
    """Build a Databricks client, turning a config/auth ValueError into a clean CLI error. If the
    failure is expired CLI credentials and a profile is set, offer to re-authenticate and retry the
    build once; any other ValueError (or a declined/failed re-auth) exits cleanly."""
    try:
        return build()
    except ValueError as e:
        # Re-auth the profile the SDK error actually names (which may differ from `profile` — e.g.
        # the account client resolves to a separate auto-discovered profile), not the one we assumed.
        reauth = _reauth_profile(str(e), profile) if _is_expired_auth(str(e)) else None
        if reauth and _reauthenticate(reauth):
            try:
                return build()
            except ValueError as e2:
                _profile_config_error(e2, profile, flag)
        _profile_config_error(e, profile, flag)


def _workspace_client_or_exit(conn: Connection):
    """Build the workspace client, converting a config/profile ValueError into a clean CLI error
    (and offering re-auth on expired credentials)."""
    from . import auth

    return _client_or_exit(lambda: auth.workspace_client(conn), conn.profile, "--profile")


def _account_client_or_exit(conn: Connection):
    """Build the account client, converting a config/profile ValueError into a clean CLI error
    (and offering re-auth on expired credentials)."""
    from . import auth

    return _client_or_exit(
        lambda: auth.account_client(conn),
        conn.account_profile or conn.profile,
        "--account-profile" if conn.account_profile else "--profile",
    )


def _account_access_error(e: Exception, conn: Connection) -> None:
    """Clean, actionable exit when the account API rejects our credentials — wrong account, wrong
    Azure AD / Entra tenant, missing account-admin rights, or (with no --account-profile) no account
    creds resolved for the account host at all. Always raises."""
    if conn.account_profile:
        creds = f"the --account-profile '{conn.account_profile}' credentials"
    else:
        creds = (
            "the account credentials resolved by unified auth — no --account-profile was given and no "
            "profile in your Databricks config matches this account's host + id, so they came from "
            "$DATABRICKS_* / an auto-discovered profile / a cached cloud login, which may be for a "
            "different tenant or account"
        )
    detail = " ".join(str(e).split())[:300] or type(e).__name__
    console.banner(
        "danger",
        f"Couldn't access the Databricks account API at {conn.account_host} for account "
        f"'{conn.account_id}' using {creds}.\n"
        f"  The API rejected the request: {type(e).__name__}: {detail}\n"
        "  This usually means those credentials are for a different account, or (on Azure) a "
        "different Entra ID / AAD tenant than the account console, or lack account-admin rights.\n"
        "  Fix: pass --account-profile <name> for an account-admin login to THIS account "
        "(create one with `databricks auth login --host <account-console-url>`), then re-run.",
    )
    raise typer.Exit(code=1) from None


def _verify_account_access_or_exit(conn: Connection, account, workspace_id):
    """Probe the account API once, right after the account client is built, so a bad account
    credential fails fast with an actionable message instead of being silently swallowed by the
    best-effort account readers (and only surfacing later as a raw SDK traceback). On expired creds,
    offers the same re-auth flow as client construction and retries once with a fresh client. Returns
    (account, workspace_object) — the account client may be rebuilt by a re-auth, so callers must
    adopt the returned one."""
    from . import acl as acl_core
    from . import auth

    prof = conn.account_profile or conn.profile
    retried = False
    while True:
        try:
            return account, acl_core.verify_account_access(account, workspace_id)
        except Exception as e:  # noqa: BLE001 - any account-API failure becomes a clean exit
            msg = str(e)
            if not retried and _is_expired_auth(msg):
                reauth = _reauth_profile(msg, prof)
                if reauth and _reauthenticate(reauth):
                    account = auth.account_client(conn)  # rebuild with the refreshed credentials
                    retried = True
                    continue
            _account_access_error(e, conn)


def _looks_like_account_console(host: str | None) -> bool:
    """True if this host is a Databricks *account* console (accounts.cloud.databricks.com,
    accounts.staging.cloud.databricks.com, accounts.azuredatabricks.net, accounts.gcp.databricks.com)
    rather than a workspace. Used to catch an --account-profile mistakenly passed as the workspace
    --profile before we call workspace-only APIs (e.g. /scim/v2/Me) on it — those return non-JSON on
    an account host and would otherwise blow up as a raw JSONDecodeError."""
    if not host:
        return False
    from urllib.parse import urlparse

    netloc = urlparse(host if "://" in host else f"https://{host}").netloc.lower()
    return netloc.startswith("accounts.")


def _account_profile_as_workspace_error(host: str) -> None:
    """Clean, actionable exit when the workspace --profile resolves to an account console host.
    Always raises."""
    console.banner(
        "danger",
        f"The workspace profile resolves to a Databricks account console ({host}), not a workspace "
        "— it looks like an account profile was passed as --profile.\n"
        "  Pass a WORKSPACE profile as --profile (its host is an adb-* / dbc-* workspace URL), and "
        "put the account profile in --account-profile.",
    )
    raise typer.Exit(code=1)


def _workspace_id_or_exit(wc) -> int:
    """Resolve the workspace id, turning an SDK failure into a clean, actionable message instead of a
    raw traceback. The common cause is a profile that points at an account console (workspace-only
    APIs like /scim/v2/Me return non-JSON there → JSONDecodeError)."""
    try:
        return wc.get_workspace_id()
    except Exception as e:  # noqa: BLE001 - any failure becomes a clean exit
        try:
            host = (wc.config.host or "").rstrip("/")
        except Exception:  # noqa: BLE001
            host = ""
        if _looks_like_account_console(host):
            _account_profile_as_workspace_error(host)
        console.banner(
            "danger",
            f"Couldn't read the workspace id from {host or 'the workspace'} ({type(e).__name__}). "
            "Check that --profile points at a reachable Databricks workspace.",
        )
        raise typer.Exit(code=1) from None


def _confirm_workspace(conn: Connection, yes: bool):
    """Resolve the workspace client and surface exactly which workspace this run reads from and (on
    apply) modifies — profile, URL, id — then gate on Y/N so the target can't be mistaken. Always
    displays; the confirmation is skipped with --yes and is a no-op non-interactively. Returns the
    WorkspaceClient (reused by the caller)."""
    import sys

    wc = _workspace_client_or_exit(conn)
    try:
        host = (wc.config.host or "").rstrip("/") or "unknown"
    except Exception:  # noqa: BLE001 - display best-effort; real auth errors surface later in use
        host = "unknown"
    # A profile pointing at an account console can't be migrated (it's not a workspace) and would
    # otherwise fail deep inside get_workspace_id with a raw JSONDecodeError — catch it up front.
    if _looks_like_account_console(host):
        _account_profile_as_workspace_error(host)
    try:
        ws_id = wc.get_workspace_id()
    except Exception:  # noqa: BLE001
        ws_id = "unknown"
    console.workspace_panel(conn.profile or "env / OAuth", host, ws_id)
    if yes or not sys.stdin.isatty():
        return wc
    if not typer.confirm(typer.style("Is this the correct workspace to migrate?", fg="yellow"), default=True):
        console.banner("info", "Aborted — re-run with the intended --profile.")
        raise typer.Exit(code=0)
    return wc


def _resolve_policy_name(cfg, conn: Connection, wc, yes: bool) -> None:
    """Resolve the policy name once. An explicit --policy-name is kept as-is; otherwise prompt for
    one (blank = the profile name, falling back to the workspace id). Mutates cfg.policy_name."""
    import sys

    if cfg.policy_name:
        return
    if getattr(getattr(cfg, "apply", None), "policy_action", "create_new") == "add_to_existing":
        return
    try:
        ws_id = wc.get_workspace_id()
    except Exception:  # noqa: BLE001
        ws_id = None
    default = conn.profile or (str(ws_id) if ws_id is not None else DEFAULT_NAME_PREFIX)
    if yes or not sys.stdin.isatty():
        cfg.policy_name = default
        return
    import questionary

    entered = (
        questionary.text(f"Policy name for the new network policy? (blank = use '{default}')").ask() or ""
    ).strip()
    cfg.policy_name = entered or default


def _acl_preflight(account, workspace_id, will_assign: bool, yes: bool, is_azure: bool = False) -> None:
    """Account-level pre-checks (run before any migration).

    * This workspace has a PAS (PrivateLink) attached -> always abort (unsupported for now; the
      produced policy would be incomplete).
    * The ACCOUNT has any registered VPC (PrivateLink) endpoints -> abort, even if this workspace
      isn't attached to one (CBI private access defaults to allow-all endpoints, so migrating now
      could change the effective access posture if PAS is later retired; blocked until CBI private
      access is GA).
      Both PrivateLink checks are skipped on Azure, which has neither a PAS nor account VPC
      endpoints — an Azure workspace only needs its IP access lists migrated.
    * An existing assigned CBI ingress policy only matters when this run will **assign** the new
      policy (assigning would replace the existing one). When assigning, an assigned policy that has
      restrictive ingress rules — enforced OR dry-run — aborts: migrating on top of an existing CBI
      ingress policy isn't supported yet. (A dry-run policy used to offer promotion to enforced then
      a re-run, but that was a dead end — the re-run just hit this same abort.)
      When NOT assigning (propose-only, --export, or --no-auto-assign) the workspace's binding is
      untouched, so we just warn and let the run create/export the (unbound) policy."""
    from . import acl as acl_core

    if is_azure:
        # Azure has no Private Access Settings and no VPC (PrivateLink) endpoints, so neither
        # PrivateLink pre-check applies — skip both and migrate the IP access lists only.
        console.banner(
            "info",
            "Azure workspace detected — Azure has no Private Access Settings so these pre-checks "
            "are skipped; only the IP access lists are migrated.",
        )
    else:
        pas = acl_core.workspace_pas_attached(account, workspace_id)
        if pas is True:
            console.banner(
                "danger",
                "This workspace has a Private Access Settings (PAS) object attached "
                "(PrivateLink). Migrating a PAS/PrivateLink workspace to CBI is NOT "
                "supported yet - aborting.",
            )
            raise typer.Exit(code=1)
        if pas is None:
            console.banner(
                "warn",
                "Couldn't verify whether a PAS/PrivateLink is attached (account read "
                "failed). If this workspace uses PrivateLink, migration is NOT "
                "supported yet.",
            )

        endpoints = acl_core.account_registered_endpoint_count(account)
        if endpoints:
            console.banner(
                "danger",
                f"This account has {endpoints} registered VPC (PrivateLink) "
                "endpoint(s). Migrating a workspace in a PrivateLink account to CBI "
                "is NOT supported yet - aborting.",
            )
            raise typer.Exit(code=1)
        if endpoints is None:
            console.banner(
                "warn",
                "Couldn't verify the account's registered VPC endpoints (account "
                "read failed). If this account uses PrivateLink, migration is NOT "
                "supported yet.",
            )

    assigned_id, state = acl_core.assigned_ingress_state(account, workspace_id)
    if state is None:
        return

    if not will_assign:
        kind = "an ENFORCED" if state == "enforced" else "a DRY-RUN"
        console.banner(
            "warn",
            f"This workspace already has {kind} CBI ingress policy "
            f"('{assigned_id}'). This run isn't assigning the new policy, so that "
            "one stays in place — the new policy will be created/exported but not "
            "bound to the workspace.",
        )
        return

    # An assigned policy with restrictive ingress rules — enforced OR dry-run — can't be migrated on
    # top of yet, so abort in both cases. (Promoting a dry-run to enforced and telling the user to
    # re-run was a dead end: the re-run would just hit this same abort.)
    kind = "an ENFORCED" if state == "enforced" else "a DRY-RUN"
    console.banner(
        "danger",
        f"This workspace already has {kind} CBI ingress policy ('{assigned_id}') with ingress "
        "rules. Migrating on top of an existing CBI ingress policy is NOT supported yet - aborting.",
    )
    raise typer.Exit(code=1)


def _confirm_overwrite(dest, yes: bool) -> bool:
    """True if it's OK to write `dest`. A new file: always. An existing file: overwrite silently
    with --yes / non-interactively (for scripting), otherwise prompt (default No)."""
    import sys

    if not dest.exists():
        return True
    if yes or not sys.stdin.isatty():
        return True
    return typer.confirm(typer.style(f"'{dest}' already exists — overwrite?", fg="yellow"), default=False)


def _write_json_export(path: str, payload: dict, yes: bool = False) -> str | None:
    """Write `payload` as pretty JSON to `path`, and return the final path written (or None if an
    existing file was kept). If `path` is a directory (or ends with a separator), write
    `<network_policy_id>.json` inside it; create missing parent dirs; and turn write failures into a
    clean error instead of a traceback."""
    import json
    import os
    from pathlib import Path

    dest = Path(path).expanduser()
    if dest.is_dir() or path.endswith(("/", os.sep)):
        name = payload.get("network_policy_id") or "network-policy"
        dest = dest / f"{name}.json"
    if not _confirm_overwrite(dest, yes):
        console.banner("info", f"Kept existing '{dest}' — not overwritten.")
        return None
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        # Pin UTF-8 so a non-ASCII rule label writes identically on macOS and Windows (whose default
        # text encoding is cp1252, which would otherwise raise on such characters).
        with dest.open("w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
    except OSError as e:
        console.banner("danger", f"Couldn't write --export to '{path}': {e}")
        raise typer.Exit(code=1) from None
    return str(dest)


def _write_tf_export(path: str, payload: dict, yes: bool = False) -> str | None:
    """Write a best-effort Terraform config for `payload` alongside the JSON, and return the path (or
    None if an existing file was kept). A directory writes `<network_policy_id>.tf` inside it; a file
    path takes a `.tf` suffix."""
    import os
    from pathlib import Path

    from . import terraform

    dest = Path(path).expanduser()
    if dest.is_dir() or path.endswith(("/", os.sep)):
        name = payload.get("network_policy_id") or "network-policy"
        dest = dest / f"{name}.tf"
    else:
        dest = dest.with_suffix(".tf")
    if not _confirm_overwrite(dest, yes):
        console.banner("info", f"Kept existing '{dest}' — not overwritten.")
        return None
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(terraform.network_policy_hcl(payload), encoding="utf-8")
    except OSError as e:
        console.banner("danger", f"Couldn't write Terraform export to '{path}': {e}")
        raise typer.Exit(code=1) from None
    return str(dest)


def _export_policy(path: str, payload: dict, yes: bool = False) -> None:
    """Write the proposed policy as both JSON (curl / REST body) and best-effort Terraform. An
    existing file is only overwritten after confirmation (or with --yes)."""
    json_dest = _write_json_export(path, payload, yes)
    tf_dest = _write_tf_export(path, payload, yes)
    if json_dest and tf_dest:
        console.banner(
            "success",
            f"Wrote proposed network-policy JSON to {json_dest} and Terraform to {tf_dest}.",
        )
    elif json_dest:
        console.banner("success", f"Wrote proposed network-policy JSON to {json_dest}.")
    elif tf_dest:
        console.banner("success", f"Wrote proposed network-policy Terraform to {tf_dest}.")


def _note_policy_name(policy_name: str) -> None:
    """Show the id the resolved policy name normalises to (so the user sees the real id when
    case/characters/length were adjusted)."""
    if not policy_name:
        return
    from . import policy

    normalized = policy.policy_name("", explicit=policy_name)
    if normalized != policy_name:
        console.banner(
            "info",
            f"Using policy id '{normalized}' (names are normalised: lowercased, "
            f"non-alphanumerics become '-', capped at {MAX_POLICY_ID_LEN} chars).",
        )


def _confirm_params(yes: bool) -> None:
    """After showing the config, ask the user to confirm before doing any work. --yes skips it, and
    it's a no-op non-interactively so scripted runs aren't blocked. Aborting exits cleanly (0)."""
    import sys

    if yes or not sys.stdin.isatty():
        return
    if not typer.confirm("Proceed with these parameters? (No to abort and adjust flags)", default=True):
        console.banner("info", "Aborted — adjust the flags and re-run (see --help).")
        raise typer.Exit(code=0)


def _confirm_write(yes: bool) -> bool:
    """The write gate. Returns True if the user has confirmed (or --yes given)."""
    if yes:
        return True
    return typer.confirm(
        typer.style(
            "Please review the proposed network policy rules above. Would you like to create/apply "
            "the network policy now?",
            fg="yellow",
        ),
        default=False,
    )


def _checkpoint(yes: bool) -> None:
    """Step-through pause after a results/preview section: let the user review it and choose whether
    to continue. Aborts the run cleanly (exit 0) on 'n'. On by default; skipped with --yes and in
    non-interactive/scripted runs."""
    import sys

    if yes or not sys.stdin.isatty():
        return
    if not typer.confirm(typer.style("Continue to the next step?", fg="yellow"), default=True):
        console.banner("info", "Stopped — nothing further was done.")
        raise typer.Exit(code=0)


def _maybe_disable_ip_acls(disable: bool, results: list[dict], workspace_client) -> None:
    """After a successful create+assign, optionally turn off the workspace's IP access lists. Only
    fires when at least one policy was actually assigned — if the apply errored and assigned nothing,
    we must NOT disable the ACLs (that would strip the workspace's protection). The create+assign
    flag combination itself is validated up front by validate_disable_ip_acls."""
    if not disable:
        return
    if not any(r.get("assigned") is not None for r in results):
        console.banner(
            "warn",
            "Skipped disabling IP access lists — no policy was assigned (the "
            "apply may have failed), so the workspace keeps its current "
            "protection.",
        )
        return
    from . import acl as acl_core

    try:
        with console.status("Disabling workspace IP access lists…"):
            acl_core.disable_ip_access_lists(workspace_client, note=lambda m: console.banner("info", m))
    except Exception as e:  # noqa: BLE001 - the policy is already applied; cleanup failure shouldn't crash
        console.banner(
            "warn",
            f"Couldn't disable the workspace IP access lists automatically: {e}. The new "
            "policy is created and assigned (the workspace stays protected — both "
            "controls just apply for now); disable the IP access lists manually in Admin "
            "settings if you want them off.",
        )


def _acl_ip_gate(analysis, wc, yes: bool, create_policy: bool = True) -> None:
    """Right after the workspace is chosen, decide whether there's anything to migrate, based on the
    workspace-wide `enableIpAccessLists` toggle × the number of IP access lists:
      * disabled + 0 rules  → nothing to migrate (exit);
      * disabled + 1+ rules → print the current config; when creating a policy, offer to re-enable
        enforcement (interactively). A propose-only run (no --create-policy) never writes, so it
        skips the offer and just previews from the individually-enabled lists;
      * enabled  + 0 rules  → nothing to migrate (exit);
      * enabled  + 1+ rules → show the current config, then proceed.
    A read failure on the toggle (None) just warns and proceeds. All exits are clean (code 0)."""
    import sys

    from . import acl as acl_core

    toggle = acl_core.ip_acl_enforcement_state(wc)
    total = len(analysis.ip_acls) + len(analysis.disabled_acls)

    if toggle is False:
        if total == 0:
            console.banner(
                "info",
                "This workspace's IP access lists are disabled and have no rules. "
                "There is nothing to migrate.",
            )
            raise typer.Exit(code=0)
        render.acl_current_config(analysis, workspace_enabled=False)
        if not create_policy:
            # Propose-only run: never write, so don't offer to re-enable enforcement. Preview from
            # the individually-enabled lists; re-enabling is offered only when creating a policy.
            console.banner(
                "info",
                "This workspace's IP access lists are disabled (not enforced). This is a "
                "propose-only run, so nothing will be changed — the preview below is built from the "
                "individually-enabled lists. Re-run with --create-policy to be offered to re-enable "
                "your IP access lists.",
            )
            return  # proceed to preview (the empty-check handles 'no enabled lists')
        # The workspace-off warning sits last, directly above the enable prompt. (Individually-
        # disabled lists are flagged + offered for re-enable just after the gate, in _run_acl.)
        console.banner(
            "warn",
            "This workspace's IP access lists are disabled, so there are no currently active rules "
            "to migrate.",
        )
        if yes or not sys.stdin.isatty():
            console.banner(
                "info",
                "Re-run interactively to enable them, or set "
                "enableIpAccessLists=true manually, then re-run — aborting.",
            )
            raise typer.Exit(code=0)
        if typer.confirm(
            typer.style(
                "Would you like to re-enable your IP access lists to continue with the migration?",
                fg="yellow",
            ),
            default=False,
        ):
            acl_core.enable_ip_access_lists(wc, note=lambda m: console.banner("info", m))
            console.banner("info", "Enabled — continuing with the migration of the now-active rules.")
            return  # proceed with the run
        console.banner("info", "Nothing to migrate — the IP access lists are not active. Aborting.")
        raise typer.Exit(code=0)

    # toggle is True or None (unknown).
    if total == 0:
        console.banner(
            "info", "This workspace's IP access lists have no rules. There is nothing to " "migrate."
        )
        raise typer.Exit(code=0)
    if toggle is None:
        console.banner(
            "warn", "Couldn't read this workspace's IP access list enforcement state — " "proceeding."
        )
    # Enforcement is on (or assumed on) and there are rules — show the current config before we
    # proceed, so the table is always visible (not just in the disabled-toggle branch above).
    render.acl_current_config(analysis, workspace_enabled=True)


def _ensure_acl_policy_name_unique(cfg: AclConfig, account, workspace_id, yes: bool) -> None:
    """This tool only *creates* new policies, so the chosen name must not already exist. If it does,
    re-prompt for a new one (interactively) or abort (non-interactive). Mutates cfg.policy_name."""
    import sys

    from . import acl as acl_core

    while acl_core.policy_exists(account, acl_core.resolve_policy_id(cfg, workspace_id)):
        pid = acl_core.resolve_policy_id(cfg, workspace_id)
        if yes or not sys.stdin.isatty():
            console.banner(
                "danger",
                f"A network policy named '{pid}' already exists. This tool only "
                "creates new policies — choose a different --policy-name.",
            )
            raise typer.Exit(code=1)
        console.banner("warn", f"A network policy named '{pid}' already exists — enter a different " "name.")
        import questionary

        entered = (questionary.text("New policy name:").ask() or "").strip()
        if not entered:
            raise typer.Abort()
        cfg.policy_name = entered


@app.callback(invoke_without_command=True)
def migrate(
    profile: str | None = typer.Option(None, help="Databricks CLI/config profile."),
    policy_mode: Mode = typer.Option(Mode.enforce, help="enforce (default) or dry_run."),
    policy_name: str = typer.Option(
        "",
        help="Policy id for the new policy. If omitted you'll be prompted (blank there = use the "
        "profile name). Normalised: lowercased, non-alphanumerics → '-', length-capped.",
    ),
    auto_assign: bool = typer.Option(True, help="Bind this workspace to the new policy."),
    disable_existing_ip_acls: bool = typer.Option(
        False,
        help="After creating AND assigning the policy, disable this workspace's IP access "
        "lists (enableIpAccessLists=false). Requires --create-policy (assign is on by "
        "default).",
    ),
    export: str = typer.Option(
        "",
        help="Write the proposed network-policy JSON (+ a sibling Terraform .tf) to this path "
        "(for curl / the REST API); a directory writes <policy-id>.json inside it (use "
        "--export . for the current directory). Works in propose-only mode too.",
    ),
    account_id: str | None = typer.Option(None, help="Databricks account_id (apply/pre-checks)."),
    account_host: str | None = typer.Option(
        None,
        help="Account API host. Default: derived from the workspace's environment (e.g. AWS staging, "
        "GCP, Azure), falling back to the AWS prod account console.",
    ),
    account_profile: str | None = typer.Option(
        None, help="Profile for account-level calls. Defaults to unified auth."
    ),
    create_policy: bool = typer.Option(
        True,
        help="Write the policy (default). For a propose-only run pass --no-create-policy "
        "--no-auto-assign. An interactive review gate still confirms before any write.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Non-interactive mode: skip all prompts — the step-through pauses between sections and "
        "the review/write gates. Use for scripted runs.",
    ),
):
    """Migrate this workspace's IP access list to a new CBI network policy."""
    # Reject invalid flag combinations FIRST — before the banner, the profile prompt, or any client
    # setup — so a bad combo fails immediately instead of after the user has been asked to pick a
    # profile (these depend only on the flags, not on any workspace/account state).
    try:
        validate_acl_apply(create_policy, auto_assign, disable_existing_ip_acls, policy_mode.value)
    except ValueError as e:
        raise typer.BadParameter(str(e)) from None

    from . import tls, usage

    tls.enable()
    usage.tag()  # tag SDK requests with the tool name (usage tracking) — before any client is built
    console.app_banner()  # splash before the profile prompt, so it's clear what's running
    cfg = AclConfig(
        policy_mode=policy_mode.value,
        policy_name=policy_name,
        auto_assign=auto_assign,
        create_policy=create_policy,
        disable_existing_ip_acls=disable_existing_ip_acls,
        export=export,
    )
    conn = _conn(profile, account_id, account_host, account_profile)
    _run_acl(cfg, conn, yes)


def _reconcile_disabled_lists(analysis, cfg: AclConfig, wc, yes: bool):
    """Flag individually-disabled IP access lists (they won't be migrated) and — interactively —
    offer to re-enable and include them in this migration. On acceptance, enable them and re-read
    the workspace so they're folded into the analysis. A propose-only run (no --create-policy) never
    writes, so it just flags them; non-interactive / --yes never re-enables a deliberately-disabled
    list. Returns the (possibly re-read) analysis."""
    import sys

    from . import acl as acl_core

    if not analysis.disabled_acls:
        return analysis
    render.acl_disabled_notice(analysis)
    if not cfg.create_policy:
        # Propose-only run: never re-enable (a write). Defer the offer to a create run.
        console.banner(
            "info",
            "Propose-only run — nothing will be re-enabled. Re-run with --create-policy for the "
            "option to re-enable and include these rules before the policy is created.",
        )
        return analysis
    if yes or not sys.stdin.isatty():
        return analysis
    import questionary

    # Let the user pick exactly which disabled rules to re-enable + include (not all-or-nothing).
    chosen = questionary.checkbox(
        "Select disabled rules to re-enable and include:",
        choices=[a["label"] for a in analysis.disabled_acls],
        # Override questionary's default hint to drop the confusing <i> (invert) and describe <a>
        # as select-all. (The keys themselves are questionary built-ins; this just re-labels them.)
        instruction="(Use arrow keys to move, <space> to select, <a> to select all, <enter> to confirm)",
    ).ask()
    if not chosen:  # none selected (or aborted) — migrate the currently-enabled lists as-is
        return analysis
    with console.status("Re-enabling IP access lists…"):
        enabled, failures = acl_core.enable_disabled_lists(wc, chosen)
    for f in failures:
        console.banner("warn", f"Couldn't re-enable {f}")
    if enabled:
        console.banner("success", f"Re-enabled {enabled} IP access list(s) — including them in the migration")
        return acl_core.analyze(cfg, wc)
    return analysis


def _run_acl(cfg: AclConfig, conn: Connection, yes: bool) -> None:
    # Flag-combination validation happens up front in the `migrate` callback (before the profile
    # prompt), so by the time we're here the combination is already known-good.
    from . import acl as acl_core

    console.title_panel(
        "IP Access List → CBI migration", "Migrate this workspace's IP ACL to a new CBI policy."
    )
    wc = _confirm_workspace(conn, yes)
    # Point account-level calls at the account console matching the workspace's environment (unless
    # --account-host was pinned), so a staging / GCP / Azure workspace doesn't fail against the AWS
    # prod default.
    _resolve_account_host(conn, wc)

    # Account access is always needed — the pre-checks (PAS / VPC endpoints / existing assigned
    # policy), the name-uniqueness check, and the apply itself are all account-level — and it's the
    # fastest way to abort. So resolve the account_id + client and run the pre-checks right after the
    # workspace is confirmed, BEFORE reading and rendering the (potentially large) IP access list
    # table or prompting about disabled lists. That way an unsupported workspace (PrivateLink) or an
    # existing enforced CBI policy fails fast, instead of after the user has scrolled the ACL table,
    # picked disabled rules, and entered an account_id.
    ws_id = _workspace_id_or_exit(wc)
    # Default the account_id from the workspace profile (so it needn't be retyped / mis-typed), then
    # prompt only if still unknown.
    _default_account_id_from_workspace(conn, wc)
    _ensure_account_id(conn, "Migrating an IP ACL (checks PrivateLink + the existing assigned policy)")
    # With the account host + id known, auto-pick a matching account-admin profile from the config so
    # account calls don't fall back to an ambient (often wrong-tenant / wrong-account) credential.
    _resolve_account_profile(conn)
    account = _account_client_or_exit(conn)
    # Probe the account API once so a bad account credential (wrong account, wrong Azure AD tenant,
    # or not account-admin) fails fast with a clear message here — rather than being silently
    # swallowed by the best-effort readers below (which would degrade to skipped PrivateLink checks
    # and a FULL_ACCESS egress) and only exploding later in policy_exists. Returns the workspace
    # object (reused for cloud detection) and the possibly-rebuilt account client.
    account, ws_obj = _verify_account_access_or_exit(conn, account, ws_id)
    # Azure has no Private Access Settings / VPC-endpoint (PrivateLink) concept, so those pre-checks
    # are skipped there. Resolve the cloud from the account workspaces API `cloud` field, falling back
    # to the workspace host's domain when the API doesn't populate it (it frequently doesn't). An
    # unknown cloud defaults to non-Azure so the checks stay on (they never falsely abort on Azure
    # anyway — it has no PAS and no back-end network config).
    ws_host = getattr(getattr(wc, "config", None), "host", None)
    cloud = acl_core.workspace_cloud(account, ws_id, host=ws_host, ws=ws_obj)
    is_azure = cloud == "azure"
    # An existing assigned policy is only replaced if we're going to assign the new one.
    _acl_preflight(
        account, ws_id, will_assign=cfg.create_policy and cfg.auto_assign, yes=yes, is_azure=is_azure
    )

    # Copy the egress of the policy the workspace currently runs under (its assigned policy, or the
    # account default-policy when nothing is assigned) into the new policy, so its egress posture is
    # preserved verbatim rather than reset to FULL_ACCESS. None → nothing readable → FULL_ACCESS.
    egress_source, existing_egress = acl_core.assigned_egress(account, ws_id)

    # Read the workspace's IP access lists + enforcement state, and decide whether there's anything
    # to migrate at all (the quadrant gate may exit cleanly).
    analysis = acl_core.analyze(cfg, wc)
    _acl_ip_gate(analysis, wc, yes, cfg.create_policy)
    # Flag any individually-disabled lists and offer to re-enable + include them (may re-read).
    analysis = _reconcile_disabled_lists(analysis, cfg, wc, yes)
    if not (analysis.allow_specs or analysis.deny_specs):
        console.banner(
            "info",
            "This workspace's IP access lists are all individually disabled — "
            "there are no enabled rules to migrate.",
        )
        raise typer.Exit(code=0)

    _resolve_policy_name(cfg, conn, wc, yes)
    _ensure_acl_policy_name_unique(cfg, account, ws_id, yes)
    render.acl_decisions(cfg)
    _note_policy_name(cfg.policy_name)
    _confirm_params(yes)

    # Show the final IP ACL set that will be migrated (reflecting any re-enables) and confirm, so the
    # step-through pause has context rather than being a bare "continue?" after the params gate.
    render.acl_current_config(analysis, workspace_enabled=True)
    _checkpoint(yes)

    preview = acl_core.preview_block(
        analysis, cfg, egress=existing_egress, note=lambda m: console.banner("info", m)
    )
    # Flag the egress as copied only when it actually restricts traffic — a FULL_ACCESS default (or
    # an unreadable source) still gets the "egress left unrestricted" warning.
    render.acl_preview(
        preview, cfg, egress_source=(egress_source if acl_core.egress_restrictive(existing_egress) else None)
    )

    if cfg.export:
        _export_policy(
            cfg.export, acl_core.policy_payload(analysis, cfg, conn.account_id, egress=existing_egress), yes
        )

    # The responsibility warning sits directly before the write gate (or the propose-only exit), just
    # after the export log — the last thing shown before you decide to create/apply.
    console.responsibility_warning()

    if not cfg.create_policy:
        console.banner("info", "Propose-only run (--no-create-policy). Nothing was written.")
        return
    if not _confirm_write(yes):
        console.banner("info", "Aborted — nothing written.")
        return

    with console.status("Applying policy…"):
        result = acl_core.apply(
            analysis,
            cfg,
            account,
            conn.account_id,
            note=lambda m: console.banner("info", m),
            egress=existing_egress,
        )
    render.apply_results([result], conn.account_host, conn.account_id)
    _maybe_disable_ip_acls(cfg.disable_existing_ip_acls, [result], wc)


if __name__ == "__main__":
    app()
