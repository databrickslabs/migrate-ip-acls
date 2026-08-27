---
name: ip-acl-migration
description: Migrate a Databricks workspace's existing IP access list (ACL) into a context-based ingress (CBI) account network policy, as-is, using the dbx-migrate-ip-acls CLI. Use when the user wants to convert / migrate an existing IP access list to a network policy, recreate their IP ACL as CBI, or stand up a network policy from the current ACL without audit-log analysis. Runs `dbx-migrate-ip-acls`, which reads this workspace's ACL (ALLOW->allow rules, BLOCK->deny rules) and recreates it verbatim — nothing added — then creates the account network policy (enforce or dry-run) and optionally auto-assigns it to the current workspace.
---

# IP Access List → CBI migration

Migrates **this workspace's existing IP access list** into a context-based ingress (CBI) account
network policy, **as-is** — no audit-log analysis, no enrichment, nothing added. The engine is the
single command `dbx-migrate-ip-acls` (this repo).

For traffic-based suggestions, threat-intel / cloud enrichment, or identity/destination scoping, use
the separate **databricks-network-policy-helper** tool (`dbx-nwp-helper ingress` / `egress`) instead.

## When to use

The user wants to: migrate / convert an existing IP access list to a network policy, recreate their
IP ACL as CBI, or create a network policy from the current ACL without analysing traffic.

## Setup

`uv sync`, then `uv run dbx-migrate-ip-acls …` (or `uv tool install .` then `dbx-migrate-ip-acls …`).
Auth is the SDK's unified auth (`--profile` or `DATABRICKS_*`). **This tool always needs
account-admin access** (pass `--account-id` with account-admin credentials): even a propose-only /
`--export` run performs account-level pre-checks (existing network policy + PrivateLink). No SQL
warehouse is needed (no traffic analysis). It is a **single command** — there is no subcommand, so
options go straight after the program name.

## What it does

1. **Right after the workspace is chosen**, decides whether there's anything to migrate, from the
   workspace-wide `enableIpAccessLists` toggle × the number of IP access lists:
   - **disabled + 0 rules** → "disabled and have no rules. Nothing to migrate." → **exit**.
   - **disabled + 1+ rules** → the rules aren't in effect, so there's nothing enabled to migrate. It
     **prints the current IP-ACL config** and (interactively) offers to **enable** them: **yes** →
     sets `enableIpAccessLists=true` and **continues** the migration in the same run; **no** → exits
     (nothing to migrate). `--yes` never auto-flips the toggle — it exits with guidance.
   - **enabled + 0 rules** → "have no rules. Nothing to migrate." → **exit**.
   - **enabled + 1+ rules** → **proceed**. (Unreadable toggle → warn + proceed.)
2. Reads the workspace's IP access lists (`w.ip_access_lists.list()`). **Individual lists that are
   disabled are flagged and NOT migrated** — only enabled lists are; the disabled ones are called out
   in the final printout (below the old + new policy) so you can vet them. Maps **ALLOW lists → allow
   rules**, **BLOCK lists → deny rules** (IPv4 only; CBI is IPv4-only), recreating each rule
   **verbatim** — the original ACL label, with no prefix and no mode suffix. The one thing it adds: if
   the ACL has **only BLOCK lists**, a catch-all allow (all public IPs) is added, because CBI
   RESTRICTED_ACCESS is default-deny — without it a deny-only policy would block everything, flipping
   the ACL's default-allow-except-blocked meaning.
3. Runs account-level **pre-checks** before migrating. The two PrivateLink checks below are **skipped
   entirely on Azure** (the cloud is resolved from the account workspaces API `cloud` field, falling
   back to the workspace host's domain when the API doesn't populate it) — an Azure workspace has
   neither a Private Access Settings object nor VPC endpoints, so it only needs its IP ACLs migrated:
   - **PAS attached?** If **this workspace** has a Private Access Settings object (front-end
     PrivateLink), migration to CBI isn't supported yet — it **aborts**.
   - **Account has registered VPC endpoints?** If the **account** has ≥1 registered VPC (PrivateLink)
     endpoint — front-end or back-end, any use case — it **aborts** too, even if *this* workspace
     isn't attached to one. CBI private access isn't GA yet and defaults to allow-all endpoints, so
     any PrivateLink account is blocked for now (this limitation lifts once CBI private access GAs).
   - **Existing *restrictive* CBI ingress policy?** Only matters when the run will **assign** the new
     policy, and only for a policy that **actually restricts traffic** — an allow-all policy such as
     the account's baseline `default-policy` is ignored. When assigning over a restrictive one —
     **enforced or dry-run** — it **aborts** (migrating on top of an existing CBI ingress policy
     isn't supported yet). When **not** assigning (propose-only, `--export`, `--no-auto-assign`), it
     just **warns**.
4. Names the new policy from `--policy-name`; if not given it **prompts** for one (leave blank there
   to use the profile name). It only **creates new** policies, so if the chosen name already exists it
   re-prompts (interactively) or aborts. `--create-policy` is **on by default** (an interactive review
   gate still confirms before the write); it creates the policy and, if `--auto-assign` (default on),
   binds the current workspace to it. For a propose-only run pass `--no-create-policy --no-auto-assign`.
5. With `--disable-existing-ip-acls` (off by default), after the policy is created **and** assigned,
   turns off the workspace's IP access list enforcement (`enableIpAccessLists=false`) so the old ACL
   and the new CBI policy don't both apply. The lists themselves are preserved (reversible). The CLI
   refuses this flag unless the run also creates and assigns the policy, so it can't leave the
   workspace with no ingress control.

> This tool deliberately does **not** auto-allow Databricks' own control-plane IPs or do any
> enrichment — it assumes the existing ACL is what the customer wants. It migrates the **ingress**
> (the IP ACLs) and, for **egress**, copies the egress block of the policy the workspace currently
> runs under **verbatim** — its enforcement mode, allowed internet (FQDN) + storage destinations, and
> blocked-internet lists — so egress posture is preserved rather than reset. The source is the
> workspace's assigned policy, or the account baseline `default-policy` when nothing is assigned; only
> when neither is readable does it fall back to a permissive `FULL_ACCESS` egress. There is no egress
> option — it always mirrors the current policy.

## Options

- `--policy-mode` — **`enforce`** (default) or `dry_run` (log-only trial).
- `--policy-name` — the new policy's id. If omitted you're **prompted** (blank there = the profile
  name; falls back to the workspace id). Normalised to a lowercase, `-`-safe, length-capped id.
- `--export <path>` — write the proposed network-policy JSON (a curl / REST-ready
  `AccountNetworkPolicy` body) **and** a sibling best-effort Terraform `.tf`
  (`databricks_account_network_policy` — review before `terraform apply`). If `<path>` is a directory
  it writes `<policy-id>.json` + `<policy-id>.tf` inside it (use `--export .` for the current
  directory); missing parent dirs are created. Works in propose-only mode too.
- `--auto-assign` / `--no-auto-assign` — bind the current workspace (default on).
- `--create-policy` / `--no-create-policy` — write the policy. **On by default** (a review gate still
  confirms). For a propose-only run use `--no-create-policy --no-auto-assign`.
- `--disable-existing-ip-acls` — after create + assign, turn off the workspace's IP access lists;
  requires create + assign **and** `--policy-mode enforce`. Off by default.
- `--account-id` (+ account-admin creds) — **always required** (pre-checks and create/assign are all
  account-level).
- `--account-host` / `--account-profile` — account API host / a dedicated profile for account-level
  calls. When `--account-host` isn't set it's **derived from the workspace's environment** (so an AWS
  staging, GCP or Azure workspace reaches the matching account console instead of the AWS prod
  default); pass `--account-host` to override, or `--account-profile` to use a specific profile's
  host + creds.

**Invalid flag combinations** (rejected up front): `--no-create-policy` with `--auto-assign` (nothing
to bind); `--disable-existing-ip-acls` without both create + assign, or with `--policy-mode dry_run`
(both would leave the workspace with no enforced ingress control).

## Safety

The tool's job **is** to create the policy, so `--create-policy` is **on by default** — but an
interactive **review gate** still confirms before any write, and by default the CLI **steps through**
each section — pausing after the existing-ACL analysis and after the proposed-policy preview to ask
whether to continue (*no* aborts cleanly). **`--yes` runs non-interactively**, skipping the pauses and
the review/write gate, so `dbx-migrate-ip-acls --yes` *will* create + assign. For a read-only run use
`--no-create-policy --no-auto-assign` (optionally with `--export`) — it writes nothing. Default
`--policy-mode enforce` will block non-matching source IPs on the assigned workspace — trial with
`--policy-mode dry_run` first if unsure.
