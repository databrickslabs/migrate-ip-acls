# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). For a CLI, the
"public API" governed by SemVer is the command and flag surface: a breaking change to it bumps
the **major** version, a backward-compatible addition bumps the **minor**, and a fix bumps the
**patch**.

The version is derived from the git tag by `hatch-vcs`, so a release is cut by tagging the
commit `vX.Y.Z` — which the release workflow then publishes to PyPI. See
[`docs/releasing.md`](docs/releasing.md).

## [Unreleased]

### Added

- **Front-end PrivateLink migration (AWS).** A workspace with a Private Access Settings (PAS)
  object is no longer rejected — its front-end PrivateLink is now recreated **as-is** in the new
  policy's `private_access` block: `private_access_level=ACCOUNT` →
  `ALLOW_ALL_REGISTERED_ENDPOINTS`; `ENDPOINT` → a `RESTRICTED_ACCESS` rule listing the registered
  endpoint ids. The PAS and the public-network-access toggle are read, never modified.
- **PrivateLink-only workspaces.** A workspace with public access disabled (PrivateLink-only) can
  now be migrated: the IP access lists aren't recreated as public rules (they aren't in effect),
  the `public_access` block becomes an explicit deny-all, and a workspace with no IP access lists is
  no longer treated as "nothing to migrate" when it has front-end PrivateLink.

### Changed

- **Per-cloud PrivateLink handling in the pre-checks.** The former account-wide "any registered VPC
  endpoint → abort" check is replaced by reading **this workspace's** PAS. GCP workspaces protected
  by Private Service Connect (PSC) still abort (planned fast-follow). Azure front-end PrivateLink
  isn't readable via the Databricks account API, so it is **not** migrated — Azure workspaces
  migrate their IP access lists only, with a note to configure Azure PrivateLink manually (planned
  fast-follow). No flag changes.

## [0.1.0] - 2026-09-18

First release. `dbx-migrate-ip-acls` recreates a Databricks workspace's existing **IP access list**
as a **context-based ingress (CBI)** account network policy, verbatim — no traffic analysis, no
enrichment.

### Added

- **Verbatim ACL → CBI migration.** Reads the workspace's IP access lists and rebuilds them as a
  CBI account network policy: `ALLOW` entries become allow rules, `BLOCK` entries become deny
  rules, and the workspace's current egress is carried over unchanged.
- **Account-level pre-checks.** Inspects the workspace's currently-assigned policy and PrivateLink
  posture, and aborts (or warns) rather than silently clobbering an existing policy.
- **Dry-run-first, review-gated apply.** `--policy-mode dry_run` (log-only) or `enforce`; an
  interactive step-through and review gate confirm before any write (bypass with `--yes`).
  Nothing is created/assigned in a propose-only run (`--no-create-policy --no-auto-assign`).
- **Optional IP-ACL disable.** `--disable-existing-ip-acls` turns off the workspace's IP access
  lists (`enableIpAccessLists=false`) only after the replacement policy is created *and* assigned.
- **Export.** `--export <path>` writes the proposed policy as JSON plus a sibling Terraform `.tf`,
  working in propose-only mode.
- **`--version`.** `dbx-migrate-ip-acls --version` reports the tool version.

[Unreleased]: https://github.com/databrickslabs/migrate-ip-acls/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/databrickslabs/migrate-ip-acls/releases/tag/v0.1.0
