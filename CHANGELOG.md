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
