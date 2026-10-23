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

## [0.2.1] - 2026-10-23

### Fixed

- **Back-end PrivateLink endpoints are now included in a restricted private policy (AWS / GCP).**
  When front-end PrivateLink is endpoint-scoped, the generated `private_access` block is
  `RESTRICTED_ACCESS` — which gates **all** private ingress, not just the front-end. Previously the
  block was built from the Private Access Settings (front-end) alone, so the workspace's back-end
  data-plane endpoints (SCC relay + REST) — which live in the network configuration, not the PAS —
  were left out and the restricted policy blocked the data plane (notebook commands failing
  "against the workspace's ingress policy"). The migration now reads those back-end endpoints from
  the workspace's network config (`network.vpc_endpoints`: AWS VPC endpoints / GCP PSC) and adds
  them as a distinct allow rule alongside the front-end endpoints. Service-direct PrivateLink
  endpoints, when access is endpoint-restricted, are already carried over verbatim via the PAS, so
  they need no special handling. A workspace with no back-end PrivateLink (e.g. front-end only, with
  back-end reaching the control plane via the compute-plane NAT gateway) migrates unchanged, with a
  note that none was detected.

## [0.2.0] - 2026-10-21

### Added

- **Front-end PrivateLink migration (AWS / GCP).** A workspace with a Private Access Settings (PAS)
  object is no longer rejected — its front-end PrivateLink (GCP: Private Service Connect, via the
  same PAS object) is now recreated **as-is** in the new
  policy's `private_access` block: `private_access_level=ACCOUNT` →
  `ALLOW_ALL_REGISTERED_ENDPOINTS`; `ENDPOINT` → a `RESTRICTED_ACCESS` rule listing the registered
  endpoint ids. The PAS and the public-network-access toggle are read, never modified.
- **PrivateLink-only workspaces.** A workspace with public access disabled (PrivateLink-only) can
  now be migrated: the IP access lists aren't recreated as public rules (they aren't in effect),
  the `public_access` block becomes an explicit deny-all, and a workspace with no IP access lists is
  no longer treated as "nothing to migrate" when it has front-end PrivateLink.
- **Preserve existing CBI rules for non-migrated dimensions.** Public and private ingress are
  independent. The generated policy now **preserves** (copies verbatim) the workspace's existing
  assigned CBI policy's `private_access` / `public_access` / `cross_workspace_access` for any
  dimension this migration doesn't itself produce — so a workspace that already has CBI private
  rules keeps them when its IP access lists are migrated to public. An account-level (allow-all)
  PAS never loosens a stricter existing CBI private policy.

### Fixed

- **Dormant IP access lists are no longer migrated.** When the workspace master toggle
  `enableIpAccessLists` is **off**, its IP access lists are not enforced — even if individual lists
  have `enabled=true`. Previously, proceeding on such a workspace (e.g. for front-end PrivateLink)
  would still turn those dormant lists into active public rules and overwrite the workspace's
  actually-enforced CBI public. Now the tool migrates IP access lists **only when enforcement is on,
  or the operator re-enables it in this run**. The re-enable offer is made whenever the toggle is
  off and there are rules (independent of PrivateLink); if declined (or the run is non-interactive /
  propose-only), no IP access list rules are migrated and the existing CBI public is preserved.

### Changed

- **Per-dimension conflict check replaces the blanket "existing CBI policy → abort".** Migration now
  aborts only on a true same-dimension collision (and only when assigning): a legacy public source
  (IP access lists / PAS public toggle) over a restrictive CBI **public** block, or an
  endpoint-scoped PAS over a restrictive CBI **private** block. Other combinations proceed and copy
  the existing blocks across, so public and private can be migrated in one pass.
- **Per-cloud PrivateLink handling.** The former account-wide "any registered VPC endpoint → abort"
  check is replaced by reading **this workspace's** PAS. **AWS and GCP** both migrate front-end
  PrivateLink from the PAS — on GCP it's Private Service Connect (PSC), surfaced through the same PAS
  object, so the mapping is identical (cloud-agnostic). **Azure** has no front-end PrivateLink to
  migrate (Azure uses Azure Private Endpoints, which context-based ingress allows by default, and the
  public network-access toggle isn't retired), so Azure migrates its IP access lists only — and still
  preserves any existing CBI private rules. No flag changes.

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

[Unreleased]: https://github.com/databrickslabs/migrate-ip-acls/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/databrickslabs/migrate-ip-acls/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/databrickslabs/migrate-ip-acls/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/databrickslabs/migrate-ip-acls/releases/tag/v0.1.0
