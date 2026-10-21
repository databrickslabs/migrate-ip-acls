# 🔁 Databricks Migrate IP ACLs

[![CI](https://github.com/databrickslabs/migrate-ip-acls/actions/workflows/ci.yml/badge.svg)](https://github.com/databrickslabs/migrate-ip-acls/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/databrickslabs/migrate-ip-acls/branch/main/graph/badge.svg)](https://codecov.io/gh/databrickslabs/migrate-ip-acls)

Recreate a Databricks workspace's **existing IP access list** — and its **front-end PrivateLink** (AWS) — as a **context-based ingress (CBI) policy** via a single, focused CLI: **`dbx-migrate-ip-acls`**.
> 💡 Looking for traffic-analysis-based ingress/egress policy generation? Those live in the sibling tool - 
> **[databricks-network-policy-helper](https://github.com/andyweaves/databricks-network-policy-helper)**
> (`ingress` / `egress`). 

## ⚠️ Warning

A network policy is a **security-enforcing** control. This tool recreates your **current** IP access
list as-is; it does not judge whether that ACL is correct or complete. You are responsible for
reviewing every rule (and the disabled-rule notice) before applying — an incorrect or incomplete
allow-list can block legitimate users (in enforce mode) or fail to block malicious ones. Trial with
`--policy-mode dry_run` first if unsure.

## 🚀 Quick start

```bash
uv sync

# Propose-only (writes nothing): read the IP ACL and preview the CBI policy
uv run dbx-migrate-ip-acls --profile my-workspace --account-id <acct-id> \
    --no-create-policy --no-auto-assign

# Migrate for real: create the policy (enforce) and bind this workspace to it
uv run dbx-migrate-ip-acls --profile my-workspace --account-id <acct-id>
```

Or install the CLI on your PATH:

```bash
uv tool install .
dbx-migrate-ip-acls --help
```

Auth is the Databricks SDK's unified auth (`--profile`, `DATABRICKS_*` env, or OAuth).
**Account-admin credentials are always required** — the pre-checks and create/assign are all
account-level (see *Account access* below).

## 🏗️ Architecture

At a high level: the CLI reads the workspace's IP access lists through a **workspace client**, and
does every check + write through an **account-admin client** against the Databricks **account** APIs.
The engine turns the ACL into a CBI policy dataclass — carrying over the workspace's current egress
verbatim — which is previewed, optionally exported (JSON + Terraform), and — once you confirm —
created and bound to the workspace.

```mermaid
flowchart LR
    U(["You"]) --> CLI["<b>dbx-migrate-ip-acls</b><br/>Typer CLI · review gates"]

    subgraph TOOL["dbx_migrate_ip_acls"]
        direction TB
        CLI --> AUTH["auth · unified auth<br/>(profile / env / OAuth)"]
        AUTH --> WSC["Workspace client"]
        AUTH --> ACC["Account client<br/>(account admin)"]
        CLI --> ENG["acl.py — analyze → build<br/>policy.py — CBI SDK builders"]
        ENG --> EXP["export<br/>JSON + Terraform"]
    end

    WSC -->|"read IP access lists +<br/>enableIpAccessLists toggle"| WAPI["Databricks<br/>Workspace API"]
    ENG -. builds policy .-> ACC
    ACC -->|"pre-checks: assigned policy ·<br/>read Private Access Settings ·<br/>create + assign"| AAPI["Databricks<br/>Account API"]
    EXP -. writes .-> FILES[["&lt;policy-id&gt;.json<br/>&lt;policy-id&gt;.tf"]]

    classDef you fill:#e2e3e5,stroke:#6c757d,color:#111
    classDef cli fill:#d1e7dd,stroke:#146c43,color:#111
    classDef comp fill:#cfe2ff,stroke:#0d6efd,color:#111
    classDef ext fill:#fff3cd,stroke:#997404,color:#111
    classDef file fill:#f8f9fa,stroke:#6c757d,color:#111
    class U you
    class CLI cli
    class AUTH,WSC,ACC,ENG,EXP comp
    class WAPI,AAPI ext
    class FILES file
```

## 🗺️ How it flows

```mermaid
flowchart TD
    A(["dbx-migrate-ip-acls"]) --> B{"Confirm target workspace?"}
    B -->|no| X1["Abort — nothing written"]
    B -->|yes| ACCT["Account access (prompt account_id) · pre-checks"]
    ACCT --> PL{"Front-end PrivateLink? (per cloud)"}
    PL -->|"AWS: PAS attached"| PLM["Read PAS → migrate private access as-is<br/>(public toggle + endpoint scope)"]
    PL -->|"GCP: PAS attached (PSC)"| X2["ABORT — not supported yet (fast-follow)"]
    PL -->|"Azure"| PLZ["Nothing to migrate (Azure PEs allowed by CBI<br/>by default) — migrate IP ACLs only"]
    PL -->|"none attached"| RDACL
    PLM --> RDACL["Read IP access lists + the existing assigned CBI policy"]
    PLZ --> RDACL
    RDACL --> CFL{"Assigning AND a legacy source collides with a<br/>restrictive CBI block of the SAME dimension?<br/>(public: IP ACLs / toggle · private: endpoint-scoped PAS)"}
    CFL -->|yes| X3["ABORT — can't migrate over it"]
    CFL -->|"no — copy existing CBI blocks<br/>for the dimensions not migrated"| GATE{"enableIpAccessLists × rule count"}
    GATE -->|"public disabled (PrivateLink-only)"| NAME
    GATE -->|"0 rules, but front-end PL present"| NAME
    GATE -->|"enabled + 0 rules, no PL"| X4["No rules — nothing to migrate, stop"]
    GATE -->|"disabled + 0 rules, no PL"| X4
    GATE -->|"disabled + rules → enable & continue"| REEN["Set enableIpAccessLists=true — continue"]
    GATE -->|"disabled + rules → decline / --yes, no PL"| X6["Not active — nothing to migrate, stop"]
    REEN --> NAME
    GATE -->|"enabled + 1+ rules"| NAME["Resolve policy name (prompt; blank = profile)<br/>must be unique — re-prompt if it exists"]
    NAME --> RD["ALLOW → allow, BLOCK → deny (IPv4, ENABLED only)<br/>labels verbatim; disabled lists flagged, not migrated.<br/>PAS → private access as-is; public-disabled → deny-all public;<br/>existing CBI blocks preserved for non-migrated dimensions"]
    RD --> P["Preview proposed policy + disabled-rule notice"]
    P --> EXP{"--export?"}
    EXP -->|yes| EXPW["Write JSON + Terraform"]
    EXP -->|no| CR{"--create-policy? (default on)"}
    EXPW --> CR
    CR -->|"no (--no-create-policy)"| X5["Propose-only — nothing written"]
    CR -->|yes| WMODE{"--policy-mode"}
    WMODE -->|enforce| WE["Create ingress (blocking)<br/>+ egress copied from current policy"]
    WMODE -->|dry_run| WD["Create ingress_dry_run (log-only)<br/>+ egress copied from current policy"]
    WE --> AS{"--auto-assign? (default on)"}
    WD --> AS
    AS -->|no| DONE(["Done"])
    AS -->|yes| ASB["Bind workspace to policy"]
    ASB --> DIS{"--disable-existing-ip-acls?"}
    DIS -->|no| DONE
    DIS -->|yes| DISB["Set enableIpAccessLists=false"]
    DISB --> DONE
    classDef stop fill:#f8d7da,stroke:#b02a37,color:#111
    classDef done fill:#e2e3e5,stroke:#6c757d,color:#111
    classDef write fill:#d1e7dd,stroke:#146c43,color:#111
    classDef warn fill:#fff3cd,stroke:#997404,color:#111
    class X2,X3 stop
    class X1,X4,X5,X6,DONE done
    class WD,WE,ASB,DISB write
    class PROM,REEN warn
```

## 🧰 What it does

1. **Right after the workspace is chosen** — and *before* the IP access lists are read or shown —
   runs account-level **pre-checks**, so an unsupported or already-migrated workspace fails fast. It
   prompts for the `account_id` if it wasn't passed, then resolves **front-end PrivateLink** per
   cloud by reading this workspace's **Private Access Settings (PAS)**:
   - **AWS** — a PAS attached is **migrated as-is** into the new policy's `private_access` block (see
     step 3); no PAS → public-only, as before.
   - **GCP** — a PAS means Private Service Connect (PSC); migrating a PSC-protected GCP workspace to
     CBI isn't supported yet → **abort** (planned fast-follow).
   - **Azure** — there's nothing to migrate: Azure front-end PrivateLink uses Azure Private
     Endpoints (not a PAS), which context-based ingress allows by default, and the public
     network-access toggle isn't being retired. So an Azure workspace migrates its IP access lists
     only (any existing CBI private rules are still preserved — see below).

   Public and private ingress are **independent dimensions**. For any dimension this migration
   doesn't itself produce, the generated policy **preserves** (copies verbatim) the workspace's
   existing assigned CBI block — so a workspace that already has CBI private rules keeps them when
   its IP access lists are migrated to public. Only when the run will **assign** does it guard a true
   same-dimension collision: a legacy public source (IP access lists / PAS public toggle) over a
   **restrictive** CBI *public* block, or an endpoint-scoped PAS over a **restrictive** CBI *private*
   block → **abort**. Allow-all blocks (e.g. the account's baseline `default-policy`) never collide,
   and an account-level (allow-all) PAS never loosens a stricter existing CBI private policy.
2. Then decides whether there's anything to migrate, from the workspace-wide `enableIpAccessLists`
   toggle × the number of IP access lists:
   - **disabled + 0 rules** → nothing to migrate → exit.
   - **disabled + 1+ rules** → the rules aren't in effect. It prints the current IP-ACL config and
     (interactively) offers to **enable** them: **yes** → sets `enableIpAccessLists=true` and
     **continues** in the same run; **no** → exits. `--yes` never auto-flips the toggle.
   - **enabled + 0 rules** → nothing to migrate → exit.
   - **enabled + 1+ rules** → proceed. (Unreadable toggle → warn + proceed.)
3. Reads the workspace's IP access lists (`w.ip_access_lists.list()`). **Individual lists that are
   disabled are flagged and NOT migrated** — only enabled lists are; the disabled ones are called
   out in the final printout so you can vet them. Maps **ALLOW → allow rules**, **BLOCK → deny
   rules** (IPv4 only; CBI is IPv4-only), recreating each rule **verbatim** — the original ACL
   label, no prefix, no mode suffix. The one thing it adds: if the ACL has **only BLOCK lists**, a
   catch-all allow (all public IPs) is added, because CBI RESTRICTED_ACCESS is default-deny —
   without it a deny-only policy would block everything. On **AWS**, it also recreates the
   workspace's **front-end PrivateLink** verbatim from its PAS: `private_access_level=ACCOUNT` →
   `ALLOW_ALL_REGISTERED_ENDPOINTS`; `private_access_level=ENDPOINT` → a `RESTRICTED_ACCESS` private
   rule listing the PAS's registered endpoint ids. When the PAS has **public access disabled**
   (PrivateLink-only), the IP access lists aren't in effect, so the `public_access` block is an
   explicit **deny-all** (RESTRICTED_ACCESS, no allow rules) rather than recreating them — public
   ingress stays closed even if the workspace's public toggle is later re-enabled. The PAS itself and
   the public toggle are **read, never modified**.
4. Names the new policy from `--policy-name` (or prompts; blank = the profile name). It only
   **creates new** policies, so a name that already exists re-prompts (or aborts non-interactively).
   `--create-policy` is **on by default** (a review gate still confirms); with `--auto-assign`
   (default on) it binds the current workspace.
5. With `--disable-existing-ip-acls` (off by default), after the policy is created **and** assigned,
   turns off the workspace's IP access list enforcement (`enableIpAccessLists=false`) so the old ACL
   and the new CBI policy don't both apply. The lists themselves are preserved (reversible).

> This tool deliberately does **not** enrich or auto-allow Databricks' own control-plane IPs — it
> assumes the existing ACL is what you want. It recreates the **ingress** (the IP ACLs, plus front-end
PrivateLink on AWS) and, for
> **egress**, copies the egress of the policy the workspace currently runs under **verbatim** — its
> enforcement mode, allowed internet (FQDN) + storage destinations, and blocked-internet lists — so
> egress posture is preserved rather than reset. The source is the workspace's assigned policy, or the
> account baseline `default-policy` when nothing is assigned; only when neither is readable does it
> fall back to a permissive `FULL_ACCESS` egress. This is automatic — there is no egress flag.

## ⚙️ Options

| Option | Meaning |
|---|---|
| `--profile` | Databricks CLI/config profile. Prompted if omitted (never guessed). |
| `--policy-mode enforce\|dry_run` | `enforce` (default) blocks non-matching source IPs once assigned; `dry_run` is log-only. |
| `--policy-name` | The new policy's id. If omitted you're prompted (blank there = the profile name, falling back to the workspace id). Normalised to a lowercase, `-`-safe id, capped at 30 chars. |
| `--export <path>` | Write the proposed policy JSON **and** a sibling best-effort Terraform `.tf` (`databricks_account_network_policy` — review before `terraform apply`). A directory writes `<policy-id>.{json,tf}` inside it (use `--export .` for the current dir); missing parents are created. Works in propose-only mode too. |
| `--auto-assign` / `--no-auto-assign` | Bind the current workspace to the new policy (default **on**). |
| `--create-policy` / `--no-create-policy` | Master write switch. **On by default** (a review gate still confirms). For a propose-only run: `--no-create-policy --no-auto-assign`. |
| `--disable-existing-ip-acls` | After create **and** assign, turn off the workspace's IP access lists. Requires create + assign **and** `--policy-mode enforce`. Off by default. |
| `--account-id` (+ account-admin creds) | Account-level (pre-checks and create/assign). When unset it **defaults to the workspace profile's own `account_id`**, else prompts. |
| `--account-host`, `--account-profile` | Account API host (when unset, **derived from the workspace's environment** — AWS staging / GCP / Azure — falling back to the AWS prod console) / a dedicated profile for account-level calls. When `--account-profile` is unset, the CLI **auto-selects a config profile whose host + account_id match** the target account, so account calls don't fall back to an ambient credential. |
| `--yes`, `-y` | Non-interactive: skip the step-through pauses and the review/write gate. `--yes` **will** create + assign. |

**Invalid flag combinations** (rejected up front — before the profile prompt or any account call, so
they fail instantly): `--no-create-policy` with `--auto-assign` (nothing to bind);
`--disable-existing-ip-acls` without both create + assign, or with `--policy-mode dry_run` (both
would leave the workspace with no enforced ingress control).

## 🔒 Account access

Every run is account-level: the pre-checks (PrivateLink / existing assigned policy) read account
APIs, and create/assign write them. Pass `--account-id <numeric id>` with **account-admin**
credentials resolvable by unified auth for the account host (an account-admin service principal via
OAuth M2M is the recommended path). A workspace-only OAuth session **cannot** call the account API —
use `--account-profile` (or env) for account creds if your workspace profile can't.

`--account-id` isn't usually typed: it **defaults to the workspace profile's `account_id`** when set.
Likewise, if you don't pass `--account-profile`, the CLI looks in your Databricks config for a profile
whose **host and `account_id` both match** the target account and uses it automatically (matching on
both, since an `account_id` alone is ambiguous across profiles and environments). If exactly one
matches it's used; none → it falls back to unified auth (and the account-access check fails fast with
a clear message if that credential is wrong); several → it uses the first and tells you.

The **account host** is chosen to match the workspace's environment: unless you pass `--account-host`,
it's derived from the workspace host (e.g. an AWS *staging* workspace →
`accounts.staging.cloud.databricks.com`; GCP → `accounts.gcp.databricks.com`; Azure →
`accounts.azuredatabricks.net`), falling back to the AWS prod console when it can't be determined. So
a non-prod workspace no longer fails against the wrong account API.

## 📈 Usage tracking

At startup the tool registers `databricks-migrate-ip-acls/<version>` as a Databricks SDK
[user-agent extra](https://databricks-sdk-py.readthedocs.io/), so it's appended to the `User-Agent`
header of every API call it makes. That lets platform-side logs attribute API traffic to this tool.
It adds only the tool name + version — no arguments, workspace data, or PII. Granularity is
**workspace-level**: cluster ids are redacted in the request logs, so per-DBU attribution isn't
possible. See `usage.py`.

## 🗂️ Repo layout

| Path | What |
|---|---|
| `src/dbx_migrate_ip_acls/cli.py` | The Typer CLI (single command) + interactive gates. |
| `src/dbx_migrate_ip_acls/acl.py` | The migration engine + network-policy state queries. |
| `src/dbx_migrate_ip_acls/policy.py` | SDK dataclass builders + policy-id naming. |
| `src/dbx_migrate_ip_acls/terraform.py` | Best-effort Terraform (HCL) rendering of the proposed policy. |
| `src/dbx_migrate_ip_acls/usage.py` | Registers the tool name in the SDK User-Agent (usage tracking). |
| `src/dbx_migrate_ip_acls/{config,auth,console,render,tls}.py` | Config/validation, auth, Rich UI, presentation, OS-trust-store TLS. |
| `tests/` | Offline unit tests (fakes/monkeypatch — no network). |

## 🧪 Development & tests

```bash
uv run pytest -q                      # tests (fully offline)
uv run pytest --cov=dbx_migrate_ip_acls --cov-report=term-missing   # with coverage
uv run ruff check src/ tests/         # lint
uv run black --check src/ tests/      # style (run `uv run black src/ tests/` to format)
```

Tests are fully offline (SDK clients and workspace/account reads are faked or monkeypatched).

**CI** (`.github/workflows/ci.yml`) runs ruff + `black --check` + pytest-with-coverage on every push
and PR across Python 3.10–3.12, and uploads coverage to Codecov (the badge above).

## 📦 Releasing

The version is **derived from the git tag** by [`hatch-vcs`](https://github.com/ofek/hatch-vcs) —
there is no version string to bump. Check `dbx-migrate-ip-acls --version` at any time; between tags
the build reports a PEP 440 dev version like `0.1.1.dev3+g<sha>`, and on a tagged commit the clean
number.

Releases are **fully automated** — there is no manual upload step. Record the highlights in
[`CHANGELOG.md`](CHANGELOG.md), then tag `main` and push the tag:

```bash
git tag -a vX.Y.Z -m "dbx-migrate-ip-acls X.Y.Z"
git push origin vX.Y.Z
```

The `release.yml` workflow then builds the sdist + wheel and publishes to **PyPI via Trusted
Publishing (OIDC)** — no stored token. One-time PyPI setup is required (Project → Publishing):
owner `databrickslabs`, repo `migrate-ip-acls`, workflow `release.yml`, environment `pypi`.
**Pushing a `v*` tag publishes to PyPI — it is irreversible**, so tag deliberately.

The full step-by-step checklist — post-merge tagging, verifying the build first, and publishing a
GitHub Release — is in [`docs/releasing.md`](docs/releasing.md).
