# 🏷️ Releasing

How to cut a release of `dbx-migrate-ip-acls`. Versioning is **tag-driven** (via
[`hatch-vcs`](https://github.com/ofek/hatch-vcs)): the git tag is the single source of truth, so
"a release" is just a `vX.Y.Z` tag on `main` — there is no version string to edit. Pushing that
tag also **publishes to PyPI automatically** (see below), so treat tagging as the release action.

## Versioning model

- **[Semantic Versioning](https://semver.org).** For this CLI the "public API" is the command +
  flag surface: a breaking change bumps the **major**, a backward-compatible addition the
  **minor**, a fix the **patch**.
- The version is derived from the git tag. `dbx-migrate-ip-acls --version` reports it. On a clean,
  tagged commit it's the exact number (`0.1.0`); between tags it's a PEP 440 dev version
  (`0.1.1.devN+g<sha>`); a dirty working tree adds a `.dYYYYMMDD` suffix.

## Automated publish

[`.github/workflows/release.yml`](../.github/workflows/release.yml) fires on any pushed `v*` tag:
it runs `uv build` and publishes the sdist + wheel to **PyPI via Trusted Publishing (OIDC)** — no
stored token. Its checkout uses `fetch-depth: 0` so `hatch-vcs` sees the tag and the published
artifact carries the exact tagged version. **Pushing a `v*` tag is therefore an irreversible
publish** — do it deliberately.

> One-time PyPI setup (Trusted Publishing): under the PyPI project's *Publishing* settings, add a
> publisher for owner `databrickslabs`, repository `migrate-ip-acls`, workflow `release.yml`,
> environment `pypi` (a "pending publisher" works before the first release).

## Steps

1. **Update the changelog.** In [`../CHANGELOG.md`](../CHANGELOG.md), move the entries under
   `[Unreleased]` into a new `[X.Y.Z] - YYYY-MM-DD` section, and update the link references at the
   bottom of the file.
2. **Land the changes on `main`** via a PR (the default branch is protected).
3. **Tag `main` after the merge** — never the feature branch (a squash/merge makes a new commit):
   ```bash
   git checkout main && git pull
   git tag -a vX.Y.Z -m "dbx-migrate-ip-acls X.Y.Z"
   git push origin vX.Y.Z        # ← triggers release.yml → publishes to PyPI
   ```
4. **Watch the release run** under the repo's *Actions* tab; confirm the new version appears on
   PyPI.
5. **(Optional) Publish a GitHub Release** from the tag for human-readable notes:
   ```bash
   gh release create vX.Y.Z --title "vX.Y.Z" --verify-tag --notes "…"  # or --notes-file
   ```

## Verify before tagging

Because the tag publishes, sanity-check the build on a clean tree first (a temporary local tag you
delete afterwards):

```bash
git tag vX.Y.Z
uv build                                       # -> dist/…-X.Y.Z-…whl (clean number = good)
uv run --reinstall dbx-migrate-ip-acls --version
git tag -d vX.Y.Z && rm -rf dist               # clean up; do NOT push this throwaway tag
```

## Notes

- **Build-dependency pins.** `build-system.requires` in [`../pyproject.toml`](../pyproject.toml)
  is upper-bounded (`hatchling<1.32`, `hatch-vcs>=0.4,<0.5`, `setuptools-scm<10`) so the build
  stays resolvable behind the internal PyPI mirror, which does not serve the newest `hatchling` or
  the `setuptools-scm` 10.x → `vcs-versioning` chain. Public PyPI (CI and the release workflow)
  resolves these fine. Relax the ceilings once the mirror approves the newer releases.
- **CI and tags.** `ci.yml` does not need tags to pass (the tests don't assert the version), so it
  is left with a shallow checkout. If you ever want CI to report accurate dev versions, add
  `fetch-depth: 0` to its checkout as well.
