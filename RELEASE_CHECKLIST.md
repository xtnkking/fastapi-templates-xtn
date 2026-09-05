# Release Checklist

**English** | [简体中文](RELEASE_CHECKLIST.zh-CN.md)

Use this checklist for the first public preview and subsequent releases.

## Local package

- [ ] The bundled Skill passes the current `skill-creator` quick validator.
- [ ] Ruff, strict mypy, and non-PostgreSQL tests pass.
- [ ] PostgreSQL-marked tests pass against PostgreSQL 17.
- [ ] No `.env`, token, credential, private key, cache, database, or build artifact
  is present.
- [ ] `LICENSE`, `NOTICE`, and `THIRD_PARTY_NOTICES.md` are present at repository,
  Skill, and copied-asset boundaries.
- [ ] README limitations match the behavior actually implemented by the asset.
- [ ] After all local checks, `python -B scripts/validate_release.py` passes from
  the final clean tree.

## GitHub repository

- [ ] Create the public canonical repository at
  `https://github.com/xtnkking/fastapi-templates-xtn` with `main` as its default
  branch.
- [ ] Do not grant external users, teams, GitHub Apps, or deploy keys write,
  maintain, or administrator access.
- [ ] Enable two-factor authentication on the maintainer account and review
  personal access tokens and authorized applications.
- [ ] Enable private vulnerability reporting.
- [ ] Enable a ruleset for `main` that blocks deletion and force pushes, requires
  CI, and permits rule bypass only for XTN.
- [ ] Protect `v*` tags from deletion or replacement.
- [ ] Keep Issues enabled. Close external pull requests according to
  `CONTRIBUTING.md`.

## Preview release

- [ ] Review the staged diff and confirm the XTN copyright year and upstream
  commit.
- [ ] Create the `v0.1.0` tag only after CI passes. A cryptographically signed
  tag is recommended when a portable key-management process is in place, but
  it is not required to publish the preview.
- [ ] Publish `v0.1.0` as a GitHub prerelease and describe the active-JTI adapter
  as planned, not implemented.
- [ ] Attach a SHA-256 checksum if a release archive is uploaded manually.
- [ ] Verify installation from the public tagged GitHub tree URL in a clean
  Codex environment.

## Later distribution

- [ ] Package the Skill as a Plugin when public installability beyond standalone
  Codex Skill workflows is required.
