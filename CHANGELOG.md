# Changelog

**English** | [简体中文](CHANGELOG.zh-CN.md)

All notable changes to this project will be documented in this file.

## [Unreleased]

- **BREAKING:** Reworked authorization into a single-project RBAC baseline built on users,
  user-role assignments, and one global authorization state. Access tokens now
  carry only the minimal identity and protocol claims. This replaces the prior
  table, API route, JWT, and locking contracts and is not an in-place upgrade
  from `v0.1.0`.
- Added optional, progressively loaded proxy availability references covering
  forced proxy routing, safe error mapping, Redis latest-result caching, list
  hydration, a five-worker frontend batch flow, and controlled routing tests.
- Added Simplified Chinese mirrors for the repository documentation and
  bilingual GitHub issue and pull-request guidance.

## [0.1.0] - 2026-09-05

- Prepared the standalone Skill for public preview distribution.
- Added XTN ownership, upstream attribution, third-party notices, repository
  governance, security reporting, and automated validation.
- Rejected empty, public-placeholder, and shorter-than-32-byte JWT secrets in the
  included PostgreSQL RBAC asset.
