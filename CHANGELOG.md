# Changelog

**English** | [简体中文](CHANGELOG.zh-CN.md)

All notable changes to this project will be documented in this file.

## [Unreleased]

## [0.3.0] - 2026-09-07

- **BREAKING:** Replaced public `/rbac` routes and non-GET/POST administration
  methods with neutral `/api/v1/permissions`, `/api/v1/roles`, `/api/v1/users`,
  and `/api/v1/system` resource and action routes. Public OpenAPI metadata and
  error codes no longer reveal the internal authorization mechanism.
- Added the thirteen-route minimum permission, role-lifecycle, permission-binding,
  and user-role administration contract with strict capability checks and strong
  ETag/`If-Match` preconditions on shared-role changes.
- Added immutable `super_admin`, `admin`, and `user` system roles, mandatory
  transactional `user` assignment for new identities, custom-role soft deletion,
  restricted administrator authority, and an atomic offline first-super-admin
  bootstrap workflow.
- Added migration and database guards for legacy multi-holder upgrades, exactly
  one `super_admin` after assignment changes, and the reserved legacy `owner`
  role key. Role mutation bodies and ETags now come from one locked snapshot,
  and denied privileged route gates are audited.

## [0.2.0] - 2026-09-06

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
