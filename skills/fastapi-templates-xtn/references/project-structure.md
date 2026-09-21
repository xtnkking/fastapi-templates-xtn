# Project Structure

Read when generating a project, adding modules, or explicitly reorganizing its
layout. The responsibility-first tree below is an optional greenfield default,
not a mandatory migration target for existing applications. Folder placement
does not require a function, class, or forwarding layer for every operation;
use [Reuse and abstraction](reuse-and-abstraction.md) for that decision.

## Select The Project Context First

Inspect the repository root, local instructions, configuration, and a
representative route-to-data flow before choosing a layout. An empty working
subdirectory inside an existing repository still belongs to that project.

| Context | Action |
| --- | --- |
| Empty project with no established framework, or an explicitly requested independent new service | Use the tree below as the default; honor a different layout chosen by the owner |
| Existing application, including a partially built scaffold | Follow its existing modules, names, dependency injection, data access, transaction ownership, and infrastructure; add only the requested behavior |
| Explicit request to reorganize architecture or adopt this layout | Apply the agreed scope, preserving unrelated modules and existing behavior; do not request the same authorization again |

For example, a project using `features/orders/` and an existing DAO should get
its new order endpoint and query there. Do not create a competing `app/api/`,
Service, or Repository system, rename its directories, replace its framework,
or overwrite its application with the bundled asset to match this example.
Map the relevant Skill responsibilities to the project's existing equivalents.

Calling this Skill, requesting a feature, or saying "fix" or "optimize" does
not itself request an architecture migration. Keep routine local fixes within
the task. If a necessary architecture change exceeds the requested scope,
explain the concrete need and affected scope and obtain direction for that
change; continue independent in-scope work. A preferred layout alone is not
such a need.

## Responsibility First In A New Service

When this default layout is selected, keep only `main.py` and `__init__.py` as
Python files directly under `app/`. Place actual implementation in the matching
directory:

| Directory | Owns |
| --- | --- |
| `api/` | HTTP routes, status/header handling, and public request/response composition |
| `core/` | Configuration, errors, i18n, observability, middleware, and shared security rules |
| `db/` | ORM base, PostgreSQL engine/session lifecycle, Redis clients |
| `dependencies/` | FastAPI authentication, permission, admission, and request adapters |
| `models/` | ORM tables, constraints, relationships; no service imports |
| `repositories/` | Reused or substantial queries, filtering, batching, and lock/load operations; no independent commits |
| `schemas/` | Typed input/output contracts and data-only validation; no database queries or service calls |
| `services/` | Business decisions, command orchestration, transaction ownership, and authoritative response snapshots |

This is the baseline's layout, not a demand to create an empty file for every
business in every directory. Start with a module for the real implementation;
split it into a package when its size or responsibilities justify multiple
files. Use precise names such as `authentication`, `access`, and `orders`.

A small service can use a compact layout like this (package `__init__.py` files
are omitted below except at the root):

```text
app/
  __init__.py
  main.py
  api/authentication.py
  core/config.py
  core/security/passwords.py
  db/postgres.py
  db/redis.py
  dependencies/authentication.py
  models/access.py
  repositories/access.py
  schemas/authentication.py
  services/authentication.py
```

This sketch illustrates placement, not the complete bundled file inventory.
The asset also has real translation resources in `assets/locales/` and the real
offline recovery command in `commands/passwords.py`. Keep those paths because
their contents are used. Add `workers/` only for implemented background jobs;
add `utils/` only when concrete shared utility behavior has no clearer existing
owner. Do not create placeholder workers, empty business packages, or a generic
utility dumping ground to make the tree look complete.

## Grow Within Each Responsibility

For a project already using this layout, group additional businesses inside
its existing layers:

```text
app/
  api/
    users.py
    orders.py
  models/
    access.py
    orders.py
  repositories/
    access.py
    orders.py
  schemas/
    authentication.py
    orders.py
  services/
    authentication.py
    orders/
      creation.py
      cancellation.py
```

Other shared directories remain as above. Do not move the whole project to
top-level `users/` and `orders/` feature packages simply because another business
appears. Nor must every business use the same number of files: a simple lookup
and a multi-step order command have different needs.

## Calls Follow Actual Responsibility

These examples describe the default layout. In an existing framework, preserve
its established equivalent boundaries and call conventions; they do not grant
permission to introduce a second architecture.

- An API may call a repository directly for a simple authorized lookup or list.
  Its dependencies still enforce authentication and the exact capability; the
  query still enforces visibility and pagination. Do not add a Service method
  that merely forwards the same arguments and return value. A one-use, short
  ORM read may stay in its route; move it into a repository when reuse,
  visibility/pagination, batching, lock ordering, or query complexity warrants
  an owner, not merely because the directory exists.
- A mutation with business rules, locks, multiple writes, or audit belongs in a
  service. That service owns one transaction and may directly call
  `session.add()` or make a simple ORM update. Do not wrap every ORM statement
  in a repository method solely to claim all writes pass through a repository.
- Extract repeated or substantial query logic into a repository and pass the
  caller's session. Preserve lock order and transaction boundaries when moving
  code; repositories and audit writers never commit the caller's work.
- Models and schemas never import services. Keep shared value types and pure
  validation in an appropriate `core/` module when both persistence and service
  code need them. Keep response builders that depend on repository visibility
  in `services/`, not in a schema module that then imports database queries.
- `main.py` wires lifecycle, middleware, exception handlers, and routers. It is
  not a second location for business endpoints or persistence rules.

For example, business auditing uses `models/business_audit.py` for its table,
`core/business_audit.py` for shared audit types and validation, and
`services/business_audit.py` for the transaction-aware writer. This separation
prevents an ORM model from depending on an application service. Username
normalization follows the same rule: schemas and provisioning both import
`normalize_identity` from `app.core.security.identity`; creating users and
assigning their initial role remain in `services/provisioning.py`.

When reorganizing, update imports, Alembic model discovery, CLI entry points,
package resources, tests, and current documentation together. Move files rather
than retaining obsolete forwarding modules without supported consumers. Public
HTTP contracts and database schema do not change merely because files move.
