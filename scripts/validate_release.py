#!/usr/bin/env python3
"""Validate the distributable Skill without external Python dependencies."""

from __future__ import annotations

import ast
import json
import re
import sys
import tomllib
from pathlib import Path
from urllib.parse import unquote

REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL_ROOT = REPO_ROOT / "skills" / "fastapi-templates-xtn"
ASSET_ROOT = SKILL_ROOT / "assets" / "postgresql-rbac"
EXPECTED_NAME = "fastapi-templates-xtn"
RELEASE_VERSION = "0.6.0"
RELEASE_DATE = "2026-09-20"
RELEASE_TAG = f"v{RELEASE_VERSION}"
RELEASE_INSTALL_URL = (
    f"https://github.com/xtnkking/fastapi-templates-xtn/tree/{RELEASE_TAG}/"
    "skills/fastapi-templates-xtn"
)
UPSTREAM_COMMIT = "47a5dbc3f9c2661c6afb13638f80d4a4d4449040"

REQUIRED_REPO_FILES = (
    ".gitattributes",
    ".gitignore",
    "LICENSE",
    "NOTICE",
    "THIRD_PARTY_NOTICES.md",
    "README.md",
    "README.zh-CN.md",
    "CHANGELOG.md",
    "CHANGELOG.zh-CN.md",
    "CONTRIBUTING.md",
    "CONTRIBUTING.zh-CN.md",
    "SECURITY.md",
    "SECURITY.zh-CN.md",
    "RELEASE_CHECKLIST.md",
    "RELEASE_CHECKLIST.zh-CN.md",
    "docs/history/v0.4.0/DESIGN_REVIEW.zh-CN.md",
    ".github/CODEOWNERS",
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/ISSUE_TEMPLATE/bug-report.yml",
    ".github/workflows/ci.yml",
)
REQUIRED_SKILL_FILES = (
    "SKILL.md",
    "LICENSE",
    "NOTICE",
    "THIRD_PARTY_NOTICES.md",
    "agents/openai.yaml",
    "references/api-response-standard.md",
    "references/api-internationalization.md",
    "references/audit-module.md",
    "references/business-audit-module.md",
    "references/business-audit-operations.md",
    "references/business-audit-postgresql.md",
    "references/architecture-overview.zh-CN.md",
    "references/country-catalog.md",
    "references/country-catalog-postgresql.md",
    "references/identity-soft-delete.md",
    "references/jwt-session-implementation.md",
    "references/jwt-session-security.md",
    "references/local-password-authentication.md",
    "references/operational-logging.md",
    "references/proxy-availability-backend.md",
    "references/proxy-availability-detection.md",
    "references/proxy-availability-frontend.md",
    "references/proxy-availability-testing.md",
    "references/rate-limiting.md",
    "references/verification-and-abuse-defense.md",
    "scripts/test_validate_country_csv.py",
    "scripts/validate_country_csv.py",
)
REQUIRED_ASSET_FILES = (
    ".env.example",
    "README.md",
    "LICENSE",
    "NOTICE",
    "THIRD_PARTY_NOTICES.md",
    "pyproject.toml",
    "alembic/env.py",
    "app/abuse_flow.py",
    "app/api_contract.py",
    "app/i18n.py",
    "app/locales/__init__.py",
    "app/locales/en.json",
    "app/locales/zh-CN.json",
    "app/abuse_defense.py",
    "app/audit.py",
    "app/authentication_api.py",
    "app/authentication_schemas.py",
    "app/authentication_service.py",
    "app/business_audit.py",
    "app/captcha.py",
    "app/observability.py",
    "app/password_models.py",
    "app/password_operator.py",
    "app/passwords.py",
    "app/rate_limit.py",
    "app/rate_limit_dependencies.py",
    "app/rate_limit_middleware.py",
    "app/redis_client.py",
    "app/rbac/api.py",
    "app/rbac/policy.py",
    "app/rbac/queries.py",
    "app/rbac/security.py",
    "app/rbac/service.py",
    "app/security_policies.py",
    "app/settings.py",
    "alembic/versions/0003_business_audit.py",
    "alembic/versions/0004_password_auth.py",
    "sql/bootstrap_super_admin.sql",
    "sql/handover_super_admin.sql",
    "tests/test_abuse_flow.py",
    "tests/test_abuse_defense.py",
    "tests/test_audit.py",
    "tests/test_authentication_api.py",
    "tests/test_authentication_service.py",
    "tests/test_integration_safety.py",
    "tests/test_health.py",
    "tests/test_i18n.py",
    "tests/test_business_audit.py",
    "tests/test_captcha.py",
    "tests/test_captcha_redis_live.py",
    "tests/test_dependency_observability.py",
    "tests/test_observability.py",
    "tests/test_observability_formatter.py",
    "tests/test_password_migration.py",
    "tests/test_password_models.py",
    "tests/test_passwords.py",
    "tests/test_policy.py",
    "tests/test_rate_limit.py",
    "tests/test_rate_limit_dependencies.py",
    "tests/test_rate_limit_middleware.py",
    "tests/test_request_observability.py",
    "tests/test_rbac_queries.py",
    "tests/test_rbac_service_observability.py",
    "tests/test_rbac_service_operations.py",
    "tests/test_schemas.py",
    "tests/test_security.py",
    "tests/test_settings.py",
    "tests/integration/test_abuse_defense_redis.py",
    "tests/integration/safety.py",
    "tests/integration/test_business_audit.py",
    "tests/integration/test_captcha_redis.py",
    "tests/integration/test_password_authentication.py",
    "tests/integration/test_password_persistence.py",
    "tests/integration/test_migrations.py",
    "tests/integration/test_postgresql_locking.py",
    "tests/integration/test_rbac_api.py",
    "tests/integration/test_rate_limit_redis.py",
    "tests/integration/test_readiness.py",
    "tests/integration/test_read_visibility.py",
    "tests/integration/test_user_role_limit.py",
)
MIRRORED_LEGAL_FILES = ("LICENSE", "NOTICE")
BILINGUAL_DOC_PAIRS = (
    ("README.md", "README.zh-CN.md"),
    ("CHANGELOG.md", "CHANGELOG.zh-CN.md"),
    ("CONTRIBUTING.md", "CONTRIBUTING.zh-CN.md"),
    ("SECURITY.md", "SECURITY.zh-CN.md"),
    ("RELEASE_CHECKLIST.md", "RELEASE_CHECKLIST.zh-CN.md"),
)
FORBIDDEN_DIRECTORY_NAMES = {
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "build",
    "dist",
    "htmlcov",
}
FORBIDDEN_DIRECTORY_SUFFIXES = (".egg-info",)
FORBIDDEN_FILE_NAMES = {".coverage"}
FORBIDDEN_FILE_SUFFIXES = {".db", ".pyc", ".pyo", ".sqlite", ".sqlite3"}
FORBIDDEN_SKILL_TABULAR_SUFFIXES = {".csv", ".tsv"}
COUNTRY_OR_FLAG_MEDIA_SUFFIXES = {
    ".apng",
    ".avif",
    ".bmp",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".png",
    ".svg",
    ".tif",
    ".tiff",
    ".webp",
}
COUNTRY_OR_FLAG_PATH_RE = re.compile(
    r"(?:^|[-_.])(?:countries|country|flags|flag)(?:$|[-_.])", re.IGNORECASE
)
TEXT_SUFFIXES = {
    "",
    ".ini",
    ".json",
    ".md",
    ".mako",
    ".py",
    ".sql",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
FRONTMATTER_RE = re.compile(r"\A---\r?\n(.*?)\r?\n---(?:\r?\n|\Z)", re.DOTALL)
LOCAL_HOME_PATH_RE = re.compile(
    r"(?:[A-Za-z]:[\\/](?:Users|home)[\\/][^\\/\r\n]+|/(?:Users|home)/[^/\r\n]+)"
)
SECRET_MATERIAL_RE = re.compile(
    r"(?:"
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
    r"|AKIA[0-9A-Z]{16}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|ghp_[A-Za-z0-9]{20,}"
    r")"
)


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def require_semantics(
    errors: list[str],
    *,
    path: Path,
    checks: tuple[tuple[str, tuple[str, ...]], ...],
) -> None:
    """Require concepts while allowing maintainers to improve prose wording."""
    content = re.sub(r"\s+", " ", path.read_text(encoding="utf-8"))
    for label, patterns in checks:
        if not any(re.search(pattern, content, re.IGNORECASE) for pattern in patterns):
            fail(
                errors,
                f"{path.relative_to(REPO_ROOT)} is missing required concept: {label}",
            )


def validate_required_files(errors: list[str]) -> None:
    for relative in REQUIRED_REPO_FILES:
        if not (REPO_ROOT / relative).is_file():
            fail(errors, f"missing repository file: {relative}")
    for relative in REQUIRED_SKILL_FILES:
        if not (SKILL_ROOT / relative).is_file():
            fail(errors, f"missing distributable Skill file: {relative}")
    for relative in REQUIRED_ASSET_FILES:
        if not (ASSET_ROOT / relative).is_file():
            fail(errors, f"missing copied-asset legal file: {relative}")


def validate_frontmatter(errors: list[str]) -> None:
    skill_md = SKILL_ROOT / "SKILL.md"
    if not skill_md.is_file():
        return
    content = skill_md.read_text(encoding="utf-8")
    match = FRONTMATTER_RE.match(content)
    if match is None:
        fail(errors, "SKILL.md has invalid YAML frontmatter delimiters")
        return

    fields: dict[str, str] = {}
    for line in match.group(1).splitlines():
        if not line.strip() or line.startswith((" ", "\t")):
            continue
        key, separator, value = line.partition(":")
        if not separator:
            fail(errors, f"SKILL.md has an invalid frontmatter line: {line!r}")
            continue
        fields[key.strip()] = value.strip().strip("\"'")

    if fields.get("name") != EXPECTED_NAME:
        fail(errors, f"SKILL.md name must be {EXPECTED_NAME!r}")
    if not fields.get("description"):
        fail(errors, "SKILL.md description must be non-empty")
    unexpected = set(fields) - {
        "name",
        "description",
        "license",
        "allowed-tools",
        "metadata",
    }
    if unexpected:
        fail(errors, f"SKILL.md has unsupported frontmatter keys: {sorted(unexpected)}")

    proxy_reference = "references/proxy-availability-detection.md"
    if proxy_reference not in content:
        fail(errors, f"SKILL.md does not route to {proxy_reference}")
    business_audit_reference = "references/business-audit-module.md"
    if business_audit_reference not in content:
        fail(errors, f"SKILL.md does not route to {business_audit_reference}")
    identity_lifecycle_reference = "references/identity-soft-delete.md"
    if identity_lifecycle_reference not in content:
        fail(errors, f"SKILL.md does not route to {identity_lifecycle_reference}")
    country_reference = "references/country-catalog.md"
    if country_reference not in content:
        fail(errors, f"SKILL.md does not route to {country_reference}")
    rate_limit_reference = "references/rate-limiting.md"
    if rate_limit_reference not in content:
        fail(errors, f"SKILL.md does not route to {rate_limit_reference}")
    verification_reference = "references/verification-and-abuse-defense.md"
    if verification_reference not in content:
        fail(errors, f"SKILL.md does not route to {verification_reference}")
    i18n_reference = "references/api-internationalization.md"
    if i18n_reference not in content:
        fail(errors, f"SKILL.md does not route to {i18n_reference}")


def validate_identity_and_row_lifecycle(errors: list[str]) -> None:
    paths = {
        "entrypoint": SKILL_ROOT / "SKILL.md",
        "reference": SKILL_ROOT / "references" / "identity-soft-delete.md",
        "models": ASSET_ROOT / "app" / "rbac" / "models.py",
        "migration": ASSET_ROOT
        / "alembic"
        / "versions"
        / "0001_single_project_rbac.py",
        "readme": REPO_ROOT / "README.md",
        "readme zh-CN": REPO_ROOT / "README.zh-CN.md",
        "checklist": REPO_ROOT / "RELEASE_CHECKLIST.md",
        "checklist zh-CN": REPO_ROOT / "RELEASE_CHECKLIST.zh-CN.md",
    }
    missing = False
    for name, path in paths.items():
        if not path.is_file():
            fail(
                errors,
                f"missing identity/lifecycle {name}: {path.relative_to(REPO_ROOT)}",
            )
            missing = True
    if missing:
        return

    text = {name: path.read_text(encoding="utf-8") for name, path in paths.items()}
    require_semantics(
        errors,
        path=paths["entrypoint"],
        checks=(
            (
                "new projects use username/password rather than email recovery",
                (r"new services? use username/password only",),
            ),
            (
                "soft-deleted usernames remain permanently reserved",
                (r"soft-deleted username remains reserved forever",),
            ),
            (
                "every row has a declared mutable, append-only, or permanent lifecycle",
                (
                    r"mutable row.*soft delet",
                    r"audit rows are append-only.*fixed .* rows are not runtime-deletable",
                ),
            ),
            (
                "physical deletion is limited to controlled maintenance or disposable tests",
                (
                    r"physical purge is only controlled maintenance, disposable tests, or a reviewed migration",
                ),
            ),
        ),
    )
    required_markers = {
        "reference": (
            "## Choose The Identity And Login Contract Before Greenfield Work",
            "Required `user_name` only in the new-project baseline",
            "Permanently reserve a deleted user's username",
            "Classify every table before creating it",
            "Mutable runtime data",
            "Append-only evidence",
            "Permanent control state or immutable system catalog",
        ),
        "models": (
            "class User(Base):",
            "user_name: Mapped[str]",
            'UniqueConstraint("user_name", name="uq_users_user_name")',
            "class RbacState(Base):",
            "class Permission(Base):",
            "class Role(Base):",
            "class RolePermission(Base):",
            "class UserRole(Base):",
            "class RbacAuditEvent(Base):",
        ),
        "migration": (
            'sa.Column("user_name", sa.String(length=32), nullable=False)',
            'sa.UniqueConstraint("user_name", name="uq_users_user_name")',
            '"deleted_at", sa.DateTime(timezone=True), nullable=True',
            'ondelete="RESTRICT"',
        ),
        "readme": (
            "username/password login",
            "cannot be reused after soft deletion",
        ),
        "readme zh-CN": (
            "用户名密码",
            "软删除",
        ),
        "checklist": (
            "required `user_name`",
            "Inventory every table and row-removal path",
        ),
        "checklist zh-CN": (
            "必填 `user_name`",
            "盘点全部表和所有数据移除路径",
        ),
    }
    for name, markers in required_markers.items():
        for marker in markers:
            if marker not in text[name]:
                fail(
                    errors,
                    f"{paths[name].relative_to(REPO_ROOT)} is missing "
                    f"identity/lifecycle marker: {marker!r}",
                )

    model_classes = {
        "User": "soft-delete",
        "Permission": "soft-delete",
        "Role": "soft-delete",
        "RolePermission": "soft-delete",
        "UserRole": "soft-delete",
        "RbacState": "permanent",
        "RbacAuditEvent": "append-only",
    }
    model_source = text["models"]
    class_positions = []
    for name, lifecycle in model_classes.items():
        position = model_source.find(f"class {name}(Base):")
        if position >= 0:
            class_positions.append((position, name, lifecycle))
    class_positions.sort()
    for index, (start, name, lifecycle) in enumerate(class_positions):
        end = (
            class_positions[index + 1][0]
            if index + 1 < len(class_positions)
            else len(model_source)
        )
        body = model_source[start:end]
        has_tombstone = "deleted_at: Mapped[" in body
        if lifecycle == "soft-delete" and not has_tombstone:
            fail(errors, f"asset model {name} must define a deleted_at tombstone")
        if lifecycle != "soft-delete" and has_tombstone:
            fail(
                errors,
                f"asset {lifecycle} model {name} must not expose soft deletion",
            )

    runtime_schema_files = sorted((ASSET_ROOT / "app").rglob("*.py"))
    runtime_schema_files.extend(sorted((ASSET_ROOT / "alembic").rglob("*.py")))
    cascade_pattern = re.compile(
        r"ondelete\s*=\s*['\"]cascade['\"]|on\s+delete\s+cascade",
        re.IGNORECASE,
    )
    for path in runtime_schema_files:
        if cascade_pattern.search(path.read_text(encoding="utf-8")):
            fail(
                errors,
                f"{path.relative_to(REPO_ROOT)} uses cascading hard deletion",
            )


def validate_links(errors: list[str]) -> None:
    for markdown in sorted(REPO_ROOT.rglob("*.md")):
        content = markdown.read_text(encoding="utf-8")
        for raw_target in LINK_RE.findall(content):
            target = raw_target.strip().strip("<>").split(maxsplit=1)[0]
            if not target or target.startswith(("#", "https://", "http://", "mailto:")):
                continue
            target_path = unquote(target.split("#", 1)[0])
            if not (markdown.parent / target_path).resolve().exists():
                relative_markdown = markdown.relative_to(REPO_ROOT)
                fail(errors, f"broken link in {relative_markdown}: {raw_target}")


def validate_bilingual_docs(errors: list[str]) -> None:
    for english_name, chinese_name in BILINGUAL_DOC_PAIRS:
        english_path = REPO_ROOT / english_name
        chinese_path = REPO_ROOT / chinese_name
        if not english_path.is_file() or not chinese_path.is_file():
            continue

        english = english_path.read_text(encoding="utf-8")
        chinese = chinese_path.read_text(encoding="utf-8")
        if f"[简体中文]({chinese_name})" not in english:
            fail(errors, f"{english_name} is missing its Simplified Chinese link")
        if f"[English]({english_name})" not in chinese:
            fail(errors, f"{chinese_name} is missing its English link")


def validate_legal_mirrors(errors: list[str]) -> None:
    for name in MIRRORED_LEGAL_FILES:
        repo_file = REPO_ROOT / name
        skill_file = SKILL_ROOT / name
        if repo_file.is_file() and skill_file.is_file():
            if repo_file.read_bytes() != skill_file.read_bytes():
                fail(errors, f"repository and distributable copies differ: {name}")

    notice_markers = (
        UPSTREAM_COMMIT,
        "Copyright (c) 2024 Seth Hobson",
        "Copyright 2009-2026 Michael Bayer",
        "MIT License",
    )
    for notice_path in (
        REPO_ROOT / "THIRD_PARTY_NOTICES.md",
        SKILL_ROOT / "THIRD_PARTY_NOTICES.md",
        ASSET_ROOT / "THIRD_PARTY_NOTICES.md",
    ):
        if not notice_path.is_file():
            continue
        notice_text = notice_path.read_text(encoding="utf-8")
        for marker in notice_markers:
            if marker not in notice_text:
                relative = notice_path.relative_to(REPO_ROOT)
                fail(errors, f"{relative} is missing required notice: {marker}")

    if (SKILL_ROOT / "SKILL.md").is_file():
        skill_text = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        if UPSTREAM_COMMIT not in skill_text:
            fail(errors, "SKILL.md does not pin the upstream attribution commit")


def validate_release_metadata(errors: list[str]) -> None:
    pyproject_path = ASSET_ROOT / "pyproject.toml"

    for readme_name in ("README.md", "README.zh-CN.md"):
        readme_path = REPO_ROOT / readme_name
        if not readme_path.is_file():
            continue
        readme = readme_path.read_text(encoding="utf-8")
        if RELEASE_INSTALL_URL not in readme:
            fail(errors, f"{readme_name} is missing the {RELEASE_TAG} installation URL")

    readme_path = REPO_ROOT / "README.md"
    if readme_path.is_file():
        readme = readme_path.read_text(encoding="utf-8")
        for stale_phrase in (
            "preparing its first preview release",
            "after its tag is published",
        ):
            if stale_phrase in readme:
                fail(
                    errors, f"README.md contains pre-release wording: {stale_phrase!r}"
                )

    for changelog_name in ("CHANGELOG.md", "CHANGELOG.zh-CN.md"):
        changelog_path = REPO_ROOT / changelog_name
        if not changelog_path.is_file():
            continue
        changelog = changelog_path.read_text(encoding="utf-8")
        release_heading = f"## [{RELEASE_VERSION}] - {RELEASE_DATE}"
        if release_heading not in changelog:
            fail(
                errors,
                f"{changelog_name} is missing release heading: {release_heading}",
            )

    checklist_headings = {
        "RELEASE_CHECKLIST.md": f"## Release {RELEASE_TAG}",
        "RELEASE_CHECKLIST.zh-CN.md": f"## 发布 {RELEASE_TAG}",
    }
    for checklist_name, release_heading in checklist_headings.items():
        checklist_path = REPO_ROOT / checklist_name
        if checklist_path.is_file() and release_heading not in (
            checklist_path.read_text(encoding="utf-8")
        ):
            fail(
                errors,
                f"{checklist_name} is missing release heading: {release_heading}",
            )

    if pyproject_path.is_file():
        pyproject = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
        asset_version = pyproject.get("project", {}).get("version")
        if asset_version != RELEASE_VERSION:
            fail(
                errors,
                "asset pyproject.toml version must match release version "
                f"{RELEASE_VERSION!r}, got {asset_version!r}",
            )


def validate_access_token_baseline(errors: list[str]) -> None:
    paths = {
        "skill": SKILL_ROOT / "SKILL.md",
        "policy": SKILL_ROOT / "references" / "jwt-session-security.md",
        "implementation": SKILL_ROOT / "references" / "jwt-session-implementation.md",
        "settings": ASSET_ROOT / "app" / "settings.py",
        "security": ASSET_ROOT / "app" / "rbac" / "security.py",
        "dependencies": ASSET_ROOT / "app" / "rbac" / "dependencies.py",
        "environment": ASSET_ROOT / ".env.example",
        "settings tests": ASSET_ROOT / "tests" / "test_settings.py",
        "security tests": ASSET_ROOT / "tests" / "test_security.py",
    }
    if any(not path.is_file() for path in paths.values()):
        return
    text = {name: path.read_text(encoding="utf-8") for name, path in paths.items()}

    require_semantics(
        errors,
        path=paths["skill"],
        checks=(
            (
                "Access Token defaults to one hour / 3600 seconds and must be reviewed",
                (
                    r"Access Tokens? default to one hour.*adjust",
                    r"3600 seconds.*adjust",
                ),
            ),
            (
                "iss and aud remain absent when the owner gives no answer",
                (r"iss.*aud.*No answer means keep both absent",),
            ),
            (
                "iss and aud require explicit consent",
                (r"iss.*aud.*explicit consent",),
            ),
            (
                "an existing configured iss/aud pair is preserved by default",
                (r"existing .* pair.*preserv",),
            ),
            (
                "PostgreSQL has no Token/session table or per-request Token lookup",
                (
                    r"no Token/session table in PostgreSQL.*no per-request Token-row query",
                ),
            ),
        ),
    )
    required_markers = {
        "policy": (
            "3600 seconds after `iat` by default",
            "Redis 5.0+ Lua operation",
            "server `TIME`",
            "SET ... NX EX <remaining_seconds>",
            "PEXPIREAT <exp * 1000>",
            "Redis is the only per-token online active-JTI gate",
        ),
        "implementation": (
            "DEFAULT_ACCESS_TTL_SECONDS = 3600",
            "ACTIVATE_JTI =",
            "redis.replicate_commands()",
            "redis.call('TIME')",
            "redis.call('SET', KEYS[1], ARGV[1], 'NX', 'EX', ttl_seconds)",
            "redis.call('PEXPIREAT', KEYS[1], expires_at * 1000)",
            "COMPARE_AND_DELETE",
        ),
        "settings": (
            "jwt_issuer: str | None = None",
            "jwt_audience: str | None = None",
            "must be configured together or omitted",
            "Field(default=3600, ge=1)",
        ),
        "security": (
            'REQUIRED_ACCESS_CLAIMS = frozenset({"sub", "jti", "iat", "exp", "token_type"})',
            'OPTIONAL_ACCESS_SCOPE_CLAIMS = frozenset({"iss", "aud"})',
            "expected_claims = _expected_access_claims(settings)",
            "if set(payload) != expected_claims",
            "if settings.jwt_issuer is not None and settings.jwt_audience is not None",
            "_ACTIVATE_JTI =",
            "redis.replicate_commands()",
            "redis.call('TIME')",
            "redis.call('SET', KEYS[1], ARGV[1], 'NX', 'EX', ttl_seconds)",
            "redis.call('PEXPIREAT', KEYS[1], expires_at * 1000)",
            "redis.eval(",
            "_COMPARE_AND_DELETE",
        ),
        "environment": ("JWT_ACCESS_TOKEN_TTL_SECONDS=3600",),
        "settings tests": (
            "test_issuer_and_audience_are_disabled_by_default",
            "test_issuer_and_audience_can_be_enabled_together",
            "test_issuer_and_audience_must_be_a_complete_nonblank_pair",
        ),
        "security tests": (
            "test_valid_access_token_resolves_only_fixed_claims",
            "test_default_mode_rejects_each_missing_required_claim",
            "test_default_mode_rejects_optional_scope_claims",
            "test_configured_issuer_and_audience_mode_accepts_exact_seven_claims",
            "test_configured_issuer_and_audience_mode_rejects_invalid_scope",
            "test_configured_issuer_and_audience_mode_rejects_each_missing_claim",
            "test_active_jti_key_does_not_depend_on_optional_issuer_or_audience",
            "test_configured_scope_uses_the_same_active_jti_lifecycle",
        ),
    }
    for name, markers in required_markers.items():
        for marker in markers:
            if marker not in text[name]:
                relative = paths[name].relative_to(REPO_ROOT)
                fail(
                    errors, f"{relative} is missing Access Token invariant: {marker!r}"
                )

    active_optional_scope = re.compile(r"^\s*JWT_(?:ISSUER|AUDIENCE)\s*=")
    if any(
        active_optional_scope.match(line)
        for line in text["environment"].splitlines()
        if not line.lstrip().startswith("#")
    ):
        fail(
            errors,
            ".env.example must leave optional JWT_ISSUER/JWT_AUDIENCE disabled",
        )

    redis_check = text["dependencies"].find("token_version = await require_active_jti(")
    postgres_check = text["dependencies"].find(
        "authority = await load_authority_snapshot("
    )
    if redis_check < 0 or postgres_check < 0 or redis_check > postgres_check:
        fail(errors, "authentication must validate Redis before PostgreSQL authority")

    if re.search(
        r"""[\"']ver[\"']\s*:|payload\s*\[\s*[\"']ver[\"']\s*\]""", text["security"]
    ):
        fail(errors, "asset JWT code must not contain a ver claim")

    forbidden_patterns = (
        re.compile(r"refresh[_\s-]+token", re.IGNORECASE),
        re.compile(r"authentication[_\s-]+sessions?", re.IGNORECASE),
        re.compile(
            r"postgresql[_\s]+(?:token|authentication)[_\s]+sessions?", re.IGNORECASE
        ),
    )
    executable_paths = tuple(
        path
        for path in ASSET_ROOT.rglob("*")
        if path.is_file() and path.suffix.lower() in {".py", ".sql"}
    )
    for path in executable_paths:
        content = path.read_text(encoding="utf-8")
        for pattern in forbidden_patterns:
            if pattern.search(content):
                relative = path.relative_to(REPO_ROOT)
                fail(
                    errors,
                    f"{relative} reintroduces a forbidden authentication concept: "
                    f"{pattern.pattern!r}",
                )


def _parse_python(
    errors: list[str],
    path: Path,
    *,
    label: str,
) -> ast.Module | None:
    try:
        return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError, UnicodeDecodeError) as exc:
        fail(errors, f"cannot parse {label} {path.relative_to(REPO_ROOT)}: {exc}")
        return None


def _module_literals(tree: ast.Module) -> dict[str, object]:
    values: dict[str, object] = {}
    for node in tree.body:
        name: str | None = None
        value: ast.expr | None = None
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            name = node.target.id
            value = node.value
        elif (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            name = node.targets[0].id
            value = node.value
        if name is None or value is None:
            continue
        try:
            values[name] = ast.literal_eval(value)
        except (TypeError, ValueError):
            continue
    return values


def _class_node(tree: ast.Module, name: str) -> ast.ClassDef | None:
    return next(
        (
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == name
        ),
        None,
    )


def _function_node(
    nodes: list[ast.stmt],
    name: str,
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    return next(
        (
            node
            for node in nodes
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == name
        ),
        None,
    )


def _returned_names(node: ast.Return) -> tuple[str, ...] | None:
    value = node.value
    if isinstance(value, ast.Name):
        return (value.id,)
    if not isinstance(value, (ast.Tuple, ast.List)):
        return None
    if not all(isinstance(item, ast.Name) for item in value.elts):
        return None
    return tuple(item.id for item in value.elts if isinstance(item, ast.Name))


def validate_local_password_authentication(errors: list[str]) -> None:
    paths = {
        "skill": SKILL_ROOT / "SKILL.md",
        "reference": SKILL_ROOT / "references" / "local-password-authentication.md",
        "README": REPO_ROOT / "README.md",
        "Chinese README": REPO_ROOT / "README.zh-CN.md",
        "environment": ASSET_ROOT / ".env.example",
        "pyproject": ASSET_ROOT / "pyproject.toml",
        "main": ASSET_ROOT / "app" / "main.py",
        "settings": ASSET_ROOT / "app" / "settings.py",
        "passwords": ASSET_ROOT / "app" / "passwords.py",
        "models": ASSET_ROOT / "app" / "password_models.py",
        "users model": ASSET_ROOT / "app" / "rbac" / "models.py",
        "schemas": ASSET_ROOT / "app" / "authentication_schemas.py",
        "API": ASSET_ROOT / "app" / "authentication_api.py",
        "service": ASSET_ROOT / "app" / "authentication_service.py",
        "operator": ASSET_ROOT / "app" / "password_operator.py",
        "Alembic environment": ASSET_ROOT / "alembic" / "env.py",
        "migration": (ASSET_ROOT / "alembic" / "versions" / "0004_password_auth.py"),
        "API tests": ASSET_ROOT / "tests" / "test_authentication_api.py",
        "service tests": ASSET_ROOT / "tests" / "test_authentication_service.py",
        "password tests": ASSET_ROOT / "tests" / "test_passwords.py",
        "PostgreSQL authentication tests": (
            ASSET_ROOT / "tests" / "integration" / "test_password_authentication.py"
        ),
        "PostgreSQL persistence tests": (
            ASSET_ROOT / "tests" / "integration" / "test_password_persistence.py"
        ),
    }
    missing = False
    for label, path in paths.items():
        if not path.is_file():
            fail(
                errors,
                f"missing local-password {label}: {path.relative_to(REPO_ROOT)}",
            )
            missing = True
    if missing:
        return

    text = {label: path.read_text(encoding="utf-8") for label, path in paths.items()}
    trees: dict[str, ast.Module] = {}
    for label in (
        "main",
        "settings",
        "passwords",
        "models",
        "users model",
        "schemas",
        "API",
        "service",
        "operator",
        "migration",
    ):
        tree = _parse_python(errors, paths[label], label=label)
        if tree is None:
            return
        trees[label] = tree

    question_markers = (
        "Is username comparison case-sensitive?",
        "must the password contain uppercase,",
        "maximum simultaneously active login count",
        "If existing users have no password",
    )
    for marker in question_markers:
        if marker not in text["reference"]:
            fail(errors, f"local-password product-question batch is missing {marker!r}")
    require_semantics(
        errors,
        path=paths["skill"],
        checks=(
            (
                "all unresolved password-product choices are asked once in one batch",
                (r"present all unresolved product choices in one batch",),
            ),
            (
                "the user may accept the displayed batch together",
                (r"`全部接受` / `Accept all`",),
            ),
            (
                "premature generic approval does not answer unasked choices",
                (
                    r"generic instruction to continue does not answer an unasked product choice",
                ),
            ),
            (
                "the owner supplies a positive session maximum without an invented default",
                (r"positive integer; there is no recommended number",),
            ),
            (
                "username case sensitivity has no invented generic default",
                (
                    r"username comparison is case-sensitive.*Require an explicit choice; neither behavior is a generic recommendation",
                ),
            ),
            (
                "the one-hour Token notice is not another blocking product question",
                (
                    r"Access Token lifetime starts at 3600 seconds.*do not turn that notice into another blocking product question",
                ),
            ),
        ),
    )
    normalized_reference = re.sub(r"\s+", " ", text["reference"])
    for marker in (
        "Do not invent",
        "neither behavior is a generic recommendation",
        "required notice, not another blocking choice",
    ):
        if marker not in normalized_reference:
            fail(
                errors,
                f"local-password decision boundary is missing {marker!r}",
            )
    if "interactive operator command" not in text["reference"]:
        fail(errors, "local-password reference must retain offline operator recovery")

    api_tree = trees["API"]
    routes: set[tuple[str, str, str, str]] = set()
    for node in api_tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if (
                not isinstance(decorator, ast.Call)
                or not isinstance(decorator.func, ast.Attribute)
                or not isinstance(decorator.func.value, ast.Name)
                or decorator.func.attr.lower()
                not in {"get", "post", "put", "patch", "delete"}
                or not decorator.args
                or not isinstance(decorator.args[0], ast.Constant)
                or not isinstance(decorator.args[0].value, str)
            ):
                continue
            routes.add(
                (
                    decorator.func.value.id,
                    decorator.func.attr.lower(),
                    decorator.args[0].value,
                    node.name,
                )
            )
    expected_routes = {
        ("registration_router", "post", "/auth/captcha", "create_public_captcha"),
        ("router", "post", "/me/captcha", "create_authenticated_captcha"),
        (
            "registration_router",
            "get",
            "/auth/registration/status",
            "read_registration_status",
        ),
        (
            "router",
            "post",
            "/auth/registration/status",
            "update_registration_status",
        ),
        (
            "registration_router",
            "post",
            "/auth/register",
            "register_local_account",
        ),
        ("router", "post", "/auth/login", "login_with_local_password"),
        ("router", "get", "/me/sessions", "my_active_sessions"),
        ("router", "post", "/me/password/change", "change_my_password"),
        (
            "router",
            "post",
            "/users/{user_id}/password/reset",
            "reset_user_password",
        ),
        (
            "router",
            "post",
            "/auth/password/reset/complete",
            "complete_temporary_password_reset",
        ),
        ("router", "post", "/users", "create_user_with_temporary_password"),
    }
    missing_routes = expected_routes - routes
    if missing_routes:
        fail(errors, f"local-password API is missing routes: {missing_routes!r}")
    unexpected_routes = sorted(
        route for route in routes if route not in expected_routes
    )
    if unexpected_routes:
        fail(
            errors,
            f"local-password API contains unexpected routes: {unexpected_routes!r}",
        )

    router_prefixes: dict[str, object] = {}
    for node in api_tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id == "APIRouter"
        ):
            prefix = next(
                (
                    keyword.value
                    for keyword in node.value.keywords
                    if keyword.arg == "prefix"
                ),
                None,
            )
            if prefix is not None:
                try:
                    router_prefixes[node.targets[0].id] = ast.literal_eval(prefix)
                except (TypeError, ValueError):
                    pass
    if (
        router_prefixes.get("router") != "/api/v1"
        or router_prefixes.get("registration_router") != "/api/v1"
    ):
        fail(errors, "both local-password routers must use the /api/v1 prefix")

    router_selector = _function_node(api_tree.body, "authentication_routers")
    router_returns = (
        [
            _returned_names(node)
            for node in router_selector.body
            if isinstance(node, ast.Return)
        ]
        if router_selector is not None
        else []
    )
    if router_returns != [("registration_router", "router")]:
        fail(
            errors,
            "public registration route must remain installed while the persisted switch changes",
        )

    active_environment = {
        key.strip(): value.strip()
        for line in text["environment"].splitlines()
        if line.strip() and not line.lstrip().startswith("#") and "=" in line
        for key, value in (line.split("=", 1),)
    }
    if "PUBLIC_REGISTRATION_ENABLED" in active_environment:
        fail(
            errors,
            "registration switch must live in PostgreSQL, not a deployment setting",
        )
    if active_environment.get("ADMIN_PASSWORD_RESET_MODE") != "direct":
        fail(
            errors,
            "administrator password reset must default to direct mode in .env.example",
        )
    for label, marker in (
        (
            "settings",
            'admin_password_reset_mode: Literal["direct", "temporary"] = "direct"',
        ),
        ("API", "reset_mode=settings.admin_password_reset_mode"),
        ("service", 'require_password_change = reset_mode == "temporary"'),
        ("service", 'else "permanent_password_set"'),
    ):
        if marker not in text[label]:
            fail(
                errors, f"{label} must implement the selected administrator reset mode"
            )
    for label, marker in (
        ("users model", "public_registration_enabled: Mapped[bool]"),
        ("service", "if not state.public_registration_enabled:"),
        ("API", "await service.set_registration_enabled("),
    ):
        if marker not in text[label]:
            fail(errors, f"{label} must enforce persisted registration switch")

    password_constants = _module_literals(trees["passwords"])
    expected_password_constants = {
        "ARGON2_MEMORY_COST_KIB": 65_536,
        "ARGON2_TIME_COST": 3,
        "ARGON2_PARALLELISM": 4,
        "ARGON2_HASH_LENGTH": 32,
        "ARGON2_SALT_LENGTH": 16,
        "MIN_PASSWORD_CHARACTERS": 8,
        "MAX_PASSWORD_CHARACTERS": 60,
        "MAX_PASSWORD_UTF8_BYTES": 1_024,
        "DEFAULT_MAX_CONCURRENT_OPERATIONS": 2,
    }
    for name, expected in expected_password_constants.items():
        if password_constants.get(name) != expected:
            fail(errors, f"password constant {name} must be {expected!r}")

    hasher_configuration: dict[str, str] | None = None
    for node in ast.walk(trees["passwords"]):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "PasswordHasher"
        ):
            hasher_configuration = {
                keyword.arg: ast.unparse(keyword.value)
                for keyword in node.keywords
                if keyword.arg is not None
            }
            break
    expected_hasher_configuration = {
        "time_cost": "ARGON2_TIME_COST",
        "memory_cost": "ARGON2_MEMORY_COST_KIB",
        "parallelism": "ARGON2_PARALLELISM",
        "hash_len": "ARGON2_HASH_LENGTH",
        "salt_len": "ARGON2_SALT_LENGTH",
        "type": "Type.ID",
    }
    if hasher_configuration != expected_hasher_configuration:
        fail(errors, "PasswordHasher must use every fixed Argon2id baseline constant")
    password_calls = {
        ast.unparse(node.func)
        for node in ast.walk(trees["passwords"])
        if isinstance(node, ast.Call)
    }
    if (
        "asyncio.to_thread" not in password_calls
        or "asyncio.Semaphore" not in password_calls
    ):
        fail(errors, "Argon2 work must be offloaded and protected by a local semaphore")

    pyproject = tomllib.loads(text["pyproject"])
    dependencies = pyproject.get("project", {}).get("dependencies", [])
    if not isinstance(dependencies, list) or not any(
        isinstance(item, str) and item.startswith("argon2-cffi")
        for item in dependencies
    ):
        fail(errors, "asset pyproject.toml must directly depend on argon2-cffi")

    schema_class_fields: dict[str, dict[str, str]] = {}
    for class_name in (
        "RegistrationRequest",
        "LoginRequest",
        "PasswordChangeRequest",
        "AdminPasswordResetRequest",
        "AdminUserCreateRequest",
        "PasswordResetCompletionRequest",
    ):
        node = _class_node(trees["schemas"], class_name)
        if node is None:
            continue
        schema_class_fields[class_name] = {
            item.target.id: ast.unparse(item.annotation)
            for item in node.body
            if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name)
        }
    required_secret_fields = {
        "RegistrationRequest": {"password"},
        "LoginRequest": {"password"},
        "PasswordChangeRequest": {"current_password", "new_password"},
        "AdminPasswordResetRequest": {"new_password"},
        "AdminUserCreateRequest": {"temporary_password"},
        "PasswordResetCompletionRequest": {"temporary_password", "new_password"},
    }
    for class_name, field_names in required_secret_fields.items():
        actual = schema_class_fields.get(class_name, {})
        for field_name in field_names:
            if actual.get(field_name) != "SecretStr":
                fail(errors, f"{class_name}.{field_name} must use SecretStr")
    if set(schema_class_fields.get("AdminPasswordResetRequest", {})) != {
        "new_password"
    }:
        fail(
            errors,
            "AdminPasswordResetRequest must expose only new_password beyond CAPTCHA fields",
        )

    user_model = _class_node(trees["users model"], "User")
    audit_model = _class_node(trees["models"], "AccountSecurityAuditEvent")
    if user_model is None or audit_model is None:
        fail(errors, "user password fields and account-security audit are required")
    else:
        audit_table = next(
            (
                ast.literal_eval(node.value)
                for node in audit_model.body
                if isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == "__tablename__"
            ),
            None,
        )
        if audit_table != "account_security_audit_events":
            fail(errors, "AccountSecurityAuditEvent table name is incorrect")
        password_fields = {
            node.target.id
            for node in user_model.body
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
        }
        expected_fields = {
            "password_hash",
            "must_change_password",
            "password_changed_at",
        }
        if not expected_fields.issubset(password_fields):
            fail(
                errors,
                "User is missing password-state fields: "
                f"{sorted(expected_fields - password_fields)!r}",
            )
    if _class_node(trees["models"], "PasswordCredential") is not None:
        fail(errors, "password state must not use a separate credential model")
    for marker in (
        'name="password_hash_shape"',
        'name="password_state_coherent"',
        'name="deleted_user_no_password"',
        "password_changed_at IS NULL",
        "deleted_at IS NULL OR password_hash IS NULL",
    ):
        if marker not in text["users model"]:
            fail(errors, f"User password-state constraint is missing {marker!r}")

    migration_literals = _module_literals(trees["migration"])
    if (
        migration_literals.get("revision") != "0004_password_auth"
        or migration_literals.get("down_revision") != "0003_business_audit"
    ):
        fail(errors, "0004_password_auth must directly follow 0003_business_audit")
    migration_calls: dict[str, list[str]] = {"create_table": [], "drop_table": []}
    added_columns: list[str] = []
    dropped_columns: list[str] = []
    for node in ast.walk(trees["migration"]):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in migration_calls
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            migration_calls[node.func.attr].append(node.args[0].value)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "users"
        ):
            if node.func.attr == "add_column":
                column = node.args[1]
                if (
                    isinstance(column, ast.Call)
                    and isinstance(column.func, ast.Attribute)
                    and column.func.attr == "Column"
                    and column.args
                    and isinstance(column.args[0], ast.Constant)
                    and isinstance(column.args[0].value, str)
                ):
                    added_columns.append(column.args[0].value)
            elif (
                node.func.attr == "drop_column"
                and isinstance(node.args[1], ast.Constant)
                and isinstance(node.args[1].value, str)
            ):
                dropped_columns.append(node.args[1].value)
    if "user_password_credentials" in (
        migration_calls["create_table"] + migration_calls["drop_table"]
    ):
        fail(errors, "migration must not create or drop a password-episode table")
    audit_table_name = "account_security_audit_events"
    if migration_calls["create_table"].count(audit_table_name) != 1:
        fail(errors, "migration must create account-security audit exactly once")
    if migration_calls["drop_table"].count(audit_table_name) != 1:
        fail(errors, "migration must drop account-security audit exactly once")
    for field in ("password_hash", "must_change_password", "password_changed_at"):
        if added_columns.count(field) != 1 or dropped_columns.count(field) != 1:
            fail(errors, f"0004 must add and drop users.{field} exactly once")
    for constraint in (
        "ck_users_password_hash_shape",
        "ck_users_password_state_coherent",
        "ck_users_deleted_user_no_password",
    ):
        if constraint not in text["migration"]:
            fail(errors, f"0004 must install {constraint}")

    revisions: dict[str, str | None] = {}
    for path in sorted((ASSET_ROOT / "alembic" / "versions").glob("*.py")):
        tree = _parse_python(errors, path, label="Alembic revision")
        if tree is None:
            return
        literals = _module_literals(tree)
        revision = literals.get("revision")
        down_revision = literals.get("down_revision")
        if not isinstance(revision, str):
            fail(errors, f"Alembic file has no literal revision: {path.name}")
            continue
        if down_revision is not None and not isinstance(down_revision, str):
            fail(errors, f"Alembic file has unsupported down_revision: {path.name}")
            continue
        if revision in revisions:
            fail(errors, f"duplicate Alembic revision: {revision}")
        revisions[revision] = down_revision
    heads = set(revisions) - {parent for parent in revisions.values() if parent}
    if heads != {"0004_password_auth"}:
        fail(
            errors, f"0004_password_auth must be the sole migration head, got {heads!r}"
        )

    append_only_markers = (
        "reject_account_security_audit_mutation",
        "BEFORE UPDATE OR DELETE ON account_security_audit_events",
        "BEFORE TRUNCATE ON account_security_audit_events",
    )
    for marker in append_only_markers:
        if marker not in text["migration"]:
            fail(errors, f"account-security audit is missing {marker!r}")

    service_class = _class_node(trees["service"], "LocalAuthenticationService")
    service_methods = (
        {
            node.name
            for node in service_class.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        if service_class is not None
        else set()
    )
    required_methods = {
        "register",
        "authenticate",
        "change_password",
        "reset_user_password",
        "complete_password_reset",
        "operator_reset_super_admin_password",
    }
    if not required_methods.issubset(service_methods):
        fail(
            errors,
            f"local authentication service is missing {required_methods - service_methods!r}",
        )
    for action in (
        "account_security.registration.completed",
        "account_security.password.changed",
        "account_security.password.admin_reset",
        "account_security.password.reset_completed",
        "account_security.password.operator_reset",
    ):
        if action not in text["service"]:
            fail(errors, f"account-security audit catalog is missing {action!r}")
    for marker in (
        "holder_ids != frozenset({user_id})",
        "load_live_super_admin_holder_ids(session)",
        "if verification.needs_rehash:",
        "user.password_hash = replacement_hash",
        "user.password_changed_at == snapshot.password_changed_at",
        "user.password_changed_at = changed_at",
        "self._same_password_state(user, concurrent_rehash_snapshot)",
        "if error.status_code >= 500:",
        "except Exception as exc:",
        '"audit.write.failed"',
    ):
        if marker not in text["service"]:
            fail(
                errors, f"local authentication service is missing safeguard {marker!r}"
            )

    operator_calls = [
        ast.unparse(node.func)
        for node in ast.walk(trees["operator"])
        if isinstance(node, ast.Call)
    ]
    if operator_calls.count("getpass.getpass") != 2:
        fail(
            errors,
            "offline operator recovery must read the password twice with getpass",
        )
    if '"--user-id"' not in text["operator"] or "--password" in text["operator"]:
        fail(errors, "offline operator recovery must accept only an immutable user ID")

    required_test_markers = {
        "API tests": (
            "test_public_registration_route_remains_present_for_runtime_switch",
            "test_captcha_is_required_before_public_registration_calls_service",
            "test_registration_status_public_read_exposes_only_boolean",
            "test_temporary_password_login_returns_403002_without_a_token",
            "test_admin_reset_defaults_to_a_direct_permanent_password",
            "test_admin_reset_and_temporary_completion_are_separate_commands",
            "test_admin_reset_request_cannot_select_the_project_mode",
            "test_password_routes_are_post_only_and_do_not_expose_the_mechanism",
        ),
        "service tests": (
            "test_unknown_and_wrong_passwords_use_one_public_failure",
            "test_successful_login_upgrades_a_stale_hash_after_rechecking_locks",
            "test_password_rotation_updates_user_row_and_timestamp",
            "test_service_self_change_rejects_reusing_the_current_password",
            "test_service_temporary_completion_rejects_reusing_the_temporary_password",
            "test_account_security_denial_audit_excludes_infrastructure_failures",
            "test_operator_reset_requires_the_exact_super_admin_holder_set",
            "test_operator_reset_accepts_only_the_target_as_sole_super_admin",
        ),
        "password tests": (
            "test_hash_and_verify_use_the_fixed_argon2id_profile",
            "test_hash_work_is_bounded_even_when_callers_run_concurrently",
        ),
        "PostgreSQL authentication tests": (
            "test_registration_and_login_persist_complete_local_identity",
            "test_registration_toggle_blocks_public_creation_but_not_admin_creation",
            "test_self_password_change_updates_user_and_revokes_old_token",
            "test_admin_reset_supports_direct_and_temporary_project_modes",
        ),
        "PostgreSQL persistence tests": (
            "test_rotation_updates_same_user_row",
            "test_deleted_user_cannot_retain_password_hash",
            "test_account_security_audit_rows_are_append_only",
        ),
    }
    for label, markers in required_test_markers.items():
        for marker in markers:
            if marker not in text[label]:
                fail(errors, f"{label} is missing local-password test {marker!r}")

    if "from app import password_models" not in text["Alembic environment"]:
        fail(errors, "Alembic metadata must import password_models")
    for label, markers in {
        "skill": (
            "Administrator password-reset mode.",
            "never let the API caller choose per request",
            "offline recovery always use temporary credentials",
        ),
        "reference": (
            "ADMIN_PASSWORD_RESET_MODE",
            "Administrator reset is a project-wide choice",
            "controls only the administrator HTTP reset",
        ),
        "README": (
            "username/password login",
            "Public registration is enabled by default",
            "Changing that holder is another guarded, audited offline PostgreSQL script",
            f"`{RELEASE_TAG}` adds a project-wide administrator password-reset choice",
        ),
        "Chinese README": (
            "用户名密码",
            "公开注册初始开启",
            "受保护的交接脚本",
            f"`{RELEASE_TAG}` 增加了项目级“管理员重置密码模式”",
        ),
    }.items():
        for marker in markers:
            if marker not in text[label]:
                fail(errors, f"{label} is missing local-password marker {marker!r}")


def validate_rate_limiting_and_verification(errors: list[str]) -> None:
    paths = {
        "rate-limit reference": SKILL_ROOT / "references" / "rate-limiting.md",
        "verification reference": (
            SKILL_ROOT / "references" / "verification-and-abuse-defense.md"
        ),
        "settings": ASSET_ROOT / "app" / "settings.py",
        "policy registry": ASSET_ROOT / "app" / "security_policies.py",
        "limiter": ASSET_ROOT / "app" / "rate_limit.py",
        "middleware": ASSET_ROOT / "app" / "rate_limit_middleware.py",
        "actor dependency": ASSET_ROOT / "app" / "rate_limit_dependencies.py",
        "abuse defense": ASSET_ROOT / "app" / "abuse_defense.py",
        "identity abuse flow": ASSET_ROOT / "app" / "abuse_flow.py",
        "captcha": ASSET_ROOT / "app" / "captcha.py",
        "redis client": ASSET_ROOT / "app" / "redis_client.py",
        "application": ASSET_ROOT / "app" / "main.py",
        "environment": ASSET_ROOT / ".env.example",
        "settings tests": ASSET_ROOT / "tests" / "test_settings.py",
        "abuse-defense tests": ASSET_ROOT / "tests" / "test_abuse_defense.py",
        "identity-flow tests": ASSET_ROOT / "tests" / "test_abuse_flow.py",
        "captcha tests": ASSET_ROOT / "tests" / "test_captcha.py",
        "captcha Redis tests": ASSET_ROOT
        / "tests"
        / "integration"
        / "test_captcha_redis.py",
        "abuse-defense Redis tests": (
            ASSET_ROOT / "tests" / "integration" / "test_abuse_defense_redis.py"
        ),
        "compose": ASSET_ROOT / "compose.dev.yaml",
        "CI": REPO_ROOT / ".github" / "workflows" / "ci.yml",
        "README": REPO_ROOT / "README.md",
        "Chinese README": REPO_ROOT / "README.zh-CN.md",
        "changelog": REPO_ROOT / "CHANGELOG.md",
        "Chinese changelog": REPO_ROOT / "CHANGELOG.zh-CN.md",
        "release checklist": REPO_ROOT / "RELEASE_CHECKLIST.md",
        "Chinese release checklist": REPO_ROOT / "RELEASE_CHECKLIST.zh-CN.md",
    }
    missing = False
    for name, path in paths.items():
        if not path.is_file():
            fail(
                errors,
                f"missing rate-limit/CAPTCHA {name}: {path.relative_to(REPO_ROOT)}",
            )
            missing = True
    if missing:
        return

    required_markers = {
        "rate-limit reference": (
            "## Redis Fixed Window",
            "Do not add an `api_global`, `api_ip`",
            "429001",
            "503001",
        ),
        "verification reference": (
            "CAPTCHA",
            "login",
            "register",
        ),
        "settings": (
            "app_environment: str = Field(",
            "rate_limit_redis_url: str | None = None",
            "rate_limit_hmac_key: SecretStr",
            "max_active_sessions_per_user: int = Field(ge=1)",
            "rate_limit_captcha_create_per_five_minutes: int = Field(default=10",
            "rate_limit_authenticated_read_per_minute: int = Field(default=600",
            "rate_limit_ordinary_write_per_minute: int = Field(default=120",
            "rate_limit_management_read_per_minute: int = Field(default=300",
            "rate_limit_authorization_write_per_minute: int = Field(default=60",
            "rate_limit_login_ip_per_five_minutes: int = Field(default=20",
            "rate_limit_registration_ip_per_hour: int = Field(default=5",
            "rate_limit_temporary_complete_ip_per_five_minutes: int = Field(",
        ),
        "policy registry": (
            "class SecurityPolicies:",
            "captcha_create=RateLimitPolicy(",
            "login=RateLimitPolicy(",
            "registration=RateLimitPolicy(",
            "temporary_complete=RateLimitPolicy(",
        ),
        "limiter": (
            "FIXED_WINDOW_SCRIPT:",
            "redis.call('INCR', KEYS[1])",
            "redis.call('EXPIRE', KEYS[1], window)",
            "redis.call('PTTL', KEYS[1])",
            "async def check_rate_limit(",
        ),
        "middleware": (
            "def trusted_client_ip(",
            "return ipaddress.ip_address(host).compressed",
            'return ""',
            "def semantic_rate_limit_headers(",
        ),
        "actor dependency": (
            "def actor_policy_for(",
            "async def enforce_principal_rate_limit(",
            "name=operation_id",
            "policies.authorization_write",
        ),
        "abuse defense": (
            "class AbuseDefenseService:",
            "async def check_login_attempt(",
            "async def check_registration_attempt(",
            "async def check_temporary_password_completion(",
            "async def check_captcha_create(",
        ),
        "identity abuse flow": (
            "class InvalidLoginCredentialsError(RuntimeError):",
            "class IdentityAbuseFlow:",
            "async def authenticate(",
            "verify_real_or_dummy_credentials",
            "async def complete_temporary_password_reset(",
            "async def register(",
            "registration_action",
        ),
        "captcha": ("class ", "async def "),
        "redis client": ("def create_rate_limit_redis_client(",),
        "application": (
            "create_rate_limit_redis_client(settings)",
            "app.state.rate_limit_redis",
            "@app.exception_handler(RateLimitExceeded)",
            "@app.exception_handler(RateLimitUnavailable)",
        ),
        "environment": (
            "RATE_LIMIT_REDIS_URL=redis://127.0.0.1:6380/0",
            "APP_ENVIRONMENT=development",
            "RATE_LIMIT_HMAC_KEY=",
            "MAX_ACTIVE_SESSIONS_PER_USER=",
            "ADMIN_PASSWORD_RESET_MODE=direct",
            "RATE_LIMIT_CAPTCHA_CREATE_PER_FIVE_MINUTES=10",
            "RATE_LIMIT_LOGIN_IP_PER_FIVE_MINUTES=20",
            "RATE_LIMIT_REGISTRATION_IP_PER_HOUR=5",
            "RATE_LIMIT_TEMPORARY_COMPLETE_IP_PER_FIVE_MINUTES=20",
        ),
        "settings tests": (
            "test_app_environment_is_required_for_every_rate_limit_mode",
            "test_rate_limit_defaults_are_explicit_and_configurable",
            "test_session_limit_must_be_positive_and_explicit",
            "test_admin_password_reset_defaults_to_direct_and_accepts_temporary",
        ),
        "abuse-defense tests": (
            "test_anonymous_quota_does_not_use_user_supplied_account",
            "test_missing_trusted_ip_never_enters_a_shared_bucket",
            "test_captcha_scene_is_independent_and_private_subject_is_actor",
        ),
        "identity-flow tests": (
            "test_invalid_credentials_have_one_generic_error_without_failure_counter",
            "test_admission_fails_before_credential_callback",
        ),
        "abuse-defense Redis tests": (
            "test_login_uses_only_per_business_ip_key",
            "test_captcha_scenes_and_subjects_do_not_share_quota",
        ),
        "captcha tests": ("test_",),
        "captcha Redis tests": ("test_",),
        "compose": (
            "redis-rate-limit:",
            '"127.0.0.1:6380:6379"',
        ),
        "CI": (
            "TEST_RATE_LIMIT_REDIS_URL: redis://127.0.0.1:6380/0",
            "redis-rate-limit:",
            "- 6380:6379",
        ),
        "README": ("Redis fixed-window quotas", "no global or cross-business quotas"),
        "Chinese README": ("Redis 限流使用简单固定窗口", "没有全站总额度"),
        "changelog": ("rate",),
        "Chinese changelog": ("限流",),
        "release checklist": ("rate",),
        "Chinese release checklist": ("限流",),
    }
    text = {name: path.read_text(encoding="utf-8") for name, path in paths.items()}
    for name, markers in required_markers.items():
        for marker in markers:
            if marker not in text[name]:
                relative = paths[name].relative_to(REPO_ROOT)
                fail(
                    errors,
                    f"{relative} is missing rate-limit/verification marker: {marker!r}",
                )

    settings_tree = _parse_python(
        errors,
        paths["settings"],
        label="rate-limit settings",
    )
    if settings_tree is None:
        return
    settings_class = _class_node(settings_tree, "Settings")
    app_environment_field = None
    if settings_class is not None:
        app_environment_field = next(
            (
                node
                for node in settings_class.body
                if isinstance(node, ast.AnnAssign)
                and isinstance(node.target, ast.Name)
                and node.target.id == "app_environment"
            ),
            None,
        )
    app_environment_value = (
        app_environment_field.value
        if isinstance(app_environment_field, ast.AnnAssign)
        else None
    )
    app_environment_is_required = (
        isinstance(app_environment_value, ast.Call)
        and isinstance(app_environment_value.func, ast.Name)
        and app_environment_value.func.id == "Field"
        and not app_environment_value.args
        and all(
            keyword.arg not in {"default", "default_factory"}
            for keyword in app_environment_value.keywords
        )
    )
    if not app_environment_is_required:
        fail(
            errors,
            "Settings.app_environment must be a required Field with no default or "
            "default_factory",
        )

    active_environment = {
        key.strip(): value.strip()
        for line in text["environment"].splitlines()
        if line.strip() and not line.lstrip().startswith("#") and "=" in line
        for key, value in (line.split("=", 1),)
    }
    if not active_environment.get("APP_ENVIRONMENT"):
        fail(errors, ".env.example must explicitly set a non-empty APP_ENVIRONMENT")

    retired_shared_quota_markers = (
        "api_global",
        "api_ip",
        "login_pair",
        "login_global",
        "registration_target",
        "registration_pair",
        "registration_global",
        "super_admin_transfer",
        "login_failure_state_retention_seconds",
        "verification_global",
        "TOKEN_BUCKET_SCRIPT",
    )
    for name in (
        "settings",
        "policy registry",
        "abuse defense",
        "identity abuse flow",
        "environment",
    ):
        for marker in retired_shared_quota_markers:
            if marker in text[name]:
                relative = paths[name].relative_to(REPO_ROOT)
                fail(
                    errors,
                    f"{relative} reintroduces retired quota marker: {marker!r}",
                )

    login_check_start = text["abuse defense"].find("async def check_login_attempt(")
    registration_check_start = text["abuse defense"].find(
        "async def check_registration_attempt(", login_check_start
    )
    login_check_body = text["abuse defense"][login_check_start:registration_check_start]
    if "self._policies.login" not in login_check_body:
        fail(errors, "login admission must use its single per-IP business quota")
    if "normalized_identifier)" in login_check_body:
        fail(errors, "login quota must not key on a submitted username")

    flow_source = text["identity abuse flow"]
    flow_order = (
        flow_source.find("await self._abuse_defense.check_login_attempt("),
        flow_source.find("result = await verify_real_or_dummy_credentials()"),
    )
    if any(position < 0 for position in flow_order) or flow_order != tuple(
        sorted(flow_order)
    ):
        fail(
            errors,
            "login flow must admit by IP before real/dummy credentials",
        )


def validate_simplified_authentication_and_administration(errors: list[str]) -> None:
    """Keep retired baseline features out of the executable asset."""

    retired_files = (
        "app/verification.py",
        "app/verification_flow.py",
        "tests/test_verification.py",
        "tests/test_verification_flow.py",
        "tests/integration/test_verification_redis.py",
        "app/authentication.py",
    )
    for relative in retired_files:
        if (ASSET_ROOT / relative).exists():
            fail(
                errors,
                f"retired optional authentication module is still bundled: {relative}",
            )

    app_root = ASSET_ROOT / "app"
    for path in sorted(app_root.rglob("*.py")):
        if any(part in FORBIDDEN_DIRECTORY_NAMES for part in path.parts):
            continue
        content = path.read_text(encoding="utf-8")
        for marker in ("can_delegate", "super_admin_transfer", "logout-all"):
            if marker in content:
                fail(errors, f"{path.relative_to(REPO_ROOT)} reintroduces {marker!r}")

    migration_path = ASSET_ROOT / "alembic" / "versions" / "0004_password_auth.py"
    if migration_path.is_file():
        migration = migration_path.read_text(encoding="utf-8")
        if (
            '"public_registration_enabled"' not in migration
            or 'sa.text("true")' not in migration
        ):
            fail(
                errors,
                "registration switch must be persisted with a true database default",
            )

    reference_paths = (
        SKILL_ROOT / "references" / "country-catalog.md",
        SKILL_ROOT / "references" / "proxy-availability-backend.md",
    )
    for path in reference_paths:
        if not path.is_file():
            continue
        content = path.read_text(encoding="utf-8")
        marker = (
            "implicit anonymous API from this Skill"
            if path.name == "country-catalog.md"
            else "never add an all-user or cross-business request quota"
        )
        if marker not in re.sub(r"\s+", " ", content):
            fail(
                errors,
                f"{path.relative_to(REPO_ROOT)} must preserve optional-feature security scope",
            )


def validate_single_project_scope(errors: list[str]) -> None:
    active_paths = [
        SKILL_ROOT / "SKILL.md",
        SKILL_ROOT / "agents" / "openai.yaml",
        *sorted((SKILL_ROOT / "references").rglob("*.md")),
    ]
    for root in (
        ASSET_ROOT / "app",
        ASSET_ROOT / "alembic",
        ASSET_ROOT / "sql",
    ):
        if root.is_dir():
            active_paths.extend(
                sorted(
                    path
                    for path in root.rglob("*")
                    if path.is_file() and path.suffix.lower() in TEXT_SUFFIXES
                )
            )

    forbidden_patterns = (
        re.compile(
            r"(?<![A-Za-z0-9])(?:multi[\s_-]*)?"
            r"(?:tenant(?:s|[_-][A-Za-z0-9_]+)?|tenancy)",
            re.IGNORECASE,
        ),
        re.compile(r"租户"),
    )
    for path in active_paths:
        if not path.is_file():
            continue
        content = path.read_text(encoding="utf-8")
        for pattern in forbidden_patterns:
            match = pattern.search(content)
            if match is None:
                continue
            line_start = content.rfind("\n", 0, match.start()) + 1
            line_end = content.find("\n", match.end())
            if line_end < 0:
                line_end = len(content)
            matched_line = content[line_start:line_end].casefold()
            if re.search(r"\b(?:do not|does not|without|no)\b", matched_line) or any(
                marker in matched_line for marker in ("不", "无", "禁止")
            ):
                continue
            line = content.count("\n", 0, match.start()) + 1
            relative = path.relative_to(REPO_ROOT)
            fail(
                errors,
                f"{relative}:{line} introduces a forbidden multi-project "
                "authorization scope",
            )


def validate_user_role_limit(errors: list[str]) -> None:
    paths = {
        "entrypoint": SKILL_ROOT / "SKILL.md",
        "RBAC reference": SKILL_ROOT / "references" / "rbac.md",
        "atomic reference": SKILL_ROOT / "references" / "atomic-consistency.md",
        "PostgreSQL reference": SKILL_ROOT
        / "references"
        / "postgresql-rbac-implementation.md",
        "migration reference": SKILL_ROOT / "references" / "migrations.md",
        "testing reference": SKILL_ROOT / "references" / "testing.md",
        "domain": ASSET_ROOT / "app" / "rbac" / "domain.py",
        "schemas": ASSET_ROOT / "app" / "rbac" / "schemas.py",
        "queries": ASSET_ROOT / "app" / "rbac" / "queries.py",
        "service": ASSET_ROOT / "app" / "rbac" / "service.py",
        "migration": ASSET_ROOT
        / "alembic"
        / "versions"
        / "0001_single_project_rbac.py",
        "bootstrap": ASSET_ROOT / "sql" / "bootstrap_super_admin.sql",
        "schema tests": ASSET_ROOT / "tests" / "test_schemas.py",
        "integration tests": ASSET_ROOT
        / "tests"
        / "integration"
        / "test_user_role_limit.py",
        "bootstrap tests": ASSET_ROOT / "tests" / "integration" / "test_bootstrap.py",
        "migration tests": ASSET_ROOT / "tests" / "integration" / "test_migrations.py",
    }
    missing = False
    for name, path in paths.items():
        if not path.is_file():
            fail(
                errors,
                f"missing user-role-limit {name}: {path.relative_to(REPO_ROOT)}",
            )
            missing = True
    if missing:
        return

    text = {name: path.read_text(encoding="utf-8") for name, path in paths.items()}
    require_semantics(
        errors,
        path=paths["entrypoint"],
        checks=(
            (
                "each user has at most ten live role assignments",
                (r"Each user has at most 10 live role assignments",),
            ),
            (
                "mandatory user, disabled roles, and super_admin count; tombstones do not",
                (
                    r"including `user`, disabled roles, and `super_admin`; tombstones do not count",
                ),
            ),
        ),
    )
    required_markers = {
        "RBAC reference": (
            "each user may have at most 10",
            "disabled role still occupies one of the 10 slots",
        ),
        "atomic reference": (
            "more than 10 live role bindings",
            "two bindings racing for a user's tenth live role slot",
        ),
        "PostgreSQL reference": (
            "at most 10 live rows per user",
            "concurrent tenth-slot race",
        ),
        "migration reference": (
            "Enforce at most 10 live `user_roles` rows per user",
            "disabled roles still occupy a slot, tombstones release one",
        ),
        "testing reference": (
            "the 10-live-role limit",
            "concurrent race for the tenth slot",
        ),
        "domain": ("MAX_ROLES_PER_USER = 10",),
        "schemas": (
            "max_length=MAX_ROLES_PER_USER",
            "permission_ids: list[uuid.UUID] = Field(min_length=1, max_length=100)",
        ),
        "queries": (
            "async def count_live_user_roles(",
            "UserRole.deleted_at.is_(None)",
        ),
        "service": (
            "live_role_count + len(changed_ids) > MAX_ROLES_PER_USER",
            'conflict("user_role_limit_exceeded")',
        ),
        "migration": (
            'revision: str = "0001_single_project_rbac"',
            "down_revision: str | None = None",
            "CREATE FUNCTION lock_rbac_state_before_user_roles_write()",
            "FOR EACH STATEMENT",
            "DEFERRABLE INITIALLY DEFERRED",
            "ct_user_roles_max_ten_live",
        ),
        "bootstrap": (
            "candidate_role_count >= 10",
            "target user already has 10 live role assignments",
        ),
        "schema tests": (
            "test_permission_batches_require_one_to_one_hundred_unique_ids",
            "test_role_batches_require_one_to_ten_unique_ids",
        ),
        "integration tests": (
            "test_service_enforces_limit_and_keeps_bind_idempotent",
            "test_database_counts_disabled_roles_and_ignores_tombstones",
            "test_concurrent_bind_cannot_create_an_eleventh_live_role",
            "test_operator_handover_rejects_a_full_target_atomically",
        ),
        "bootstrap tests": (
            "test_operator_sql_uses_the_tenth_role_slot_and_replays_idempotently",
            "test_operator_sql_rejects_a_full_target_without_partial_changes",
        ),
        "migration tests": (
            'assert revision == "0004_password_auth"',
            "role_limit_trigger_count == 1",
        ),
    }
    for name, markers in required_markers.items():
        normalized_content = re.sub(r"\s+", " ", text[name])
        for marker in markers:
            if re.sub(r"\s+", " ", marker) not in normalized_content:
                relative = paths[name].relative_to(REPO_ROOT)
                fail(
                    errors,
                    f"{relative} is missing user-role-limit marker: {marker!r}",
                )

    role_request_start = text["schemas"].find("class RoleIdsRequest(BaseModel):")
    role_request_end = text["schemas"].find("\nclass ", role_request_start + 1)
    role_request = text["schemas"][
        role_request_start : role_request_end if role_request_end >= 0 else None
    ]
    if "max_length=100" in role_request:
        fail(errors, "RoleIdsRequest must not retain the old 100-item batch limit")


def validate_administrative_read_visibility(errors: list[str]) -> None:
    paths = {
        "entrypoint": SKILL_ROOT / "SKILL.md",
        "hierarchy reference": SKILL_ROOT
        / "references"
        / "administrative-hierarchy.md",
        "atomic reference": SKILL_ROOT / "references" / "atomic-consistency.md",
        "PostgreSQL reference": SKILL_ROOT
        / "references"
        / "postgresql-rbac-implementation.md",
        "testing reference": SKILL_ROOT / "references" / "testing.md",
        "queries": ASSET_ROOT / "app" / "rbac" / "queries.py",
        "policy": ASSET_ROOT / "app" / "rbac" / "policy.py",
        "routes": ASSET_ROOT / "app" / "rbac" / "api.py",
        "service": ASSET_ROOT / "app" / "rbac" / "service.py",
        "policy tests": ASSET_ROOT / "tests" / "test_policy.py",
        "dependency tests": ASSET_ROOT / "tests" / "test_dependency_observability.py",
        "query tests": ASSET_ROOT / "tests" / "test_rbac_queries.py",
        "service audit tests": ASSET_ROOT
        / "tests"
        / "test_rbac_service_observability.py",
        "read integration tests": ASSET_ROOT
        / "tests"
        / "integration"
        / "test_read_visibility.py",
        "locking integration tests": ASSET_ROOT
        / "tests"
        / "integration"
        / "test_postgresql_locking.py",
        "write integration tests": ASSET_ROOT
        / "tests"
        / "integration"
        / "test_rbac_api.py",
    }
    missing = False
    for name, path in paths.items():
        if not path.is_file():
            fail(
                errors,
                f"missing administrative-visibility {name}: "
                f"{path.relative_to(REPO_ROOT)}",
            )
            missing = True
    if missing:
        return

    text = {name: path.read_text(encoding="utf-8") for name, path in paths.items()}
    require_semantics(
        errors,
        path=paths["entrypoint"],
        checks=(
            (
                "administrative list/count/search/detail/nested/bulk/export share strict hierarchy",
                (
                    r"Hide self, peer, higher, protected, and incomparable targets from administrative list, count, search, detail, nested, bulk, and export",
                ),
            ),
            (
                "super_admin is the only administrator allowed complete visibility",
                (
                    r"Except for the sole super administrator, an actor may manage only strictly lower",
                ),
            ),
            (
                "the actor reads its own authority only through /api/v1/me/access",
                (r"actor sees itself only at `/api/v1/me/access`",),
            ),
            (
                "capability is checked before target visibility",
                (r"Check the exact capability before target visibility",),
            ),
        ),
    )
    required_markers = {
        "hierarchy reference": (
            "## Administrative Read Visibility",
            "### Administrative Write Visibility",
            "the current `super_admin` may list and inspect every non-deleted user and role",
            "strictly lower than the actor's tier",
            "Batch-load role grants and user authority",
            "collections such as `assigned_role_ids` contain only roles visible to the",
            "A caller without that capability receives `403001`",
            "is concealed with the same `404001`",
        ),
        "atomic reference": (
            "Public nested collections such as `assigned_role_ids` use the",
            "Do not reopen a route/request `Session`",
        ),
        "PostgreSQL reference": (
            "Assemble page authorities and role grants in bounded",
            "`assigned_role_ids` contains only roles visible to the actor",
        ),
        "testing reference": (
            "role and user pages loading grants and authority in a bounded number of",
            "nested `assigned_role_ids`",
        ),
        "queries": (
            "def _actor_is_super_admin(",
            "async def load_role_grants_for_roles(",
            "async def load_user_access_views(",
            "actor: AuthoritySnapshot",
            "if not _actor_is_super_admin(actor):",
            "Role.management_tier < actor.management_tier",
            "Role.is_protected.is_(False)",
            "async def list_visible_roles_page(",
            "async def list_visible_users_page(",
            "async def load_authority_snapshots_for_users(",
        ),
        "policy": (
            "def is_administrative_user_visible(",
            "actor.user_id != target.user_id",
            "target.management_tier < actor.management_tier",
            "def is_administrative_role_visible(",
            "role.management_tier < actor.management_tier",
        ),
        "routes": (
            "roles, total = await list_visible_roles_page(",
            "grants = await load_role_grants_for_roles(session, roles=roles)",
            "users, total = await list_visible_users_page(",
            "access_by_user_id = await load_user_access_views(",
        ),
        "service": (
            "async def _lock_actor_and_target_user(",
            "not is_administrative_user_visible(actor=actor, target=visible_target)",
            "not is_administrative_role_visible(actor=actor, role=grant)",
            "async def _lock_shared_role_change(",
            "not is_administrative_role_visible(actor=actor, role=role_before)",
            "affected_by_user_id = await load_authority_snapshots_for_users(",
            "except RbacError as exc:",
            "except Exception as audit_exc:",
            '"audit.write.failed"',
        ),
        "policy tests": (
            "test_administrative_user_visibility_is_strictly_downward_for_admin",
            "test_administrative_role_visibility_is_strictly_downward_for_admin",
        ),
        "dependency tests": (
            "test_audit_log_failure_does_not_replace_permission_denial",
            "assert caught.value.status_code == 403",
        ),
        "query tests": (
            "test_batch_authority_loader_uses_one_select_for_multiple_users",
            "test_batch_role_grant_loader_uses_one_select_for_multiple_roles",
        ),
        "service audit tests": (
            "test_denied_audit_failure_preserves_original_rbac_error",
            "((forbidden, 403), (not_found, 404), (conflict, 409))",
        ),
        "read integration tests": (
            "test_user_reads_apply_strict_visibility_and_filtered_pagination",
            "test_role_reads_hide_peer_and_higher_authority",
            "test_disabled_roles_remain_assigned_but_do_not_contribute_authority",
            "test_list_select_count_does_not_grow_with_page_size",
        ),
        "locking integration tests": (
            "test_shared_role_lock_select_count_does_not_grow_with_holders",
        ),
        "write integration tests": (
            "test_lower_authority_cannot_manage_users",
            "test_admin_user_writes_conceal_self_peer_higher_and_protected_targets",
            "test_admin_role_writes_conceal_peer_higher_and_protected_roles",
            "test_user_role_batch_conceals_hidden_role_and_remains_atomic",
        ),
    }
    for name, markers in required_markers.items():
        for marker in markers:
            if marker not in text[name]:
                relative = paths[name].relative_to(REPO_ROOT)
                fail(
                    errors,
                    f"{relative} is missing administrative-visibility marker: "
                    f"{marker!r}",
                )

    query_sections = {
        "user projection": (
            "async def load_user_access_views(",
            "def _select_visible_users(",
            (
                "if not _actor_is_super_admin(actor):",
                "Role.management_tier < actor.management_tier",
                "assigned_role_ids[row.user_id].add(row.role_id)",
            ),
        ),
        "visible users": (
            "def _select_visible_users(",
            "def _select_visible_roles(",
            (
                "if _actor_is_super_admin(actor):",
                "User.id != actor.user_id",
                "active_authority.c.management_tier, 0) < actor.management_tier",
            ),
        ),
        "visible roles": (
            "def _select_visible_roles(",
            "async def list_visible_roles_page(",
            (
                "if _actor_is_super_admin(actor):",
                "Role.management_tier < actor.management_tier",
                "Role.is_protected.is_(False)",
            ),
        ),
    }
    query_source = text["queries"]
    for name, (start_marker, end_marker, markers) in query_sections.items():
        start = query_source.find(start_marker)
        end = query_source.find(end_marker, start + 1)
        if start < 0 or end < 0:
            continue
        section = query_source[start:end]
        for marker in markers:
            if marker not in section:
                fail(
                    errors,
                    f"{paths['queries'].relative_to(REPO_ROOT)} {name} section "
                    f"is missing {marker!r}",
                )

    service_source = text["service"]
    denial = service_source.find("except RbacError as exc:")
    audit_failure = service_source.find("except Exception as audit_exc:", denial + 1)
    reraises_original = service_source.find("\n            raise\n", audit_failure + 1)
    outcome_return = service_source.find(
        "\n        return outcome.value", audit_failure + 1
    )
    if not (
        denial >= 0
        and audit_failure > denial
        and reraises_original > audit_failure
        and outcome_return > reraises_original
    ):
        fail(
            errors,
            "RBAC service must log denied-audit failure and re-raise the original "
            "authorization error",
        )

    service_sections = {
        "user write gate": (
            "async def _lock_actor_and_target_user(",
            "async def update_user_status(",
            (
                "if required_permission.value not in actor.permissions:",
                "if target_user_id not in users:",
                "if not is_administrative_user_visible(actor=actor, target=visible_target):",
            ),
        ),
        "user-role batch gate": (
            "async def change_user_roles(",
            "async def assign_role(",
            (
                "grants_by_role_id = await load_role_grants_for_roles(",
                "not is_administrative_role_visible(actor=actor, role=grant)",
                "decision = decide_role_change(",
            ),
        ),
        "role write gate": (
            "async def _lock_shared_role_change(",
            "def _require_role_administration(",
            (
                "if required_permission.value not in actor.permissions:",
                "role = locked_roles.get(role_id)",
                "if not is_administrative_role_visible(actor=actor, role=role_before):",
            ),
        ),
    }
    for name, (start_marker, end_marker, ordered_markers) in service_sections.items():
        start = service_source.find(start_marker)
        end = service_source.find(end_marker, start + 1)
        if start < 0 or end < 0:
            fail(
                errors,
                f"{paths['service'].relative_to(REPO_ROOT)} {name} section missing",
            )
            continue
        section = service_source[start:end]
        positions = [section.find(marker) for marker in ordered_markers]
        if any(position < 0 for position in positions) or positions != sorted(
            positions
        ):
            fail(
                errors,
                f"{paths['service'].relative_to(REPO_ROOT)} {name} must keep "
                "capability, visibility, and policy checks in non-leaking order",
            )


def validate_super_admin_bootstrap(errors: list[str]) -> None:
    sql_path = ASSET_ROOT / "sql" / "bootstrap_super_admin.sql"
    handover_path = ASSET_ROOT / "sql" / "handover_super_admin.sql"
    legacy_python_path = ASSET_ROOT / "app" / "rbac" / "bootstrap.py"
    if legacy_python_path.exists():
        fail(
            errors,
            "legacy Python super-admin bootstrap entry point must not be distributed",
        )
    if not sql_path.is_file():
        return

    sql = sql_path.read_text(encoding="utf-8")
    required_markers = (
        "\\set ON_ERROR_STOP on",
        "BEGIN;",
        "rbac_state",
        "WHERE scope = 'global'",
        "FOR UPDATE",
        "target user account does not exist",
        "INSERT INTO user_roles",
        "SET authz_version = authz_version + 1",
        "SET epoch = epoch + 1",
        "INSERT INTO rbac_audit_events",
        "super_admin.bootstrap",
        "COMMIT;",
    )
    for marker in required_markers:
        if marker not in sql:
            relative = sql_path.relative_to(REPO_ROOT)
            fail(errors, f"{relative} is missing bootstrap invariant: {marker!r}")

    if "INSERT INTO users" in sql:
        fail(errors, "super-admin bootstrap SQL must require an existing user")
    if not handover_path.is_file():
        fail(errors, "offline super-admin handover SQL is missing")
        return
    handover = handover_path.read_text(encoding="utf-8")
    for marker in (
        "\\set ON_ERROR_STOP on",
        "BEGIN;",
        "rbac_state",
        "FOR UPDATE",
        "UPDATE user_roles",
        "INSERT INTO user_roles",
        "INSERT INTO rbac_audit_events",
        "COMMIT;",
    ):
        if marker not in handover:
            fail(errors, f"offline super-admin handover SQL is missing {marker!r}")
    if "INSERT INTO users" in handover:
        fail(errors, "offline super-admin handover must require an existing user")


def validate_rbac_database_naming(errors: list[str]) -> None:
    paths = {
        "model": ASSET_ROOT / "app" / "rbac" / "models.py",
        "migration": ASSET_ROOT
        / "alembic"
        / "versions"
        / "0001_single_project_rbac.py",
        "bootstrap": ASSET_ROOT / "sql" / "bootstrap_super_admin.sql",
        "schema reference": SKILL_ROOT
        / "references"
        / "postgresql-rbac-implementation.md",
    }
    if any(not path.is_file() for path in paths.values()):
        return

    required_markers = {
        "model": (
            "class RbacState(Base):",
            '__tablename__ = "rbac_state"',
            "class RbacAuditEvent(Base):",
            '__tablename__ = "rbac_audit_events"',
            'Index("ix_rbac_audit_actor_created"',
            'Index("ix_rbac_audit_request_id"',
            "is_super_admin: Mapped[bool]",
            '"uq_roles_single_super_admin"',
        ),
        "migration": (
            '"rbac_state"',
            'name="pk_rbac_state"',
            'name="scope_global"',
            'name="epoch_nonnegative"',
            '"rbac_audit_events"',
            'name="pk_rbac_audit_events"',
            '"ix_rbac_audit_actor_created"',
            '"ix_rbac_audit_request_id"',
            '"is_super_admin"',
            '"uq_roles_single_super_admin"',
        ),
        "bootstrap": (
            "FROM rbac_state",
            "UPDATE rbac_state",
            "INSERT INTO rbac_audit_events",
        ),
        "schema reference": ("`rbac_state`", "`rbac_audit_events`"),
    }
    for name, markers in required_markers.items():
        content = paths[name].read_text(encoding="utf-8")
        for marker in markers:
            if marker not in content:
                relative = paths[name].relative_to(REPO_ROOT)
                fail(errors, f"{relative} is missing RBAC database marker: {marker!r}")

    stale_markers = (
        "authorization_audit_events",
        "AuthorizationAuditEvent",
        "ix_authz_audit",
        "authorization_state",
        "AuthorizationState",
        "lock_authorization_state",
        "authorization-state",
        "authorization_scope_global",
        "authorization_epoch_nonnegative",
        "pk_authorization_state",
        "is_owner",
        "owner_tier_reserved",
        "owner_shape",
        "uq_roles_single_owner",
    )
    for path in SKILL_ROOT.rglob("*"):
        relative_parts = path.relative_to(SKILL_ROOT).parts
        if any(
            part in FORBIDDEN_DIRECTORY_NAMES
            or part.endswith(FORBIDDEN_DIRECTORY_SUFFIXES)
            for part in relative_parts
        ):
            continue
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        content = path.read_text(encoding="utf-8")
        for marker in stale_markers:
            if marker in content:
                relative = path.relative_to(REPO_ROOT)
                fail(errors, f"{relative} contains obsolete RBAC name: {marker!r}")


def validate_api_internationalization(errors: list[str]) -> None:
    paths = {
        "entrypoint": SKILL_ROOT / "SKILL.md",
        "reference": SKILL_ROOT / "references" / "api-internationalization.md",
        "response reference": SKILL_ROOT / "references" / "api-response-standard.md",
        "Chinese architecture": (
            SKILL_ROOT / "references" / "architecture-overview.zh-CN.md"
        ),
        "README": REPO_ROOT / "README.md",
        "Chinese README": REPO_ROOT / "README.zh-CN.md",
        "asset README": ASSET_ROOT / "README.md",
        "changelog": REPO_ROOT / "CHANGELOG.md",
        "Chinese changelog": REPO_ROOT / "CHANGELOG.zh-CN.md",
        "release checklist": REPO_ROOT / "RELEASE_CHECKLIST.md",
        "Chinese release checklist": REPO_ROOT / "RELEASE_CHECKLIST.zh-CN.md",
        "implementation": ASSET_ROOT / "app" / "i18n.py",
        "contract": ASSET_ROOT / "app" / "api_contract.py",
        "application": ASSET_ROOT / "app" / "main.py",
        "errors": ASSET_ROOT / "app" / "rbac" / "errors.py",
        "pyproject": ASSET_ROOT / "pyproject.toml",
        "tests": ASSET_ROOT / "tests" / "test_i18n.py",
        "Chinese catalog": ASSET_ROOT / "app" / "locales" / "zh-CN.json",
        "English catalog": ASSET_ROOT / "app" / "locales" / "en.json",
    }
    if any(not path.is_file() for path in paths.values()):
        return

    require_semantics(
        errors,
        path=paths["reference"],
        checks=(
            (
                "default Chinese and English Accept-Language contract",
                (r"Accept-Language.*zh-CN.*en",),
            ),
            (
                "canonical response language and cache variation headers",
                (r"Content-Language.*Vary.*Accept-Language",),
            ),
            (
                "stable machine fields are not translated",
                (r"HTTP status.*business code.*remain language-independent",),
            ),
            (
                "validation uses stable error types rather than raw messages",
                (
                    r"Do not return Pydantic.s raw.*error\[.type.\]",
                    r"error\[.type.\].*raw",
                ),
            ),
            (
                "validation paths do not reflect attacker-controlled keys",
                (r"mask an extra field.*mapping keys",),
            ),
            (
                "request language never selects a resource path",
                (r"Never turn a request value into a file path or dynamic import",),
            ),
            (
                "specific language exclusions override broad fallbacks",
                (r"specific language range.*q=0.*wildcard",),
            ),
        ),
    )
    for label in (
        "entrypoint",
        "response reference",
        "Chinese architecture",
        "README",
        "Chinese README",
        "asset README",
    ):
        text = paths[label].read_text(encoding="utf-8")
        for marker in ("Accept-Language", "Content-Language", "Vary: Accept-Language"):
            if marker not in text:
                fail(errors, f"{label} is missing API i18n marker {marker!r}")

    document_markers = {
        "Chinese architecture": (
            "api-internationalization.md",
            "OpenAPI",
            "数据库",
        ),
        "README": (f"`{RELEASE_TAG}`", "Database-authored", "OpenAPI"),
        "Chinese README": (f"`{RELEASE_TAG}`", "数据库", "OpenAPI"),
        "asset README": ("Database-authored", "OpenAPI developer metadata"),
    }
    for label, markers in document_markers.items():
        content = paths[label].read_text(encoding="utf-8")
        for marker in markers:
            if marker not in content:
                fail(errors, f"{label} is missing API i18n boundary {marker!r}")

    release_documents = {
        "changelog": (
            f"## [{RELEASE_VERSION}] - {RELEASE_DATE}",
            "Accept-Language",
        ),
        "Chinese changelog": (
            f"## [{RELEASE_VERSION}] - {RELEASE_DATE}",
            "Accept-Language",
        ),
        "release checklist": (
            f"## {RELEASE_TAG} acceptance baseline",
            "Accept-Language",
        ),
        "Chinese release checklist": (
            f"## {RELEASE_TAG} 验收基线",
            "Accept-Language",
        ),
    }
    for label, (heading, marker) in release_documents.items():
        content = paths[label].read_text(encoding="utf-8")
        _, separator, remainder = content.partition(heading)
        if not separator:
            fail(errors, f"{label} is missing {heading!r}")
            continue
        release_section = remainder.split("\n## ", maxsplit=1)[0]
        if marker not in release_section:
            fail(errors, f"{label} does not document API i18n under {heading!r}")

    implementation_tree = _parse_python(
        errors, paths["implementation"], label="API i18n implementation"
    )
    if implementation_tree is None:
        return
    message_key_class = _class_node(implementation_tree, "MessageKey")
    if message_key_class is None:
        fail(errors, "API i18n implementation is missing MessageKey")
        return
    message_keys = {
        node.value.value
        for node in message_key_class.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    }
    if not message_keys:
        fail(errors, "MessageKey must contain a closed set of string keys")
        return

    catalogs: dict[str, dict[str, object]] = {}
    for label in ("Chinese catalog", "English catalog"):
        try:
            raw_catalog = json.loads(paths[label].read_text(encoding="utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            fail(errors, f"{label} is not valid UTF-8 JSON: {exc}")
            continue
        if not isinstance(raw_catalog, dict):
            fail(errors, f"{label} must be a JSON object")
            continue
        catalogs[label] = raw_catalog
        if set(raw_catalog) != message_keys:
            fail(errors, f"{label} keys do not exactly match MessageKey")
        for key, value in raw_catalog.items():
            if (
                not isinstance(key, str)
                or not isinstance(value, str)
                or value != value.strip()
                or not value
                or len(value) > 200
                or any(ord(character) < 32 for character in value)
            ):
                fail(errors, f"{label} contains an unsafe value for {key!r}")

    implementation = paths["implementation"].read_text(encoding="utf-8")
    for marker in (
        'DEFAULT_LOCALE = "zh-CN"',
        'SUPPORTED_LOCALES = ("zh-CN", "en")',
        "_MAX_ACCEPT_LANGUAGE_LENGTH",
        "_MAX_LANGUAGE_RANGES",
        "_match_specificity",
        "def validation_field",
        "request.state.locale",
        'headers["Content-Language"]',
        'headers["Vary"]',
        "CATALOGS[locale][key.value]",
    ):
        if marker not in implementation:
            fail(errors, f"API i18n implementation is missing {marker!r}")

    required_code_markers = {
        "contract": (
            "message_key: MessageKey",
            "translate(request, message_key)",
            "apply_language_headers(localized_headers, locale_for_request(request))",
        ),
        "application": (
            "request.state.locale = locale_for_request(request)",
            "apply_language_headers(response_headers, request.state.locale)",
            "field=validation_field(error)",
            "message=validation_message(request, error)",
        ),
        "errors": ("message_key: MessageKey", "self.message_key = message_key"),
        "pyproject": ('app = ["locales/*.json"]',),
        "tests": (
            "test_catalogs_are_complete_bounded_and_safe",
            "test_accept_language_negotiation",
            "test_untrusted_language_values_never_escape_supported_locales",
            "test_concurrent_requests_do_not_share_locale",
            "test_validation_outer_and_field_messages_are_localized",
            "test_validation_fields_do_not_echo_untrusted_keys",
            "test_unhandled_500_keeps_language_headers",
            '"zh-CN;q=0, *;q=1"',
            '"zh-CN;q=0, zh;q=1"',
        ),
    }
    for label, markers in required_code_markers.items():
        content = paths[label].read_text(encoding="utf-8")
        for marker in markers:
            if marker not in content:
                fail(errors, f"{label} is missing API i18n marker {marker!r}")

    for source_path in sorted((ASSET_ROOT / "app").rglob("*.py")):
        source = source_path.read_text(encoding="utf-8")
        relative = source_path.relative_to(REPO_ROOT)
        if "public_message" in source:
            fail(errors, f"{relative} stores rendered public_message instead of a key")
        if source_path.name != "i18n.py" and re.search(r"[\u4e00-\u9fff]", source):
            fail(
                errors,
                f"{relative} contains rendered Chinese API text outside catalogs",
            )
        tree = _parse_python(errors, source_path, label=str(relative))
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            call_name = (
                node.func.id
                if isinstance(node.func, ast.Name)
                else node.func.attr
                if isinstance(node.func, ast.Attribute)
                else None
            )
            keyword_names = {keyword.arg for keyword in node.keywords}
            if call_name in {"api_response", "error_content"}:
                if "message" in keyword_names or "message_key" not in keyword_names:
                    fail(errors, f"{relative} has a response call without message_key")
            if call_name == "RbacError" and (
                "public_message" in keyword_names or "message_key" not in keyword_names
            ):
                fail(errors, f"{relative} constructs RbacError without message_key")


def validate_api_response_contract(errors: list[str]) -> None:
    paths = {
        "entrypoint": SKILL_ROOT / "SKILL.md",
        "reference": SKILL_ROOT / "references" / "api-response-standard.md",
        "contract": ASSET_ROOT / "app" / "api_contract.py",
        "application": ASSET_ROOT / "app" / "main.py",
        "routes": ASSET_ROOT / "app" / "rbac" / "api.py",
        "errors": ASSET_ROOT / "app" / "rbac" / "errors.py",
        "schemas": ASSET_ROOT / "app" / "rbac" / "schemas.py",
        "service": ASSET_ROOT / "app" / "rbac" / "service.py",
        "proxy backend": SKILL_ROOT / "references" / "proxy-availability-backend.md",
        "proxy frontend": SKILL_ROOT / "references" / "proxy-availability-frontend.md",
    }
    if any(not path.is_file() for path in paths.values()):
        return

    required_markers = {
        "entrypoint": (
            "references/api-response-standard.md",
            "`code`, `message`, `data`",
            "`expected_version`",
            "`409002`",
        ),
        "reference": (
            "`items`, `page`, `page_size`, and `total`",
            "server-generated UUIDv4",
            "Resource Version Instead Of A Strong Envelope ETag",
        ),
        "contract": (
            "class BusinessCode(IntEnum):",
            "STALE_RESOURCE_VERSION = 409002",
            "class ApiResponse[T](BaseModel):",
            "class PageData[T](BaseModel):",
            'ConfigDict(extra="forbid", frozen=True)',
            "code: int = Field(strict=True",
            "request_id: UUID4",
            "class RequestIdRoute(APIRoute):",
        ),
        "application": (
            "request.state.request_id = str(uuid.uuid4())",
            'response_headers["X-Request-ID"]',
            "handle_request_validation_error",
            "handle_unexpected_error",
            "handle_database_unavailable",
            'headers.setdefault("WWW-Authenticate", "Bearer")',
            "500: (BusinessCode.INTERNAL_ERROR",
        ),
        "routes": (
            "route_class=RequestIdRoute",
            "response_model=ApiResponse[PageData[PermissionResponse]]",
            "response_model=ApiResponse[PageData[RoleResponse]]",
            "response_model=ApiResponse[PageData[UserResponse]]",
            "expected_version=body.expected_version",
        ),
        "errors": (
            "status_code=status.HTTP_400_BAD_REQUEST",
            "business_code=BusinessCode.BAD_REQUEST",
        ),
        "schemas": ("expected_version: int = Field(strict=True, ge=0)",),
        "service": (
            "_require_expected_role_version",
            "decide_role_permissions_change",
        ),
        "proxy backend": ("business code `503002`",),
        "proxy frontend": ("business code\n`503002`",),
    }
    for name, markers in required_markers.items():
        content = paths[name].read_text(encoding="utf-8")
        for marker in markers:
            if marker not in content:
                relative = paths[name].relative_to(REPO_ROOT)
                fail(errors, f"{relative} is missing API contract marker: {marker!r}")

    route_text = paths["routes"].read_text(encoding="utf-8")
    for stale_marker in ("IfMatchHeader", 'response.headers["ETag"]'):
        if stale_marker in route_text:
            relative = paths["routes"].relative_to(REPO_ROOT)
            fail(errors, f"{relative} contains stale API contract: {stale_marker!r}")

    schema_text = paths["schemas"].read_text(encoding="utf-8")
    strict_version_marker = "expected_version: int = Field(strict=True, ge=0)"
    if schema_text.count(strict_version_marker) != 3:
        fail(errors, "all three role version request fields must be strict integers")

    service_text = paths["service"].read_text(encoding="utf-8")
    policy_markers = {
        "update_role": "_require_role_administration",
        "set_role_active": "_require_role_administration",
        "soft_delete_role": "_require_role_administration",
        "change_role_permissions": "decide_role_permissions_change",
    }
    for method_name, policy_marker in policy_markers.items():
        start = service_text.find(f"    async def {method_name}(")
        end = service_text.find("\n    async def ", start + 1)
        method_text = service_text[start : end if end >= 0 else None]
        policy_position = method_text.find(policy_marker)
        version_position = method_text.find("_require_expected_role_version")
        if (
            start < 0
            or policy_position < 0
            or version_position < 0
            or policy_position > version_position
        ):
            fail(
                errors,
                f"{method_name} must authorize the locked proposal before "
                "checking expected_version",
            )

    for name in ("proxy backend", "proxy frontend"):
        if "availability_cache_available" in paths[name].read_text(encoding="utf-8"):
            relative = paths[name].relative_to(REPO_ROOT)
            fail(errors, f"{relative} contains an invalid fifth envelope flag")


def validate_observability_and_audit(errors: list[str]) -> None:
    paths = {
        "entrypoint": SKILL_ROOT / "SKILL.md",
        "logging reference": SKILL_ROOT / "references" / "operational-logging.md",
        "audit reference": SKILL_ROOT / "references" / "audit-module.md",
        "logging implementation": ASSET_ROOT / "app" / "observability.py",
        "audit implementation": ASSET_ROOT / "app" / "audit.py",
        "application": ASSET_ROOT / "app" / "main.py",
        "database": ASSET_ROOT / "app" / "database.py",
        "settings": ASSET_ROOT / "app" / "settings.py",
        "model": ASSET_ROOT / "app" / "rbac" / "models.py",
        "migration": ASSET_ROOT
        / "alembic"
        / "versions"
        / "0001_single_project_rbac.py",
        "bootstrap": ASSET_ROOT / "sql" / "bootstrap_super_admin.sql",
        "logging tests": ASSET_ROOT / "tests" / "test_observability.py",
        "logging formatter tests": ASSET_ROOT
        / "tests"
        / "test_observability_formatter.py",
        "request logging tests": ASSET_ROOT / "tests" / "test_request_observability.py",
        "audit tests": ASSET_ROOT / "tests" / "test_audit.py",
        "database tests": ASSET_ROOT
        / "tests"
        / "integration"
        / "test_rbac_constraints.py",
    }
    if any(not path.is_file() for path in paths.values()):
        return

    require_semantics(
        errors,
        path=paths["entrypoint"],
        checks=(
            (
                "entrypoint routes logging and RBAC audit work to their references",
                (r"references/operational-logging\.md.*references/audit-module\.md",),
            ),
            (
                "operational request logging has one canonical completion event",
                (r"Emit one-line structured operational logs",),
            ),
            (
                "RBAC and business audits are server-owned append-only evidence",
                (r"Audits are server-owned and append-only",),
            ),
        ),
    )
    required_markers = {
        "logging reference": (
            "## Non-Negotiable Boundary",
            "## Request Completion Contract",
            "## Safe Exception Telemetry",
            "## Formatter And Emitter Safety",
            "## Forbidden Data",
            "## Required Verification",
            "http.request.completed",
            "http.request.post_response_failed",
            "background.task.failed",
        ),
        "audit reference": (
            "## `rbac_audit_events` Schema",
            "## Transaction Outcomes",
            "## Integrity And Database Access",
            "## Retention, Partitioning, And Recovery",
            "## Verification",
        ),
        "logging implementation": (
            "class SafeJsonFormatter(logging.Formatter):",
            "def bind_request_context(",
            "def deactivate_request_context(",
            "def reset_request_context(",
            "def request_log_level(",
            "def safe_exception_metadata(",
            "def safe_log(",
            "def create_detached_task",
            "def configure_logging(",
            '"uvicorn.access"',
            "third_party_logger.disabled = True",
        ),
        "audit implementation": (
            "class AuditSource(StrEnum):",
            "def sanitize_audit_state(",
            "def validate_audit_action(",
            "def validate_audit_reason(",
            "def validate_audit_request_id(",
        ),
        "application": (
            "configure_logging(",
            "bind_request_context(",
            "reset_request_context(",
            '"http.request.completed"',
            '"business_code"',
            '"duration_ms"',
            '"response_started"',
            '"response_completed"',
            '"client_disconnected"',
            '"http.request.post_response_failed"',
        ),
        "database": ("hide_parameters=True",),
        "settings": (
            "service_name: str",
            "service_version: str",
            "log_level: str",
            "log_include_exception_details: bool",
        ),
        "model": (
            "source IN ('http', 'service', 'job', 'operator', 'migration')",
            'CheckConstraint("schema_version = 1"',
            'Index("ix_rbac_audit_created_id"',
            '@validates("before_state", "after_state")',
        ),
        "migration": (
            "CREATE FUNCTION reject_rbac_audit_event_mutation()",
            "CREATE TRIGGER trg_rbac_audit_events_append_only",
            "BEFORE UPDATE OR DELETE ON rbac_audit_events",
            '"ix_rbac_audit_created_id"',
        ),
        "bootstrap": ("'operator'",),
        "logging tests": (
            "test_json_log_contains_stable_context_and_redacts_nested_secrets",
            "test_request_completion_log_uses_response_request_id",
        ),
        "logging formatter tests": (
            "test_safe_exception_metadata_is_unique_and_omits_message_and_locals",
            "test_detached_task_clears_request_context_and_reports_failure",
        ),
        "request logging tests": (
            "test_stream_failure_emits_one_error_completion_with_started_status",
            "test_multichunk_stream_emits_one_successful_completion",
            "test_send_failure_records_the_observed_response_boundary",
            "test_client_disconnect_without_response_is_recorded",
        ),
        "audit tests": (
            "test_audit_state_rejects_credentials_tokens_and_direct_identifiers",
        ),
        "database tests": ("test_rbac_audit_rows_are_append_only",),
    }
    for name, markers in required_markers.items():
        content = paths[name].read_text(encoding="utf-8")
        for marker in markers:
            if marker not in content:
                relative = paths[name].relative_to(REPO_ROOT)
                fail(
                    errors,
                    f"{relative} is missing observability/audit marker: {marker!r}",
                )


def validate_business_audit(errors: list[str]) -> None:
    paths = {
        "entrypoint": SKILL_ROOT / "SKILL.md",
        "policy reference": SKILL_ROOT / "references" / "business-audit-module.md",
        "postgresql reference": SKILL_ROOT
        / "references"
        / "business-audit-postgresql.md",
        "operations reference": SKILL_ROOT
        / "references"
        / "business-audit-operations.md",
        "implementation": ASSET_ROOT / "app" / "business_audit.py",
        "migration": ASSET_ROOT / "alembic" / "versions" / "0003_business_audit.py",
        "alembic environment": ASSET_ROOT / "alembic" / "env.py",
        "unit tests": ASSET_ROOT / "tests" / "test_business_audit.py",
        "database tests": ASSET_ROOT
        / "tests"
        / "integration"
        / "test_business_audit.py",
        "database fixtures": ASSET_ROOT / "tests" / "integration" / "conftest.py",
        "test configuration": ASSET_ROOT / "pyproject.toml",
    }
    missing = False
    for name, path in paths.items():
        if not path.is_file():
            relative = path.relative_to(REPO_ROOT)
            fail(errors, f"missing business-audit {name}: {relative}")
            missing = True
    if missing:
        return

    require_semantics(
        errors,
        path=paths["entrypoint"],
        checks=(
            (
                "all three business-audit references are routed by task",
                (
                    r"references/business-audit-module\.md.*references/business-audit-postgresql\.md.*references/business-audit-operations\.md",
                ),
            ),
            (
                "business audit requires an explicit action catalog and allowlisted state",
                (r"explicit action catalog and safe per-action state allowlist",),
            ),
            (
                "successful protected business mutation and audit share a PostgreSQL transaction",
                (r"Successful protected changes commit with their audit",),
            ),
            (
                "business audit outcomes are succeeded, failed, and denied",
                (r"`succeeded`.*`failed`.*`denied`",),
            ),
        ),
    )
    required_markers = {
        "policy reference": (
            "`rbac_audit_events`",
            "business_audit_events",
            "## Core Event Contract",
            "## Outcome Semantics",
            "## Starter Event Catalog",
            "## Trusted Event Construction",
            "## Safe Snapshots And Context",
            "## Transaction Decision Table",
        ),
        "postgresql reference": (
            "CREATE TABLE business_audit_events",
            "ck_business_audit_id_uuid4",
            "BusinessAuditActionSpec",
            "BusinessAuditWriter",
            "action_specs=BUSINESS_AUDIT_CATALOG",
            "actor_type=BusinessAuditActorType.USER",
            "event_id=uuid.uuid4()",
            "event_id=command.audit_event_id",
            "add_succeeded(",
            "add_after_savepoint_rollback(",
            "write_after_rollback(",
            "## Append-Only Controls",
            "BEFORE UPDATE OR DELETE ON business_audit_events",
            "BEFORE TRUNCATE ON business_audit_events",
        ),
        "operations reference": (
            "append-only source of truth",
            "## Read And Export Access",
            "## Retention And Partitioning",
            "## Legal Hold And Privacy",
            "## Backup And Recovery",
        ),
        "implementation": (
            "class BusinessAuditOutcome(StrEnum):",
            "class BusinessAuditActorType(StrEnum):",
            "class BusinessAuditActionSpec:",
            "class BusinessAuditFacts:",
            "class BusinessAuditEvent(Base):",
            '__tablename__ = "business_audit_events"',
            'name=conv("ck_business_audit_id_uuid4")',
            'name=conv("ck_business_audit_actor_presence")',
            'name=conv("ck_business_audit_non_success_after")',
            "class BusinessAuditWriter:",
            "def add_succeeded(",
            "def add_after_savepoint_rollback(",
            "async def write_after_rollback(",
            "if not session.in_transaction():",
            "async with self._session_factory() as session:",
        ),
        "migration": (
            'revision: str = "0003_business_audit"',
            'down_revision: str | None = "0002_system_roles"',
            '"business_audit_events"',
            'name=op.f("ck_business_audit_id_uuid4")',
            'name=op.f("ck_business_audit_outcome")',
            'name=op.f("ck_business_audit_actor_presence")',
            'name=op.f("ck_business_audit_non_success_after")',
            "CREATE FUNCTION reject_business_audit_mutation()",
            "CREATE TRIGGER trg_business_audit_no_update_delete",
            "BEFORE UPDATE OR DELETE ON business_audit_events",
            "CREATE TRIGGER trg_business_audit_no_truncate",
            "BEFORE TRUNCATE ON business_audit_events",
        ),
        "alembic environment": (
            "from app import business_audit as business_audit_models",
            "target_metadata = Base.metadata",
        ),
        "unit tests": (
            "test_writer_builds_catalog_owned_event_shape",
            "test_writer_rejects_non_allowlisted_or_sensitive_snapshots",
            "test_writer_rejects_nested_email_and_network_values",
            "test_non_success_event_cannot_claim_after_state",
            "test_successful_event_requires_caller_owned_transaction",
            "test_savepoint_event_requires_finished_nested_rollback",
            "test_string_success_cannot_use_after_rollback_writer",
        ),
        "database tests": (
            "pytestmark = pytest.mark.postgresql",
            "test_successful_business_mutation_and_audit_commit_together",
            "test_unsafe_required_audit_rolls_back_business_mutation",
            "test_non_success_is_written_only_after_business_rollback",
            "test_required_denial_commits_after_nested_savepoint_rollback",
            "test_business_audit_rows_are_append_only",
            "test_database_rejects_invalid_raw_business_audit_events",
            "TRUNCATE TABLE business_audit_events",
        ),
        "database fixtures": (
            "pytestmark = pytest.mark.postgresql",
            "DISABLE TRIGGER",
            "trg_business_audit_no_truncate",
            "TRUNCATE TABLE business_audit_events",
        ),
        "test configuration": (
            "[tool.pytest.ini_options]",
            '"postgresql: requires the PostgreSQL and Redis services',
        ),
    }
    text = {name: path.read_text(encoding="utf-8") for name, path in paths.items()}
    for name, markers in required_markers.items():
        for marker in markers:
            if marker not in text[name]:
                relative = paths[name].relative_to(REPO_ROOT)
                fail(
                    errors,
                    f"{relative} is missing business-audit marker: {marker!r}",
                )

    removed_delivery_markers = (
        "## Optional Delivery Outbox",
        "build_business_outbox_rows(",
        "lease_token",
        "lease_expires_at",
        "lost the lease",
    )
    for name in (
        "entrypoint",
        "policy reference",
        "postgresql reference",
        "operations reference",
    ):
        for marker in removed_delivery_markers:
            if marker in text[name]:
                relative = paths[name].relative_to(REPO_ROOT)
                fail(
                    errors,
                    f"{relative} reintroduces the removed business-audit "
                    f"delivery subsystem: {marker!r}",
                )

    for name in ("implementation", "migration", "alembic environment"):
        if "business_audit_delivery_outbox" in text[name]:
            relative = paths[name].relative_to(REPO_ROOT)
            fail(
                errors,
                f"{relative} implements the removed business-audit delivery table",
            )

    if (
        "Never put business activity into `rbac_audit_events`"
        not in text["policy reference"]
    ):
        fail(errors, "business and RBAC audit event catalogs must remain separate")

    outcome_values = ("succeeded", "failed", "denied")
    for name in ("policy reference", "implementation", "migration"):
        for outcome in outcome_values:
            if outcome not in text[name]:
                relative = paths[name].relative_to(REPO_ROOT)
                fail(errors, f"{relative} is missing business-audit outcome: {outcome}")


def validate_country_catalog(errors: list[str]) -> None:
    paths = {
        "entrypoint": SKILL_ROOT / "SKILL.md",
        "contract": SKILL_ROOT / "references" / "country-catalog.md",
        "implementation": SKILL_ROOT / "references" / "country-catalog-postgresql.md",
        "validator": SKILL_ROOT / "scripts" / "validate_country_csv.py",
        "validator tests": SKILL_ROOT / "scripts" / "test_validate_country_csv.py",
        "readme": REPO_ROOT / "README.md",
        "Chinese readme": REPO_ROOT / "README.zh-CN.md",
        "changelog": REPO_ROOT / "CHANGELOG.md",
        "Chinese changelog": REPO_ROOT / "CHANGELOG.zh-CN.md",
        "release checklist": REPO_ROOT / "RELEASE_CHECKLIST.md",
        "Chinese release checklist": REPO_ROOT / "RELEASE_CHECKLIST.zh-CN.md",
        "CI": REPO_ROOT / ".github" / "workflows" / "ci.yml",
    }
    if any(not path.is_file() for path in paths.values()):
        return

    text = {name: path.read_text(encoding="utf-8") for name, path in paths.items()}
    require_semantics(
        errors,
        path=paths["entrypoint"],
        checks=(
            (
                "country policy and PostgreSQL implementation are routed only on explicit request",
                (
                    r"Explicitly requested country/region directory.*references/country-catalog\.md.*references/country-catalog-postgresql\.md",
                ),
            ),
            (
                "the default PostgreSQL asset does not create or seed country data",
                (r"default country data", r"country .* optional additions"),
            ),
        ),
    )
    required_markers = {
        "contract": (
            "This module is optional",
            "country_code,calling_code,name_zh,name_en,flag_url",
            "calling_code` is a string",
            "It is not unique.",
            "Every ordinary runtime removal sets `is_active=false` and `deleted_at`",
            "Never reactivate a disabled row, restore a deleted row",
            "Do not put a source data file into a public Skill",
            "python -B scripts/validate_country_csv.py",
            "Formal import with any non-empty `flag_url` requires",
            "approved ASCII DNS hostnames",
            "`--structure-only` is never import approval",
            "`membership_checked=false`",
        ),
        "implementation": (
            '__tablename__ = "countries"',
            "pg_advisory_xact_lock",
            "on_conflict_do_update",
            "Country.deleted_at.is_not(None)",
            "Country.version + 1",
            "The import intentionally does not update `is_active`",
            "Do not mount a write or import",
        ),
        "validator": (
            "EXPECTED_HEADER",
            "MAX_CSV_BYTES",
            "MAX_DATA_ROWS",
            "MAX_EXPECTED_CODES_BYTES",
            "_read_bounded_bytes",
            "handle.read(limit + 1)",
            'raw_source.decode("utf-8-sig", errors="strict")',
            "expected_codes",
            "structure_only",
            "_normalize_dns_hostname",
            "allowed_flag_hosts",
            "non-empty flag URLs require an approved allowed_flag_hosts set",
            "structure-only result is not import approval",
            "membership_checked=expected_codes is not None and not structure_only",
            "CSV must contain at least one data row",
            "shared_calling_codes",
            "calling_code must not be unique",
            'payload["valid"]',
            "parsed.username is not None",
            "parsed.password is not None",
            "or parsed.fragment",
        ),
        "validator tests": (
            "test_valid_csv_accepts_shared_calling_codes_and_utf8_bom",
            "test_header_only_csv_is_rejected",
            "test_expected_code_set_is_required_unless_structure_only_is_explicit",
            "test_file_size_limit_is_enforced_before_csv_parsing",
            "test_data_row_limit_is_enforced",
            "test_expected_code_manifest_size_limit_is_enforced",
            "test_expected_code_manifest_detects_missing_and_unexpected_codes",
            "test_invalid_ascii_dns_hostnames_are_rejected",
            "test_flag_host_allowlist_matching_is_case_insensitive",
            "test_control_characters_are_rejected",
            "test_unsafe_flag_url_is_rejected",
            "test_import_ready_flag_urls_require_an_approved_host",
            "test_cli_json_includes_valid_and_membership_status",
            "test_cli_validation_failure_returns_one_and_json_report",
            "test_cli_requires_an_authoritative_or_structure_only_mode",
        ),
        "readme": (
            "country catalog guide",
            "The country dataset is not bundled.",
        ),
        "Chinese readme": (
            "国家目录",
            "仓库不捆绑第三方国家数据集",
        ),
        "changelog": (
            "Release validation rejects bundled CSV/TSV country",
            "ASCII DNS",
            "`membership_checked=false`",
        ),
        "Chinese changelog": (
            "发布校验会",
            "CSV/TSV 国家数据",
            "ASCII DNS",
            "`membership_checked=false`",
        ),
        "release checklist": (
            "country catalog remains opt-in",
            "source CSV/TSV or flag asset",
            "ASCII DNS",
            "`membership_checked=false`",
        ),
        "Chinese release checklist": (
            "国家目录保持按需启用",
            "CSV/TSV 或旗帜资产",
            "ASCII DNS",
            "`membership_checked=false`",
        ),
        "CI": (
            "python -B skills/fastapi-templates-xtn/scripts/test_validate_country_csv.py",
            "python -B scripts/validate_release.py",
            'python -B -m pytest -p no:cacheprovider -m "not postgresql"',
            "python -B -m pytest -p no:cacheprovider -m postgresql",
            'test "$(alembic heads)" = "0004_password_auth (head)"',
        ),
    }
    for name, markers in required_markers.items():
        for marker in markers:
            if marker not in text[name]:
                relative = paths[name].relative_to(REPO_ROOT)
                fail(
                    errors,
                    f"{relative} is missing country-catalog marker: {marker!r}",
                )

    python_command_re = re.compile(r"^\s*(?:run:\s*)?python\s+(?!-B(?:\s|$))")
    for name in (
        "contract",
        "implementation",
        "readme",
        "Chinese readme",
        "release checklist",
        "Chinese release checklist",
        "CI",
    ):
        if any(python_command_re.match(line) for line in text[name].splitlines()):
            relative = paths[name].relative_to(REPO_ROOT)
            fail(
                errors,
                f"{relative} contains a Python command that does not use python -B",
            )

    if any(
        re.match(r"^\s*run:\s*pytest(?:\s|$)", line) for line in text["CI"].splitlines()
    ):
        fail(errors, "CI contains a bare pytest invocation")


def validate_ci_and_current_documentation(errors: list[str]) -> None:
    ci_path = REPO_ROOT / ".github" / "workflows" / "ci.yml"
    pyproject_path = ASSET_ROOT / "pyproject.toml"
    limiter_path = ASSET_ROOT / "app" / "rate_limit_dependencies.py"
    limiter_tests_path = ASSET_ROOT / "tests" / "test_rate_limit_dependencies.py"
    openai_path = SKILL_ROOT / "agents" / "openai.yaml"
    if any(
        not path.is_file()
        for path in (
            ci_path,
            pyproject_path,
            limiter_path,
            limiter_tests_path,
            openai_path,
        )
    ):
        return

    ci = ci_path.read_text(encoding="utf-8")
    action_pins = {
        "actions/checkout": "11d5960a326750d5838078e36cf38b85af677262",
        "actions/setup-python": "a26af69be951a213d495a4c3e4e4022e16d87065",
    }
    for action, commit in action_pins.items():
        references = re.findall(rf"uses:\s*{re.escape(action)}@([^\s#]+)", ci)
        if not references or any(reference != commit for reference in references):
            fail(errors, f"CI must pin every {action} use to full commit {commit}")

    for command in (
        'python -B -m pip install --upgrade "pip>=26.2"',
        "ruff format --check --no-cache .",
        "ruff check --no-cache .",
        "mypy app tests",
        "pip-audit --local --skip-editable --progress-spinner off",
    ):
        if command not in ci:
            fail(errors, f"CI is missing required quality command: {command}")

    pyproject = pyproject_path.read_text(encoding="utf-8")
    if '"pip-audit>=2.7,<3"' not in pyproject:
        fail(errors, "asset test dependencies must include bounded pip-audit")
    if '"pytest>=9.0.3,<10"' not in pyproject:
        fail(
            errors, "asset test dependencies must require the fixed pytest release line"
        )
    if '"pytest-asyncio>=1.4,<2"' not in pyproject:
        fail(
            errors,
            "asset test dependencies must use a pytest-asyncio line compatible with pytest 9",
        )

    limiter = limiter_path.read_text(encoding="utf-8")
    limiter_tests = limiter_tests_path.read_text(encoding="utf-8")
    for marker in (
        "AUTHENTICATED_RATE_LIMIT_RULES",
        "AUTHENTICATED_RATE_LIMIT_EXEMPT_OPERATIONS",
    ):
        if marker not in limiter:
            fail(errors, f"authenticated route policy mapping is missing {marker!r}")
    if not re.search(
        r'"revoke_user_sessions"\s*:\s*\(\s*"POST"\s*,\s*"authorization_write"',
        limiter,
    ):
        fail(errors, "revoke_user_sessions must use the authorization-write quota")
    if "test_every_registered_operation_has_an_explicit_admission_class" not in (
        limiter_tests
    ):
        fail(errors, "route policy tests must enumerate every registered operation")

    openai = openai_path.read_text(encoding="utf-8")
    for marker in (
        "all five required graphical CAPTCHA flows",
        "do not implement anonymous password recovery",
        "email/SMS verification or MFA only when explicitly requested",
    ):
        if marker not in openai:
            fail(errors, f"agents/openai.yaml is missing current behavior: {marker!r}")
    for stale in ("optional verification", "authentication and recovery"):
        if stale in openai.casefold():
            fail(errors, f"agents/openai.yaml retains stale wording: {stale!r}")

    active_references = (
        SKILL_ROOT / "references" / "jwt-session-security.md",
        SKILL_ROOT / "references" / "jwt-session-implementation.md",
        SKILL_ROOT / "references" / "postgresql-rbac-implementation.md",
    )
    stale_patterns = (
        re.compile(r"\bUnreleased\b", re.IGNORECASE),
        re.compile(
            r"(?:login|token issuance).{0,80}(?:not wired|not implemented)",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?:尚未|仍未).{0,30}(?:接入|实现).{0,30}(?:登录|Token)",
            re.IGNORECASE,
        ),
    )
    for path in active_references:
        content = path.read_text(encoding="utf-8")
        for pattern in stale_patterns:
            if pattern.search(content):
                fail(
                    errors,
                    f"{path.relative_to(REPO_ROOT)} retains stale release-state wording",
                )

    readme_requirements = {
        "README.md": (
            "references/architecture-overview.zh-CN.md",
            "Python 3.12",
            "PostgreSQL 17",
            "Redis 7",
            "/health/live",
            "/health/ready",
            "ruff format --check --no-cache",
            "pip-audit --local --skip-editable --progress-spinner off",
        ),
        "README.zh-CN.md": (
            "references/architecture-overview.zh-CN.md",
            "Python 3.12",
            "PostgreSQL 17",
            "Redis 7",
            "/health/live",
            "/health/ready",
            "ruff format --check --no-cache",
            "pip-audit --local --skip-editable --progress-spinner off",
        ),
    }
    for readme_name, markers in readme_requirements.items():
        readme_path = REPO_ROOT / readme_name
        if not readme_path.is_file():
            continue
        readme = readme_path.read_text(encoding="utf-8")
        for marker in markers:
            if marker not in readme:
                fail(
                    errors, f"{readme_name} is missing current documentation: {marker}"
                )

    security_requirements = {
        "SECURITY.md": (
            "pip-audit",
            "--ignore-vuln",
            "vulnerability identifier",
            "impact",
            "reason",
            "responsible owner",
            "review date",
        ),
        "SECURITY.zh-CN.md": (
            "pip-audit",
            "--ignore-vuln",
            "漏洞编号",
            "影响",
            "原因",
            "负责人",
            "复查日期",
        ),
    }
    for security_name, markers in security_requirements.items():
        security_path = REPO_ROOT / security_name
        if not security_path.is_file():
            continue
        security = security_path.read_text(encoding="utf-8")
        for marker in markers:
            if marker not in security:
                fail(
                    errors,
                    f"{security_name} is missing audit-exception field: {marker}",
                )

    old_design_path = REPO_ROOT / "DESIGN_REVIEW.zh-CN.md"
    archived_design_path = (
        REPO_ROOT / "docs" / "history" / "v0.4.0" / "DESIGN_REVIEW.zh-CN.md"
    )
    if old_design_path.exists():
        fail(errors, "the v0.4.0 design review must not remain at the repository root")
    if archived_design_path.is_file():
        archived_design = archived_design_path.read_text(encoding="utf-8")
        if not re.search(
            r"^# .*v0\.4\.0.*不代表当前实现", archived_design, re.MULTILINE
        ):
            fail(errors, "the archived v0.4.0 design review lacks a historical warning")


def validate_tree_hygiene(errors: list[str]) -> None:
    for path in REPO_ROOT.rglob("*"):
        if ".git" in path.parts:
            continue
        forbidden_directory = next(
            (
                part
                for part in path.parts
                if part in FORBIDDEN_DIRECTORY_NAMES
                or part.endswith(FORBIDDEN_DIRECTORY_SUFFIXES)
            ),
            None,
        )
        if forbidden_directory is not None:
            if path.name == forbidden_directory:
                fail(
                    errors,
                    f"release package contains generated directory: "
                    f"{path.relative_to(REPO_ROOT)}",
                )
            continue
        if path.is_symlink():
            fail(
                errors,
                f"release package contains a symlink: {path.relative_to(REPO_ROOT)}",
            )
        if not path.is_file():
            continue
        try:
            skill_relative = path.relative_to(SKILL_ROOT)
        except ValueError:
            skill_relative = None

        suffix = path.suffix.lower()
        top_level = ""
        path_has_country_or_flag_hint = False
        if skill_relative is not None:
            top_level = skill_relative.parts[0].casefold()
            path_has_country_or_flag_hint = any(
                COUNTRY_OR_FLAG_PATH_RE.search(part) is not None
                for part in skill_relative.parts
            )

        if (
            skill_relative is not None
            and suffix in FORBIDDEN_SKILL_TABULAR_SUFFIXES
            and (top_level in {"data", "datasets"} or path_has_country_or_flag_hint)
        ):
            fail(
                errors,
                "distributable Skill contains a potential bundled country CSV/TSV "
                f"dataset: {path.relative_to(REPO_ROOT)}",
            )

        if skill_relative is not None and suffix in COUNTRY_OR_FLAG_MEDIA_SUFFIXES:
            if top_level in {"data", "datasets", "references", "scripts"} or (
                path_has_country_or_flag_hint
            ):
                fail(
                    errors,
                    "distributable Skill contains a potential bundled country/flag "
                    f"media asset: {path.relative_to(REPO_ROOT)}",
                )
        if (
            path.name in FORBIDDEN_FILE_NAMES
            or path.suffix.lower() in FORBIDDEN_FILE_SUFFIXES
        ):
            fail(
                errors,
                f"release package contains generated data: {path.relative_to(REPO_ROOT)}",
            )
        if path.name == ".env" or (
            path.name.startswith(".env.") and not path.name.endswith(".example")
        ):
            fail(
                errors,
                f"release package contains a real environment file: {path.relative_to(REPO_ROOT)}",
            )

        if path.suffix.lower() in TEXT_SUFFIXES:
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                fail(errors, f"expected UTF-8 text: {path.relative_to(REPO_ROOT)}")
                continue
            if LOCAL_HOME_PATH_RE.search(text):
                fail(errors, f"local home path leaked in {path.relative_to(REPO_ROOT)}")
            if SECRET_MATERIAL_RE.search(text):
                fail(
                    errors, f"secret material detected in {path.relative_to(REPO_ROOT)}"
                )


def main() -> int:
    errors: list[str] = []
    validate_required_files(errors)
    validate_frontmatter(errors)
    validate_identity_and_row_lifecycle(errors)
    validate_links(errors)
    validate_bilingual_docs(errors)
    validate_legal_mirrors(errors)
    validate_release_metadata(errors)
    validate_single_project_scope(errors)
    validate_access_token_baseline(errors)
    validate_local_password_authentication(errors)
    validate_rate_limiting_and_verification(errors)
    validate_simplified_authentication_and_administration(errors)
    validate_user_role_limit(errors)
    validate_administrative_read_visibility(errors)
    validate_super_admin_bootstrap(errors)
    validate_rbac_database_naming(errors)
    validate_api_internationalization(errors)
    validate_api_response_contract(errors)
    validate_observability_and_audit(errors)
    validate_business_audit(errors)
    validate_country_catalog(errors)
    validate_ci_and_current_documentation(errors)
    validate_tree_hygiene(errors)

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print(
            f"Release validation failed with {len(errors)} error(s).", file=sys.stderr
        )
        return 1

    file_count = sum(
        path.is_file() and ".git" not in path.parts for path in REPO_ROOT.rglob("*")
    )
    print(f"Release package is valid: {file_count} files checked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
