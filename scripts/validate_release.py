#!/usr/bin/env python3
"""Validate the distributable Skill without external Python dependencies."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path
from urllib.parse import unquote

REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL_ROOT = REPO_ROOT / "skills" / "fastapi-templates-xtn"
ASSET_ROOT = SKILL_ROOT / "assets" / "postgresql-rbac"
EXPECTED_NAME = "fastapi-templates-xtn"
RELEASE_VERSION = "0.1.0"
RELEASE_DATE = "2026-09-05"
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
    "references/proxy-availability-backend.md",
    "references/proxy-availability-detection.md",
    "references/proxy-availability-frontend.md",
    "references/proxy-availability-testing.md",
)
REQUIRED_ASSET_FILES = (
    "LICENSE",
    "NOTICE",
    "THIRD_PARTY_NOTICES.md",
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
TEXT_SUFFIXES = {
    "",
    ".ini",
    ".md",
    ".mako",
    ".py",
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
        fields[key.strip()] = value.strip().strip('"\'')

    if fields.get("name") != EXPECTED_NAME:
        fail(errors, f"SKILL.md name must be {EXPECTED_NAME!r}")
    if not fields.get("description"):
        fail(errors, "SKILL.md description must be non-empty")
    unexpected = set(fields) - {"name", "description", "license", "allowed-tools", "metadata"}
    if unexpected:
        fail(errors, f"SKILL.md has unsupported frontmatter keys: {sorted(unexpected)}")

    proxy_reference = "references/proxy-availability-detection.md"
    if proxy_reference not in content:
        fail(errors, f"SKILL.md does not route to {proxy_reference}")


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
                fail(errors, f"README.md contains pre-release wording: {stale_phrase!r}")

    for changelog_name in ("CHANGELOG.md", "CHANGELOG.zh-CN.md"):
        changelog_path = REPO_ROOT / changelog_name
        if not changelog_path.is_file():
            continue
        changelog = changelog_path.read_text(encoding="utf-8")
        release_heading = f"## [{RELEASE_VERSION}] - {RELEASE_DATE}"
        if release_heading not in changelog:
            fail(errors, f"{changelog_name} is missing release heading: {release_heading}")

    if pyproject_path.is_file():
        pyproject = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
        asset_version = pyproject.get("project", {}).get("version")
        if asset_version != RELEASE_VERSION:
            fail(
                errors,
                "asset pyproject.toml version must match release version "
                f"{RELEASE_VERSION!r}, got {asset_version!r}",
            )


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
            fail(errors, f"release package contains a symlink: {path.relative_to(REPO_ROOT)}")
        if not path.is_file():
            continue
        if path.name in FORBIDDEN_FILE_NAMES or path.suffix.lower() in FORBIDDEN_FILE_SUFFIXES:
            fail(errors, f"release package contains generated data: {path.relative_to(REPO_ROOT)}")
        if path.name == ".env" or (
            path.name.startswith(".env.") and not path.name.endswith(".example")
        ):
            fail(errors, f"release package contains a real environment file: {path.relative_to(REPO_ROOT)}")

        if path.suffix.lower() in TEXT_SUFFIXES:
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                fail(errors, f"expected UTF-8 text: {path.relative_to(REPO_ROOT)}")
                continue
            if LOCAL_HOME_PATH_RE.search(text):
                fail(errors, f"local home path leaked in {path.relative_to(REPO_ROOT)}")
            if SECRET_MATERIAL_RE.search(text):
                fail(errors, f"secret material detected in {path.relative_to(REPO_ROOT)}")


def main() -> int:
    errors: list[str] = []
    validate_required_files(errors)
    validate_frontmatter(errors)
    validate_links(errors)
    validate_bilingual_docs(errors)
    validate_legal_mirrors(errors)
    validate_release_metadata(errors)
    validate_tree_hygiene(errors)

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print(f"Release validation failed with {len(errors)} error(s).", file=sys.stderr)
        return 1

    file_count = sum(
        path.is_file() and ".git" not in path.parts for path in REPO_ROOT.rglob("*")
    )
    print(f"Release package is valid: {file_count} files checked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
