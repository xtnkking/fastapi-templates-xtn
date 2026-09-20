#!/usr/bin/env python3
"""Install or update fastapi-templates-xtn with staging and rollback."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import stat
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

SKILL_NAME = "fastapi-templates-xtn"
VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
IGNORED_DIRECTORY_NAMES = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
        "build",
        "dist",
    }
)
IGNORED_FILE_NAMES = frozenset({".coverage"})
IGNORED_FILE_SUFFIXES = (".pyc", ".pyo")


class UpdateError(RuntimeError):
    """Raised when an installation cannot be validated or replaced safely."""


def _absolute_without_resolving(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _is_link_or_reparse_directory(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False

    if stat.S_ISLNK(metadata.st_mode):
        return True
    is_junction = getattr(path, "is_junction", None)
    if is_junction is not None and is_junction():
        return True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)
    attributes = getattr(metadata, "st_file_attributes", 0)
    return stat.S_ISDIR(metadata.st_mode) and bool(attributes & reparse_flag)


def _reject_linked_path_components(path: Path, *, label: str) -> None:
    absolute = _absolute_without_resolving(path)
    for candidate in (absolute, *absolute.parents):
        if _is_link_or_reparse_directory(candidate):
            raise UpdateError(
                f"{label} must not traverse a symbolic link or Windows "
                f"junction/reparse directory: {candidate}"
            )


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _validate_skill_tree(root: Path, *, require_canonical_name: bool = True) -> str:
    if not root.is_dir() or _is_link_or_reparse_directory(root):
        raise UpdateError(f"Skill source must be a real directory: {root}")
    if require_canonical_name and root.name != SKILL_NAME:
        raise UpdateError(f"Skill directory must be named {SKILL_NAME!r}: {root}")

    required = (root / "SKILL.md", root / "VERSION")
    for path in required:
        if not path.is_file() or path.is_symlink():
            raise UpdateError(f"Missing regular file: {path}")

    pending = [root]
    while pending:
        directory = pending.pop()
        for path in directory.iterdir():
            if _is_link_or_reparse_directory(path):
                raise UpdateError(
                    "Symbolic links and Windows junction/reparse directories are "
                    f"not accepted in the Skill: {path}"
                )
            if path.is_dir():
                pending.append(path)
            elif path.is_file() and path.name == ".env":
                raise UpdateError(f"Refusing to install a local .env file: {path}")

    skill_text = (root / "SKILL.md").read_text(encoding="utf-8")
    if not re.search(
        r"\A---\s+.*?^name:\s*fastapi-templates-xtn\s*$.*?^---\s*$",
        skill_text,
        re.DOTALL | re.MULTILINE,
    ):
        raise UpdateError("SKILL.md does not declare name: fastapi-templates-xtn")

    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    if not VERSION_RE.fullmatch(version):
        raise UpdateError(f"VERSION must contain one semantic version, got {version!r}")
    return version


def _installed_tree_matches(
    root: Path,
    *,
    source_version: str,
    source_manifest: dict[str, str],
) -> bool:
    pending = [root]
    while pending:
        directory = pending.pop()
        for path in directory.iterdir():
            if _is_link_or_reparse_directory(path):
                raise UpdateError(
                    "Symbolic links and Windows junction/reparse directories are "
                    f"not accepted in the installed Skill: {path}"
                )
            if path.is_dir():
                pending.append(path)

    version_file = root / "VERSION"
    if not version_file.is_file():
        return False
    installed_version = version_file.read_text(encoding="utf-8").strip()
    return installed_version == source_version and _manifest(root) == source_manifest


def _is_ignored(path: Path, root: Path) -> bool:
    relative = path.relative_to(root)
    return (
        any(
            part in IGNORED_DIRECTORY_NAMES or part.endswith(".egg-info")
            for part in relative.parts[:-1]
        )
        or path.name in IGNORED_FILE_NAMES
        or path.name.endswith(IGNORED_FILE_SUFFIXES)
        or (path.is_dir() and path.name in IGNORED_DIRECTORY_NAMES)
        or (path.is_dir() and path.name.endswith(".egg-info"))
    )


def _manifest(root: Path) -> dict[str, str]:
    manifest: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not _is_ignored(path, root):
            relative = path.relative_to(root).as_posix()
            manifest[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return manifest


def _ignore_copy_artifacts(directory: str, names: list[str]) -> set[str]:
    ignored = set()
    for name in names:
        path = Path(directory) / name
        if (
            name in IGNORED_DIRECTORY_NAMES
            or name.endswith(".egg-info")
            or name in IGNORED_FILE_NAMES
            or name.endswith(IGNORED_FILE_SUFFIXES)
        ):
            ignored.add(name)
        elif path.is_file() and name == ".env":
            ignored.add(name)
    return ignored


def _remove_owned_staging(path: Path, parent: Path) -> None:
    if (
        path.parent != parent
        or not path.name.startswith(f".{SKILL_NAME}.staging-")
        or _is_link_or_reparse_directory(path)
    ):
        raise UpdateError(f"Refusing to remove an unrecognized staging path: {path}")
    if path.exists():
        shutil.rmtree(path)


def update_skill(
    *,
    source: Path,
    target: Path,
    backup_dir: Path | None = None,
    dry_run: bool = False,
) -> Path | None:
    raw_source = _absolute_without_resolving(source)
    raw_target = _absolute_without_resolving(target)
    _reject_linked_path_components(raw_source, label="Source path")
    _reject_linked_path_components(raw_target, label="Target path")

    source = raw_source.resolve(strict=True)
    target = raw_target.resolve(strict=False)
    target_parent = target.parent
    raw_backup_root = (
        _absolute_without_resolving(backup_dir)
        if backup_dir is not None
        else target_parent.parent / "skill-backups"
    )
    _reject_linked_path_components(raw_backup_root, label="Backup path")
    backup_root = raw_backup_root.resolve(strict=False)

    version = _validate_skill_tree(source)
    if target.name != SKILL_NAME:
        raise UpdateError(f"Target directory must be named {SKILL_NAME!r}: {target}")
    if not target_parent.is_dir() or target_parent.is_symlink():
        raise UpdateError(
            f"Target parent must be an existing real directory: {target_parent}"
        )
    if source == target or _is_within(source, target) or _is_within(target, source):
        raise UpdateError(
            "Source and target must be separate, non-overlapping directories"
        )
    if target.exists() and (not target.is_dir() or target.is_symlink()):
        raise UpdateError(f"Existing target must be a real directory: {target}")
    if _is_within(backup_root, target_parent):
        raise UpdateError(
            "Backup directory must be outside the Skill discovery directory"
        )
    if _is_within(backup_root, source) or _is_within(source, backup_root):
        raise UpdateError(
            "Backup directory and Skill source must be separate, "
            "non-overlapping directories"
        )
    if backup_root.exists() and (not backup_root.is_dir() or backup_root.is_symlink()):
        raise UpdateError(f"Backup path must be a real directory: {backup_root}")
    if not backup_root.parent.is_dir() or backup_root.parent.is_symlink():
        raise UpdateError(
            f"Backup parent must be an existing real directory: {backup_root.parent}"
        )
    backup_device_path = backup_root if backup_root.exists() else backup_root.parent
    if os.stat(target_parent).st_dev != os.stat(backup_device_path).st_dev:
        raise UpdateError("Backup and target must be on the same filesystem")

    source_manifest = _manifest(source)
    action = "update" if target.exists() else "install"
    print(f"Validated source version {version}: {source}")
    print(f"Planned {action} target: {target}")
    if target.exists() and _installed_tree_matches(
        target,
        source_version=version,
        source_manifest=source_manifest,
    ):
        print(
            f"Target already contains version {version} with the same manifest; "
            "no files were changed and no backup was created."
        )
        return None
    if target.exists():
        print(f"Planned backup directory: {backup_root}")
    if dry_run:
        print("Dry run complete; no files were changed.")
        return None

    unique = uuid.uuid4().hex[:8]
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    staging = target_parent / f".{SKILL_NAME}.staging-{unique}"
    backup = backup_root / f"{SKILL_NAME}.backup-{timestamp}-{unique}"
    if staging.exists() or backup.exists():
        raise UpdateError(
            "Generated staging or backup path already exists; retry the command"
        )

    try:
        shutil.copytree(
            source,
            staging,
            copy_function=shutil.copy2,
            ignore=_ignore_copy_artifacts,
        )
        staged_version = _validate_skill_tree(staging, require_canonical_name=False)
        if staged_version != version or _manifest(staging) != source_manifest:
            raise UpdateError("Staged copy does not exactly match the validated source")

        if target.exists():
            backup_root.mkdir(exist_ok=True)
            _reject_linked_path_components(backup_root, label="Backup path")
            target.rename(backup)
            try:
                staging.rename(target)
            except BaseException as replacement_error:
                try:
                    backup.rename(target)
                except BaseException as rollback_error:
                    raise UpdateError(
                        "Replacement and automatic rollback both failed. "
                        f"The previous Skill remains at {backup}; inspect the target "
                        "and backup paths before retrying."
                    ) from rollback_error
                raise UpdateError(
                    "Replacement failed; the previous Skill was restored"
                ) from replacement_error
            print(f"Installed version {version}: {target}")
            print(f"Previous installation retained as backup: {backup}")
            return backup

        staging.rename(target)
        print(f"Installed version {version}: {target}")
        print("No previous installation existed, so no backup was created.")
        return None
    finally:
        if staging.exists():
            _remove_owned_staging(staging, target_parent)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Install or update fastapi-templates-xtn after staging and byte-for-byte "
            "validation. Existing installations are retained as timestamped backups."
        )
    )
    parser.add_argument(
        "--source",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "skills" / SKILL_NAME,
        help="validated source Skill directory (defaults to this repository)",
    )
    parser.add_argument(
        "--target",
        type=Path,
        required=True,
        help="exact installed Skill directory; its final name must be fastapi-templates-xtn",
    )
    parser.add_argument(
        "--backup-dir",
        type=Path,
        help=(
            "optional same-filesystem backup directory outside the Skill discovery "
            "directory; defaults to a sibling skill-backups directory"
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate and print resolved paths without changing files",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        update_skill(
            source=args.source,
            target=args.target,
            backup_dir=args.backup_dir,
            dry_run=args.dry_run,
        )
    except (OSError, UnicodeError, UpdateError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
