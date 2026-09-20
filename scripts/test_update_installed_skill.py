#!/usr/bin/env python3
"""Focused tests for the staged Skill installer/updater."""

from __future__ import annotations

import importlib.util
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).with_name("update_installed_skill.py")
SPEC = importlib.util.spec_from_file_location("update_installed_skill", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Cannot import {SCRIPT}")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def make_skill(root: Path, version: str, marker: str) -> Path:
    skill = root / MODULE.SKILL_NAME
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        f"---\nname: {MODULE.SKILL_NAME}\ndescription: test\n---\n{marker}\n",
        encoding="utf-8",
    )
    (skill / "VERSION").write_text(f"{version}\n", encoding="utf-8")
    (skill / "marker.txt").write_text(marker, encoding="utf-8")
    return skill


class UpdateInstalledSkillTests(unittest.TestCase):
    def test_fresh_install_uses_staged_exact_copy(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            source = make_skill(base / "source", "0.6.1", "new")
            install_parent = base / "installed"
            install_parent.mkdir()
            target = install_parent / MODULE.SKILL_NAME

            backup = MODULE.update_skill(source=source, target=target)

            self.assertIsNone(backup)
            self.assertEqual(MODULE._manifest(target), MODULE._manifest(source))

    def test_update_retains_complete_backup(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            source = make_skill(base / "source", "0.6.1", "new")
            target = make_skill(base / "installed", "0.6.0", "old")
            old_manifest = MODULE._manifest(target)

            backup = MODULE.update_skill(source=source, target=target)

            self.assertIsNotNone(backup)
            assert backup is not None
            self.assertEqual(backup.parent, target.parent.parent / "skill-backups")
            self.assertEqual(MODULE._manifest(backup), old_manifest)
            self.assertEqual(MODULE._manifest(target), MODULE._manifest(source))

    def test_identical_installation_is_a_no_op_without_backup(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            source = make_skill(base / "source", "0.6.1", "same")
            target = make_skill(base / "installed", "0.6.1", "same")
            generated = target / "__pycache__"
            generated.mkdir()
            (generated / "ignored.pyc").write_bytes(b"ignored")
            before_manifest = MODULE._manifest(target)
            output = io.StringIO()

            with redirect_stdout(output):
                backup = MODULE.update_skill(source=source, target=target)

            self.assertIsNone(backup)
            self.assertEqual(MODULE._manifest(target), before_manifest)
            self.assertFalse((base / "skill-backups").exists())
            self.assertIn("no backup was created", output.getvalue())

    def test_legacy_installation_without_version_can_still_be_updated(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            source = make_skill(base / "source", "0.6.1", "new")
            target = make_skill(base / "installed", "0.6.0", "old")
            (target / "VERSION").unlink()

            backup = MODULE.update_skill(source=source, target=target)

            self.assertIsNotNone(backup)
            self.assertEqual(MODULE._manifest(target), MODULE._manifest(source))

    def test_generated_artifacts_are_not_installed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            source = make_skill(base / "source", "0.6.1", "new")
            cache = source / "nested" / "__pycache__"
            cache.mkdir(parents=True)
            (cache / "module.pyc").write_bytes(b"ignored")
            egg_info = source / "example.egg-info"
            egg_info.mkdir()
            (egg_info / "PKG-INFO").write_text("ignored", encoding="utf-8")
            install_parent = base / "installed"
            install_parent.mkdir()
            target = install_parent / MODULE.SKILL_NAME

            MODULE.update_skill(source=source, target=target)

            self.assertFalse((target / "nested" / "__pycache__").exists())
            self.assertFalse((target / "example.egg-info").exists())

    def test_failed_replacement_restores_previous_installation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            source = make_skill(base / "source", "0.6.1", "new")
            target = make_skill(base / "installed", "0.6.0", "old")
            old_manifest = MODULE._manifest(target)
            real_rename = Path.rename

            def fail_staging_rename(path: Path, destination: Path) -> Path:
                if path.name.startswith(f".{MODULE.SKILL_NAME}.staging-"):
                    raise OSError("injected replacement failure")
                return real_rename(path, destination)

            with mock.patch.object(Path, "rename", new=fail_staging_rename):
                with self.assertRaisesRegex(
                    MODULE.UpdateError, "previous Skill was restored"
                ):
                    MODULE.update_skill(source=source, target=target)

            self.assertEqual(MODULE._manifest(target), old_manifest)
            self.assertEqual(
                list(target.parent.glob(f".{MODULE.SKILL_NAME}.staging-*")), []
            )

    def test_dry_run_changes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            source = make_skill(base / "source", "0.6.1", "new")
            target = make_skill(base / "installed", "0.6.0", "old")
            old_manifest = MODULE._manifest(target)

            backup = MODULE.update_skill(source=source, target=target, dry_run=True)

            self.assertIsNone(backup)
            self.assertEqual(MODULE._manifest(target), old_manifest)
            self.assertEqual(list(target.parent.glob("*.backup-*")), [])

    def test_rejects_overlapping_source_and_target(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            source = make_skill(Path(raw) / "source", "0.6.1", "new")
            with self.assertRaises(MODULE.UpdateError):
                MODULE.update_skill(source=source, target=source)

    def test_rejects_reparse_component_before_resolving_paths(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            source_root = base / "source"
            source = make_skill(source_root, "0.6.1", "new")
            install_parent = base / "installed"
            install_parent.mkdir()
            target = install_parent / MODULE.SKILL_NAME
            backup_dir = base / "backups"
            backup_dir.mkdir()

            for label, flagged_path in (
                ("Source path", source_root),
                ("Target path", install_parent),
                ("Backup path", backup_dir),
            ):
                with self.subTest(label=label):
                    with mock.patch.object(
                        MODULE,
                        "_is_link_or_reparse_directory",
                        side_effect=lambda path, flagged=flagged_path: path == flagged,
                    ):
                        with self.assertRaisesRegex(MODULE.UpdateError, label):
                            MODULE.update_skill(
                                source=source,
                                target=target,
                                backup_dir=backup_dir,
                            )

    def test_refuses_to_remove_reparse_staging_directory(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            staging = parent / f".{MODULE.SKILL_NAME}.staging-test"
            staging.mkdir()

            with mock.patch.object(
                MODULE,
                "_is_link_or_reparse_directory",
                return_value=True,
            ):
                with self.assertRaisesRegex(MODULE.UpdateError, "unrecognized staging"):
                    MODULE._remove_owned_staging(staging, parent)

            self.assertTrue(staging.exists())

    def test_rejects_backup_inside_skill_discovery_directory(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            source = make_skill(base / "source", "0.6.1", "new")
            install_parent = base / "installed"
            install_parent.mkdir()
            target = install_parent / MODULE.SKILL_NAME
            backup_dir = install_parent / "backups"

            with self.assertRaisesRegex(
                MODULE.UpdateError, "outside the Skill discovery directory"
            ):
                MODULE.update_skill(
                    source=source,
                    target=target,
                    backup_dir=backup_dir,
                )

    def test_rejects_backup_overlapping_source_in_either_direction(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            source_root = base / "source"
            source = make_skill(source_root, "0.6.1", "new")
            nested_backup = source / "backups"
            nested_backup.mkdir()
            install_parent = base / "installed"
            install_parent.mkdir()
            target = install_parent / MODULE.SKILL_NAME

            for backup_dir in (nested_backup, source_root):
                with self.subTest(backup_dir=backup_dir):
                    with self.assertRaisesRegex(
                        MODULE.UpdateError, "source must be separate"
                    ):
                        MODULE.update_skill(
                            source=source,
                            target=target,
                            backup_dir=backup_dir,
                        )

    def test_double_failure_message_does_not_promise_staging_is_retained(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            source = make_skill(base / "source", "0.6.1", "new")
            target = make_skill(base / "installed", "0.6.0", "old")
            real_rename = Path.rename

            def fail_replacement_and_rollback(path: Path, destination: Path) -> Path:
                if path.name.startswith(f".{MODULE.SKILL_NAME}.staging-"):
                    raise OSError("injected replacement failure")
                if path.name.startswith(f"{MODULE.SKILL_NAME}.backup-"):
                    raise OSError("injected rollback failure")
                return real_rename(path, destination)

            with mock.patch.object(
                Path,
                "rename",
                new=fail_replacement_and_rollback,
            ):
                with self.assertRaisesRegex(
                    MODULE.UpdateError,
                    "inspect the target and backup paths",
                ) as raised:
                    MODULE.update_skill(source=source, target=target)

            self.assertNotIn("staging remains", str(raised.exception))
            self.assertEqual(
                list(target.parent.glob(f".{MODULE.SKILL_NAME}.staging-*")), []
            )


if __name__ == "__main__":
    unittest.main()
