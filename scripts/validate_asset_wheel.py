#!/usr/bin/env python3
"""Build the reference asset wheel and verify required packaged files."""

from __future__ import annotations

import argparse
import email.parser
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

REQUIRED_SUFFIXES = (
    "/licenses/LICENSE",
    "/licenses/NOTICE",
    "/licenses/THIRD_PARTY_NOTICES.md",
    "/app/assets/locales/en.json",
    "/app/assets/locales/zh-CN.json",
)


def validate_wheel(asset_root: Path, version_file: Path) -> None:
    asset_root = asset_root.resolve(strict=True)
    version_file = version_file.resolve(strict=True)
    expected_version = version_file.read_text(encoding="utf-8").strip()

    with tempfile.TemporaryDirectory(prefix="fastapi-templates-xtn-wheel-") as raw:
        output = Path(raw)
        build_source = output / "source"
        wheel_output = output / "wheel"
        wheel_output.mkdir()
        shutil.copytree(
            asset_root,
            build_source,
            ignore=shutil.ignore_patterns(
                ".coverage",
                ".mypy_cache",
                ".pytest_cache",
                ".ruff_cache",
                "*.egg-info",
                "*.pyc",
                "*.pyo",
                "__pycache__",
                "build",
                "dist",
            ),
        )
        subprocess.run(
            [
                sys.executable,
                "-B",
                "-m",
                "pip",
                "wheel",
                "--disable-pip-version-check",
                "--no-deps",
                "--no-build-isolation",
                "--wheel-dir",
                str(wheel_output),
                str(build_source),
            ],
            check=True,
        )
        wheels = list(wheel_output.glob("*.whl"))
        if len(wheels) != 1:
            raise RuntimeError(f"Expected exactly one wheel, found {len(wheels)}")

        with zipfile.ZipFile(wheels[0]) as archive:
            names = tuple(f"/{name}" for name in archive.namelist())
            for suffix in REQUIRED_SUFFIXES:
                if not any(name.endswith(suffix) for name in names):
                    raise RuntimeError(
                        f"Wheel is missing required file suffix: {suffix}"
                    )
            metadata_names = [
                name[1:] for name in names if name.endswith(".dist-info/METADATA")
            ]
            if len(metadata_names) != 1:
                raise RuntimeError("Wheel must contain exactly one dist-info/METADATA")
            metadata = email.parser.BytesParser().parsebytes(
                archive.read(metadata_names[0])
            )
            if metadata.get("Version") != expected_version:
                raise RuntimeError(
                    "Wheel metadata version does not match Skill VERSION: "
                    f"{metadata.get('Version')!r} != {expected_version!r}"
                )

            installed = output / "installed"
            archive.extractall(installed)

        # Import from the built artifact, outside the checkout, so source-tree
        # imports cannot hide missing packages or a broken locale resource path.
        subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                (
                    "import importlib, pathlib, sys; "
                    "root = pathlib.Path(sys.argv[1]); sys.path.insert(0, str(root)); "
                    "modules = [importlib.import_module(name) for name in "
                    "('app.core.i18n', 'app.models.access', "
                    "'app.models.account_security', 'app.models.business_audit', "
                    "'app.repositories.access', 'app.db.redis', "
                    "'app.core.security.tokens', 'app.core.security.captcha')]; "
                    "assert all(pathlib.Path(m.__file__).is_relative_to(root) "
                    "for m in modules); "
                    "assert set(modules[0].CATALOGS) == {'zh-CN', 'en'}"
                ),
                str(installed),
            ],
            cwd=output,
            check=True,
        )

    print(f"Asset wheel is valid for Skill version {expected_version}.")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("asset_root", type=Path)
    parser.add_argument("version_file", type=Path)
    args = parser.parse_args()
    try:
        validate_wheel(args.asset_root, args.version_file)
    except (
        OSError,
        RuntimeError,
        subprocess.CalledProcessError,
        zipfile.BadZipFile,
    ) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
