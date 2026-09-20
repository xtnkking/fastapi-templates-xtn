#!/usr/bin/env python3
"""Verify that the Linux/Python 3.12 dependency closure is exactly pinned."""

from __future__ import annotations

import importlib.metadata
import platform
import re
import sys
import tomllib
from collections.abc import Iterable, Mapping, Sequence
from collections import deque
from pathlib import Path

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

REPO_ROOT = Path(__file__).resolve().parents[1]
ASSET_ROOT = (
    REPO_ROOT / "skills" / "fastapi-templates-xtn" / "assets" / "postgresql-rbac"
)
PYPROJECT_PATH = ASSET_ROOT / "pyproject.toml"
CONSTRAINTS_PATH = ASSET_ROOT / "constraints-ci-py312.txt"
EXPLICIT_TOOL_ROOTS = ("pip", "setuptools")


def _load_pins() -> dict[str, str]:
    pins: dict[str, str] = {}
    for raw_line in CONSTRAINTS_PATH.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+)", line)
        if match is None:
            raise RuntimeError(f"constraint is not an exact pin: {line!r}")
        name = canonicalize_name(match.group(1))
        if name in pins:
            raise RuntimeError(f"duplicate constraint for {name}")
        pins[name] = match.group(2)
    return pins


def _marker_applies(requirement: Requirement, parent_extras: frozenset[str]) -> bool:
    if requirement.marker is None:
        return True
    environment = {key: str(value) for key, value in default_environment().items()}
    candidates = parent_extras | frozenset({""})
    return any(
        requirement.marker.evaluate({**environment, "extra": extra})
        for extra in candidates
    )


def _root_requirements() -> list[Requirement]:
    project = tomllib.loads(PYPROJECT_PATH.read_text(encoding="utf-8"))["project"]
    requirements = list(project.get("dependencies", []))
    requirements.extend(project.get("optional-dependencies", {}).get("test", []))
    requirements.extend(EXPLICIT_TOOL_ROOTS)
    return [Requirement(value) for value in requirements]


def _index_installed_distributions(
    distributions: Iterable[importlib.metadata.Distribution],
) -> dict[str, tuple[importlib.metadata.Distribution, ...]]:
    grouped: dict[str, list[importlib.metadata.Distribution]] = {}
    for distribution in distributions:
        raw_name = distribution.metadata.get("Name")
        if not raw_name:
            continue
        grouped.setdefault(canonicalize_name(raw_name), []).append(distribution)
    return {name: tuple(matches) for name, matches in grouped.items()}


def _require_unique_distribution(
    installed: Mapping[str, Sequence[importlib.metadata.Distribution]],
    name: str,
) -> importlib.metadata.Distribution:
    matches = installed.get(name, ())
    if not matches:
        raise RuntimeError(f"selected dependency {name!r} is not installed")
    if len(matches) != 1:
        versions = ", ".join(sorted(distribution.version for distribution in matches))
        raise RuntimeError(
            f"selected dependency {name!r} has {len(matches)} installed metadata "
            f"records ({versions}); expected exactly one"
        )
    return matches[0]


def main() -> int:
    if sys.platform != "linux" or sys.version_info[:2] != (3, 12):
        print(
            "ERROR: this lock verifier must run on CPython 3.12/Linux",
            file=sys.stderr,
        )
        return 1
    if platform.python_implementation() != "CPython":
        print("ERROR: this lock verifier requires CPython", file=sys.stderr)
        return 1

    try:
        pins = _load_pins()
        installed = _index_installed_distributions(importlib.metadata.distributions())
        queue: deque[tuple[Requirement, frozenset[str], str]] = deque(
            (requirement, frozenset({""}), "project root")
            for requirement in _root_requirements()
        )
        resolved_extras: dict[str, frozenset[str]] = {}
        visited: set[str] = set()

        while queue:
            requirement, parent_extras, source = queue.popleft()
            if not _marker_applies(requirement, parent_extras):
                continue

            name = canonicalize_name(requirement.name)
            pin = pins.get(name)
            if pin is None:
                raise RuntimeError(
                    f"selected dependency {name!r} from {source} has no exact constraint"
                )

            distribution = _require_unique_distribution(installed, name)
            if distribution.version != pin:
                raise RuntimeError(
                    f"installed {name}=={distribution.version}, expected exact pin {pin}"
                )
            if (
                requirement.specifier
                and distribution.version not in requirement.specifier
            ):
                raise RuntimeError(
                    f"installed {name}=={distribution.version} does not satisfy "
                    f"{requirement.specifier} from {source}"
                )

            requested_extras = frozenset(requirement.extras)
            previous_extras = resolved_extras.get(name, frozenset())
            combined_extras = previous_extras | requested_extras
            if name in visited and combined_extras == previous_extras:
                continue
            visited.add(name)
            resolved_extras[name] = combined_extras

            for dependency_text in distribution.requires or ():
                dependency = Requirement(dependency_text)
                queue.append((dependency, combined_extras, name))

        if "uvicorn" in visited and "uvloop" not in visited:
            raise RuntimeError(
                "uvicorn[standard] did not select uvloop on CPython 3.12/Linux"
            )
    except (
        importlib.metadata.PackageNotFoundError,
        KeyError,
        OSError,
        RuntimeError,
    ) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(
        "CI dependency closure is installed and exactly constrained: "
        f"{len(visited)} packages checked."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
