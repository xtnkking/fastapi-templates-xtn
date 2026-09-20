from __future__ import annotations

import importlib.metadata
import unittest
from types import SimpleNamespace
from typing import cast

import validate_ci_environment


def stub_distribution(
    name: str | None,
    version: str,
) -> importlib.metadata.Distribution:
    metadata = {} if name is None else {"Name": name}
    return cast(
        importlib.metadata.Distribution,
        SimpleNamespace(metadata=metadata, version=version),
    )


class InstalledDistributionTests(unittest.TestCase):
    def test_index_canonicalizes_names_and_ignores_unnamed_metadata(self) -> None:
        first = stub_distribution("Demo_Pkg", "1.0")
        second = stub_distribution("demo-pkg", "2.0")
        unnamed = stub_distribution(None, "3.0")

        indexed = validate_ci_environment._index_installed_distributions(
            (first, second, unnamed)
        )

        self.assertEqual(indexed, {"demo-pkg": (first, second)})

    def test_missing_selected_distribution_is_rejected(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "is not installed"):
            validate_ci_environment._require_unique_distribution({}, "demo")

    def test_duplicate_same_version_metadata_is_rejected(self) -> None:
        installed = {
            "demo": (
                stub_distribution("demo", "1.0"),
                stub_distribution("Demo", "1.0"),
            )
        }

        with self.assertRaisesRegex(RuntimeError, "2 installed metadata records"):
            validate_ci_environment._require_unique_distribution(installed, "demo")

    def test_duplicate_different_version_metadata_is_rejected(self) -> None:
        installed = {
            "demo": (
                stub_distribution("demo", "1.0"),
                stub_distribution("demo", "2.0"),
            )
        }

        with self.assertRaisesRegex(RuntimeError, r"\(1\.0, 2\.0\)"):
            validate_ci_environment._require_unique_distribution(installed, "demo")

    def test_unique_distribution_is_returned(self) -> None:
        distribution = stub_distribution("demo", "1.0")

        selected = validate_ci_environment._require_unique_distribution(
            {"demo": (distribution,)},
            "demo",
        )

        self.assertIs(selected, distribution)


if __name__ == "__main__":
    unittest.main()
