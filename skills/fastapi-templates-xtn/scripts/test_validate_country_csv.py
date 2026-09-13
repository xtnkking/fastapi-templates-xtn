from __future__ import annotations

import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from validate_country_csv import (
    EXPECTED_HEADER,
    MAX_CSV_BYTES,
    MAX_DATA_ROWS,
    MAX_EXPECTED_CODES_BYTES,
    load_expected_codes,
    validate_country_csv,
)

VALIDATOR = Path(__file__).with_name("validate_country_csv.py")


class CountryCsvValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)

    def write_rows(
        self,
        rows: list[list[str]],
        *,
        header: tuple[str, ...] = EXPECTED_HEADER,
    ) -> Path:
        path = self.root / "countries.csv"
        with path.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.writer(handle, lineterminator="\r\n")
            writer.writerow(header)
            writer.writerows(rows)
        return path

    def test_valid_csv_accepts_shared_calling_codes_and_utf8_bom(self) -> None:
        path = self.write_rows(
            [
                ["CA", "1", "加拿大", "Canada", "https://flagcdn.com/w40/ca.png"],
                ["US", "1", "美国", "United States", ""],
            ]
        )

        report = validate_country_csv(
            path,
            expected_count=2,
            expected_codes={"CA", "US"},
            allowed_flag_hosts={"flagcdn.com"},
        )

        self.assertTrue(report.is_valid)
        self.assertEqual(report.shared_calling_codes, {"1": ["CA", "US"]})
        self.assertTrue(
            any("must not be unique" in item.message for item in report.warnings)
        )

    def test_header_must_match_exactly(self) -> None:
        path = self.write_rows([], header=("code", *EXPECTED_HEADER[1:]))

        report = validate_country_csv(path, expected_codes={"US"})

        self.assertFalse(report.is_valid)
        self.assertTrue(
            any("header must be exactly" in item.message for item in report.errors)
        )

    def test_header_only_csv_is_rejected(self) -> None:
        path = self.write_rows([])

        report = validate_country_csv(path, expected_codes={"US"})

        self.assertFalse(report.is_valid)
        self.assertTrue(
            any("at least one data row" in item.message for item in report.errors)
        )

    def test_expected_code_set_is_required_unless_structure_only_is_explicit(
        self,
    ) -> None:
        path = self.write_rows([["US", "1", "美国", "United States", ""]])

        default_report = validate_country_csv(path)
        structure_report = validate_country_csv(path, structure_only=True)

        self.assertFalse(default_report.is_valid)
        self.assertTrue(
            any(
                "expected country-code set" in item.message
                for item in default_report.errors
            )
        )
        self.assertTrue(structure_report.is_valid)
        self.assertFalse(structure_report.membership_checked)
        self.assertTrue(
            any(
                "not import approval" in item.message
                for item in structure_report.warnings
            )
        )

    def test_file_size_limit_is_enforced_before_csv_parsing(self) -> None:
        path = self.root / "countries.csv"
        path.write_bytes(b"x" * (MAX_CSV_BYTES + 1))

        report = validate_country_csv(path, structure_only=True)

        self.assertFalse(report.is_valid)
        self.assertEqual(report.row_count, 0)
        self.assertTrue(
            any("byte validation limit" in item.message for item in report.errors)
        )

    def test_data_row_limit_is_enforced(self) -> None:
        row = ["US", "1", "美国", "United States", ""]
        path = self.write_rows([row] * (MAX_DATA_ROWS + 1))

        report = validate_country_csv(path, structure_only=True)

        self.assertFalse(report.is_valid)
        self.assertEqual(report.row_count, MAX_DATA_ROWS + 1)
        self.assertTrue(
            any("row validation limit" in item.message for item in report.errors)
        )

    def test_expected_code_manifest_size_limit_is_enforced(self) -> None:
        manifest = self.root / "approved-codes.txt"
        manifest.write_bytes(b"A" * (MAX_EXPECTED_CODES_BYTES + 1))

        with self.assertRaisesRegex(
            ValueError,
            rf"expected-code manifest exceeds the {MAX_EXPECTED_CODES_BYTES}-byte",
        ):
            load_expected_codes(manifest)

    def test_duplicate_country_code_is_rejected(self) -> None:
        path = self.write_rows(
            [
                ["US", "1", "美国", "United States", ""],
                ["US", "1", "美利坚", "United States of America", ""],
            ]
        )

        report = validate_country_csv(path, expected_codes={"US"})

        self.assertFalse(report.is_valid)
        self.assertTrue(
            any("duplicate of line" in item.message for item in report.errors)
        )

    def test_expected_code_manifest_detects_missing_and_unexpected_codes(self) -> None:
        path = self.write_rows([["CA", "1", "加拿大", "Canada", ""]])

        report = validate_country_csv(path, expected_codes={"CN", "US"})

        messages = {item.message for item in report.errors}
        self.assertTrue(
            any(message.startswith("missing expected") for message in messages)
        )
        self.assertTrue(
            any(message.startswith("contains unexpected") for message in messages)
        )

    def test_unsafe_flag_url_is_rejected(self) -> None:
        unsafe_urls = (
            "https://user:pass@example.com/us.png",
            "https://flagcdn.com:444/w40/us.png",
            "https://flagcdn.com/w40/us.png?size=40",
            "https://flagcdn.com/w40/us.png#",
        )
        for unsafe_url in unsafe_urls:
            with self.subTest(unsafe_url=unsafe_url):
                path = self.write_rows(
                    [["US", "1", "美国", "United States", unsafe_url]]
                )

                report = validate_country_csv(
                    path,
                    expected_codes={"US"},
                    allowed_flag_hosts={"example.com", "flagcdn.com"},
                )

                self.assertFalse(report.is_valid)
                self.assertTrue(
                    any("no credentials" in item.message for item in report.errors)
                )

    def test_invalid_ascii_dns_hostnames_are_rejected(self) -> None:
        for hostname in (
            "bad_host.example",
            "-bad.example",
            "bad-.example",
            "bad..example",
        ):
            with self.subTest(hostname=hostname):
                path = self.write_rows(
                    [
                        [
                            "US",
                            "1",
                            "美国",
                            "United States",
                            f"https://{hostname}/w40/us.png",
                        ]
                    ]
                )

                report = validate_country_csv(
                    path,
                    expected_codes={"US"},
                    allowed_flag_hosts={"flagcdn.com"},
                )

                self.assertFalse(report.is_valid)
                self.assertTrue(
                    any(
                        item.column == "flag_url"
                        and "valid ASCII DNS host" in item.message
                        for item in report.errors
                    )
                )

        path = self.write_rows([["US", "1", "美国", "United States", ""]])
        report = validate_country_csv(
            path,
            expected_codes={"US"},
            allowed_flag_hosts={"bad_host.example"},
        )
        self.assertFalse(report.is_valid)
        self.assertTrue(
            any("invalid allowed flag host" in item.message for item in report.errors)
        )

    def test_flag_host_allowlist_matching_is_case_insensitive(self) -> None:
        path = self.write_rows(
            [["US", "1", "美国", "United States", "https://FlagCDN.com/w40/us.png"]]
        )

        report = validate_country_csv(
            path,
            expected_codes={"US"},
            allowed_flag_hosts={"FLAGCDN.COM"},
        )

        self.assertTrue(report.is_valid, report.errors)

    def test_control_characters_are_rejected(self) -> None:
        for unsafe_name in (
            "United\tStates",
            "United\nStates",
            "United\rStates",
            "United\u0085States",
            "United\u200bStates",
        ):
            with self.subTest(unsafe_name=repr(unsafe_name)):
                path = self.write_rows([["US", "1", "美国", unsafe_name, ""]])

                report = validate_country_csv(path, expected_codes={"US"})

                self.assertFalse(report.is_valid)
                self.assertTrue(
                    any(
                        "control or Unicode formatting characters" in item.message
                        for item in report.errors
                    )
                )

    def test_derived_flag_path_can_be_enforced(self) -> None:
        path = self.write_rows(
            [["US", "1", "美国", "United States", "https://flagcdn.com/w40/ca.png"]]
        )

        report = validate_country_csv(
            path,
            expected_codes={"US"},
            allowed_flag_hosts={"flagcdn.com"},
            require_derived_flag_path=True,
        )

        self.assertFalse(report.is_valid)
        self.assertTrue(any("derived path" in item.message for item in report.errors))

    def test_import_ready_flag_urls_require_an_approved_host(self) -> None:
        path = self.write_rows(
            [["US", "1", "美国", "United States", "https://flagcdn.com/w40/us.png"]]
        )

        report = validate_country_csv(path, expected_codes={"US"})

        self.assertFalse(report.is_valid)
        self.assertTrue(
            any("allowed_flag_hosts" in item.message for item in report.errors)
        )

    def test_cli_json_includes_valid_and_membership_status(self) -> None:
        path = self.write_rows([["US", "1", "美国", "United States", ""]])
        manifest = self.root / "approved-codes.txt"
        manifest.write_text("US\n", encoding="utf-8")

        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(VALIDATOR),
                str(path),
                "--expected-codes-file",
                str(manifest),
                "--json",
            ],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertTrue(payload["valid"])
        self.assertTrue(payload["membership_checked"])

    def test_cli_validation_failure_returns_one_and_json_report(self) -> None:
        path = self.write_rows([["us", "1", "美国", "United States", ""]])

        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(VALIDATOR),
                str(path),
                "--structure-only",
                "--json",
            ],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(completed.stderr, "")
        payload = json.loads(completed.stdout)
        self.assertFalse(payload["valid"])
        self.assertFalse(payload["membership_checked"])
        self.assertEqual(payload["row_count"], 1)
        self.assertTrue(payload["errors"])
        self.assertEqual(
            set(payload["errors"][0]),
            {"line", "column", "message"},
        )

    def test_cli_requires_an_authoritative_or_structure_only_mode(self) -> None:
        path = self.write_rows([["US", "1", "美国", "United States", ""]])

        completed = subprocess.run(
            [sys.executable, "-B", str(VALIDATOR), str(path)],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(completed.returncode, 2)
        self.assertIn("--expected-codes-file", completed.stderr)


if __name__ == "__main__":
    unittest.main()
