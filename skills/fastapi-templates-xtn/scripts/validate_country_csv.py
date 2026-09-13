#!/usr/bin/env python3
"""Validate an optional country-catalog CSV without changing the input file."""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
import unicodedata
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlsplit

EXPECTED_HEADER = (
    "country_code",
    "calling_code",
    "name_zh",
    "name_en",
    "flag_url",
)
COUNTRY_CODE_RE = re.compile(r"^[A-Z]{2}$")
CALLING_CODE_RE = re.compile(r"^[1-9][0-9]{0,2}$")
CONTROL_CHARACTER_RE = re.compile(r"[\x00-\x1f\x7f]")
HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
MAX_CSV_BYTES = 1_048_576
MAX_DATA_ROWS = 1_000
MAX_EXPECTED_CODES_BYTES = 65_536


def _contains_forbidden_character(value: str) -> bool:
    return CONTROL_CHARACTER_RE.search(value) is not None or any(
        unicodedata.category(character) in {"Cc", "Cf", "Cs"} for character in value
    )


def _normalize_dns_hostname(value: str) -> str | None:
    if not value or len(value) > 253 or value.endswith(".") or not value.isascii():
        return None
    if any(HOST_LABEL_RE.fullmatch(label) is None for label in value.split(".")):
        return None
    return value.casefold()


@dataclass(frozen=True)
class Finding:
    line: int | None
    column: str | None
    message: str


@dataclass(frozen=True)
class ValidationReport:
    row_count: int
    country_code_count: int
    calling_code_count: int
    membership_checked: bool
    shared_calling_codes: dict[str, list[str]]
    errors: list[Finding]
    warnings: list[Finding]

    @property
    def is_valid(self) -> bool:
        return not self.errors


def _finding(
    message: str,
    *,
    line: int | None = None,
    column: str | None = None,
) -> Finding:
    return Finding(line=line, column=column, message=message)


def _format_codes(codes: set[str]) -> str:
    ordered = sorted(codes)
    if len(ordered) <= 20:
        return ", ".join(ordered)
    return f"{', '.join(ordered[:20])}, ... ({len(ordered)} total)"


def _read_bounded_bytes(path: Path, *, limit: int, label: str) -> bytes:
    """Read no more than ``limit + 1`` bytes and reject oversized input."""

    with path.open("rb") as handle:
        content = handle.read(limit + 1)
    if len(content) > limit:
        raise ValueError(f"{label} exceeds the {limit}-byte validation limit")
    return content


def load_expected_codes(path: Path) -> set[str]:
    """Load a project-approved exact code set from comma/whitespace text."""

    raw_manifest = _read_bounded_bytes(
        path,
        limit=MAX_EXPECTED_CODES_BYTES,
        label="expected-code manifest",
    )
    text = raw_manifest.decode("utf-8-sig", errors="strict")
    without_comments = "\n".join(line.partition("#")[0] for line in text.splitlines())
    codes = {value for value in re.split(r"[\s,]+", without_comments) if value}
    invalid = {code for code in codes if COUNTRY_CODE_RE.fullmatch(code) is None}
    if invalid:
        raise ValueError(
            "expected-code manifest contains invalid values: " + _format_codes(invalid)
        )
    if not codes:
        raise ValueError("expected-code manifest is empty")
    return codes


def validate_country_csv(
    path: Path,
    *,
    expected_count: int | None = None,
    expected_codes: set[str] | None = None,
    structure_only: bool = False,
    required_codes: set[str] | None = None,
    allowed_flag_hosts: set[str] | None = None,
    require_derived_flag_path: bool = False,
) -> ValidationReport:
    errors: list[Finding] = []
    warnings: list[Finding] = []
    country_lines: dict[str, int] = {}
    calling_codes: dict[str, list[str]] = defaultdict(list)
    name_zh_values: list[tuple[str, int]] = []
    name_en_values: list[tuple[str, int]] = []
    country_codes_in_order: list[str] = []
    row_count = 0

    hosts: set[str] = set()
    for host in allowed_flag_hosts or set():
        normalized_host = _normalize_dns_hostname(host)
        if normalized_host is None:
            errors.append(_finding(f"invalid allowed flag host: {host!r}"))
        else:
            hosts.add(normalized_host)
    required = required_codes or set()
    saw_flag_url = False

    try:
        raw_source = _read_bounded_bytes(
            path,
            limit=MAX_CSV_BYTES,
            label="CSV",
        )
    except OSError as exc:
        return ValidationReport(
            row_count=0,
            country_code_count=0,
            calling_code_count=0,
            membership_checked=False,
            shared_calling_codes={},
            errors=[_finding(f"cannot open strict UTF-8 CSV: {exc}")],
            warnings=[],
        )
    except ValueError as exc:
        return ValidationReport(
            row_count=0,
            country_code_count=0,
            calling_code_count=0,
            membership_checked=False,
            shared_calling_codes={},
            errors=[_finding(str(exc))],
            warnings=[],
        )
    try:
        source = raw_source.decode("utf-8-sig", errors="strict")
    except UnicodeError as exc:
        return ValidationReport(
            row_count=0,
            country_code_count=0,
            calling_code_count=0,
            membership_checked=False,
            shared_calling_codes={},
            errors=[_finding(f"cannot decode strict UTF-8 CSV: {exc}")],
            warnings=[],
        )

    with io.StringIO(source, newline="") as handle:
        reader = csv.reader(handle, strict=True)
        try:
            header = next(reader)
        except StopIteration:
            errors.append(_finding("CSV is empty", line=1))
            header = []
        except csv.Error as exc:
            errors.append(_finding(f"cannot parse CSV header: {exc}", line=1))
            header = []

        if tuple(header) != EXPECTED_HEADER:
            errors.append(
                _finding(
                    "header must be exactly: " + ",".join(EXPECTED_HEADER),
                    line=1,
                )
            )

        if tuple(header) == EXPECTED_HEADER:
            try:
                for values in reader:
                    row_count += 1
                    line_number = reader.line_num
                    if row_count > MAX_DATA_ROWS:
                        errors.append(
                            _finding(
                                f"CSV exceeds the {MAX_DATA_ROWS}-row validation limit",
                                line=line_number,
                            )
                        )
                        break
                    if len(values) != len(EXPECTED_HEADER):
                        errors.append(
                            _finding(
                                f"expected {len(EXPECTED_HEADER)} columns, got {len(values)}",
                                line=line_number,
                            )
                        )
                        continue

                    row = dict(zip(EXPECTED_HEADER, values, strict=True))
                    for column, value in row.items():
                        if value != value.strip():
                            errors.append(
                                _finding(
                                    "leading or trailing whitespace is not allowed",
                                    line=line_number,
                                    column=column,
                                )
                            )
                        if _contains_forbidden_character(value):
                            errors.append(
                                _finding(
                                    "control or Unicode formatting characters are not allowed",
                                    line=line_number,
                                    column=column,
                                )
                            )

                    code = row["country_code"]
                    calling_code = row["calling_code"]
                    name_zh = row["name_zh"]
                    name_en = row["name_en"]
                    flag_url = row["flag_url"]

                    if COUNTRY_CODE_RE.fullmatch(code) is None:
                        errors.append(
                            _finding(
                                "must be two uppercase ASCII letters",
                                line=line_number,
                                column="country_code",
                            )
                        )
                    elif code in country_lines:
                        errors.append(
                            _finding(
                                f"duplicate of line {country_lines[code]}",
                                line=line_number,
                                column="country_code",
                            )
                        )
                    else:
                        country_lines[code] = line_number
                        country_codes_in_order.append(code)

                    if CALLING_CODE_RE.fullmatch(calling_code) is None:
                        errors.append(
                            _finding(
                                "must contain one to three digits, without '+' or a leading zero",
                                line=line_number,
                                column="calling_code",
                            )
                        )
                    else:
                        calling_codes[calling_code].append(code)

                    for column, value in (("name_zh", name_zh), ("name_en", name_en)):
                        if not value:
                            errors.append(
                                _finding(
                                    "must not be empty",
                                    line=line_number,
                                    column=column,
                                )
                            )
                        elif len(value) > 128:
                            errors.append(
                                _finding(
                                    "must not exceed 128 Unicode characters",
                                    line=line_number,
                                    column=column,
                                )
                            )
                    name_zh_values.append((name_zh, line_number))
                    name_en_values.append((name_en.casefold(), line_number))

                    if flag_url:
                        saw_flag_url = True
                        if len(flag_url) > 2048:
                            errors.append(
                                _finding(
                                    "must not exceed 2048 characters",
                                    line=line_number,
                                    column="flag_url",
                                )
                            )
                        try:
                            parsed = urlsplit(flag_url)
                            hostname = parsed.hostname
                            normalized_hostname = (
                                _normalize_dns_hostname(hostname)
                                if hostname is not None
                                else None
                            )
                            port = parsed.port
                        except ValueError:
                            parsed = None
                            hostname = None
                            normalized_hostname = None
                            port = None
                        if (
                            parsed is None
                            or parsed.scheme != "https"
                            or not hostname
                            or normalized_hostname is None
                            or port not in (None, 443)
                            or parsed.username is not None
                            or parsed.password is not None
                            or "?" in flag_url
                            or "#" in flag_url
                            or parsed.fragment
                        ):
                            errors.append(
                                _finding(
                                    "must be an absolute HTTPS URL with a valid ASCII "
                                    "DNS host, the default port, and no credentials, "
                                    "query, or fragment",
                                    line=line_number,
                                    column="flag_url",
                                )
                            )
                        elif hosts and normalized_hostname not in hosts:
                            errors.append(
                                _finding(
                                    f"host {hostname!r} is not in the approved allowlist",
                                    line=line_number,
                                    column="flag_url",
                                )
                            )
                        if require_derived_flag_path and parsed is not None:
                            expected_path = f"/w40/{code.casefold()}.png"
                            if parsed.path != expected_path or parsed.query:
                                errors.append(
                                    _finding(
                                        f"must use the derived path {expected_path!r} without a query",
                                        line=line_number,
                                        column="flag_url",
                                    )
                                )
                    elif require_derived_flag_path:
                        errors.append(
                            _finding(
                                "is required when derived flag paths are enforced",
                                line=line_number,
                                column="flag_url",
                            )
                        )
            except csv.Error as exc:
                errors.append(
                    _finding(f"cannot parse CSV row: {exc}", line=reader.line_num)
                )

    codes = set(country_lines)
    if row_count == 0:
        errors.append(_finding("CSV must contain at least one data row"))
    if expected_count is not None and row_count != expected_count:
        errors.append(
            _finding(f"expected {expected_count} data rows, found {row_count}")
        )
    missing_required = required - codes
    if missing_required:
        errors.append(
            _finding(
                "missing required country codes: " + _format_codes(missing_required)
            )
        )
    if expected_codes is not None and structure_only:
        errors.append(
            _finding("expected_codes and structure_only are mutually exclusive")
        )
    elif expected_codes is not None:
        missing = expected_codes - codes
        unexpected = codes - expected_codes
        if missing:
            errors.append(
                _finding("missing expected country codes: " + _format_codes(missing))
            )
        if unexpected:
            errors.append(
                _finding(
                    "contains unexpected country codes: " + _format_codes(unexpected)
                )
            )
    elif structure_only:
        warnings.append(
            _finding(
                "structure-only result is not import approval; country-code membership "
                "and completeness were not checked"
            )
        )
    else:
        errors.append(
            _finding(
                "an approved expected country-code set is required; use structure_only "
                "only for an explicitly non-authoritative inspection"
            )
        )

    if saw_flag_url and not hosts:
        finding = _finding(
            "non-empty flag URLs require an approved allowed_flag_hosts set"
        )
        if structure_only:
            warnings.append(finding)
        else:
            errors.append(finding)

    if country_codes_in_order != sorted(country_codes_in_order):
        warnings.append(_finding("rows are not sorted by country_code"))

    for label, values in (("name_zh", name_zh_values), ("name_en", name_en_values)):
        counts = Counter(value for value, _line in values if value)
        duplicates = {value for value, count in counts.items() if count > 1}
        if duplicates:
            warnings.append(
                _finding(
                    f"{label} contains duplicate display names; names must not be keys or unique",
                    column=label,
                )
            )

    shared = {
        code: sorted(countries)
        for code, countries in sorted(calling_codes.items())
        if len(countries) > 1
    }
    if shared:
        warnings.append(
            _finding(
                f"{len(shared)} calling codes are shared; calling_code must not be unique"
            )
        )

    return ValidationReport(
        row_count=row_count,
        country_code_count=len(codes),
        calling_code_count=len(calling_codes),
        membership_checked=expected_codes is not None and not structure_only,
        shared_calling_codes=shared,
        errors=errors,
        warnings=warnings,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate a five-column UTF-8 country-catalog CSV read-only."
    )
    parser.add_argument("csv_path", type=Path)
    parser.add_argument("--expected-count", type=int)
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument(
        "--expected-codes-file",
        type=Path,
        help="UTF-8 comma/whitespace list defining the exact approved code set.",
    )
    scope.add_argument(
        "--structure-only",
        action="store_true",
        help="Check shape only; this explicitly does not approve the file for import.",
    )
    parser.add_argument("--required-code", action="append", default=[])
    parser.add_argument("--allowed-flag-host", action="append", default=[])
    parser.add_argument("--require-derived-flag-path", action="store_true")
    parser.add_argument("--json", action="store_true", dest="as_json")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    required_codes = set(args.required_code)
    invalid_required = {
        code for code in required_codes if COUNTRY_CODE_RE.fullmatch(code) is None
    }
    if invalid_required:
        print(
            "invalid --required-code values: " + _format_codes(invalid_required),
            file=sys.stderr,
        )
        return 2

    expected_codes: set[str] | None = None
    if args.expected_codes_file is not None:
        try:
            expected_codes = load_expected_codes(args.expected_codes_file)
        except (OSError, UnicodeError, ValueError) as exc:
            print(f"cannot load expected-code manifest: {exc}", file=sys.stderr)
            return 2

    report = validate_country_csv(
        args.csv_path,
        expected_count=args.expected_count,
        expected_codes=expected_codes,
        structure_only=args.structure_only,
        required_codes=required_codes,
        allowed_flag_hosts=set(args.allowed_flag_host),
        require_derived_flag_path=args.require_derived_flag_path,
    )

    if args.as_json:
        payload = asdict(report)
        payload["valid"] = report.is_valid
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    else:
        for finding in report.errors:
            location = ""
            if finding.line is not None:
                location += f" line={finding.line}"
            if finding.column is not None:
                location += f" column={finding.column}"
            print(f"ERROR{location}: {finding.message}", file=sys.stderr)
        for finding in report.warnings:
            print(f"WARNING: {finding.message}")
        print(
            "rows={rows} country_codes={countries} calling_codes={calling} "
            "shared_calling_codes={shared} membership_checked={membership} "
            "valid={valid}".format(
                rows=report.row_count,
                countries=report.country_code_count,
                calling=report.calling_code_count,
                shared=len(report.shared_calling_codes),
                membership=str(report.membership_checked).lower(),
                valid=str(report.is_valid).lower(),
            )
        )

    return 0 if report.is_valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
