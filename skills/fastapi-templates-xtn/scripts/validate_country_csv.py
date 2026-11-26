#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 说明:
#    只读校验可选国家目录 CSV 的格式、成员集合和旗帜地址，输出错误、警告与汇总。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/13    XTN       V1.000        完善国家目录校验函数的通俗说明与步骤注释
# 2026/11/26    XTN       V1.001        汇总输出改用直接插值，保留原有文字和结果
# --------------------------------------------------------------------------------------------------

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

# CSV 必须严格使用这五列和此顺序；校验时不自动纠正名称或重新排列。
EXPECTED_HEADER = (
    "country_code",
    "calling_code",
    "name_zh",
    "name_en",
    "flag_url",
)
# 国家码为两个大写 ASCII 字母；电话区号为一到三位数字，不含加号且不以 0 开头。
COUNTRY_CODE_RE = re.compile(r"^[A-Z]{2}$")
CALLING_CODE_RE = re.compile(r"^[1-9][0-9]{0,2}$")
# 隐藏控制字符和不合法主机标签会拒绝；主机标签只接受 ASCII 字母、数字和内部连字符。
CONTROL_CHARACTER_RE = re.compile(r"[\x00-\x1f\x7f]")
HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
# CSV 最多 1 MiB、1000 条数据；批准国家码清单最多 64 KiB，避免读取无上限输入。
MAX_CSV_BYTES = 1_048_576
MAX_DATA_ROWS = 1_000
MAX_EXPECTED_CODES_BYTES = 65_536


def _contains_forbidden_character(value: str) -> bool:
    """
        判断文本是否包含控制字符、隐藏格式字符或 Unicode 代理字符。

    :param value: 一个 CSV 单元格的原始文本。
    :return: 含有不允许字符时返回 True，全部字符可接受时返回 False。
    """
    # 同时检查 ASCII 控制范围和 Unicode 分类，避免只拦住肉眼可见的异常字符。
    return CONTROL_CHARACTER_RE.search(value) is not None or any(
        unicodedata.category(character) in {"Cc", "Cf", "Cs"} for character in value
    )


def _normalize_dns_hostname(value: str) -> str | None:
    """
        检查 DNS 主机名的长度和标签格式，通过后转成小写用于白名单比较。
        不进行 DNS 查询，也不把 Unicode 域名转换成 ASCII 编码。

    :param value: 不含端口的主机名文本。
    :return: 合法主机名的小写形式；为空、过长、尾点或标签不合法时返回 None。
    """
    # 先排除空值、过长、尾点及非 ASCII 文本，再逐段检查长度和连字符位置。
    if not value or len(value) > 253 or value.endswith(".") or not value.isascii():
        return None
    if any(HOST_LABEL_RE.fullmatch(label) is None for label in value.split(".")):
        return None
    return value.casefold()


@dataclass(frozen=True)
class Finding:
    """
        保存一条校验问题的原始提示，以及可选的 CSV 行号和列名。
    """

    # None 表示问题属于整个文件，不能定位到某一行或列。
    line: int | None
    column: str | None
    message: str


@dataclass(frozen=True)
class ValidationReport:
    """
        汇总只读校验结果；错误决定是否通过，警告记录需要人工了解的数据特点。
    """

    # 数据行数含已读到的异常行；国家码和区号数量只统计各自格式通过的不同值。
    row_count: int
    country_code_count: int
    calling_code_count: int
    # True 表示已与批准的完整国家码集合比较，结构检查模式永远为 False。
    membership_checked: bool
    shared_calling_codes: dict[str, list[str]]
    errors: list[Finding]
    warnings: list[Finding]

    @property
    def is_valid(self) -> bool:
        """
            判断本次检查是否没有错误；警告不会单独让结果失败。

        :return: 错误列表为空时返回 True，否则返回 False。
        """
        # 结构检查是否可用于导入另有明确警告，此属性仅判断错误列表。
        return not self.errors


def _finding(
    message: str,
    *,
    line: int | None = None,
    column: str | None = None,
) -> Finding:
    """
        将提示和定位信息封装成错误或警告共用的问题记录。

    :param message: 面向命令行或 JSON 输出的原始提示文本。
    :param line: CSV 的实际行号，None 表示整个文件的问题。
    :param column: 固定表头中的列名，None 表示没有具体列位置。
    :return: 包含提示和定位信息的 Finding 记录。
    """
    # 保留调用方给出的原始提示，不翻译机器可读取的外部工具输出。
    return Finding(line=line, column=column, message=message)


def _format_codes(codes: set[str]) -> str:
    """
        把国家码集合整理成稳定、长度受限的提示文本。

    :param codes: 要在错误提示中展示的国家码集合。
    :return: 按字母排序的逗号列表；超过 20 个时只展示前 20 个并附总数。
    """
    # 排序让每次提示顺序一致，大集合截短显示以免输出被异常输入撑大。
    ordered = sorted(codes)
    if len(ordered) <= 20:
        return ", ".join(ordered)
    return f"{', '.join(ordered[:20])}, ... ({len(ordered)} total)"


def _read_bounded_bytes(path: Path, *, limit: int, label: str) -> bytes:
    """
        以只读方式读取文件，最多多读一个字节以识别超过限制的输入。

    :param path: 要检查的输入文件路径。
    :param limit: 允许的最大字节数，不是字符数。
    :param label: 超限提示中使用的文件类别名称。
    :return: 未超过上限的原始字节内容，文件在返回前已关闭。
    :raises ValueError: 文件字节数超过允许上限。
    :raises OSError: 文件不能打开或读取。
    """
    # 只读取 limit + 1 字节，超大文件无需全部载入内存就能判断超限。
    with path.open("rb") as handle:
        content = handle.read(limit + 1)
    if len(content) > limit:
        raise ValueError(f"{label} exceeds the {limit}-byte validation limit")
    return content


def load_expected_codes(path: Path) -> set[str]:
    """
        从批准清单读取必须完全匹配的国家码集合，接受逗号或空白分隔及井号行尾注释。

    :param path: UTF-8 国家码清单路径，允许 UTF-8 BOM，最多读取 64 KiB。
    :return: 去除重复项后的非空国家码集合，每项必须是两个大写 ASCII 字母。
    :raises ValueError: 清单过大、包含格式错误的国家码或没有任何国家码。
    :raises OSError: 清单无法打开或读取。
    :raises UnicodeError: 清单不符合严格 UTF-8 编码。
    """
    # 先限制读取字节数，再严格解码；批准清单不能通过替换坏字节悄悄改变成员。
    raw_manifest = _read_bounded_bytes(
        path,
        limit=MAX_EXPECTED_CODES_BYTES,
        label="expected-code manifest",
    )
    text = raw_manifest.decode("utf-8-sig", errors="strict")
    # 每行去掉井号后的说明，再按逗号或空白切分，集合自然合并重复国家码。
    without_comments = "\n".join(line.partition("#")[0] for line in text.splitlines())
    codes = {value for value in re.split(r"[\s,]+", without_comments) if value}
    # 清单自身必须正确且非空，不能用有问题的基准判定 CSV 完整性。
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
    """
        只读检查五列国家目录 CSV，收集格式错误、成员缺失及可人工判断的警告。
        文件读取和行数都有上限，UTF-8 严格解码，遇到坏表头不继续按错误列解释数据。
        批准集合用于核对成员与完整性；只查结构时会明确提示结果不是导入批准。

    :param path: 待检查的 CSV 文件路径，不会修改输入内容。
    :param expected_count: 可选的准确数据行数；None 不做数量相等检查，表头不计入数据行。
    :param expected_codes: 可选的批准国家码全集；提供时逐一报告缺失成员和多余成员。
    :param structure_only: True 只检查结构并给出未批准导入警告；False 必须提供批准集合。
    :param required_codes: 必须存在的国家码子集；None 表示不增加额外的必含成员要求。
    :param allowed_flag_hosts: 非空旗帜 URL 允许使用的 DNS 主机集合；None 等同未提供白名单。
    :param require_derived_flag_path: True 要求每行有 /w40/小写国家码.png 的旗帜路径；False 不强制此路径。
    :return: 数据数量、是否核对成员、共享区号、全部错误和警告的 ValidationReport。
    """
    # 分开收集错误和警告；国家码保留首次出现的行号，用于定位重复和统计有效成员。
    errors: list[Finding] = []
    warnings: list[Finding] = []
    country_lines: dict[str, int] = {}
    calling_codes: dict[str, list[str]] = defaultdict(list)
    name_zh_values: list[tuple[str, int]] = []
    name_en_values: list[tuple[str, int]] = []
    country_codes_in_order: list[str] = []
    row_count = 0

    # 白名单先按同一规则规范主机名；白名单本身不合法也要成为可见错误。
    hosts: set[str] = set()
    for host in allowed_flag_hosts or set():
        normalized_host = _normalize_dns_hostname(host)
        if normalized_host is None:
            errors.append(_finding(f"invalid allowed flag host: {host!r}"))
        else:
            hosts.add(normalized_host)
    required = required_codes or set()
    saw_flag_url = False

    # 限制文件大小并严格按 UTF-8 解码；读取或编码失败时直接返回尚未检查成员的报告。
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

    # 使用 CSV 解析器保留引号和换行语义，先要求五个表头名称及顺序完全一致。
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
                # 逐行限制总数并校验列数；缺列或多列的行不进入后续字段检查。
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

                    # 对每个单元格统一检查边缘空白和隐藏字符，不自动清洗异常输入。
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

                    # 国家码必须格式正确且唯一，格式通过的不同国家码才进入成员集合。
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

                    # 电话区号允许多个国家共用，记录对应国家以便最后输出共享区号警告。
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

                    # 展示名必须非空且不超过 128 个字符；英文重名比较忽略大小写。
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

                    # 旗帜地址可为空；非空时检查 HTTPS、默认端口和无凭据、查询、片段的要求。
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
                        # 合法地址还必须落在批准主机集合中；主机名比较忽略大小写。
                        elif hosts and normalized_hostname not in hosts:
                            errors.append(
                                _finding(
                                    f"host {hostname!r} is not in the approved allowlist",
                                    line=line_number,
                                    column="flag_url",
                                )
                            )
                        # 开启固定路径要求时，按当前国家码核对图片路径，不接受查询参数。
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

    # 逐行读取结束后检查非空、准确行数和必含成员；这些要求与字段格式检查各自记录。
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
    # 批准集合和结构模式互斥；正常审批必须同时发现缺失国家和未批准的多余国家。
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

    # 使用了旗帜 URL 却没有合法主机白名单时，结构模式警告，正常校验则判为错误。
    if saw_flag_url and not hosts:
        finding = _finding(
            "non-empty flag URLs require an approved allowed_flag_hosts set"
        )
        if structure_only:
            warnings.append(finding)
        else:
            errors.append(finding)

    # 排序、展示名重复和区号共享都是数据特点，只给警告，不错误地要求名字或区号唯一。
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

    # 一次汇总全部发现，membership_checked 明确说明是否真正核对过批准集合。
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
    """
        定义国家目录校验命令，要求选择批准清单或明确的结构检查模式。

    :return: 尚未读取命令行参数的 ArgumentParser，包含校验范围和输出格式选项。
    """
    # 两种校验范围必须二选一，避免没有批准集合却被误认为完成了成员校验。
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
    """
        读取校验参数，加载批准清单并输出 JSON 或人可阅读的错误、警告和数量汇总。

    :param argv: 可选参数列表，不含程序名；None 使用当前进程的命令行参数。
    :return: 校验没有错误返回 0，CSV 校验失败返回 1，必含国家码或批准清单无效返回 2。
    :raises SystemExit: 命令行缺少必需选项、格式错误或请求帮助时由解析器退出。
    """
    # 先检查命令行里的必含国家码，参数错误不能被当成 CSV 文件问题。
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

    # 批准清单读取失败用状态码 2 返回；不会继续拿缺失的基准去审批 CSV。
    expected_codes: set[str] | None = None
    if args.expected_codes_file is not None:
        try:
            expected_codes = load_expected_codes(args.expected_codes_file)
        except (OSError, UnicodeError, ValueError) as exc:
            print(f"cannot load expected-code manifest: {exc}", file=sys.stderr)
            return 2

    # 将确认过的校验范围交给只读校验函数，再按选项展示同一份报告。
    report = validate_country_csv(
        args.csv_path,
        expected_count=args.expected_count,
        expected_codes=expected_codes,
        structure_only=args.structure_only,
        required_codes=required_codes,
        allowed_flag_hosts=set(args.allowed_flag_host),
        require_derived_flag_path=args.require_derived_flag_path,
    )

    # JSON 保留结构化定位信息；文本模式把错误写入标准错误，警告及汇总写入标准输出。
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
            f"rows={report.row_count} country_codes={report.country_code_count} "
            f"calling_codes={report.calling_code_count} shared_calling_codes={len(report.shared_calling_codes)} "
            f"membership_checked={str(report.membership_checked).lower()} valid={str(report.is_valid).lower()}"
        )

    return 0 if report.is_valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
