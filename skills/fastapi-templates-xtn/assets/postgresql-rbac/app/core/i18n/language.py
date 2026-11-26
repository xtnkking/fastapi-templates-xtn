#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    读取 Accept-Language 并为每次请求选择中英文，统一设置响应语言头。
#    不加载文案目录，也不处理业务或参数校验错误。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/30    XTN       V1.000        从多语言模块分离请求语言协商和响应头处理
# 2026/09/30    XTN       V1.001        简化中英文选择，保留常用语言权重和响应头
# 2026/10/13    XTN       V1.002        补充语言权重、请求缓存和响应头合并的通俗步骤
# --------------------------------------------------------------------------------------------------

import re

from fastapi import Request
from starlette.datastructures import MutableHeaders

DEFAULT_LOCALE = "zh-CN"  # 缺失、不支持或不合法的语言请求默认使用简体中文。
SUPPORTED_LOCALES = ("zh-CN", "en")  # 只返回这两种标准语言标识；扩展语言时同步增加目录文件。
_MAX_ACCEPT_LANGUAGE_LENGTH = 512  # 请求头的最大字符数，防止超长输入拖慢解析。
_MAX_LANGUAGE_RANGES = 20  # 最多检查前 20 个候选，避免处理无限长的列表。
# 语言标签只允许字母、数字和连字符；不把请求内容当作文件名或文案键。
_LANGUAGE_TAG_PATTERN = re.compile(r"^[A-Za-z]{1,8}(?:-[A-Za-z0-9]{1,8})*$")


def select_locale(accept_language: str | None) -> str:
    """
        从常见的浏览器语言列表中选中文或英文，无法选择时用中文。
        q=0 的候选不参与选择；相同权重按请求头出现顺序决定。

    :param accept_language: 可选的 HTTP Accept-Language 请求头。
    :return: 固定的 zh-CN 或 en；不回显原始请求头。
    """
    # 1. 缺少语言、过长或含控制字符时直接使用中文，避免继续处理不可信的请求头。
    if (
        not accept_language
        or len(accept_language) > _MAX_ACCEPT_LANGUAGE_LENGTH
        or any(ord(character) < 32 and character != "\t" for character in accept_language)
    ):
        return DEFAULT_LOCALE

    # 2. 只检查有限个候选；先认出项目支持的语言，再比较它们的 q 权重。
    best_locale = DEFAULT_LOCALE
    best_quality = 0.0
    for raw_range in accept_language.split(",")[:_MAX_LANGUAGE_RANGES]:
        language_range, _, parameter = raw_range.strip().partition(";")
        language_range = language_range.strip().replace("_", "-").casefold()
        if not _LANGUAGE_TAG_PATTERN.fullmatch(language_range):
            continue

        # 仅识别本项目提供文案的语言；其他语言和 * 最终回退中文。
        if language_range in {"zh", "zh-cn", "zh-hans", "zh-sg"}:
            locale = "zh-CN"
        elif language_range == "en" or language_range.startswith("en-"):
            locale = "en"
        else:
            continue

        # 未写 q 时默认最优先；错误权重或 q=0 不参与，权重相同保留先出现的候选。
        quality = 1.0
        if parameter:
            name, separator, value = parameter.strip().partition("=")
            if name.casefold() != "q" or not separator:
                continue
            try:
                quality = float(value.strip())
            except ValueError:
                continue
        if 0.0 < quality <= 1.0 and quality > best_quality:
            best_locale = locale
            best_quality = quality

    return best_locale


def locale_for_request(request: Request) -> str:
    """
        取得并缓存本次请求的语言，不在进程全局保存用户选择。

    :param request: 当前 FastAPI 请求，包含语言头和独立的请求状态。
    :return: 当前请求固定使用的 zh-CN 或 en。
    """
    # 同一请求已选好语言就复用；否则解析请求头后只缓存到该请求，避免串到其他用户。
    locale = getattr(request.state, "locale", None)
    if locale in SUPPORTED_LOCALES:
        return str(locale)
    locale = select_locale(request.headers.get("accept-language"))
    request.state.locale = locale
    return locale


def apply_language_headers(headers: MutableHeaders, locale: str) -> None:
    """
        标记响应实际使用的语言，并提醒缓存按请求语言区分内容。

    :param headers: 需要原地更新的响应头。
    :param locale: 已选择的标准语言标识。
    :return: 无返回值；设置 Content-Language 并合并 Vary。
    """
    # 写明实际文案语言，并在保留其他缓存区分项的同时补入 Accept-Language，避免重复。
    headers["Content-Language"] = locale
    vary = [item.strip() for item in headers.get("Vary", "").split(",") if item.strip()]
    if not any(item.casefold() == "accept-language" for item in vary):
        vary.append("Accept-Language")
    headers["Vary"] = ", ".join(vary)
