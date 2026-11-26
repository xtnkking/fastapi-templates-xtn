#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    为文件日志提取有大小限制的请求和响应摘要、被操作人及新密码指纹。
#    只旁观应用已经收发的消息，不额外读取请求，不改变验证、限流或业务结果。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/14    XTN       V1.000        新建
# 2026/10/14    XTN       V1.001        响应顶层保留业务提示，请求和嵌套自由文本继续脱敏
# 2026/10/15    XTN       V1.002        文件日志动作直接使用路由函数名，取消逐接口重复登记
# 2026/10/15    XTN       V1.003        统一提取请求目标和新建结果，路由不再赋值日志目标
# 2026/10/16    XTN       V1.004        文件日志与操作审计共用脱敏摘要和新密码指纹
# 2026/10/20    XTN       V1.005        日志保留角色 level 和用户 role_level 数值
# --------------------------------------------------------------------------------------------------

import hashlib
import hmac
import json
import re
from itertools import islice
from typing import cast

from fastapi import Request
from starlette.types import Message

from app.core.ids import ROLE_ID_PATTERN, USER_ID_PATTERN
from app.core.logging.events import JsonValue, _safe_value

BODY_CAPTURE_MAX_BYTES = 16_384  # 每侧最多暂存 16 KiB，超出后清空，避免日志额外占用大量内存。
SUMMARY_MAX_BYTES = 4096  # 每份脱敏摘要最多 4 KiB，给整条 16 KiB 日志留下关联字段空间。
# 只保留已知业务字段；新业务增加字段时在这里显式决定是否可公开到日志。
# 未列出的字段只计数，不保存任意字段名，防止有人把秘密直接放进 JSON 的键名。
_SAFE_FIELDS = frozenset({
    "id", "user_id", "role_id", "role_ids", "permission_id", "permission_ids",
    "key", "keys", "code", "data", "request_id", "items", "page", "page_size", "total",
    "tier", "enabled", "status", "is_system", "changed", "expected_version",
    "version", "token_version", "roles", "permissions", "permission_keys",
    "role_keys", "created_at", "updated_at", "deleted_at", "password_changed_at", "expires_at",
    "expires_in", "token_type", "errors", "scene", "count", "max_sessions",
    # 当前用户、角色变更响应的已知结构；允许展开安全字段，名称和说明仍逐字段遮盖。
    "user", "role", "bound_role_ids", "effective_role_ids", "effective_permissions",
    "level", "role_level", "is_active", "is_protected",
    # 重复脱敏时保留采集器已生成的数字统计/布尔标记，不能重新把省略数量算成一个未知字段。
    "_redacted_fields", "_truncated",
})
# 这些常见敏感字段保留固定名称方便定位，但所有值都写成 [REDACTED]。
_REDACTED_FIELDS = frozenset({
    "username", "user_name", "password", "new_password", "current_password", "password_hash",
    "captcha_id", "captcha_answer", "captcha_code", "access_token", "refresh_token", "token",
    "authorization", "cookie", "secret", "email", "phone", "image_base64", "name", "description",
    "message", "field",
})
# 只有这四个静态业务接口会记录“准备设置的新密码”的指纹，登录和旧密码一律不做指纹。
_PASSWORD_OPERATIONS = {
    "register": ("/api/v1/auth/register", "password"),
    "create_user": ("/api/v1/users/create", "password"),
    "reset_user_password": ("/api/v1/users/password/reset", "new_password"),
    "change_my_password": ("/api/v1/me/password/change", "new_password"),
}


def _summarize(value: object, *, field_name: str = "", depth: int = 0) -> JsonValue:
    """
        递归保留已知业务字段，遮盖敏感或未知字段，并限制展开的层数和数量。

    :param value: 已从有限 JSON 中解析出的值，不接受任意业务对象。
    :param field_name: 当前字段名，用于决定是否允许保留它的值。
    :param depth: 当前展开层数，过深时不再读取内部内容。
    :return: 可直接交给安全 JSON 格式器的脱敏副本，不修改原请求或响应。
    """
    # 1. 先看字段是否在允许清单中；未知字段整体遮盖，不向下读取其中的数据。
    if field_name and field_name not in _SAFE_FIELDS:
        return "[REDACTED]"
    if depth > 4:
        return "[MAX_DEPTH]"
    # 2. 已知的对象和数组最多展开有限项，剩余项用标记说明。
    if type(value) is dict:
        source = cast(dict[str, object], value)
        result: dict[str, JsonValue] = {}
        redacted_fields = 0
        for key, item in islice(source.items(), 40):
            if key in _SAFE_FIELDS or key in _REDACTED_FIELDS:
                result[key] = _summarize(item, field_name=key, depth=depth + 1)
            else:
                redacted_fields += 1
        if redacted_fields:
            result["_redacted_fields"] = redacted_fields
        if len(source) > 40:
            result["_truncated"] = True
        return result
    if type(value) is list:
        items = cast(list[object], value)
        result_items = [_summarize(item, field_name=field_name, depth=depth + 1) for item in items[:20]]
        if len(items) > 20:
            result_items.append("[TRUNCATED]")
        return result_items
    # 3. 字符串只保留合规的机器字段；根部字符串、data 文本和伪装成数字的原文都遮盖。
    if isinstance(value, str):
        if field_name in {"id", "user_id", "role_id", "role_ids", "permission_id", "permission_ids",
                          "bound_role_ids", "effective_role_ids"}:
            if re.fullmatch(r"(?:[URP][A-Z0-9]{14}|UR[A-Z0-9]{13}|RP[A-Z0-9]{13})", value) is None:
                return "[REDACTED]"
        elif field_name == "request_id":
            if re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value) is None:
                return "[REDACTED]"
        elif field_name in {"key", "keys", "role_keys", "permission_keys", "permissions", "effective_permissions",
                            "scene", "token_type"}:
            if re.fullmatch(r"[a-z][a-z0-9_]*(?::[a-z][a-z0-9_]*){0,3}", value) is None:
                return "[REDACTED]"
        elif field_name.endswith("_at"):
            if re.fullmatch(r"[0-9T:Z+.\-]{10,40}", value) is None:
                return "[REDACTED]"
        elif field_name in {"page", "page_size", "total", "code", "tier", "status", "expected_version",
                            "level", "role_level"}:
            if re.fullmatch(r"[0-9]{1,10}", value) is None:
                return "[REDACTED]"
        else:
            return "[REDACTED]"
    # 4. 合规标量仍使用已有安全规则，日期和其他固定文本也有长度限制。
    safe = _safe_value(value, field_name=field_name)
    return safe[:256] + "...[TRUNCATED]" if isinstance(safe, str) and len(safe) > 256 else safe


def summarize_log_data(value: object, *, keep_response_message: bool = False) -> JsonValue:
    """
        按同一白名单生成日志或审计摘要，遮盖秘密并将结果限制在 4 KiB 内。

    :param value: 已解析的 JSON 数据；None 表示没有需要记录的数据。
    :param keep_response_message: True 仅保留响应最外层的普通提示，不放开嵌套自由文本。
    :return: 脱敏副本；过大时返回固定省略原因，不返回原始对象。
    """
    # 1. 保留采集器自己的省略说明；固定原因和数字长度不能夹带正文。
    if isinstance(value, dict) and isinstance(value.get("_omitted"), str) and value.get("_omitted") in {
        "body_too_large", "body_incomplete", "non_json_or_invalid_json", "summary_too_large", "query_too_large",
    }:
        omitted: dict[str, JsonValue] = {"_omitted": value["_omitted"]}
        if type(value.get("bytes")) is int and value["bytes"] >= 0:
            omitted["bytes"] = value["bytes"]
        return omitted
    # 2. 所有普通数据都逐层脱敏；外层响应提示仍经过凭据文本过滤。
    safe = _summarize(value)
    if (keep_response_message and isinstance(value, dict) and isinstance(safe, dict)
            and isinstance(value.get("message"), str)):
        safe["message"] = _safe_value(value["message"], field_name="message")
    # 3. 用实际 UTF-8 字节数限制落盘大小，中文不能按字符数冒充字节数。
    if len(json.dumps(safe, ensure_ascii=False).encode("utf-8")) > SUMMARY_MAX_BYTES:
        return {"_omitted": "summary_too_large"}
    return safe


class _JsonLogBody:
    """
        暂存一侧已经收发的有限 JSON 字节，超大、未完整或非 JSON 时只留下省略说明。
    """

    def __init__(self) -> None:
        """
            初始化本次请求专用的缓冲区，不打开文件或读取网络。

        :return: 无返回值，此时尚未收到正文。
        """
        # 每个请求各有两份独立缓冲区，不与其他请求共用正文或密码。
        self.buffer = bytearray()  # 应用已经读到或成功发出的有限正文。
        self.total_bytes = 0  # 实际观察到的字节数，超过上限后仍只计数。
        self.complete = False  # 是否已经观察到正文最后一段。

    def append(self, body: bytes, complete: bool) -> None:
        """
            旁观一段正文；超过上限就清空缓冲，只保留长度与完成状态。

        :param body: 下游已接收或成功发送的本段字节。
        :param complete: True 表示这是本侧正文的最后一段。
        :return: 无返回值，不改变交给业务或客户端的原消息。
        """
        # 先数实际字节，再决定暂存或清空；以后继续收到大正文也不会重新积累。
        self.total_bytes += len(body)
        if self.total_bytes <= BODY_CAPTURE_MAX_BYTES:
            self.buffer.extend(body)
        else:
            self.buffer.clear()
        self.complete = complete

    def read_json(self, content_type: str) -> object:
        """
            只解析完整、未超大且声明为 JSON 的正文，其他情况返回 None。

        :param content_type: 本侧实际的 Content-Type，不包含任何正文内容。
        :return: 已解析的 JSON 值；空、未完整、超大、非 JSON 或非法 JSON 返回 None。
        """
        # 不尝试解释表单、文件或半截 JSON，避免猜错格式而把原文写进日志。
        media_type = content_type.split(";", 1)[0].strip().lower()
        if (not self.complete or not self.total_bytes or self.total_bytes > BODY_CAPTURE_MAX_BYTES
                or not (media_type == "application/json" or media_type.endswith("+json"))):
            return None
        try:
            return json.loads(self.buffer)
        except (ValueError, UnicodeError, RecursionError):
            return None

    def summary(self, parsed: object, *, keep_response_message: bool = False) -> JsonValue:
        """
            将已解析正文脱敏后限制到 4 KiB，无法记录时给出不含正文的原因。
            响应可保留最外层的业务提示，例如“查询成功”；请求和嵌套文本仍然遮盖。

        :param parsed: read_json 得到的 JSON 值；None 表示没有可解析正文。
        :param keep_response_message: 是否保留响应最外层的 message；True 保留普通业务提示，
            False 按请求摘要规则遮盖。此选项不放开 data 内的 message 或其他敏感字段。
        :return: 脱敏摘要、None 或正文省略原因，不返回任何原始字节。
        """
        # 1. 正文不适合展开时只记原因和长度，不把它作为字符串退回日志。
        if not self.total_bytes:
            return None
        if self.total_bytes > BODY_CAPTURE_MAX_BYTES:
            return {"_omitted": "body_too_large", "bytes": self.total_bytes}
        if not self.complete:
            return {"_omitted": "body_incomplete"}
        if parsed is None:
            return {"_omitted": "non_json_or_invalid_json"}
        # 2. 先遮盖正文敏感值；只有响应最外层的 message 保留正常业务提示。
        return summarize_log_data(parsed, keep_response_message=keep_response_message)


class HttpLogDetails:
    """
        汇总本次请求的安全业务线索；只供日志使用，不代替权限、参数或密码校验。
    """

    def __init__(self, request: Request,
                 log_hmac_key: bytes | None
                 ) -> None:
        """
            保存本次请求及独立日志密钥，建立两侧有限正文缓冲区。

        :param request: 当前请求，仅从服务端路由和已认证状态读取身份。
        :param log_hmac_key: 独立 LOG_HMAC_KEY 的字节值，不是登录或限流密钥。
        :return: 无返回值，不主动读取请求体。
        """
        # 密钥只留在内存用于计算指纹，不加入任何日志字段或异常正文。
        self.request = request
        self.log_hmac_key = log_hmac_key
        self.request_body = _JsonLogBody()
        self.response_body = _JsonLogBody()
        self.response_content_type = ""  # 在实际响应头成功发送后确定。
        self.created_user_id: str | None = None  # 成功响应里的新用户 ID，发送失败时也保留。
        self.created_role_id: str | None = None  # 成功响应里的新角色 ID，不从客户端输入猜测。

    def record_created_target(self, data: object) -> None:
        """
            从新建业务的成功结果中保存新 ID，不必让每个路由单独填写日志目标。
            由统一响应入口在发送前调用，因此创建成功后即使发送失败也能找到新对象。

        :param data: 服务返回并已装入成功响应的业务数据，支持响应模型或字典。
        :return: 无返回值；仅保存合规的新用户或角色 ID，不保存其他响应数据。
        """
        # 1. 只处理固定的新建接口；查询列表、拒绝响应和客户端传来的 ID 不属于新建结果。
        route_path = getattr(self.request.scope.get("route"), "path", "")
        if self.request.method != "POST":
            return
        if route_path in {"/api/v1/auth/register", "/api/v1/users/create"}:
            # 2. 注册和管理员新增用户都返回 data.user_id；普通用户资料不能冒充新建结果。
            user_id = data.get("user_id") if isinstance(data, dict) else getattr(data, "user_id", None)
            if isinstance(user_id, str) and re.fullmatch(USER_ID_PATTERN, user_id):
                self.created_user_id = user_id
        elif route_path == "/api/v1/roles/create":
            # 3. 新角色放在 data.role.id；只读取这个对象，不扫描权限或分页列表中的 ID。
            role = data.get("role") if isinstance(data, dict) else getattr(data, "role", None)
            role_id = role.get("id") if isinstance(role, dict) else getattr(role, "id", None)
            if isinstance(role_id, str) and re.fullmatch(ROLE_ID_PATTERN, role_id):
                self.created_role_id = role_id

    def observe_request(self, message: Message) -> None:
        """
            在业务已经读取请求消息后暂存有限正文，不增加一次读取。

        :param message: 服务端原样返回给下游的 ASGI 请求消息。
        :return: 无返回值，消息继续原样交给下游。
        """
        # 只旁观请求正文，断开连接等其他消息不当作正文解析。
        if message["type"] == "http.request":
            self.request_body.append(message.get("body", b""), not message.get("more_body", False))

    def observe_response(self, message: Message) -> None:
        """
            在消息成功发送后记录 JSON 类型和有限正文，失败发送不会被记成已返回。

        :param message: 已由下游 send 成功接收的 ASGI 响应消息。
        :return: 无返回值，不改动任何响应头或正文。
        """
        # 响应头决定格式；正文按原来分段顺序观察，文件和流不会被强制转换为 JSON。
        if message["type"] == "http.response.start":
            headers = message.get("headers", [])
            self.response_content_type = next(
                (value.decode("latin-1") for key, value in headers if key.lower() == b"content-type"), ""
            )
        elif message["type"] == "http.response.body":
            self.response_body.append(message.get("body", b""), not message.get("more_body", False))

    def audit_request_data(self) -> dict[str, JsonValue]:
        """
            在审计提交前取已读请求的脱敏副本，查询参数和 JSON 正文分开放置。

        :return: query/body 两部分；没有查询时 query 为空对象，没有正文时 body 为空。
        """
        # 1. 正文只用中间件已经旁观到的内容；不会主动调用 request.body 或 request.json。
        parsed = self.request_body.read_json(self.request.headers.get("content-type", ""))
        body = self.request_body.summary(parsed)
        # 2. GET 和 POST 都可能带查询参数；超出采集上限只记原因。
        query_bytes = self.request.scope.get("query_string", b"")
        query: JsonValue = {}
        if len(query_bytes) > BODY_CAPTURE_MAX_BYTES:
            query = {"_omitted": "query_too_large", "bytes": len(query_bytes)}
        elif query_bytes:
            query = summarize_log_data(dict(self.request.query_params))
        # 3. 合计也不得超过摘要上限，不能让两份各自合规的摘要翻倍占用空间。
        result = {"query": query, "body": body}
        if len(json.dumps(result, ensure_ascii=False).encode("utf-8")) > SUMMARY_MAX_BYTES:
            return {"query": {}, "body": {"_omitted": "summary_too_large"}}
        return result

    def password_fingerprint(self) -> str | None:
        """
            为四种设置新密码的接口生成可比较指纹，不记录密码原文或登录输入。

        :return: 独立密钥 HMAC-SHA256 的前 32 个十六进制字符；不适用或无密钥时为空。
        """
        # 1. 只接受服务端登记的固定路由，不能靠请求字段指定记录哪一个密码。
        route = self.request.scope.get("route")
        operation = _PASSWORD_OPERATIONS.get(getattr(route, "name", ""))
        if (self.request.method != "POST" or operation is None
                or getattr(route, "path", "") != operation[0] or not self.log_hmac_key):
            return None
        # 2. 从有限完整 JSON 取新密码；登录密码和 current_password 没有登记，所以不会进入这里。
        parsed = self.request_body.read_json(self.request.headers.get("content-type", ""))
        password = parsed.get(operation[1]) if isinstance(parsed, dict) else None
        if not isinstance(password, str) or not password:
            return None
        # 3. 同密钥同原文得到同值，可比较重复输入；它不是可解密密文，也不代替 Argon2id。
        return hmac.new(
            self.log_hmac_key, b"password\x00" + password.encode("utf-8"), hashlib.sha256
        ).hexdigest()[:32]

    def fields(self) -> dict[str, object]:
        """
            在请求结束时组装脱敏正文、目标及新密码指纹；普通请求没有的字段为 None。
            失败请求中的目标只表示请求指定的对象，不表示权限通过或变更成功。
            动作直接读取服务端的路由函数名，例如 reset_user_password，新增路由无需额外登记。

        :return: 日志附加字段；不改变当前用户身份、业务状态或数据库审计。
        """
        # 1. 先解析已经观察到的有限正文，GET 参数用同一清单脱敏，不记录原始 URL。
        request = self.request
        parsed = self.request_body.read_json(request.headers.get("content-type", ""))
        body = parsed if isinstance(parsed, dict) else {}
        query_bytes = request.scope.get("query_string", b"")
        query_too_large = len(query_bytes) > BODY_CAPTURE_MAX_BYTES
        query = dict(request.query_params) if request.method == "GET" and not query_too_large else {}
        response = self.response_body.read_json(self.response_content_type)
        route = request.scope.get("route")
        route_path = getattr(route, "path", "")
        route_name = getattr(route, "name", None)

        # 2. 操作人仍由认证依赖记录；现有对象从请求取，新对象从成功结果取。
        # 新建失败不能采信请求伪造的 ID；总列表也没有唯一目标，不扫描列表里的对象。
        target_user_id = self.created_user_id
        target_role_id = self.created_role_id
        inputs = query if request.method == "GET" else body
        if (route_path.startswith("/api/v1/users/")
                and route_path not in {"/api/v1/users/create", "/api/v1/users/list"}):
            target_user_id = inputs.get("user_id")
        if (route_path.startswith("/api/v1/roles/")
                and route_path not in {"/api/v1/roles/create", "/api/v1/roles/list"}):
            target_role_id = inputs.get("role_id")
        if route_path == "/api/v1/me/password/change":
            # 本人改密只信完整认证后的当前用户，不能由请求里的 user_id 指定其他人。
            target_user_id = getattr(request.state, "user_id", None)
        if not isinstance(target_user_id, str) or not re.fullmatch(USER_ID_PATTERN, target_user_id):
            target_user_id = None
        if not isinstance(target_role_id, str) or not re.fullmatch(ROLE_ID_PATTERN, target_role_id):
            target_role_id = None

        # 3. 只对指定设置密码操作的新密码做指纹；同密钥同原文得同值，换用户也可比对。
        # 加入 password 加零字节的用途标识；不是可解密密文，也不替代数据库 Argon2id 哈希。
        fingerprint = self.password_fingerprint()

        # 4. GET 查询也先检查整体大小，不能为写日志无限展开 URL 参数或丢掉整条关联记录。
        request_data = self.request_body.summary(parsed)
        if request.method == "GET" and query_bytes:
            request_data = {"_omitted": "query_too_large", "bytes": len(query_bytes)}
            if not query_too_large:
                request_data = _summarize(query)
                if len(json.dumps(request_data, ensure_ascii=False).encode("utf-8")) > SUMMARY_MAX_BYTES:
                    request_data = {"_omitted": "summary_too_large"}
        # 5. 返回的是脱敏副本和机器标识；响应最外层保留业务提示，其他敏感值仍遮盖。
        return {
            "action": route_name,
            "target_user_id": target_user_id,
            "target_role_id": target_role_id,
            "reason_code": getattr(request.state, "reason_code", None),
            "request_data": request_data,
            "response_data": self.response_body.summary(response, keep_response_message=True),
            "password_fingerprint": fingerprint,
        }
