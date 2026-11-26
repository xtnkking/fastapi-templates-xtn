#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    用 audit_success 和 audit_denied 统一记录账号安全与权限管理操作。
#    从日志采集结果中取请求参数和密码指纹，保存提交前的业务结果。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/16    XTN       V1.000        新建
# 2026/10/16    XTN       V1.001        统一审计入口前缀，自动确定分类、身份、来源和响应快照
# 2026/10/19    XTN       V1.002        精简审计注释，说明记录内容和保存时机
# 2026/10/20    XTN       V1.003        登录身份统一使用 login_info，认证依赖改用直观入口
# --------------------------------------------------------------------------------------------------

import logging
from collections.abc import Mapping
from typing import Any

from fastapi.encoders import jsonable_encoder
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.access.authorization import AuthorizationContext
from app.core.audit import (
    AccountAuditAction,
    AuditCategory,
    AuditOutcome,
    AuditSource,
    RbacAuditAction,
    get_audit_request_id,
)
from app.core.codes import BusinessCode
from app.core.exceptions import AppError
from app.core.i18n.language import DEFAULT_LOCALE, locale_for_request
from app.core.i18n.messages import MessageKey, translate_for_locale
from app.core.ids import new_audit_id
from app.core.logging.context import current_http_details
from app.core.logging.details import summarize_log_data
from app.core.logging.events import safe_exception_metadata, safe_log
from app.models.postgres.operation_audit import OperationAuditEvent

logger = logging.getLogger(__name__)


class AuditService:
    """
        记录账号和权限操作；成功审计随业务保存，拒绝审计在回滚后另存。
    """

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        """
            保存创建审计会话的工厂，不立即连接数据库。

        :param session_factory: 与业务使用同一 PostgreSQL 的异步会话工厂。
        :return: 无返回值；会话工厂已保存。
        """
        # 只在补写拒绝审计时另开会话，成功审计使用业务会话。
        self._session_factory = session_factory

    @staticmethod
    def _response_snapshot(*,
                           message_key: MessageKey,
                           data: object = None,
                           code: int | BusinessCode = BusinessCode.OK
                           ) -> dict[str, Any]:
        """
            把业务结果整理成脱敏字典，供审计保存；实际响应仍由路由返回。

        :param message_key: 与路由一致的提示消息键。
        :param data: 本次业务结果；没有时为空。
        :param code: 与路由一致的五位业务码，默认 20000。
        :return: 不超过 4 KiB 的脱敏响应数据，不代表已发送给客户端。
        """
        # 1. 使用本次请求的语言和请求 ID；线下操作默认中文。
        details = current_http_details()
        locale = locale_for_request(details.request) if details is not None else DEFAULT_LOCALE
        snapshot = {
            "code": int(code),
            "message": translate_for_locale(locale, message_key),
            "data": jsonable_encoder(data),
            "request_id": get_audit_request_id(),
        }
        # 2. 按文件日志的规则脱敏，并限制数据大小。
        safe = summarize_log_data(snapshot, keep_response_message=True)
        if not isinstance(safe, dict):
            raise ValueError("audit response snapshot must be an object")
        return safe

    @staticmethod
    def _build_event(*,
                     action: AccountAuditAction | RbacAuditAction | str,
                     context: AuthorizationContext | None = None,
                     outcome: str = AuditOutcome.SUCCEEDED,
                     reason_code: str | None = None,
                     target_user_id: str | None = None,
                     target_role_id: str | None = None,
                     source: AuditSource | None = None,
                     before_state: Mapping[str, object] | None = None,
                     after_state: Mapping[str, object] | None = None,
                     response_data: Mapping[str, object] | None = None
                     ) -> OperationAuditEvent:
        """
            整理一条审计，自动补上请求参数和新密码指纹；这里只构造记录，不写数据库。

        :param action: 账号或权限动作枚举；权限依赖的动态拒绝动作只接受 api. 前缀。
        :param context: 已验证的当前用户上下文；匿名注册、线下恢复时为空。
        :param outcome: succeeded 成功、denied 拒绝或 failed 明确失败。
        :param reason_code: 固定原因标识，无额外原因时为空。
        :param target_user_id: 被操作用户，无唯一用户目标时为空。
        :param target_role_id: 被操作角色，无角色目标时为空。
        :param source: 非 HTTP 入口可明确指定来源；不传时先用身份上下文，再识别当前 HTTP 请求。
        :param before_state: 允许留档的修改前状态，不含秘密字段。
        :param after_state: 允许留档的修改后状态；拒绝或失败时为空。
        :param response_data: 提交前确定的业务结果；没有 HTTP 结果时可为空。
        :return: 检查通过的审计模型，尚未加入数据库会话。
        :raises RuntimeError: 入口没有绑定有效关联上下文。
        :raises ValueError: 审计事实格式错误，或失败事件带有操作后状态。
        """
        # 1. 根据动作区分账号操作和权限操作，拒绝未知动作。
        if isinstance(action, AccountAuditAction):
            category = AuditCategory.ACCOUNT
        elif isinstance(action, RbacAuditAction) or isinstance(action, str) and action.startswith("api."):
            category = AuditCategory.PERMISSION
        else:
            raise ValueError("audit action must be a built-in enum or an api. denial action")
        action_value = action.value if isinstance(action, (AccountAuditAction, RbacAuditAction)) else action

        # 2. 未成功的操作不能记录“修改后状态”，避免把尝试值当成已保存的值。
        if outcome != AuditOutcome.SUCCEEDED and after_state is not None:
            raise ValueError("unsuccessful audit cannot include after_state")
        details = current_http_details()
        if source is None:
            source = context.audit_source if context is not None else (
                AuditSource.HTTP if details is not None else AuditSource.SERVICE
            )
        # 3. 从已验证身份取操作人，从当前日志上下文取脱敏请求和密码指纹。
        return OperationAuditEvent(
            id=new_audit_id("OA"),
            category=category,
            action=action_value,
            outcome=outcome,
            reason_code=reason_code,
            user_id=context.login_info.user_id if context is not None else None,
            target_user_id=target_user_id,
            target_role_id=target_role_id,
            source=source,
            request_data=details.audit_request_data() if details is not None else None,
            response_data=dict(response_data) if response_data is not None else None,
            password_fingerprint=details.password_fingerprint() if details is not None else None,
            before_state=dict(before_state) if before_state is not None else None,
            after_state=dict(after_state) if after_state is not None else None,
            request_id=get_audit_request_id(),
        )

    @staticmethod
    def audit_success(session: AsyncSession, *,
                      action: AccountAuditAction | RbacAuditAction,
                      context: AuthorizationContext | None = None,
                      target_user_id: str | None = None,
                      target_role_id: str | None = None,
                      message_key: MessageKey | None = None,
                      data: object = None,
                      code: int | BusinessCode = BusinessCode.OK,
                      reason_code: str | None = None,
                      before_state: Mapping[str, object] | None = None,
                      after_state: Mapping[str, object] | None = None,
                      source: AuditSource | None = None
                      ) -> OperationAuditEvent:
        """
            把成功审计加入业务事务，随业务一起保存或撤回。

        :param session: 调用方当前正在使用的数据库事务会话。
        :param action: 本次账号或权限操作的固定枚举，自动决定审计分类。
        :param context: 已验证的当前用户；匿名注册、线下恢复时不传。
        :param target_user_id: 被操作用户 ID，没有用户目标时为空。
        :param target_role_id: 被操作角色 ID，没有角色目标时为空。
        :param message_key: 与路由一致的成功提示键；线下操作没有 HTTP 响应时不传。
        :param data: 与路由一致的业务结果，内部会自动脱敏。
        :param code: 与路由一致的五位业务码，默认成功码；新建资源时传 CREATED。
        :param reason_code: 固定原因码，不填用户输入或异常原文。
        :param before_state: 业务明确允许记录的修改前状态，没有时为空。
        :param after_state: 业务已经完成的修改后状态，没有时为空。
        :param source: 线下命令等入口明确填写来源；HTTP 和身份上下文会自动识别。
        :return: 已加入当前会话但尚未提交的审计记录。
        :raises ValueError: 动作、状态或快照内容不符合审计规则。
        :raises RuntimeError: 入口没有绑定有效的请求或操作关联 ID。
        """
        # 1. 成功审计只接受固定动作；api. 开头的名称只用于权限拒绝。
        if not isinstance(action, (AccountAuditAction, RbacAuditAction)):
            raise ValueError("successful audit requires a built-in action enum")
        # 2. 有成功提示才整理响应数据，线下操作可以留空。
        response = None if message_key is None else AuditService._response_snapshot(
            message_key=message_key, data=data, code=code,
        )
        # 3. 构造记录，自动补齐分类、操作人和请求信息。
        event = AuditService._build_event(
            action=action, context=context, reason_code=reason_code,
            target_user_id=target_user_id, target_role_id=target_role_id, source=source,
            before_state=before_state, after_state=after_state, response_data=response,
        )
        # 4. add 只加入会话，最终由业务统一提交或回滚。
        session.add(event)
        return event

    async def audit_denied(self, *, error: AppError,
                           action: AccountAuditAction | RbacAuditAction | str,
                           context: AuthorizationContext | None = None,
                           target_user_id: str | None = None,
                           target_role_id: str | None = None,
                           source: AuditSource | None = None
                           ) -> None:
        """
            业务回滚后另存拒绝审计；保存失败也不改变原业务错误。

        :param error: 原业务异常，自动取拒绝原因、业务码和公开消息；5xx 故障不记为用户拒绝。
        :param action: 被拒绝的动作枚举；权限依赖也可传 api. 开头的路由动作。
        :param context: 已认证操作人上下文，未登录或线下入口不传。
        :param target_user_id: 请求涉及的被操作用户，无目标时为空。
        :param target_role_id: 请求涉及的角色，无目标时为空。
        :param source: 非 HTTP 入口可明确指定来源，其余从上下文自动识别。
        :return: 无返回值；尝试保存拒绝审计，不改变原业务异常。
        """
        # 1. 数据库掉线等 5xx 是服务故障，不记成用户被拒绝。
        if error.status_code >= 500:
            return
        try:
            # 2. 原业务已回滚，另开事务保存拒绝原因和响应数据。
            response = self._response_snapshot(
                message_key=error.message_key, code=error.business_code,
            )
            async with self._session_factory() as session:
                async with session.begin():
                    session.add(self._build_event(
                        action=action,
                        context=context,
                        outcome=AuditOutcome.DENIED,
                        reason_code=error.reason_code,
                        target_user_id=target_user_id,
                        target_role_id=target_role_id,
                        source=source,
                        response_data=response,
                    ))
        except Exception as exc:
            # 3. 审计失败只记安全日志，不覆盖原错误，也不能因此放行业务。
            safe_log(logger, logging.ERROR, "audit.write.failed", extra={
                "audit_action": action, **safe_exception_metadata(exc),
            })
