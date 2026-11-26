#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    PostgreSQL 操作审计模型，统一记录账号安全和权限管理的操作事实与脱敏请求、响应。
#    记录随业务事务新增，不提供修改、删除入口；实际 HTTP 收发结果查看同 request_id 的文件日志。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/16    XTN       V1.000        新建
# --------------------------------------------------------------------------------------------------

import re
from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, Index, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.core.audit import (
    AuditCategory,
    AuditOutcome,
    AuditSource,
    sanitize_audit_request,
    sanitize_audit_state,
    validate_audit_action,
    validate_audit_reason,
    validate_audit_request_id,
)
from app.core.ids import (
    AUDIT_ID_LENGTH,
    ENTITY_ID_LENGTH,
    OPERATION_AUDIT_ID_PATTERN,
    ROLE_ID_PATTERN,
    USER_ID_PATTERN,
    new_audit_id,
    require_audit_id,
    require_entity_id,
)
from app.core.logging.details import summarize_log_data
from app.models.postgres.base import Base


class OperationAuditEvent(Base):
    """
        一条账号安全或权限管理操作的持久化证据，共 16 个字段，缺失的信息保留为空。
        操作人和被操作人分别保存；没有用户身份的注册或线下入口不能冒用目标用户身份。
    """

    __tablename__ = "operation_audit_events"  # 默认唯一审计表；普通查询仍只写文件日志。
    __table_args__ = (
        CheckConstraint(f"id ~ '{OPERATION_AUDIT_ID_PATTERN}'", name="id_format"),
        CheckConstraint(f"user_id IS NULL OR user_id ~ '{USER_ID_PATTERN}'", name="user_id_format"),
        CheckConstraint(f"target_user_id IS NULL OR target_user_id ~ '{USER_ID_PATTERN}'",
                        name="target_user_id_format"),
        CheckConstraint(f"target_role_id IS NULL OR target_role_id ~ '{ROLE_ID_PATTERN}'",
                        name="target_role_id_format"),
        CheckConstraint("category IN ('account', 'permission')", name="category_valid"),
        CheckConstraint("outcome IN ('succeeded', 'denied', 'failed')", name="outcome_valid"),
        CheckConstraint("source IN ('http', 'service', 'job', 'operator', 'migration')", name="source_valid"),
        CheckConstraint(
            "char_length(action) BETWEEN 3 AND 120 AND action ~ '^[a-z][a-z0-9]*([._:-][a-z0-9]+)*$'",
            name="action_format",
        ),
        CheckConstraint(
            "reason_code IS NULL OR (char_length(reason_code) BETWEEN 2 AND 80 "
            "AND reason_code ~ '^[a-z][a-z0-9_]*$')", name="reason_code_format",
        ),
        CheckConstraint(
            "char_length(request_id) BETWEEN 1 AND 128 AND request_id ~ '^[A-Za-z0-9][A-Za-z0-9:._-]*$'",
            name="request_id_format",
        ),
        CheckConstraint("password_fingerprint IS NULL OR password_fingerprint ~ '^[0-9a-f]{32}$'",
                        name="password_fingerprint_format"),
        CheckConstraint("request_data IS NULL OR jsonb_typeof(request_data) = 'object'", name="request_data_object"),
        CheckConstraint("response_data IS NULL OR jsonb_typeof(response_data) = 'object'", name="response_data_object"),
        CheckConstraint("before_state IS NULL OR jsonb_typeof(before_state) = 'object'", name="before_state_object"),
        CheckConstraint("after_state IS NULL OR jsonb_typeof(after_state) = 'object'", name="after_state_object"),
        CheckConstraint("outcome = 'succeeded' OR after_state IS NULL", name="after_state_success_only"),
        Index("ix_operation_audit_created_id", "created_at", "id"),
        Index("ix_operation_audit_user_created", "user_id", "created_at"),
        Index("ix_operation_audit_target_user_created", "target_user_id", "created_at"),
        Index("ix_operation_audit_target_role_created", "target_role_id", "created_at"),
        Index("ix_operation_audit_request_id", "request_id"),
        Index("ix_operation_audit_action_outcome_created", "action", "outcome", "created_at"),
    )

    # OA + 北京时间 YYMMDDHHMMSSmm + 6 位随机字符，共 22 位；它是审计 ID，不是请求 ID。
    id: Mapped[str] = mapped_column(String(AUDIT_ID_LENGTH, collation="C"), primary_key=True,
                                    default=lambda: new_audit_id("OA"))
    # account 为账号安全，permission 为权限管理；同表查询时先按此字段区分业务。
    category: Mapped[str] = mapped_column(String(16), nullable=False)
    # 稳定机器动作，例如 account_security.password.admin_reset，不翻译或拼接用户输入。
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    # succeeded 成功、denied 拒绝、failed 失败；不能用“通过权限检查”代替业务成功。
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    # 可检索的内部原因标识；没有额外原因时为空，不存异常正文。
    reason_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    # 操作人的已认证用户 ID；匿名注册、没有在线身份的线下操作为空。
    user_id: Mapped[str | None] = mapped_column(String(ENTITY_ID_LENGTH, collation="C"), nullable=True)
    # 被新增、改密、停用等操作影响的用户；没有唯一目标时为空。
    target_user_id: Mapped[str | None] = mapped_column(String(ENTITY_ID_LENGTH, collation="C"), nullable=True)
    # 本次被创建、修改或绑定的角色；未操作角色时为空。
    target_role_id: Mapped[str | None] = mapped_column(String(ENTITY_ID_LENGTH, collation="C"), nullable=True)
    # HTTP、内部服务、任务或受控线下入口；不额外增加服务名、环境名。
    source: Mapped[str] = mapped_column(String(16), nullable=False, default=AuditSource.SERVICE.value)
    # 已经脱敏的 query/body；密码字段名可保留，值只能是 [REDACTED]。
    request_data: Mapped[dict[str, Any] | None] = mapped_column(JSONB(none_as_null=True), nullable=True)
    # 提交前确定的业务响应快照；不代表客户端已经收到，不能在发送后回头更新此行。
    response_data: Mapped[dict[str, Any] | None] = mapped_column(JSONB(none_as_null=True), nullable=True)
    # 仅新密码设置操作产生的 32 位 HMAC 指纹；登录密码、旧密码和其他操作为空。
    password_fingerprint: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # 操作前白名单状态；绝不保存密码、数据库密码哈希或整份 ORM 对象。
    before_state: Mapped[dict[str, Any] | None] = mapped_column(JSONB(none_as_null=True), nullable=True)
    # 操作成功后的白名单状态；失败或拒绝为空，禁止把尝试修改的值当成已完成状态。
    after_state: Mapped[dict[str, Any] | None] = mapped_column(JSONB(none_as_null=True), nullable=True)
    # 自动读取当前入口的关联 ID，与响应及文件日志对应；无级联外键，历史不随账号删除。
    request_id: Mapped[str] = mapped_column(String(128), nullable=False)
    # 数据库生成的带时区时间；展示时转北京时间，SQL 范围查询仍用 timestamptz。
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    @validates("category", "outcome", "source")
    def validate_choice(self, key: str,
                        value: str
                        ) -> str:
        """
            将分类、结果和来源限制为已有业务枚举，拼错时立即报错。

        :param key: SQLAlchemy 当前赋值的字段名，决定使用哪一组枚举。
        :param value: 待保存的机器标识或对应字符串枚举。
        :return: 已校验的字符串值。
        :raises ValueError: 值不在对应业务枚举中。
        """
        # 每个字段只接受自己的业务选项，不能把 http 当成操作结果保存。
        choices = {"category": AuditCategory, "outcome": AuditOutcome, "source": AuditSource}
        return choices[key](value).value

    @validates("id", "action", "reason_code", "request_id", "password_fingerprint",
               "user_id", "target_user_id", "target_role_id")
    def validate_identifier(self, key: str,
                            value: str | None
                            ) -> str | None:
        """
            检查业务 ID、动作、原因、关联 ID 和密码指纹的格式，不接受秘密正文。

        :param key: 当前赋值的标识字段名。
        :param value: 待保存的字符串；操作人、目标、原因和指纹允许为空。
        :return: 符合所属字段规则的原值。
        :raises ValueError: 必填值为空，或标识格式不符合规则。
        """
        # 1. 没有在线操作人或唯一目标时允许缺省；审计 ID、动作和关联 ID 不能静默漏记。
        if value is None:
            if key in {"reason_code", "password_fingerprint", "user_id", "target_user_id", "target_role_id"}:
                return None
            raise ValueError("audit ID, action and request ID are required")
        # 2. 各种标识使用自己的既有规则；审计不能误用 UUID 或用户 ID。
        if key == "id":
            return require_audit_id(value, "OA")
        if key in {"user_id", "target_user_id", "target_role_id"}:
            return require_entity_id(value, "R" if key == "target_role_id" else "U")
        if key == "action":
            return validate_audit_action(value)
        if key == "reason_code":
            return validate_audit_reason(value)
        if key == "request_id":
            return validate_audit_request_id(value)
        # 指纹必须是 HMAC 输出的固定 32 位小写十六进制，不能误传原密码。
        if re.fullmatch(r"[0-9a-f]{32}", value) is None:
            raise ValueError("invalid password fingerprint")
        return value

    @validates("request_data", "response_data", "before_state", "after_state")
    def validate_data(self, key: str,
                      value: dict[str, Any] | None
                      ) -> dict[str, Any] | None:
        """
            请求响应先脱敏，前后状态严格拒绝秘密，二者按不同用途检查。

        :param key: 当前赋值的请求、响应或前后状态字段。
        :param value: 业务提供的 JSON 对象；缺失时为空。
        :return: 安全副本，不修改调用方提供的数据。
        :raises ValueError: 前后状态含秘密或超限，或响应不是 JSON 对象。
        """
        # 1. 前后状态由业务白名单构造，发现秘密就回滚，不能用脱敏掩盖业务编程错误。
        if key in {"before_state", "after_state"}:
            return sanitize_audit_state(value)
        if key == "request_data":
            return sanitize_audit_request(value)
        # 2. 响应允许保留普通提示，其余字段与文件日志共用递归脱敏和大小限制。
        if value is None:
            return None
        safe = summarize_log_data(value, keep_response_message=True)
        if not isinstance(safe, dict):
            raise ValueError("audit response must be a JSON object")
        return safe
