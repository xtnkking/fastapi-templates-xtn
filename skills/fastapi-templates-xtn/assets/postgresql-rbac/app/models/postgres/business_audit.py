#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    通用业务审计的 PostgreSQL 模型，只追加证据，不修改既有事件。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        说明业务审计各字段、载荷限制和检索索引用途
# 2026/09/23    XTN       V1.002        类方法参数逐行对齐，整理业务调用排版
# 2026/10/09    XTN       V1.003        业务审计 ID 的长度及格式统一引用核心规则
# 2026/10/10    XTN       V1.004        通用审计发起者字段、约束和索引统一使用 operator
# 2026/10/10    XTN       V1.005        区分操作人、被操作人、非用户来源及目标对象并同步约束索引
# 2026/10/13    XTN       V1.006        补齐字段校验函数的通俗说明和逻辑步骤
# --------------------------------------------------------------------------------------------------


from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, Index, SmallInteger, String, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, validates
from sqlalchemy.schema import conv

from app.core.audit import AuditSource, validate_audit_reason, validate_audit_request_id
from app.core.business_audit import (
    BUSINESS_AUDIT_ACTION_PATTERN,
    MAX_BUSINESS_AUDIT_CONTEXT_BYTES,
    BusinessAuditOutcome,
    BusinessAuditSourceType,
    require_business_event_id,
    require_business_identifier,
    require_business_machine_name,
    sanitize_business_payload,
)
from app.core.ids import (
    AUDIT_ID_LENGTH,
    BUSINESS_AUDIT_ID_PATTERN,
    ENTITY_ID_LENGTH,
    USER_ID_PATTERN,
    require_entity_id,
)
from app.models.postgres.base import Base


class BusinessAuditEvent(Base):
    """
        分别记录操作人、被操作人、非用户来源、目标对象及执行结果。
        事件仅追加，不提供更新或删除入口；拒绝或失败事件不能含成功后的状态。
    """

    # 主业务的追加式证据表；具体记录哪些动作和字段由业务动作目录决定。
    __tablename__ = "business_audit_events"
    # 约束身份配对、目标标识、动作格式与载荷大小，不替代业务动作白名单校验。
    __table_args__ = (
        CheckConstraint(
            f"id ~ '{BUSINESS_AUDIT_ID_PATTERN}'",
            name=conv("ck_business_audit_id_format"),
        ),
        CheckConstraint(
            "domain ~ '^[a-z][a-z0-9_]{0,63}$'",
            name=conv("ck_business_audit_domain_format"),
        ),
        CheckConstraint(
            "action ~ '^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*){2,}$' "
            "AND length(action) <= 120",
            name=conv("ck_business_audit_action_format"),
        ),
        CheckConstraint(
            "split_part(action, '.', 1) = domain",
            name=conv("ck_business_audit_action_domain"),
        ),
        CheckConstraint(
            "outcome IN ('succeeded', 'failed', 'denied')",
            name=conv("ck_business_audit_outcome"),
        ),
        CheckConstraint(
            "reason_code ~ '^[a-z][a-z0-9_]{1,79}$'",
            name=conv("ck_business_audit_reason_format"),
        ),
        CheckConstraint(
            "source_type IN ('user', 'service', 'system', 'job', 'maintenance')",
            name=conv("ck_business_audit_source_type"),
        ),
        CheckConstraint(
            "(source_type = 'user' AND user_id IS NOT NULL AND source_id IS NULL) "
            "OR (source_type = 'system' AND user_id IS NULL AND source_id IS NULL) "
            "OR (source_type IN ('service', 'job', 'maintenance') "
            "AND user_id IS NULL AND source_id IS NOT NULL)",
            name=conv("ck_business_audit_source_identity"),
        ),
        CheckConstraint(
            f"user_id IS NULL OR user_id ~ '{USER_ID_PATTERN}'",
            name=conv("ck_business_audit_user_id_format"),
        ),
        CheckConstraint(
            "source_id IS NULL OR source_id ~ '^[A-Za-z0-9][A-Za-z0-9:_-]{0,127}$'",
            name=conv("ck_business_audit_source_id_format"),
        ),
        CheckConstraint(
            f"target_user_id IS NULL OR target_user_id ~ '{USER_ID_PATTERN}'",
            name=conv("ck_business_audit_target_user_id_format"),
        ),
        CheckConstraint(
            "target_type ~ '^[a-z][a-z0-9_]{0,63}$'",
            name=conv("ck_business_audit_target_type_format"),
        ),
        CheckConstraint(
            "target_id ~ '^[A-Za-z0-9][A-Za-z0-9:_-]{0,127}$'",
            name=conv("ck_business_audit_target_id_format"),
        ),
        CheckConstraint(
            "target_type <> 'user' OR (target_user_id IS NOT NULL AND target_user_id = target_id)",
            name=conv("ck_business_audit_user_target"),
        ),
        CheckConstraint(
            "entrypoint IN ('http', 'service', 'job', 'operator', 'migration')",
            name=conv("ck_business_audit_entrypoint"),
        ),
        CheckConstraint(
            "schema_version > 0",
            name=conv("ck_business_audit_schema_version"),
        ),
        CheckConstraint(
            "before_state IS NULL OR jsonb_typeof(before_state) = 'object'",
            name=conv("ck_business_audit_before_object"),
        ),
        CheckConstraint(
            "after_state IS NULL OR jsonb_typeof(after_state) = 'object'",
            name=conv("ck_business_audit_after_object"),
        ),
        CheckConstraint(
            "jsonb_typeof(context) = 'object'",
            name=conv("ck_business_audit_context_object"),
        ),
        CheckConstraint(
            "before_state IS NULL OR octet_length(before_state::text) <= 16384",
            name=conv("ck_business_audit_before_size"),
        ),
        CheckConstraint(
            "after_state IS NULL OR octet_length(after_state::text) <= 16384",
            name=conv("ck_business_audit_after_size"),
        ),
        CheckConstraint(
            "octet_length(context::text) <= 4096",
            name=conv("ck_business_audit_context_size"),
        ),
        CheckConstraint(
            "outcome = 'succeeded' OR after_state IS NULL",
            name=conv("ck_business_audit_non_success_after"),
        ),
        CheckConstraint(
            "request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'",
            name=conv("ck_business_audit_request_id_format"),
        ),
    )

    # 业务服务提供 BA + 中国时间 + 6 位随机字符；同一事件重试复用 ID。
    id: Mapped[str] = mapped_column(String(AUDIT_ID_LENGTH, collation="C"), primary_key=True)
    # 业务域机器名，例如 order；不表示公司、租户或数据库名称。
    domain: Mapped[str] = mapped_column(String(64), nullable=False)
    # 稳定动作名，例如 order.payment.confirmed；首段必须与 domain 一致。
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    # succeeded/failed/denied 分别表示业务成功、执行失败、规则拒绝。
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    # 对结果的稳定原因标识，不放内部异常堆栈或用户可翻译文案。
    reason_code: Mapped[str] = mapped_column(String(80), nullable=False)
    # 谁执行操作：用户、服务、系统、任务或维护人员；它不表示接口入口。
    source_type: Mapped[str] = mapped_column(String(16), nullable=False)
    # 操作人的用户 ID；只有用户操作填写，服务和任务不能冒用这个字段。
    user_id: Mapped[str | None] = mapped_column(String(ENTITY_ID_LENGTH), nullable=True)
    # 服务、任务或维护身份的稳定 ID；用户操作和系统自身动作必须留空。
    source_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # 被操作人的用户 ID；本人操作时可与 user_id 相同，没有关联用户时留空。
    target_user_id: Mapped[str | None] = mapped_column(String(ENTITY_ID_LENGTH), nullable=True)
    # 被操作对象的类别，例如 order 或 user；来自动作目录，不能由请求任意指定。
    target_type: Mapped[str] = mapped_column(String(64), nullable=False)
    # 被操作对象的 ID，例如订单 ID；目标是用户时必须等于 target_user_id。
    target_id: Mapped[str] = mapped_column(String(128), nullable=False)
    # 从哪个入口执行：HTTP、服务、任务、受控维护或迁移；与来源身份分开记录。
    entrypoint: Mapped[str] = mapped_column(String(16), nullable=False)
    # 当前动作载荷结构的正整数版本；格式变化时用于解释历史数据，不控制登录有效性。
    schema_version: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    # 动作发生前的白名单状态，最多 16 KiB；无前态时为 None，不保存整个业务对象。
    before_state: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB(none_as_null=True), nullable=True
    )
    # 成功动作后的白名单状态，最多 16 KiB；失败或拒绝事件必须为 None。
    after_state: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB(none_as_null=True), nullable=True
    )
    # 当前动作允许的补充上下文，最多 4 KiB；默认空字典，不能放请求体或凭据原文。
    context: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    # 原始业务请求或任务的关联 ID，用于把审计与运行日志串起来。
    request_id: Mapped[str] = mapped_column(String(128), nullable=False)
    # 当前插入语句的带时区时间，由数据库生成，不是事件耗时。
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("statement_timestamp()"),
    )

    @validates("id")
    def validate_id(self, _key: str,
                    value: str
                    ) -> str:
        """
            校验业务审计事件使用 BA 开头的 22 位标识。

        :param _key: SQLAlchemy 传入的 id 属性名，此处不参与校验。
        :param value: 待保存的业务审计事件 ID。
        :return: 通过格式检查的事件 ID。
        :raises ValueError: 事件 ID 格式错误。
        """
        # 检查 BA 开头的业务审计 ID，避免误用用户 ID 或其他审计 ID。
        return require_business_event_id(value)

    @validates("domain", "target_type")
    def validate_machine_name(self, key: str,
                              value: str
                              ) -> str:
        """
            校验业务域或目标类型的机器可读名称，保持事件目录命名一致。

        :param key: 正在赋值的 domain 或 target_type 属性名。
        :param value: 需要保存的业务域或目标类型名称。
        :return: 满足长度和命名规则的名称。
        :raises ValueError: 名称含不允许字符或超出长度限制。
        """
        # 根据当前字段检查业务域或对象类别的固定名称，不把页面展示文案当成机器标识。
        return require_business_machine_name(value, field=key.replace("_", " "))

    @validates("action")
    def validate_action(self, _key: str,
                        value: str
                        ) -> str:
        """
            校验业务审计动作的分段格式和最大长度。

        :param _key: SQLAlchemy 传入的 action 属性名，此处不参与校验。
        :param value: 业务域、资源和操作组成的动作名称。
        :return: 通过格式与长度检查的业务动作。
        :raises ValueError: 动作过长或分段格式不符合规则。
        """
        # 检查“业务域.资源.操作”的分段写法和长度，写错就拒绝保存，方便后续统一查询。
        if len(value) > 120 or BUSINESS_AUDIT_ACTION_PATTERN.fullmatch(value) is None:
            raise ValueError("invalid business audit action")
        return value

    @validates("outcome")
    def validate_outcome(self, _key: str,
                         value: str | BusinessAuditOutcome
                         ) -> str:
        """
            将业务结果限定为成功、失败或拒绝并规范为数据库字符串。

        :param _key: SQLAlchemy 传入的 outcome 属性名，此处不参与校验。
        :param value: 业务执行结果枚举或字符串。
        :return: 合法的业务结果字符串。
        :raises ValueError: 业务结果未在允许的枚举中定义。
        """
        # 只允许成功、失败或拒绝三种结果，再转换成数据库使用的文字值。
        return BusinessAuditOutcome(value).value

    @validates("reason_code")
    def validate_reason_code(self, _key: str,
                             value: str
                             ) -> str:
        """
            校验业务审计原因码的通用长度和命名规则。

        :param _key: SQLAlchemy 传入的 reason_code 属性名，此处不参与校验。
        :param value: 业务执行结果对应的稳定原因标识。
        :return: 通过格式校验的原因码。
        :raises ValueError: 原因码长度或字符格式不符合要求。
        """
        # 原因只保存固定标识；共用规则检查长度和字符，不能用异常正文代替。
        return validate_audit_reason(value)

    @validates("source_type")
    def validate_source_type(self, _key: str,
                             value: str | BusinessAuditSourceType
                             ) -> str:
        """
            校验是谁执行操作，并转换为数据库保存的来源类型字符串。

        :param _key: SQLAlchemy 传入的 source_type 属性名，此处不参与校验。
        :param value: 用户、服务、系统、任务或维护来源类型。
        :return: 允许的来源类型字符串。
        :raises ValueError: 来源类型未在业务审计枚举中定义。
        """
        # 确认是谁执行操作：用户、服务、系统、任务或维护人员，不与请求入口混淆。
        return BusinessAuditSourceType(value).value

    @validates("user_id", "target_user_id")
    def validate_user_id(self, _key: str,
                         value: str | None
                         ) -> str | None:
        """
            操作人和被操作人都使用同一套 U 前缀用户 ID 格式。
            没有对应用户时允许空值；是否必须填写由来源和目标约束决定。

        :param _key: SQLAlchemy 传入的 user_id 或 target_user_id 属性名。
        :param value: 操作人或被操作人的用户 ID，允许为 None。
        :return: 合法用户 ID，或输入的 None。
        :raises ValueError: 非空用户 ID 的前缀、长度或字符格式错误。
        """
        # 没有关联用户就保留空值；有用户时，操作人和被操作人都检查同一套 U 前缀格式。
        return None if value is None else require_entity_id(value, "U")

    @validates("source_id")
    def validate_source_id(self, _key: str,
                           value: str | None
                           ) -> str | None:
        """
            校验服务、任务和维护操作的稳定来源标识。
            来源类型与 ID 是否配对仍由数据库约束保证。

        :param _key: SQLAlchemy 传入的 source_id 属性名，此处不参与校验。
        :param value: 非用户来源标识；用户操作和系统自身动作必须留空。
        :return: 合法来源 ID，或输入的 None。
        :raises ValueError: 非空来源 ID 含不允许字符或超出长度限制。
        """
        # 非用户来源可以有独立 ID；空值保留，非空值按审计标识规则检查。
        return (
            None
            if value is None
            else require_business_identifier(value, field="source ID")
        )

    @validates("target_id")
    def validate_target_id(self, _key: str,
                           value: str
                           ) -> str:
        """
            校验被操作对象的字符串 ID，允许订单等业务使用自己的非自增标识。

        :param _key: SQLAlchemy 传入的 target_id 属性名，此处不参与校验。
        :param value: 被操作对象的字符串 ID。
        :return: 满足字符和长度规则的目标对象 ID。
        :raises ValueError: 目标 ID 不符合审计标识约定。
        """
        # 检查订单等被操作对象的 ID 长度和字符；这一步不判断目标是否存在或有无权限。
        return require_business_identifier(value, field="target ID")

    @validates("entrypoint")
    def validate_entrypoint(self, _key: str,
                            value: str | AuditSource
                            ) -> str:
        """
            校验本次操作从哪个入口执行，并转换为数据库字符串。

        :param _key: SQLAlchemy 传入的 entrypoint 属性名，此处不参与校验。
        :param value: HTTP、服务、任务、受控维护或迁移等执行入口。
        :return: 合法的执行入口字符串。
        :raises ValueError: 执行入口未在 AuditSource 枚举中定义。
        """
        # 只接受已定义的执行入口；例如 HTTP 请求和后台任务使用不同入口值。
        return AuditSource(value).value

    @validates("schema_version")
    def validate_schema_version(self, _key: str,
                                value: int
                                ) -> int:
        """
            校验业务事件数据格式版本为正整数，明确拒绝布尔值冒充整数。

        :param _key: SQLAlchemy 传入的 schema_version 属性名，此处不参与校验。
        :param value: 当前事件载荷格式的版本号。
        :return: 大于零的整数版本号。
        :raises ValueError: 版本是布尔值、非整数或小于一。
        """
        # 数据格式版本必须是正整数；Python 的 True/False 也能当整数，所以要单独拒绝。
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError("business audit schema version must be a positive integer")
        return value

    @validates("before_state", "after_state")
    def validate_state(self, _key: str,
                       value: dict[str, Any] | None
                       ) -> dict[str, Any] | None:
        """
            清理业务事件前后状态，并把每份状态载荷限制在 16 KiB 内。

        :param _key: 被赋值的 before_state 或 after_state 属性名。
        :param value: 待保存的业务状态字典，未提供时为 None。
        :return: 可存入 JSONB 的安全状态字典，或输入的 None。
        :raises ValueError: 状态结构、内容或序列化大小不符合审计规则。
        """
        # 清理变更前后状态并检查每份不超过16 KiB；没有状态则保留 None，不存整个请求。
        return sanitize_business_payload(value, max_bytes=16 * 1024)

    @validates("context")
    def validate_context(self, _key: str,
                         value: dict[str, Any]
                         ) -> dict[str, Any]:
        """
            清理业务审计补充上下文，并应用比前后状态更小的载荷上限。

        :param _key: SQLAlchemy 传入的 context 属性名，此处不参与校验。
        :param value: 当前动作允许记录的补充业务上下文。
        :return: 清理后可存入 JSONB 的字典；可以是空字典，但不能是 None。
        :raises ValueError: 上下文结构、内容或大小不符合审计规则。
        """
        # 1. 补充上下文使用更小的大小上限，先检查并清理不能保存的内容。
        sanitized = sanitize_business_payload(
            value, max_bytes=MAX_BUSINESS_AUDIT_CONTEXT_BYTES
        )
        # 2. 本字段需要字典，不能用 None 代替；确认后才交回模型保存。
        assert sanitized is not None
        return sanitized

    @validates("request_id")
    def validate_request_id(self, _key: str,
                            value: str
                            ) -> str:
        """
            校验业务审计请求 ID，用于关联业务日志与同次操作的其他事件。

        :param _key: SQLAlchemy 传入的 request_id 属性名，此处不参与校验。
        :param value: 原业务请求或任务的关联 ID。
        :return: 满足字符和长度限制的审计请求 ID。
        :raises ValueError: 请求 ID 不符合审计关联格式。
        """
        # 检查请求关联 ID，方便把这条业务审计和同次操作的日志串起来。
        return validate_audit_request_id(value)


# 时间加事件 ID 提供稳定的倒序翻页依据，避免相同时间的事件顺序飘动。
Index(
    "ix_business_audit_created",
    BusinessAuditEvent.created_at.desc(),
    BusinessAuditEvent.id.desc(),
)
# 支持按业务域过滤，再按最新发生顺序查看。
Index(
    "ix_business_audit_domain_created",
    BusinessAuditEvent.domain,
    BusinessAuditEvent.created_at.desc(),
    BusinessAuditEvent.id.desc(),
)
# 从操作人的用户 ID 查找其做过的操作，空值不进入这个索引。
Index(
    "ix_business_audit_user_created",
    BusinessAuditEvent.user_id,
    BusinessAuditEvent.created_at.desc(),
    BusinessAuditEvent.id.desc(),
    postgresql_where=BusinessAuditEvent.user_id.is_not(None),
)
# 从被操作人的用户 ID 查询其关联事件，与“谁操作”的检索分开。
Index(
    "ix_business_audit_target_user_created",
    BusinessAuditEvent.target_user_id,
    BusinessAuditEvent.created_at.desc(),
    BusinessAuditEvent.id.desc(),
    postgresql_where=BusinessAuditEvent.target_user_id.is_not(None),
)
# 非用户来源必须连同类型查询，避免服务 ID 与任务 ID 相同而混在一起。
Index(
    "ix_business_audit_source_created",
    BusinessAuditEvent.source_type,
    BusinessAuditEvent.source_id,
    BusinessAuditEvent.created_at.desc(),
    BusinessAuditEvent.id.desc(),
    postgresql_where=BusinessAuditEvent.source_id.is_not(None),
)
# 支持查看某类业务对象的单个 ID 所经历的完整操作历史。
Index(
    "ix_business_audit_target_created",
    BusinessAuditEvent.target_type,
    BusinessAuditEvent.target_id,
    BusinessAuditEvent.created_at.desc(),
    BusinessAuditEvent.id.desc(),
)
# 根据响应中的 request_id 定位同一次请求产生的业务审计。
Index("ix_business_audit_request", BusinessAuditEvent.request_id)
# 按动作与结果查找失败、拒绝或成功记录，再按时间稳定排序。
Index(
    "ix_business_audit_action_outcome_created",
    BusinessAuditEvent.action,
    BusinessAuditEvent.outcome,
    BusinessAuditEvent.created_at.desc(),
    BusinessAuditEvent.id.desc(),
)
