#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    按项目定义的业务动作记录审计，区分成功、拒绝和失败的保存时机。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        补充面向初学者的业务权限、执行顺序和事务结果说明
# 2026/09/23    XTN       V1.002        类方法参数逐行对齐，整理业务调用排版
# 2026/09/26    XTN       V1.003        将写入器更名为职责明确的业务审计服务
# 2026/10/10    XTN       V1.004        业务审计事实和持久化映射统一使用 operator
# 2026/10/10    XTN       V1.005        明确操作人和目标对象，按来源类型校验并保留执行入口
# 2026/10/13    XTN       V1.006        补齐载荷和事务前置检查，说明成功、保存点及独立失败审计的边界
# 2026/10/16    XTN       V1.007        构造业务审计时自动读取当前执行上下文的请求关联 ID
# 2026/10/19    XTN       V1.008        精简业务审计注释，说明检查和保存步骤
# --------------------------------------------------------------------------------------------------


import logging
from collections.abc import Mapping

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.audit import AuditJsonValue, AuditSource, get_audit_request_id
from app.core.business_audit import (
    MAX_BUSINESS_AUDIT_CONTEXT_BYTES,
    BusinessAuditActionSpec,
    BusinessAuditFacts,
    BusinessAuditOutcome,
    require_business_event_id,
    require_business_identifier,
    sanitize_business_payload,
)
from app.core.logging.events import safe_log
from app.models.postgres.business_audit import BusinessAuditEvent

logger = logging.getLogger(__name__)


class BusinessAuditService:
    """
        记录项目自己定义的业务变化，不代替业务权限检查。
        成功审计随业务一起提交，避免业务失败却留下成功记录。
    """

    def __init__(self, session_factory: async_sessionmaker[AsyncSession],
                 action_specs: Mapping[str, BusinessAuditActionSpec]
                 ) -> None:
        """
            保存会话工厂和动作目录，检查目录是否有效。

        :param session_factory: 为回滚后的失败审计创建独立事务的会话工厂。
        :param action_specs: 每个动作允许记录的字段、结果和原因码。
        :return: 无返回值；会话工厂和检查通过的目录已保存。
        :raises ValueError: 目录为空，或目录键与动作定义不一致。
        """
        self._session_factory = session_factory
        # 保留一份目录副本，并检查每个目录键是否对应正确的动作。
        self._action_specs = dict(action_specs)
        if not self._action_specs:
            raise ValueError("business audit action catalog cannot be empty")
        for action, spec in self._action_specs.items():
            if action != spec.action:
                raise ValueError("business audit catalog key must match its action")

    @staticmethod
    def _safe_payload(state: Mapping[str, object] | None, *,
                      allowed_fields: frozenset[str],
                      max_bytes: int
                      ) -> dict[str, AuditJsonValue] | None:
        """
            只保留允许留档的字段，并检查 JSON 格式和大小。

        :param state: 待保存的状态或上下文，未提供时为 None。
        :param allowed_fields: 当前业务动作允许写入审计的字段名称。
        :param max_bytes: 序列化后的最大字节数。
        :return: 可保存的 JSON 字典；输入为 None 时返回 None。
        :raises ValueError: 含不允许的字段，或内容格式、大小不合要求。
        """
        # 未提供就留空；提供时拒绝名单外字段，防止密码等额外数据入库。
        if state is None:
            return None
        if set(state) - allowed_fields:
            raise ValueError("business audit payload contains a non-allowlisted field")
        # 再检查值的类型、嵌套层数和总大小。
        return sanitize_business_payload(state, max_bytes=max_bytes)

    def build_event(self, facts: BusinessAuditFacts, *,
                    outcome: BusinessAuditOutcome
                    ) -> BusinessAuditEvent:
        """
            检查审计内容并构造记录，这里不写数据库。
            请求 ID 从当前操作获取，未绑定时直接报错。

        :param facts: 本次操作的人、目标、来源和修改前后状态。
        :param outcome: 本次业务执行结果，必须在该动作允许的结果中。
        :return: 检查通过的审计模型。
        :raises ValueError: 动作未注册，或审计事实不符合目录约束。
        :raises RuntimeError: 当前入口未绑定有效的请求关联上下文。
        """
        # 1. 查找动作，检查结果、原因码和来源是否在允许范围内。
        spec = self._action_specs.get(facts.action)
        if spec is None:
            raise ValueError("business audit action is not registered")
        outcome = BusinessAuditOutcome(outcome)
        if outcome not in spec.allowed_outcomes:
            raise ValueError("business audit outcome is not allowed for this action")
        if facts.reason_code not in spec.reason_codes:
            raise ValueError("business audit reason is not registered for this action")
        if facts.source_type not in spec.source_types:
            raise ValueError("business audit source type is not allowed for this action")
        # 2. 操作用户时，目标 ID 和被操作人 ID 必须一致；未成功不能记修改后状态。
        if spec.target_type == "user" and facts.target_user_id != facts.target_id:
            raise ValueError("user business audit target must match its target user ID")
        if (
            outcome is not BusinessAuditOutcome.SUCCEEDED
            and facts.after_state is not None
        ):
            raise ValueError("denied and failed events cannot claim an after state")
        require_business_event_id(facts.event_id)
        require_business_identifier(facts.target_id, field="target ID")
        entrypoint = AuditSource(facts.entrypoint)
        # 共用入口绑定的请求 ID，不让业务逐层传递。
        request_id = get_audit_request_id()
        # 3. 检查允许留档的字段；前后状态各限 16 KiB，补充信息限 4 KiB。
        before_state = self._safe_payload(
            facts.before_state,
            allowed_fields=spec.before_fields,
            max_bytes=16 * 1024,
        )
        after_state = self._safe_payload(
            facts.after_state,
            allowed_fields=spec.after_fields,
            max_bytes=16 * 1024,
        )
        context = self._safe_payload(
            facts.context or {},
            allowed_fields=spec.context_fields,
            max_bytes=MAX_BUSINESS_AUDIT_CONTEXT_BYTES,
        )
        assert context is not None
        # 4. 按字段整理记录，交给后续方法保存。
        return BusinessAuditEvent(
            id=facts.event_id,
            domain=spec.domain,
            action=spec.action,
            outcome=outcome.value,
            reason_code=facts.reason_code,
            source_type=facts.source_type.value,
            user_id=facts.user_id,
            source_id=facts.source_id,
            target_user_id=facts.target_user_id,
            target_type=spec.target_type,
            target_id=facts.target_id,
            entrypoint=entrypoint.value,
            schema_version=spec.schema_version,
            before_state=before_state,
            after_state=after_state,
            context=context,
            request_id=request_id,
        )

    def add_succeeded(self, session: AsyncSession,
                      facts: BusinessAuditFacts
                      ) -> BusinessAuditEvent:
        """
            把成功审计加入已开启的业务事务，随业务一起提交或回滚。

        :param session: 调用方管理且已开启事务的 PostgreSQL 异步会话。
        :param facts: 本次成功操作的审计内容。
        :return: 已加入会话但尚未提交的成功审计。
        :raises RuntimeError: 调用方尚未开启事务，或当前入口未绑定有效的请求关联上下文。
        :raises ValueError: 审计事实不符合动作目录、标识或载荷约束。
        """
        # 必须已有业务事务，才能让审计随业务失败一起回滚。
        if not session.in_transaction():
            raise RuntimeError(
                "successful business audit requires a caller-owned transaction"
            )
        event = self.build_event(facts, outcome=BusinessAuditOutcome.SUCCEEDED)
        # 只加入会话，最终由业务提交。
        session.add(event)
        return event

    def add_after_savepoint_rollback(self, session: AsyncSession,
                                     facts: BusinessAuditFacts,
                                     *,
                                     outcome: BusinessAuditOutcome
                                     ) -> BusinessAuditEvent:
        """
            局部业务已回滚、外层事务仍有效时，在外层保存拒绝或失败审计。
            保存点就是事务内的局部撤销位置；必须等它回滚结束后再调用。

        :param session: 保存点已回滚、外层事务仍有效的会话。
        :param facts: 拒绝或失败的审计内容，不含修改后状态。
        :param outcome: 拒绝或失败结果，不能传入成功结果。
        :return: 已加入外层事务、等待调用方提交的审计事件。
        :raises ValueError: 结果不是合法的拒绝/失败结果，或审计事实不符合动作目录约束。
        :raises RuntimeError: 没有外层事务、嵌套事务尚未结束，或当前入口未绑定有效的请求关联上下文。
        """
        # 先确认结果和事务状态，避免审计也落入将被回滚的保存点。
        outcome = BusinessAuditOutcome(outcome)
        if outcome is BusinessAuditOutcome.SUCCEEDED:
            raise ValueError("successful audit must use the protected transaction")
        if not session.in_transaction():
            raise RuntimeError("savepoint audit requires a caller-owned transaction")
        if session.in_nested_transaction():
            raise RuntimeError("savepoint audit requires the nested rollback to finish")
        # 加入仍有效的外层事务，等待调用方提交。
        event = self.build_event(facts, outcome=outcome)
        session.add(event)
        return event

    async def write_after_rollback(self, facts: BusinessAuditFacts, *,
                                   outcome: BusinessAuditOutcome
                                   ) -> bool:
        """
            业务回滚后，另开事务保存拒绝或失败审计。
            保存失败返回 False，不覆盖原业务错误。

        :param facts: 需要单独保存的拒绝或失败审计内容。
        :param outcome: 拒绝或失败结果，成功审计必须使用原业务事务。
        :return: 独立审计事务提交成功时为 True，保存失败时为 False。
        :raises ValueError: 结果值无效或传入成功结果；写入阶段的检查失败则返回 False。
        """
        # 成功审计必须随业务保存，不能从这里另开事务补写。
        outcome = BusinessAuditOutcome(outcome)
        if outcome is BusinessAuditOutcome.SUCCEEDED:
            raise ValueError("successful audit must use the protected transaction")
        try:
            # 原业务已回滚，用新事务单独保存失败记录。
            async with self._session_factory() as session:
                async with session.begin():
                    session.add(self.build_event(facts, outcome=outcome))
            return True
        except Exception as exc:
            # 失败只记异常类型，避免异常原文泄露业务数据。
            safe_log(
                logger,
                logging.ERROR,
                "audit.write.failed",
                extra={
                    "audit_domain": "business",
                    "exception_type": type(exc).__name__,
                },
            )
            return False
