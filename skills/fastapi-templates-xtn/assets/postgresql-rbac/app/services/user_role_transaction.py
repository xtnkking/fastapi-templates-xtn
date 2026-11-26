#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    用户和角色修改的公共事务：修改与成功审计一起保存，失败一起回滚，拒绝记录单独保存。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        对齐业务模型归属并整理事务审计调用，保留原有提交与拒绝语义
# 2026/09/23    XTN       V1.002        补充面向初学者的业务权限、执行顺序和事务结果说明
# 2026/09/23    XTN       V1.003        逐项排列事务参数与审计字段，便于核对记录内容
# 2026/09/30    XTN       V1.004        统一权限依赖和业务事务的拒绝审计故障处理
# 2026/10/02    XTN       V1.005        逐项展示拒绝审计失败时的安全日志字段
# 2026/10/08    XTN       V1.006        关系操作使用普通字符串，在实际判断处说明允许值
# 2026/10/10    XTN       V1.007        统一用户身份命名，区分用户 ID、当前用户及目标用户
# 2026/10/13    XTN       V1.008        补齐锁后身份复查与独立拒绝审计的执行、提交和容错说明
# 2026/10/16    XTN       V1.009        成功与拒绝审计统一从当前操作上下文读取请求 ID
# 2026/10/16    XTN       V1.010        异常构造器名称统一标明固定 HTTP 状态
# 2026/10/16    XTN       V1.011        成功与拒绝统一写入操作审计，移除重复拒绝写入边界
# 2026/10/16    XTN       V1.012        事务只交出数据库会话，业务直接调用成功审计入口
# 2026/10/19    XTN       V1.013        精简注释，用大白话说明事务和拒绝审计
# 2026/10/20    XTN       V1.014        登录身份统一使用 login_info，认证依赖改用直观入口
# 2026/10/24    XTN       V1.015        简化校验名称与参数，取消无用返回值，事务目标默认可省略
# 2026/10/24    XTN       V1.016        文件与事务入口按用户和角色业务命名
# --------------------------------------------------------------------------------------------------


from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.access.authorization import AuthorizationContext
from app.core.audit import RbacAuditAction
from app.core.exceptions import AppError, unauthenticated_401
from app.models.postgres.user import User
from app.services.audit_service import AuditService


def check_role_operation(operation: str) -> None:
    """
        只允许绑定和解绑两种操作。

    :param operation: 调用方传入的 bind 或 unbind 操作名称。
    :return: 无返回值；检查通过后由调用方继续绑定或解绑。
    :raises ValueError: 操作不是 bind 或 unbind。
    """
    # 拒绝未知操作，避免把拼错的名称当成解绑。
    if operation not in ("bind", "unbind"):
        raise ValueError("operation must be 'bind' or 'unbind'")


def check_locked_user(user: User | None, *, token_version: int) -> None:
    """
        加锁后确认账号仍可用、登录未失效；具体操作权限由后续步骤检查。

    :param user: 已锁定且未删除的当前用户；未找到时为 None。
    :param token_version: 本次登录绑定的版本，与数据库中的当前版本比较。
    :return: 无返回值；账号可用且登录版本一致时允许继续。
    :raises AppError: 操作者已不存在、已禁用或 Token 版本已经失效。
    """
    # 等待锁时账号可能被停用或强制下线，不能沿用请求开始时的状态。
    if user is None:
        raise unauthenticated_401("user_missing")
    if not user.is_active or user.token_version != token_version:
        raise unauthenticated_401("user_no_longer_active")


@asynccontextmanager
async def user_role_transaction(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    context: AuthorizationContext,
    action: RbacAuditAction,
    target_user_id: str | None = None,
    target_role_id: str | None = None,
) -> AsyncIterator[AsyncSession]:
    """
        让用户、角色修改和成功审计一起保存，任一步失败就一起撤回。
        调用方在 with 内加锁、检查权限、修改数据，再调用 audit_success。
        拒绝操作回滚后另存审计；审计失败不改变原业务错误。

    :param session_factory: 创建独立 PostgreSQL 异步会话的工厂。
    :param context: 当前用户身份、权限和审计来源。
    :param action: 本次操作的审计动作，与块内成功审计一致。
    :param target_user_id: 本次操作的目标用户 ID，没有用户目标时可省略。
    :param target_role_id: 本次操作的目标角色 ID，没有角色目标时可省略。
    :yield: 本次数据库会话；正常退出时提交，异常时回滚，最后关闭会话。
    :raises AppError: 权限或业务决策拒绝，原异常继续传给调用方。
    :raises RuntimeError: 审计时未绑定有效操作上下文；事务回滚。
    """
    try:
        # 1. 外层负责关闭会话，即使内层提交或回滚时抛错，也会执行清理。
        async with session_factory() as session:
            # 2. 内层负责事务；调用方在块内修改业务，并调用 audit_success 添加成功审计。
            async with session.begin():
                yield session
                # 3. 块内没有异常才尝试提交；业务和成功审计使用同一个事务。
    except AppError as exc:
        # 4. 原事务及会话已退出，再另开事务保存拒绝记录；审计失败也保留原业务错误。
        # audit_denied 会跳过 5xx，避免把服务故障算成用户被拒绝。
        await AuditService(session_factory).audit_denied(
            error=exc,
            action=action,
            context=context,
            target_user_id=target_user_id,
            target_role_id=target_role_id,
        )
        raise
