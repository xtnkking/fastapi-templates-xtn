#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    仅供受控命令行使用的超级管理员密码恢复业务。
#    不进入新项目默认生成结果，也不提供 HTTP 接口。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/02    XTN       V1.000        从普通认证服务移出线下密码恢复事务
# 2026/10/02    XTN       V1.001        唯一持有人查询改由维护命令专用仓储完成
# 2026/10/09    XTN       V1.002        线下密码恢复引用集中定义的账号安全审计动作
# 2026/10/10    XTN       V1.003        对齐账号审计发起者类型和 user_id 字段
# 2026/10/13    XTN       V1.004        通俗说明线下改密的资源保存、加锁与审计提交步骤
# 2026/10/16    XTN       V1.005        线下密码恢复审计自动读取入口绑定的请求关联 ID
# 2026/10/16    XTN       V1.006        异常构造器名称统一标明固定 HTTP 状态
# 2026/10/16    XTN       V1.007        线下改密写统一操作审计，保留明确来源和同事务提交
# 2026/10/16    XTN       V1.008        成功审计直接加入现有事务，移除分类与结果的重复传参
# 2026/10/22    XTN       V1.009        线下恢复从统一用户仓储读取目标权限
# 2026/10/22    XTN       V1.010        密码保存方法统一命名为 update_password
# 2026/10/22    XTN       V1.011        直接用已锁住的目标用户读取角色权限，取消重复账号查询
# 2026/10/23    XTN       V1.012        单用户恢复统一使用批量权限查询入口
# 2026/10/26    XTN       V1.013        用户权限结果字段明确区分生效信息与含停用角色的信息
# 2026/11/26    XTN       V1.014        线下密码恢复使用统一密码规则
# --------------------------------------------------------------------------------------------------

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.commands.operator_password_repository import operator_password_repository
from app.core.audit import AccountAuditAction, AuditSource
from app.core.exceptions import conflict_409, forbidden_403, not_found_404, password_policy_response_400
from app.core.security.password_rules import PasswordPolicyError, validate_new_password
from app.core.security.passwords import PasswordManager
from app.repositories.postgres.rbac_state_repository import rbac_state_repository
from app.repositories.postgres.user_repository import user_repository
from app.services.audit_service import AuditService


class OperatorPasswordService:
    """
        只为线下维护命令执行超级管理员密码恢复，不参与普通登录或管理员 API。
    """

    def __init__(self, session_factory: async_sessionmaker[AsyncSession],
                 manager: PasswordManager
                 ) -> None:
        """
            保存会话工厂和密码处理器，恢复时自行管理数据库事务。

        :param session_factory: 创建 PostgreSQL 异步会话的工厂。
        :param manager: 在数据库锁外计算 Argon2 密码哈希的处理器。
        :return: 无返回值；服务不保存本次操作的密码或活动会话。
        """
        # 只保存创建会话和处理密码的工具；到执行重置时才创建本次数据库会话。
        self._session_factory = session_factory
        self._password_manager = manager

    async def reset_super_admin_password(self, *, user_id: str,
                                         new_password: str
                                         ) -> bool:
        """
            仅为当前唯一有效超级管理员设置可直接登录的新密码。
            锁内确认唯一持有人和账号状态，密码、旧登录失效及审计一起提交。
            调用入口必须已绑定本次操作的请求关联上下文，审计构造时自动读取。

        :param user_id: 当前唯一超级管理员的用户 ID。
        :param new_password: 操作员在本地终端输入的新密码，不保存原文。
        :return: 数据库事务成功提交时返回 True。
        :raises AppError: 目标不可用、不是唯一超级管理员或密码不符合规则。
        :raises RuntimeError: 当前入口未绑定有效的请求关联上下文。
        """
        # 1. 先把新密码算成安全哈希，不保存明文；放在数据库锁外计算，减少其他写操作等待。
        try:
            new_hash = await self._password_manager.hash_new_password(new_password)
        except PasswordPolicyError as exc:
            raise password_policy_response_400(exc) from exc

        async with self._session_factory() as session:
            async with session.begin():
                # 2. 先锁授权状态，再锁目标用户；遵守同一锁顺序，防止核验后身份又被修改。
                await rbac_state_repository.lock_rbac_state(session)
                users = await user_repository.lock_users(session, {user_id})
                user = users.get(user_id)
                if user is None or not user.is_active:
                    raise not_found_404("user_not_found")
                holder_ids = await operator_password_repository.load_live_super_admin_holder_ids(session)
                # 3. 目标必须就是现有唯一超级管理员；不能借重置密码创建或转移这个角色。
                if holder_ids != frozenset({user_id}):
                    raise conflict_409("operator_reset_requires_sole_super_admin")
                # 已经锁住目标账号，直接查它的角色；禁用角色仍参与身份保护检查。
                permissions_by_user = await user_repository.get_user_permissions(
                    session,
                    users=(user,),
                )
                user_permissions = permissions_by_user[user.user_id]
                if not user_permissions.user_info_with_disabled_roles.is_super_admin:
                    raise forbidden_403("operator_reset_requires_super_admin")
                # 4. 密码计算期间用户名可能已改变，保存前按刚读到的用户名再查一次密码规则。
                try:
                    validate_new_password(new_password, user_name=user.user_name)
                except PasswordPolicyError as exc:
                    raise password_policy_response_400(exc) from exc
                await user_repository.update_password(
                    session,
                    user=user,
                    password_hash=new_hash,
                )
                # 5. 更新登录版本，让旧 Token 下次认证时失效；拿着数据库锁期间不调用 Redis。
                user.token_version += 1
                # 6. 把安全审计和密码修改放在同一事务；全部成功才提交，出错则一起回滚。
                AuditService.audit_success(
                    session,
                    action=AccountAuditAction.OPERATOR_RESET_PASSWORD,
                    reason_code="permanent_password_set",
                    target_user_id=user.user_id,
                    source=AuditSource.OPERATOR,
                )
        return True
