#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    创建用户，查询用户信息，管理角色、账号状态、密码和登录。
# History:
# Date          Author    Version       Modification
# 2026/10/19    XTN       V1.038        直接导入共享业务服务，删除仅返回实例的依赖入口
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        归并管理员新增与重置密码，保持事务、等级及审计边界
# 2026/09/23    XTN       V1.002        补充面向初学者的业务权限、执行顺序和事务结果说明
# 2026/09/23    XTN       V1.003        类方法参数逐行对齐，整理业务调用排版
# 2026/09/23    XTN       V1.004        逐项排列公开响应字段并纠正拒绝审计说明
# 2026/09/26    XTN       V1.005        统一用户详情、账号审计和操作结果名称
# 2026/09/26    XTN       V1.006        用户创建和密码规则统一使用具体用户名语义
# 2026/09/29    XTN       V1.007        按用户管理和角色可见性分别导入策略判断
# 2026/09/29    XTN       V1.008        密码规则响应统一从错误模块导入
# 2026/09/29    XTN       V1.009        用户角色上限返回用户专属业务码
# 2026/09/30    XTN       V1.010        管理员新增和重置直接设置可登录密码
# 2026/09/30    XTN       V1.011        管理员会话查询复用用户详情的可见范围
# 2026/10/02    XTN       V1.012        用具名锁定结果替代五项位置元组
# 2026/10/02    XTN       V1.013        管理员新增直接沿用共享创建服务的用户名冲突提示
# 2026/10/02    XTN       V1.014        展开用户角色绑定的状态检查和审计结果分支
# 2026/10/02    XTN       V1.015        会话统计归入用户业务，读取目标后释放数据库会话再访问 Redis
# 2026/10/02    XTN       V1.016        澄清角色 ID 的接口校验边界并展开会话时间组装
# 2026/10/08    XTN       V1.017        角色操作直接使用普通字符串，沿用实际操作校验
# 2026/10/09    XTN       V1.018        管理员会话统计结果从用户模型导入
# 2026/10/09    XTN       V1.019        用户管理和密码操作引用所属审计动作枚举
# 2026/10/09    XTN       V1.020        对齐用户锁定方法参数并说明角色锁与目标快照的用途
# 2026/10/09    XTN       V1.021        接口响应模型统一使用 Response 后缀，保留返回字段与行为
# 2026/10/10    XTN       V1.022        统一用户身份命名，区分用户 ID、当前用户及目标用户
# 2026/10/13    XTN       V1.023        补齐用户管理分阶段说明，明确锁后复查、版本失效、发送写入和审计提交边界
# 2026/10/13    XTN       V1.024        会话统计只按用户定位 Redis 记录，删除无用配置参数
# 2026/10/15    XTN       V1.025        移除用户权限版本的更新和输出，保留登录撤销及锁内权限检查
# 2026/10/15    XTN       V1.026        用户创建和角色绑定统一使用 bound_by_user_id
# 2026/10/15    XTN       V1.027        角色绑定集合在加锁和响应链路统一为 bound_role_ids
# 2026/10/15    XTN       V1.028        收拢共用用户创建，简化创建入口并删除独立创建服务
# 2026/10/15    XTN       V1.029        创建时同时写入密码和设置时间，取消新增后的补设密码
# 2026/10/16    XTN       V1.030        用户 ID 统一在创建方法内生成，删除外部指定入口
# 2026/10/16    XTN       V1.031        审计读取当前操作关联 ID，删除创建及用户管理的重复传参
# 2026/10/16    XTN       V1.032        补清创建及管理流程注释，异常构造器标明 HTTP 状态
# 2026/10/16    XTN       V1.033        默认 user 角色仅检查存在与可用状态，删除固定属性重复校验
# 2026/10/16    XTN       V1.034        默认角色一次加锁查询，用户名并发冲突统一在共享创建入口处理
# 2026/10/16    XTN       V1.035        移除无消费用途的全局授权计数，保留统一行锁和锁后权限复查
# 2026/10/16    XTN       V1.036        用户与密码操作统一操作审计，合并创建记录并保存脱敏请求响应
# 2026/10/16    XTN       V1.037        用户业务直接调用成功或拒绝审计，取消预建记录和快照嵌套
# 2026/10/19    XTN       V1.039        精简用户业务注释，改用简短的大白话说明
# 2026/10/19    XTN       V1.040        操作结果不返回 changed，保留内部幂等判断和审计原因
# 2026/10/20    XTN       V1.041        创建用户时直接校验用户名，不再重复传入字段名
# 2026/10/20    XTN       V1.042        用户响应和审计摘要的最高角色等级统一为 role_level
# 2026/10/20    XTN       V1.043        登录身份统一使用 login_info，认证依赖改用直观入口
# 2026/10/22    XTN       V1.044        用户资料、权限与可见范围统一使用用户仓储
# 2026/10/22    XTN       V1.045        密码保存方法统一命名为 update_password
# 2026/10/22    XTN       V1.046        用户查询直观命名，复用已锁用户并一次读取目标角色权限
# 2026/10/23    XTN       V1.047        单个和多个用户统一调用同一权限查询入口
# 2026/10/23    XTN       V1.048        登录列表改由 Redis 登录仓储查询
# 2026/10/24    XTN       V1.049        列表透传用户 ID、启停和软删除筛选，保持分页与总数一致
# 2026/10/24    XTN       V1.050        用户页面资料改用 display_info 和 user_info，区分完整权限
# 2026/10/24    XTN       V1.051        用户列表、详情和会话查询使用直观的仓储方法名
# 2026/10/24    XTN       V1.052        用户角色操作对齐 bind 和 unbind 权限名称
# 2026/10/24    XTN       V1.053        用户角色操作返回 UserRoleResponse，保持响应字段不变
# 2026/10/24    XTN       V1.054        角色绑定统一使用按角色 ID 返回的权限查询
# 2026/10/24    XTN       V1.055        对齐简洁用户角色仓储入口，明确已绑定角色和数量变量
# 2026/10/24    XTN       V1.056        批量用户资料统一使用 get_users_info、UserDetails 和具体变量名
# 2026/10/24    XTN       V1.057        使用简洁事务校验入口，只传实际审计目标
# 2026/10/24    XTN       V1.058        公共事务改用 user_role_transaction 模块与入口
# 2026/10/26    XTN       V1.059        用户角色权限信息类型统一命名为 UserInfo
# 2026/10/26    XTN       V1.060        用户权限结果字段明确区分生效信息与含停用角色的信息
# 2026/11/26    XTN       V1.061        创建用户调用直观命名的用户名校验入口
# 2026/11/26    XTN       V1.062        创建和重置密码统一引用密码规则文件
# --------------------------------------------------------------------------------------------------

from collections.abc import Iterable
from dataclasses import dataclass, replace
from datetime import UTC, datetime

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.access.authorization import AuthorizationContext, UserInfo
from app.core.access.permissions import PermissionKey
from app.core.access.role_policy import is_administrative_role_visible
from app.core.access.roles import MAX_ROLES_PER_USER, SystemRoleKey
from app.core.access.user_policy import (
    decide_role_change,
    decide_user_password_reset,
    decide_user_sessions_revoke,
    decide_user_status_change,
    is_administrative_user_visible,
)
from app.core.audit import AccountAuditAction, RbacAuditAction
from app.core.codes import BusinessCode
from app.core.exceptions import (
    AppError,
    conflict_409,
    forbidden_403,
    invalid_request_400,
    not_found_404,
    password_policy_response_400,
)
from app.core.i18n.messages import MessageKey
from app.core.ids import new_entity_id
from app.core.response import PageResponse
from app.core.security.password_rules import PasswordPolicyError, validate_new_password
from app.core.security.passwords import (
    PasswordManager,
    password_manager,
)
from app.core.security.user_name import validate_user_name
from app.db.postgres_db import SessionFactory, get_constraint_name
from app.db.redis_db import RedisClient
from app.models.postgres.role import Role
from app.models.postgres.user import User, UserRole
from app.repositories.postgres.rbac_state_repository import rbac_state_repository
from app.repositories.postgres.role_repository import role_repository
from app.repositories.postgres.user_repository import UserDetails, user_repository
from app.repositories.postgres.user_role_repository import user_role_repository
from app.repositories.redis.login_session_repository import login_session_repository
from app.schemas.user import ActiveSessionsResponse, UserResponse, UserRoleResponse
from app.services.audit_service import AuditService
from app.services.user_role_transaction import (
    check_locked_user,
    check_role_operation,
    user_role_transaction,
)


def _snapshot_payload(snapshot: UserInfo) -> dict[str, object]:
    """
        整理用户变更前后的信息，供审计记录使用。

    :param snapshot: 本次操作时查到的用户状态、角色和权限。
    :return: 要写入审计的信息，不含密码和 Token。
    """
    # 只取审计需要的字段，把角色和权限整理成列表。
    return {
        "user_id": str(snapshot.user_id),
        "is_active": snapshot.user_is_active,
        "role_ids": [str(role.role_id) for role in snapshot.roles],
        "role_keys": sorted(role.key for role in snapshot.roles),
        "permissions": sorted(snapshot.permissions),
        "role_level": snapshot.role_level,
        "is_protected": snapshot.is_protected,
        "is_super_admin": snapshot.is_super_admin,
    }


@dataclass(slots=True)
class _LockedUserChange:
    """
        保存已加锁的用户和角色，供后续管理操作使用。
    """

    # 当前操作人的最新角色和权限。
    current_user: UserInfo
    # 被操作人变更前的信息，用来检查权限并记录审计。
    target_before: UserInfo
    # 已锁住的被操作人记录，修改写在这个对象上。
    target_row: User
    # 已锁住的角色记录，通过角色 ID 查找。
    roles: dict[str, Role]


class UserService:
    """
        处理用户创建、查询和管理员操作。
        注册和管理员新增共用 create_user。
    """

    def __init__(self, session_factory: async_sessionmaker[AsyncSession],
                 manager: PasswordManager = password_manager
                 ) -> None:
        """
            准备数据库、密码处理和审计工具。

        :param session_factory: 用于创建每次操作的数据库会话。
        :param manager: 检查密码规则并计算密码哈希的工具。
        :return: 无返回值；保存后续操作需要的工具。
        """
        # 每次操作单独创建会话，不共用同一条数据库连接。
        self._session_factory = session_factory
        # 新增和重置密码使用同一套密码规则。
        self._password_manager = manager
        # 用户管理操作统一通过它记录审计。
        self._audit = AuditService(session_factory)

    @staticmethod
    def username_exists_error() -> AppError:
        """
            创建“用户名已占用”的错误对象。

        :return: 用户名冲突错误，HTTP 状态为 409。
        """
        # 查重和插入冲突使用相同提示，由调用方 raise。
        return AppError(
            status_code=409,
            business_code=BusinessCode.USER_CREATE_CONFLICT,
            message_key=MessageKey.ERROR_USER_NAME_TAKEN,
            reason_code="user_already_exists",
        )

    async def list_users(self, session: AsyncSession, *,
                         current_user: UserInfo,
                         page: int,
                         page_size: int,
                         user_id: str | None = None,
                         user_name: str | None = None,
                         is_active: bool | None = None,
                         is_deleted: bool = False
                         ) -> PageResponse[UserResponse]:
        """
            分页查询当前操作人能查看的用户。
            调用方需先检查 users:read（查看用户）权限。

        :param session: 调用方提供并负责关闭的数据库会话。
        :param current_user: 当前操作人的角色和权限。
        :param page: 从 1 开始的页码。
        :param page_size: 每页条数，由接口检查范围。
        :param user_id: 按完整用户 ID 筛选；None 表示不筛选。
        :param user_name: 按完整用户名筛选；None 表示不筛选。
        :param is_active: True 只查启用，False 只查禁用，None 包含两种状态。
        :param is_deleted: False 只查未删除用户，True 只查已软删除用户。
        :return: 本页用户和符合条件的用户总数。
        """
        # 1. 在可见范围内同时匹配已传条件；本页记录和总数使用相同条件。
        users, total = await user_repository.list_users(
            session,
            current_user=current_user,
            page=page,
            page_size=page_size,
            user_id=user_id,
            user_name=user_name,
            is_active=is_active,
            is_deleted=is_deleted,
        )
        # 2. 一次整理本页角色和权限；已删除用户只展示账号资料，不再加载权限。
        user_details_by_id = await user_repository.get_users_info(
            session,
            users=users,
            current_user=current_user,
        )
        return PageResponse(
            items=[self._user_response(user_details_by_id[user.user_id]) for user in users],
            page=page,
            page_size=page_size,
            total=total,
        )

    async def get_user_detail(self, session: AsyncSession, *,
                              current_user: UserInfo,
                              user_id: str
                              ) -> UserResponse:
        """
            查询用户详情，只返回当前操作人能查看的角色和权限。
            调用方需先检查 users:read（查看用户）权限。

        :param session: 调用方提供并负责关闭的数据库会话。
        :param current_user: 当前操作人的角色和权限。
        :param user_id: 要查看的用户 ID。
        :return: 用户信息及允许查看的角色和权限。
        :raises AppError: 用户不存在或不允许查看。
        """
        # 1. 不可见和不存在都报“用户不存在”，避免泄露账号信息。
        user = await user_repository.get_user_detail(
            session,
            current_user=current_user,
            user_id=user_id,
        )
        if user is None:
            raise not_found_404("user_not_found")
        # 2. 只返回允许查看的角色和权限；这份展示结果不能用于判断修改权限。
        user_details_by_id = await user_repository.get_users_info(
            session,
            users=(user,),
            current_user=current_user,
        )
        return self._user_response(user_details_by_id[user.user_id])

    async def list_user_sessions(self, *, current_user: UserInfo,
                                 user_id: str,
                                 redis: RedisClient
                                 ) -> ActiveSessionsResponse:
        """
            查询用户当前有几次有效登录，以及各次登录时间。
            调用方需先检查 users:read（查看用户）权限；登录次数不等于设备数量。

        :param current_user: 当前操作人的角色和权限。
        :param user_id: 要查询的用户 ID。
        :param redis: 保存登录记录的 Redis 客户端。
        :return: 有效登录数量及各次登录的 UTC 时间。
        :raises AppError: 用户不存在、不允许查看，或登录记录暂时无法读取。
        """
        # 1. 确认用户可以查看，并读取登录版本，用来排除已失效的登录。
        async with self._session_factory() as session:
            user = await user_repository.get_user_detail(
                session,
                current_user=current_user,
                user_id=user_id,
            )
            if user is None:
                raise not_found_404("user_not_found")
            token_version = user.token_version

        # 2. 先释放数据库连接，再从 Redis 读取有效登录时间。
        timestamps = await login_session_repository.list_active_sessions(
            redis,
            user_id=user_id,
            token_version=token_version,
        )
        # 3. 把时间戳转成 UTC 时间，返回查询时的登录数量。
        return ActiveSessionsResponse(
            active_count=len(timestamps),
            login_times=tuple(
                datetime.fromtimestamp(value, UTC).isoformat()
                for value in timestamps
            ),
        )

    async def create_user(self, session: AsyncSession, *,
                          user_name: str,
                          password_hash: str,
                          bound_by_user_id: str | None = None
                          ) -> User:
        """
            创建用户并绑定默认 user 角色，供注册和管理员新增共用。
            调用前先检查密码并计算哈希；管理员新增还需检查新增权限。
            用户、角色绑定和审计由调用方一起提交，失败一起撤回。

        :param session: 调用方已开启事务的数据库会话。
        :param user_name: 新用户的用户名，已删除账号的名称也不能重用。
        :param password_hash: 已算好的 Argon2id 密码哈希，不是明文密码。
        :param bound_by_user_id: 分配角色的管理员 ID；自行注册为 None。
        :return: 新用户对象，此时尚未提交。
        :raises RuntimeError: 未开启事务，或默认角色不是启用中的系统角色。
        :raises ValueError: 用户名不符合规则。
        :raises AppError: 用户名已占用、操作人不存在，或默认角色、授权记录缺失。
        :raises IntegrityError: 其他数据库约束冲突，或主键碰撞重试已达到上限。
        """
        # 1. 必须由调用方先开启事务，保证用户、角色绑定和审计一起保存。
        if not session.in_transaction():
            raise RuntimeError("caller must start the user creation transaction")
        # 用户名按统一规则处理，查重和保存都使用这个值。
        normalized_user_name = validate_user_name(user_name)
        # 自动生成 U 开头的用户 ID，插入时若重复会重新生成。
        new_user_id = new_entity_id("U")

        # 2. 按授权记录、用户、角色的顺序加锁，让同时改权限的请求按顺序执行。
        await rbac_state_repository.lock_rbac_state(session)
        if bound_by_user_id is not None:
            # 管理员新增时，确认分配角色的管理员还存在。
            locked_users = await user_repository.lock_users(session, {bound_by_user_id})
            if bound_by_user_id not in locked_users:
                raise not_found_404("user_create_operator_not_found")

        # 3. 检查用户名是否已占用，已删除账号也算。
        existing = await user_repository.user_name_exists(session, user_name=normalized_user_name)
        if existing:
            raise self.username_exists_error()

        # 4. 创建带密码的用户；只有用户 ID 重复才换 ID 重试，最多三次。
        for attempt in range(3):
            user = User(
                user_id=new_user_id,
                user_name=normalized_user_name,
                password_hash=password_hash,
                # 使用数据库时间记录首次设置密码的时刻。
                password_changed_at=func.statement_timestamp(),
                # 新账号默认启用，注册后仍需单独登录。
                is_active=True,
                # 普通新用户不属于受保护的系统账号。
                is_protected=False,
                # 登录版本从 0 开始，改密或停用时加 1，让旧登录失效。
                token_version=0,
            )
            try:
                # 保存点只撤回这次失败的插入，方便换 ID 后继续尝试。
                async with session.begin_nested():
                    session.add(user)
                    # 立即检查数据库约束，尚未提交。
                    await session.flush()
                break
            except IntegrityError as exc:
                # 根据违反的数据库约束，区分用户名冲突和 ID 重复。
                constraint = get_constraint_name(exc)
                # 查重后仍可能被其他请求抢先使用，统一报“用户名已占用”。
                if constraint == "uq_users_user_name":
                    raise self.username_exists_error() from exc
                # 其他错误不能靠换 ID 解决；第三次仍重复也停止。
                if constraint != "pk_users" or attempt == 2:
                    raise
                new_user_id = new_entity_id("U")

        # 5. 锁住默认 user 角色，确认它存在、已启用且是系统角色。
        user_role = await role_repository.lock_role_by_key(session, key=SystemRoleKey.USER.value)
        # 默认角色缺失或不可用就停止，外层事务会撤回新用户。
        if user_role is None:
            raise not_found_404("default_user_role_missing")
        if not user_role.is_system or not user_role.is_active:
            raise RuntimeError("default user role must be an active system role")

        # 6. 给用户绑定默认角色；绑定 ID 重复时最多尝试三次，不重新创建用户。
        for attempt in range(3):
            binding = UserRole(
                # UR 开头的 ID 标识这条用户与角色的绑定记录。
                id=new_entity_id("UR"),
                user_id=user.user_id,
                role_id=user_role.id,
                bound_by_user_id=bound_by_user_id,
            )
            try:
                # 失败只撤回这次绑定，已插入的用户仍在外层事务中。
                async with session.begin_nested():
                    session.add(binding)
                    await session.flush()
                break
            except IntegrityError as exc:
                # 只对绑定 ID 重复重试，其他约束错误直接抛出。
                constraint = get_constraint_name(exc)
                if constraint != "pk_user_roles" or attempt == 2:
                    raise
        # 7. 返回新用户，由调用方添加审计后统一提交。
        return user

    async def admin_create_user(self, *, context: AuthorizationContext,
                                user_name: str,
                                password: str
                                ) -> str:
        """
            管理员新增用户，默认绑定 user 角色。
            需要 users:create（新增用户）权限。

        :param context: 当前管理员的身份信息，供权限检查和审计使用。
        :param user_name: 新用户的用户名，已删除账号的名称也不能重用。
        :param password: 管理员提供的初始密码，不保存原文。
        :return: 创建并提交成功后的用户 ID。
        :raises AppError: 没有新增权限、用户名已占用或密码不符合规则。
        :raises IntegrityError: 不属于用户名唯一约束的数据库冲突。
        """
        # 1. 先检查密码并计算哈希，避免占着数据库锁等待耗时计算。
        try:
            password_hash = await self._password_manager.hash_new_password(
                password, user_name=user_name
            )
        except PasswordPolicyError as exc:
            # 密码不符合规则时，转成统一的密码错误提示。
            raise password_policy_response_400(exc) from exc
        # 以下操作一起提交，任何一步失败都回滚。
        async with self._session_factory() as session, session.begin():
            # 2. 加锁后重查管理员身份和权限，防止计算密码期间账号被停用或权限被撤回。
            await rbac_state_repository.lock_rbac_state(session)
            await user_repository.lock_users(
                session, {context.login_info.user_id}
            )
            current_user = await user_repository.check_current_user(
                session,
                user_id=context.login_info.user_id,
                token_version=context.login_info.token_version,
            )
            if PermissionKey.USERS_CREATE.value not in current_user.permissions:
                raise forbidden_403("missing_operation_permission")
            # 3. 复用创建方法，新用户默认只有 user 角色。
            user = await self.create_user(
                session,
                user_name=user_name,
                password_hash=password_hash,
                bound_by_user_id=context.login_info.user_id,
            )
            # 4. 记录本次新增，和用户、角色绑定一起提交。
            self._audit.audit_success(
                session,
                action=AccountAuditAction.ADMIN_CREATE_USER,
                context=context,
                reason_code="permanent_password_set",
                target_user_id=user.user_id,
                after_state={"user_id": user.user_id, "default_role_key": "user"},
                message_key=MessageKey.AUTH_USER_CREATED,
                code=BusinessCode.CREATED,
                data={"user_id": user.user_id},
            )
        return user.user_id

    async def reset_user_password(self, *, context: AuthorizationContext,
                                  target_user_id: str,
                                  new_password: str
                                  ) -> None:
        """
            管理员重置用户密码，需要 users:password:reset 权限，且只能操作可管理的用户。
            新密码保存后立即可用，旧登录全部失效；改密和成功审计一起提交。

        :param context: 当前管理员的身份和审计信息。
        :param target_user_id: 要重置密码的用户 ID。
        :param new_password: 管理员指定的新密码，不保存原文。
        :return: 无返回值；正常结束表示密码重置及审计已提交，旧登录失效。
        :raises AppError: 无权操作该用户，或新密码不符合规则。
        """
        # 1. 先确认能操作这个用户，记下用户名后释放锁。
        try:
            async with self._session_factory() as session:
                async with session.begin():
                    target_user = await self._lock_authorized_reset_target(
                        session,
                        context=context,
                        target_user_id=target_user_id,
                    )
                    # 用户名用于检查新密码，写入密码时会重新查询用户。
                    target_user_name = target_user.user_name
        except AppError as exc:
            # 被拒绝也要留审计记录；单独保存，记录失败不影响原错误。
            await self._audit.audit_denied(
                error=exc,
                action=AccountAuditAction.ADMIN_RESET_PASSWORD,
                context=context,
                target_user_id=target_user_id,
            )
            raise

        # 2. 检查新密码并计算哈希。这一步较慢，不占着数据库锁等待。
        try:
            new_password_hash = await self._password_manager.hash_new_password(
                new_password, user_name=target_user_name,
            )
        except PasswordPolicyError as exc:
            # 把密码规则错误转成接口提示；其他故障不能误报成密码不合规。
            raise password_policy_response_400(exc) from exc

        # 3. 计算期间权限或用户名可能改变，重新加锁确认后才能改密码。
        try:
            async with self._session_factory() as session:
                async with session.begin():
                    target_user = await self._lock_authorized_reset_target(
                        session,
                        context=context,
                        target_user_id=target_user_id,
                    )
                    try:
                        validate_new_password(
                            new_password,
                            user_name=target_user.user_name,
                        )
                    except PasswordPolicyError as exc:
                        # 用户可能刚改名，要再次确认密码没有和当前用户名相同。
                        raise password_policy_response_400(exc) from exc

                    # 4. 保存密码，增加 Token 版本让旧登录失效，并一起保存成功审计。
                    await user_repository.update_password(
                        session,
                        user=target_user,
                        password_hash=new_password_hash,
                    )
                    target_user.token_version += 1
                    self._audit.audit_success(
                        session,
                        action=AccountAuditAction.ADMIN_RESET_PASSWORD,
                        context=context,
                        reason_code="permanent_password_set",
                        target_user_id=target_user.user_id,
                        message_key=MessageKey.AUTH_PASSWORD_RESET_SUCCEEDED,
                        data=None,
                    )
        except AppError as exc:
            # 本次改动会自动回滚；另记拒绝审计，再抛出原错误。
            await self._audit.audit_denied(
                error=exc,
                action=AccountAuditAction.ADMIN_RESET_PASSWORD,
                context=context,
                target_user_id=target_user_id,
            )
            raise

    async def _lock_authorized_reset_target(self, session: AsyncSession, *,
                                            context: AuthorizationContext,
                                            target_user_id: str
                                            ) -> User:
        """
            锁定相关记录，重新确认管理员有权重置这个用户的密码。
            这里只检查并返回用户，改密和提交由调用方完成。

        :param session: 调用方已开启事务的数据库会话。
        :param context: 当前管理员的身份和 Token 版本。
        :param target_user_id: 待重置密码的目标用户 ID。
        :return: 已锁定、允许重置密码的用户。
        :raises AppError: 登录失效，或无权操作这个用户。
        """
        # 1. 先锁权限状态，再锁用户；锁后重查管理员身份和权限，防止使用刚被撤回的权限。
        await rbac_state_repository.lock_rbac_state(session)
        users = await user_repository.lock_users(session, {context.login_info.user_id, target_user_id})
        current_user = await user_repository.check_current_user(
            session,
            user_id=context.login_info.user_id,
            token_version=context.login_info.token_version,
        )
        # 先查重置权限，避免无权限的人借接口探测用户是否存在。
        if PermissionKey.USERS_PASSWORD_RESET.value not in current_user.permissions:
            raise forbidden_403("missing_operation_permission")
        # 找不到用户和无权查看用户，都提示不存在。
        target_user = users.get(target_user_id)
        if target_user is None:
            raise not_found_404("user_not_found")
        # 2. 直接使用已锁住的用户查角色权限，不再按 ID 重查这个账号。
        permissions_by_user = await user_repository.get_user_permissions(
            session,
            users=(target_user,),
        )
        # 禁用角色仍算入等级保护，防止先禁用角色再越级改密。
        target = permissions_by_user[target_user.user_id].user_info_with_disabled_roles
        if not is_administrative_user_visible(current_user=current_user, target=target):
            raise not_found_404("user_not_found")
        # 3. 能看到用户还不够，再检查是否允许重置其密码。
        decision = decide_user_password_reset(current_user=current_user, target_before=target)
        if not decision.allowed:
            raise forbidden_403(decision.reason_code)
        return target_user

    async def update_user_status(self, *, context: AuthorizationContext,
                                 target_user_id: str,
                                 is_active: bool
                                 ) -> UserResponse:
        """
            启用或停用用户，需要 users:status:update 权限，且只能操作可管理的用户。
            状态改变时让旧登录失效；账号修改和成功审计一起提交。

        :param context: 当前管理员的身份和审计信息。
        :param target_user_id: 要修改状态的用户 ID。
        :param is_active: True 启用，False 停用；状态未变时保留当前登录。
        :return: 保存后的用户信息，只包含管理员有权查看的角色。
        :raises AppError: 登录失效，或不允许修改这个用户的状态。
        """
        # 1. 加锁后重查权限，确认能否启用或停用这个用户。
        action = RbacAuditAction.UPDATE_USER_STATUS
        async with user_role_transaction(
            self._session_factory,
            context=context,
            action=action,
            target_user_id=target_user_id,
        ) as session:
            locked = await self._lock_current_and_target_user(
                session,
                context=context,
                target_user_id=target_user_id,
                required_permission=PermissionKey.USERS_STATUS_UPDATE,
            )
            decision = decide_user_status_change(
                current_user=locked.current_user,
                target_before=locked.target_before,
            )
            if not decision.allowed:
                raise forbidden_403(decision.reason_code)

            # 2. 比较新旧状态，并准备审计要记录的修改后信息。
            changed = locked.target_row.is_active != is_active
            target_after = replace(locked.target_before, user_is_active=is_active)
            if changed:
                # 停用和重新启用都会让旧登录失效，避免解封后旧 Token 又能使用。
                locked.target_row.is_active = is_active
                locked.target_row.token_version += 1
            # 3. 先把修改写入当前事务，供下面查询使用；此时还没提交。
            await session.flush()
            # 查询修改后的用户信息，过滤无权查看的角色。
            user_details_by_id = await user_repository.get_users_info(
                session,
                users=(locked.target_row,),
                current_user=locked.current_user,
            )
            user_details = user_details_by_id[target_user_id]
            result = self._user_response(user_details)
            # 4. 审计记录本次修改和返回结果，与账号修改一起提交。
            self._audit.audit_success(
                session,
                action=action,
                context=context,
                target_user_id=target_user_id,
                reason_code="user_status_updated" if changed else "user_status_unchanged",
                before_state=_snapshot_payload(locked.target_before),
                after_state=_snapshot_payload(target_after),
                message_key=MessageKey.COMMON_OPERATION_SUCCESS,
                data=result,
            )

        return result

    async def revoke_user_sessions(self, *, context: AuthorizationContext,
                                   target_user_id: str
                                   ) -> None:
        """
            强制用户全部退出，需要 users:sessions:revoke 权限，且只能操作可管理的用户。
            增加 Token 版本，让旧登录下次请求时失效；版本修改和成功审计一起提交。

        :param context: 当前管理员的身份和审计信息。
        :param target_user_id: 要强制退出的用户 ID。
        :return: 无返回值；保存成功后，该用户全部旧登录失效。
        :raises AppError: 登录失效，或无权强制这个用户退出。
        """
        # 1. 加锁后重查权限，确认能否强制这个用户退出。
        action = RbacAuditAction.LOGOUT_USER_SESSIONS
        async with user_role_transaction(
            self._session_factory,
            context=context,
            action=action,
            target_user_id=target_user_id,
        ) as session:
            locked = await self._lock_current_and_target_user(
                session,
                context=context,
                target_user_id=target_user_id,
                required_permission=PermissionKey.USERS_SESSIONS_REVOKE,
            )
            decision = decide_user_sessions_revoke(
                current_user=locked.current_user,
                target_before=locked.target_before,
            )
            if not decision.allowed:
                raise forbidden_403(decision.reason_code)
            # 2. 记下旧版本供审计对比，再增加版本让旧登录失效，无须逐个删除 Redis 记录。
            previous_version = locked.target_row.token_version
            locked.target_row.token_version += 1
            # 3. 版本修改和成功审计一起提交；失败则一起回滚。
            self._audit.audit_success(
                session,
                action=action,
                context=context,
                target_user_id=target_user_id,
                reason_code="user_sessions_revoked",
                before_state={"token_version": previous_version},
                after_state={"token_version": locked.target_row.token_version},
                message_key=MessageKey.COMMON_OPERATION_SUCCESS,
                data=None,
            )

    async def change_user_roles(self, *, context: AuthorizationContext,
                                target_user_id: str,
                                role_ids: Iterable[str],
                                operation: str
                                ) -> UserRoleResponse:
        """
            给用户绑定或解绑角色，同时记录审计；失败时一起回滚。
            绑定需要 roles:bind，解绑需要 roles:unbind。
            还要检查双方等级、系统角色保护和角色数量，不能给自己提权。

        :param context: 当前操作人的身份和审计信息。
        :param target_user_id: 要修改角色的用户 ID。
        :param role_ids: 要绑定或解绑的角色 ID；请求接口会拒绝重复项，这里也会去重。
        :param operation: bind 绑定，unbind 解绑并保留历史记录。
        :return: 是否有改动，以及操作人能查看的用户信息。
        :raises AppError: 没选角色、无权操作、角色不可见或绑定数量超限。
        :raises ValueError: operation 不是 bind 或 unbind。
        """
        # 1. 确认是绑定还是解绑，并去掉重复角色；不能一个角色都不选。
        check_role_operation(operation)
        requested_role_ids = frozenset(role_ids)
        if not requested_role_ids:
            raise invalid_request_400("role_ids_required", business_code=BusinessCode.USER_ROLE_SELECTION_INVALID)
        # 选好审计动作，成功或拒绝都按这个动作记录。
        audit_action = (RbacAuditAction.BIND_USER_ROLES if operation == "bind"
                        else RbacAuditAction.UNBIND_USER_ROLES)
        async with user_role_transaction(
            self._session_factory,
            context=context,
            action=audit_action,
            target_user_id=target_user_id,
        ) as session:
            # 2. 按绑定或解绑选择权限，再加锁重查双方，避免执行期间权限被改掉。
            required_permission = (
                PermissionKey.ROLES_BIND
                if operation == "bind"
                else PermissionKey.ROLES_UNBIND
            )
            locked = await self._lock_current_and_target_user(
                session,
                context=context,
                target_user_id=target_user_id,
                required_permission=required_permission,
                additional_role_ids=set(requested_role_ids),
            )
            # 3. 找出本次提交的角色中，哪些已经绑定给这个用户。
            already_bound_role_ids = await user_role_repository.get_role_ids(
                session,
                user_ids={target_user_id},
                role_ids=requested_role_ids,
            )
            # 读取角色，检查它是否存在、启用，以及当前操作人能否查看。
            requested_roles: list[Role] = []
            for role_id in sorted(requested_role_ids, key=str):
                role = locked.roles.get(role_id)
                if role is None:
                    raise not_found_404("role_not_found")
                # 禁用角色不能新绑定，但已绑定的可以解绑或重复提交。
                if operation == "bind" and role_id not in already_bound_role_ids and not role.is_active:
                    raise not_found_404("role_not_found")
                requested_roles.append(role)
            role_info_by_id = await role_repository.get_role_permissions(
                session,
                roles=requested_roles,
            )
            # 有任何角色不可见，都按不存在处理。
            grants = [role_info_by_id[role.id] for role in requested_roles]
            if any(
                not is_administrative_role_visible(current_user=locked.current_user, role=grant)
                for grant in grants
            ):
                raise not_found_404("role_not_found")

            # 4. 先算出改完会拥有哪些角色和权限，此时还不修改数据库。
            target_after = locked.target_before
            if operation == "bind":
                for grant in grants:
                    target_after = target_after.with_role(grant)
                # 已绑定的不再新增。
                changed_ids = requested_role_ids - already_bound_role_ids
            else:
                for grant in grants:
                    target_after = target_after.without_role(grant.role_id)
                # 只解绑实际存在的绑定。
                changed_ids = requested_role_ids & already_bound_role_ids

            # 5. 检查改完是否越权、给自己提权或动到受保护角色，通过后再检查数量。
            decision = decide_role_change(
                operation=operation,
                current_user=locked.current_user,
                target_before=locked.target_before,
                target_after=target_after,
                changed_roles=tuple(grants),
            )
            if not decision.allowed:
                raise forbidden_403(decision.reason_code)
            if operation == "bind" and changed_ids:
                # 禁用角色也占绑定名额，不能靠禁用角色绕过数量上限。
                bound_role_count = await user_role_repository.count_roles(
                    session,
                    user_id=target_user_id,
                )
                if bound_role_count + len(changed_ids) > MAX_ROLES_PER_USER:
                    raise conflict_409("user_role_limit_exceeded", business_code=BusinessCode.USER_ROLE_LIMIT_EXCEEDED)

            # 6. 只写入真正新增或解除的绑定，重复请求不重复修改。
            changed = bool(changed_ids)
            if changed:
                if operation == "bind":
                    session.add_all(
                        UserRole(
                            user_id=target_user_id,
                            role_id=role_id,
                            bound_by_user_id=locked.current_user.user_id,
                        )
                        for role_id in sorted(changed_ids, key=str)
                    )
                else:
                    # 解绑保留时间和操作人，方便以后查历史。
                    deleted_at = datetime.now(UTC)
                    await user_role_repository.unbind_roles(
                        session,
                        user_id=target_user_id,
                        role_ids=changed_ids,
                        deleted_at=deleted_at,
                        deleted_by_user_id=locked.current_user.user_id,
                    )
            # 7. flush 让后面的查询读到改动，但还没提交；用户信息和审计准备好后一起提交。
            await session.flush()
            user_details_by_id = await user_repository.get_users_info(
                session,
                users=(locked.target_row,),
                current_user=locked.current_user,
            )
            user_details = user_details_by_id[target_user_id]
            result = UserRoleResponse(
                user=self._user_response(user_details),
            )
            if not changed:
                reason_code = "user_roles_unchanged"
            elif operation == "bind":
                reason_code = "user_roles_bound"
            else:
                reason_code = "user_roles_unbound"
            self._audit.audit_success(
                session,
                action=audit_action,
                context=context,
                target_user_id=target_user_id,
                reason_code=reason_code,
                before_state=_snapshot_payload(locked.target_before),
                after_state=_snapshot_payload(target_after),
                message_key=MessageKey.COMMON_OPERATION_SUCCESS,
                data=result,
            )

        return result

    async def _lock_current_and_target_user(self, session: AsyncSession, *,
                                            context: AuthorizationContext,
                                            target_user_id: str,
                                            required_permission: PermissionKey,
                                            additional_role_ids: set[str] | None = None
                                            ) -> _LockedUserChange:
        """
            加锁后重查操作人的身份和权限，确认目标用户是否可见。
            目标用户的禁用角色也保留等级保护，不能先禁用再绕过限制。

        :param session: 本次事务使用的数据库会话。
        :param context: 当前操作人的身份和 Token 版本。
        :param target_user_id: 被操作的用户 ID。
        :param required_permission: 本次操作必须具备的权限。
        :param additional_role_ids: 还要一起锁住的待绑定或解绑角色，可不传。
        :return: 加锁后的双方信息、目标用户记录和相关角色记录。
        :raises AppError: 登录失效、没有权限，或目标不存在、不可见。
        """
        # 1. 按“授权状态 → 用户 → 角色”的固定顺序加锁，避免多个请求互相等锁。
        await rbac_state_repository.lock_rbac_state(session)
        # user_id 是操作人，target_user_id 是被操作人，两人都要锁住。
        user_id = context.login_info.user_id
        users = await user_repository.lock_users(
            session,
            {user_id, target_user_id},
        )
        # 确认账号可用、登录版本有效，再重查当前权限。
        check_locked_user(
            users.get(user_id),
            token_version=context.login_info.token_version,
        )
        current_user = await user_repository.check_current_user(
            session,
            user_id=user_id,
            token_version=context.login_info.token_version,
        )
        # 先查操作权限，再查目标，避免无权用户探测别人是否存在。
        if required_permission.value not in current_user.permissions:
            raise forbidden_403("missing_operation_permission")
        if target_user_id not in users:
            raise not_found_404("target_user_not_found")

        # 2. 锁住双方已有角色和本次要改的角色，防止检查时等级或权限被改动。
        user_ids = {user_id, target_user_id}
        # 先收集双方已有角色，再加上本次要绑定或解绑的角色。
        bound_role_ids = await user_role_repository.get_role_ids(
            session,
            user_ids=user_ids,
        )
        locked_roles = await role_repository.lock_roles(
            session,
            role_ids=bound_role_ids | (additional_role_ids or set()),
        )
        # 角色锁拿到后再查一次权限，不能继续使用等待加锁前的结果。
        current_user = await user_repository.check_current_user(
            session,
            user_id=user_id,
            token_version=context.login_info.token_version,
        )
        # 3. 使用已锁住的目标用户，一次查齐启用和禁用角色，不再重复查账号和角色。
        target_user = users[target_user_id]
        permissions_by_user = await user_repository.get_user_permissions(
            session,
            users=(target_user,),
        )
        target_permissions = permissions_by_user[target_user.user_id]
        # 能否查看按启用角色判断；禁用角色不提供当前权限。
        if not is_administrative_user_visible(current_user=current_user, target=target_permissions.user_info):
            raise not_found_404("target_user_not_found")
        # 4. 再把禁用角色算进等级保护，防止先禁用高等级角色，再越级修改用户。
        return _LockedUserChange(
            current_user=current_user,
            target_before=target_permissions.user_info_with_disabled_roles,
            target_row=target_user,
            roles=locked_roles,
        )

    @staticmethod
    def _user_response(user_details: UserDetails) -> UserResponse:
        """
            把操作人能查看的用户信息整理成返回结果。

        :param user_details: 已查出的用户名、可见角色和有效权限，仅用于展示。
        :return: 用户身份、角色、管理等级和有效权限。
        """
        # 使用查好的信息，不再查询数据库，也不返回密码字段。
        user_info = user_details.user_info
        # 已绑定角色和生效角色分开返回：禁用后仍有绑定，但不再提供权限。
        return UserResponse(
            user_id=user_info.user_id,
            user_name=user_details.user_name,
            is_active=user_info.user_is_active,
            bound_role_ids=user_details.bound_role_ids,
            effective_role_ids=tuple(role.role_id for role in user_info.roles),
            role_level=user_info.role_level,
            effective_permissions=tuple(sorted(user_info.permissions)),
        )


# 共用这个服务实例；每次请求的用户和数据库会话不会保存在实例里。
user_service = UserService(SessionFactory)
