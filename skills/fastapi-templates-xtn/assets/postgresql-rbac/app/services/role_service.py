#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    查询和管理角色，检查修改是否会影响无权管理的用户。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        收回角色响应转换，简化更新参数并整理事务内业务步骤
# 2026/09/23    XTN       V1.002        补充面向初学者的业务权限、执行顺序和事务结果说明
# 2026/09/23    XTN       V1.003        类方法参数逐行对齐，整理业务调用排版
# 2026/09/23    XTN       V1.004        展开角色和审计字段，准确说明写入与权限版本用途
# 2026/09/26    XTN       V1.005        统一角色详情、请求和操作结果名称
# 2026/09/29    XTN       V1.006        从角色专属策略模块导入授权判断
# 2026/09/29    XTN       V1.007        角色标识冲突返回角色专属业务码
# 2026/10/02    XTN       V1.008        复用已加载角色并展开审计原因分支，理顺查询与修改步骤
# 2026/10/08    XTN       V1.009        删除角色操作提示清单，保持原有操作校验
# 2026/10/09    XTN       V1.010        角色生命周期和权限绑定引用固定审计动作
# 2026/10/09    XTN       V1.011        角色主键冲突复用约束名读取，保留原保存点和重试上限
# 2026/10/09    XTN       V1.012        接口响应模型统一使用 Response 后缀，保留返回字段与行为
# 2026/10/10    XTN       V1.013        统一用户身份命名，区分用户 ID、当前用户及目标用户
# 2026/10/13    XTN       V1.014        补齐角色业务分阶段说明、短函数步骤及并发版本和共享权限边界
# 2026/10/15    XTN       V1.015        角色修改不再写入持有者权限版本，保留完整受影响用户检查
# 2026/10/15    XTN       V1.016        权限绑定统一使用 bound_by_user_id 记录操作人
# 2026/10/16    XTN       V1.017        异常构造器名称统一标明固定 HTTP 状态
# 2026/10/16    XTN       V1.018        保留授权行锁与角色编辑版本，删除全局授权计数和单行版本转发方法
# 2026/10/16    XTN       V1.019        权限操作审计在提交前补齐脱敏业务响应快照
# 2026/10/16    XTN       V1.020        角色业务直接调用成功审计，事务不再传递待填写的审计对象
# 2026/10/19    XTN       V1.021        直接导入共享业务服务，删除仅返回实例的依赖入口
# 2026/10/19    XTN       V1.022        精简角色注释，说明权限检查和事务步骤
# 2026/10/19    XTN       V1.023        角色操作只返回最终角色信息，保留内部变更判断和审计
# 2026/10/20    XTN       V1.024        角色创建、响应及审计摘要统一使用 level
# 2026/10/20    XTN       V1.025        登录身份统一使用 login_info，认证依赖改用直观入口
# 2026/10/22    XTN       V1.026        角色查询归角色仓储，用户权限读取归用户仓储
# 2026/10/22    XTN       V1.027        用户权限读取直观命名，明确保留停用角色的等级保护
# 2026/10/23    XTN       V1.028        角色持有人统一使用用户权限查询入口
# 2026/10/24    XTN       V1.029        使用简洁角色仓储入口，单个与批量权限走同一查询
# 2026/10/24    XTN       V1.030        使用简洁用户角色查询和解绑入口
# 2026/10/24    XTN       V1.031        简化角色业务命名和步骤，复用已读权限并整理辅助函数位置
# 2026/10/24    XTN       V1.032        使用简洁事务校验入口，只传实际审计目标
# 2026/10/24    XTN       V1.033        公共事务改用 user_role_transaction 模块与入口
# 2026/10/26    XTN       V1.034        用户角色权限信息类型统一命名为 UserInfo
# 2026/10/26    XTN       V1.035        用户权限结果字段明确区分生效信息与含停用角色的信息
# 2026/10/26    XTN       V1.036        角色列表透传六项筛选，软删除结果只展示基本信息
# 2026/10/26    XTN       V1.037        减少角色长属性链，展开列表组装并集中权限操作选择
# --------------------------------------------------------------------------------------------------


from collections.abc import Iterable
from dataclasses import dataclass, replace
from datetime import UTC, datetime

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.access.authorization import AuthorizationContext, RoleGrant, UserInfo
from app.core.access.permissions import PermissionKey
from app.core.access.role_policy import (
    decide_role_administration,
    decide_role_create,
    decide_role_permissions_change,
    is_administrative_role_visible,
)
from app.core.access.roles import RESERVED_ROLE_KEYS, SUPER_ADMIN_PERMISSION_KEYS
from app.core.audit import RbacAuditAction
from app.core.codes import BusinessCode
from app.core.exceptions import (
    conflict_409,
    forbidden_403,
    invalid_request_400,
    not_found_404,
    stale_resource_version_409,
)
from app.core.i18n.messages import MessageKey
from app.core.ids import new_entity_id
from app.core.response import PageResponse
from app.db.postgres_db import SessionFactory, get_constraint_name
from app.models.postgres.role import Role, RolePermission
from app.repositories.postgres.permission_repository import permission_repository
from app.repositories.postgres.rbac_state_repository import rbac_state_repository
from app.repositories.postgres.role_repository import role_repository
from app.repositories.postgres.user_repository import user_repository
from app.repositories.postgres.user_role_repository import user_role_repository
from app.schemas.role import (
    RoleCreateRequest,
    RoleMutationResponse,
    RoleResponse,
    RoleUpdateRequest,
)
from app.services.audit_service import AuditService
from app.services.user_role_transaction import (
    check_locked_user,
    check_role_operation,
    user_role_transaction,
)


@dataclass(slots=True)
class _LockedRole:
    """
        修改角色前锁定的数据，用于检查是否越权。
    """

    # 当前用户的完整权限，用于本次检查。
    current_user: UserInfo
    # 已锁定的目标角色，后续直接修改它。
    role: Role
    # 修改前的角色信息和权限；校验、去重和审计都使用这一份。
    role_info: RoleGrant
    # 绑定了这个角色的用户信息，保留停用角色用于检查等级。
    bound_users: tuple[UserInfo, ...]
    # 持有这个角色的全部用户 ID。
    bound_user_ids: frozenset[str]


class RoleService:
    """
        管理角色及其权限，检查当前用户能否查看和修改目标。
    """

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        """
            保存会话工厂，供每次角色修改创建事务。

        :param session_factory: 创建 PostgreSQL 异步会话的工厂。
        :return: 无返回值；会话工厂已保存。
        """
        # 共享实例只保存工厂，不保存当前用户或数据库连接。
        self._session_factory = session_factory

    @staticmethod
    def _build_role_audit(role: RoleResponse) -> dict[str, object]:
        """
            从角色响应中取出需要留档的审计字段。

        :param role: 修改前或修改后的角色响应。
        :return: 包含角色信息、权限、软删除状态和版本的审计字典。
        """
        # 复用已有结果，权限转成列表即可保存，不再查库。
        return {
            "role_id": str(role.id),
            "key": role.key,
            "name": role.name,
            "description": role.description,
            "level": role.level,
            "is_active": role.is_active,
            "is_system": role.is_system,
            "is_deleted": role.deleted_at is not None,
            "permissions": list(role.permissions),
            "version": role.version,
        }

    @staticmethod
    def _build_role_response(role: Role,
                             permissions: Iterable[str]
                             ) -> RoleResponse:
        """
            把已加载的角色和权限整理成响应，不再查库。

        :param role: 当前操作者可以查看或本事务已经修改的角色模型。
        :param permissions: 已读取且允许公开的权限键集合。
        :return: 角色字段副本，权限按名称排序。
        """
        # 复制需要公开的字段，离开事务后不再读取数据库模型。
        return RoleResponse(
            id=role.id,
            key=role.key,
            name=role.name,
            description=role.description,
            level=role.level,
            is_active=role.is_active,
            is_system=role.is_system,
            is_protected=role.is_protected,
            permissions=tuple(sorted(permissions)),
            version=role.version,
            deleted_at=role.deleted_at,
        )

    @staticmethod
    def _check_role_version(role: Role,
                            expected_version: int
                            ) -> None:
        """
            检查页面版本，避免覆盖别人刚保存的修改。

        :param role: 当前事务已经锁定的角色模型。
        :param expected_version: 页面读到的版本号；与数据库不同时须刷新后再操作。
        :return: 无返回值，版本一致时允许继续变更。
        :raises AppError: 角色当前版本与预期版本不一致。
        """
        # 加锁后再比较版本；不一致就要求刷新页面。
        if role.version != expected_version:
            raise stale_resource_version_409("stale_role_version")

    async def _lock_role(self, session: AsyncSession, *,
                         context: AuthorizationContext,
                         role_id: str,
                         required_permission: PermissionKey,
                         include_inactive: bool = False
                         ) -> _LockedRole:
        """
            锁住目标角色和相关用户，再重查权限，供后续判断能否修改。

        :param session: 调用方已经开启事务的 PostgreSQL 异步会话。
        :param context: 当前操作者身份与 Token 版本。
        :param role_id: 即将修改的角色 ID。
        :param required_permission: 当前操作要求操作者持有的权限键。
        :param include_inactive: False 拒绝停用角色；True 允许读取以便改资料、启停或删除，仍须检查管理权限。
        :return: 已锁定角色、修改前的角色信息和绑定用户信息。
        :raises AppError: 身份失效、权限不足，或角色不存在、不可见。
        """
        # 1. 按状态行、用户、角色、权限绑定的顺序加锁，减少互相等待。
        # 先找齐绑定这个角色的用户，改角色也会影响他们。
        await rbac_state_repository.lock_rbac_state(session)
        user_id = context.login_info.user_id
        bound_user_ids = await user_role_repository.get_user_ids(session, role_id=role_id)
        user_ids_to_lock = bound_user_ids | {user_id}
        locked_users = await user_repository.lock_users(session, user_ids_to_lock)
        check_locked_user(locked_users.get(user_id), token_version=context.login_info.token_version)

        # 2. 锁住这些用户的全部角色，重查当前用户权限。
        role_ids_to_lock = await user_role_repository.get_role_ids(session, user_ids=user_ids_to_lock)
        locked_roles = await role_repository.lock_roles(session, role_ids=role_ids_to_lock | {role_id})
        # 等待时可能刚被撤权，必须使用加锁后查到的权限。
        current_user = await user_repository.check_current_user(
            session,
            user_id=user_id,
            token_version=context.login_info.token_version,
        )
        if required_permission.value not in current_user.permissions:
            raise forbidden_403("missing_operation_permission")

        # 3. 操作权限通过后，再检查目标是否存在、状态是否允许，以及当前用户能否看到它。
        role = locked_roles.get(role_id)
        if role is None or role.deleted_at is not None or (not include_inactive and not role.is_active):
            raise not_found_404("role_not_found")
        # 锁住权限绑定，再读取角色信息；后续直接用其中的权限判断是否已经绑定。
        await role_repository.lock_permission_bindings(session, role_id=role_id)
        role_info_by_id = await role_repository.get_role_permissions(session, roles=(role,))
        role_info = role_info_by_id[role.id]
        if not is_administrative_role_visible(current_user=current_user, role=role_info):
            raise not_found_404("role_not_found")
        # 4. 一次读齐持有者权限，连同停用角色的等级一起检查，防止间接越权。
        bound_user_accounts = tuple(locked_users[user_id] for user_id in sorted(bound_user_ids, key=str))
        user_permissions_by_id = await user_repository.get_user_permissions(
            session,
            users=bound_user_accounts,
        )
        # 停用角色仍参与等级检查，避免借改角色影响无权管理的用户。
        bound_users = tuple(
            user_permissions_by_id[user.user_id].user_info_with_disabled_roles for user in bound_user_accounts)
        return _LockedRole(
            current_user=current_user,
            role=role,
            role_info=role_info,
            bound_users=bound_users,
            bound_user_ids=frozenset(bound_user_ids),
        )

    @staticmethod
    def _check_role_change(locked_role: _LockedRole, *,
                           operation: str
                           ) -> None:
        """
            检查修改角色是否越级，或会影响受保护用户。

        :param locked_role: 已锁定的角色、当前用户和全部持有者权限。
        :param operation: update/enable/disable/delete，分别表示修改资料、启用、禁用、删除，决定系统角色保护规则。
        :return: 无返回值；检查通过后可继续操作。
        :raises AppError: 角色管理策略拒绝本次操作。
        """
        # 一并检查全部持有者，不能借改角色绕过对用户的等级保护。
        check_result = decide_role_administration(
            operation=operation,
            current_user=locked_role.current_user,
            changed_role=locked_role.role_info,
            current_user_holds_role=locked_role.current_user.user_id in locked_role.bound_user_ids,
            affected=locked_role.bound_users,
        )
        if not check_result.allowed:
            raise forbidden_403(check_result.reason_code)

    async def list_roles(self, session: AsyncSession, *,
                         current_user: UserInfo,
                         page: int,
                         page_size: int,
                         role_id: str | None = None,
                         key: str | None = None,
                         name: str | None = None,
                         is_active: bool | None = None,
                         is_system: bool | None = None,
                         is_deleted: bool = False
                         ) -> PageResponse[RoleResponse]:
        """
            按条件分页查询可见角色；已软删除角色只返回基本信息和空权限列表。
            调用方须先检查 roles:read（查看角色）。

        :param session: 调用方管理生命周期的 PostgreSQL 异步会话。
        :param current_user: 已通过查询权限检查的当前用户及其完整权限。
        :param page: 从 1 开始的页码。
        :param page_size: 经过接口范围校验的每页条数。
        :param role_id: 角色 ID 精确匹配；None 不按 ID 筛选。
        :param key: 角色编码精确匹配；None 不按编码筛选。
        :param name: 名称包含的文字；None 不按名称筛选。
        :param is_active: True 只查启用，False 只查禁用，None 不限制启用状态。
        :param is_system: True 只查系统角色，False 只查自定义角色，None 不限制类型。
        :param is_deleted: False 只查未删除角色，True 只查已软删除角色。
        :return: 当前页角色信息、权限与可见角色总数。
        """
        # 1. 筛选和可见范围都交给仓储，列表与总数使用同一条件。
        roles, total_roles = await role_repository.list_roles(
            session,
            current_user=current_user,
            page=page,
            page_size=page_size,
            role_id=role_id,
            key=key,
            name=name,
            is_active=is_active,
            is_system=is_system,
            is_deleted=is_deleted,
        )
        # 2. 只为未删除角色批量读取权限；已删除记录不能再加载旧授权。
        not_deleted_roles = tuple(role for role in roles if role.deleted_at is None)
        # 空集合交给仓储直接返回，不会查询数据库。
        role_info_by_id = await role_repository.get_role_permissions(session, roles=not_deleted_roles)
        role_responses = []
        for role in roles:
            permissions: Iterable[str] = ()
            if role.deleted_at is None:
                permissions = role_info_by_id[role.id].permissions
            role_responses.append(self._build_role_response(role, permissions))
        # 3. 返回本页角色和同一查询范围的总数。
        return PageResponse(
            items=role_responses,
            page=page,
            page_size=page_size,
            total=total_roles,
        )

    async def get_role_detail(self, session: AsyncSession, *,
                              current_user: UserInfo,
                              role_id: str
                              ) -> RoleResponse:
        """
            查询可见角色的详情；不可见和不存在都返回同一种错误。
            调用方须先检查 roles:read（查看角色）。

        :param session: 调用方管理生命周期的 PostgreSQL 异步会话。
        :param current_user: 已通过查询权限检查的当前用户及其完整权限。
        :param role_id: 要查看的角色 ID。
        :return: 角色信息及其未软删除的权限集合。
        :raises AppError: 角色不存在或不在操作者可见范围内。
        """
        # 1. 只查询当前用户可见的角色，避免泄露隐藏角色。
        role = await role_repository.get_role_detail(
            session,
            current_user=current_user,
            role_id=role_id,
        )
        if role is None:
            raise not_found_404("role_not_found")
        # 2. 整理角色和权限；停用角色仍可查看，方便管理员调整配置。
        role_info_by_id = await role_repository.get_role_permissions(session, roles=(role,))
        return self._build_role_response(role, role_info_by_id[role.id].permissions)

    async def create_role(self, *, context: AuthorizationContext,
                          body: RoleCreateRequest
                          ) -> RoleMutationResponse:
        """
            检查 roles:create（创建角色），只创建低于当前用户等级的普通角色。
            角色和成功审计一起保存，失败一起回滚。

        :param context: 当前操作者身份与审计上下文。
        :param body: 新角色的键、名称、说明和管理等级。
        :return: 已提交的新角色；新角色尚无权限。
        :raises AppError: 越权创建、角色键为系统保留值或角色键已经被占用。
        :raises IntegrityError: 并发角色键冲突、其他约束冲突，或角色主键重试达到上限。
        """
        # 先生成角色 ID，方便关联审计；此时还没有创建角色。
        role_id = new_entity_id("R")
        action = RbacAuditAction.CREATE_ROLE
        async with user_role_transaction(
            self._session_factory,
            context=context,
            action=action,
            target_role_id=role_id,
        ) as session:
            # 1. 按状态行、用户、角色的顺序加锁，再重查权限，防止等待时刚被撤权。
            await rbac_state_repository.lock_rbac_state(session)
            user_id = context.login_info.user_id
            locked_users = await user_repository.lock_users(session, {user_id})
            check_locked_user(locked_users.get(user_id), token_version=context.login_info.token_version)
            current_user_role_ids = await user_role_repository.get_role_ids(session, user_ids={user_id})
            await role_repository.lock_roles(session, role_ids=current_user_role_ids)
            current_user = await user_repository.check_current_user(
                session,
                user_id=user_id,
                token_version=context.login_info.token_version,
            )
            # 2. 检查创建权限、角色等级和角色标识。
            check_result = decide_role_create(current_user=current_user, level=body.level)
            if not check_result.allowed:
                raise forbidden_403(check_result.reason_code)
            if body.key in RESERVED_ROLE_KEYS:
                raise conflict_409("reserved_role_key", business_code=BusinessCode.ROLE_KEY_CONFLICT)
            # 已删除角色仍占用原标识；提前检查便于提示，数据库唯一约束防止并发重复。
            existing_role_id = await role_repository.get_role_id_by_key(session, key=body.key)
            if existing_role_id is not None:
                raise conflict_409("role_key_exists", business_code=BusinessCode.ROLE_KEY_CONFLICT)

            # 3. 创建普通角色。随机 ID 撞号时最多尝试 3 次，其他冲突直接抛出。
            for attempt in range(3):
                role = Role(
                    id=role_id,
                    key=body.key,
                    name=body.name,
                    description=body.description,
                    level=body.level,
                    is_active=True,
                    is_protected=False,
                    is_system=False,
                    is_super_admin=False,
                )
                try:
                    async with session.begin_nested():
                        session.add(role)
                        # flush 先发送 INSERT 检查约束，还没有提交外层事务。
                        await session.flush()
                    break
                except IntegrityError as exc:
                    # 保存点只撤回本次插入；只有主键撞号能靠换 ID 重试。
                    constraint = get_constraint_name(exc)
                    if constraint != "pk_roles" or attempt == 2:
                        raise
                    role_id = new_entity_id("R")
            # 4. 整理结果并添加审计，退出外层事务时一起提交。
            role_after = self._build_role_response(role, ())
            response = RoleMutationResponse(role=role_after)
            # 审计保存脱敏业务结果，不代表已向客户端返回响应。
            AuditService.audit_success(
                session,
                action=action,
                context=context,
                target_role_id=role_id,
                reason_code="role_created",
                after_state=self._build_role_audit(role_after),
                message_key=MessageKey.COMMON_CREATED,
                code=BusinessCode.CREATED,
                data=response,
            )

        return response

    async def update_role(self, *, context: AuthorizationContext,
                          body: RoleUpdateRequest
                          ) -> RoleMutationResponse:
        """
            检查 roles:update（修改角色信息）后修改名称、说明，不改等级或权限。
            修改前检查角色持有者和版本，修改与审计一起提交。

        :param context: 当前操作者身份和审计上下文。
        :param body: 目标角色 ID、预期版本以及可更新的名称与说明。
        :return: 提交后的角色信息；内容未变时不增加版本。
        :raises AppError: 身份或权限失效、目标不可见、管理策略拒绝或角色版本过期。
        """
        # 1. 锁定角色和持有者，重查管理范围及页面版本。
        action = RbacAuditAction.UPDATE_ROLE
        async with user_role_transaction(
            self._session_factory,
            context=context,
            action=action,
            target_role_id=body.role_id,
        ) as session:
            locked_role = await self._lock_role(
                session,
                context=context,
                role_id=body.role_id,
                required_permission=PermissionKey.ROLES_UPDATE,
                include_inactive=True,
            )
            self._check_role_change(locked_role, operation="update")
            # role 就是本事务锁住的角色，下面直接修改它。
            role = locked_role.role
            self._check_role_version(role, body.expected_version)
            permissions_before = locked_role.role_info.permissions
            role_before = self._build_role_response(role, permissions_before)

            # 2. 只修改本次提交且与原值不同的字段。
            changed = False
            if body.name is not None and body.name != role.name:
                role.name = body.name
                changed = True
            if body.description is not None and body.description != role.description:
                role.description = body.description
                changed = True
            if changed:
                # 内容变了才增加版本，让旧页面刷新后再修改。
                role.version += 1
            # 3. 整理结果和修改前后状态，随审计一起提交。
            role_after = self._build_role_response(role, permissions_before)
            response = RoleMutationResponse(role=role_after)
            AuditService.audit_success(
                session,
                action=action,
                context=context,
                target_role_id=body.role_id,
                reason_code="role_updated" if changed else "role_unchanged",
                before_state=self._build_role_audit(role_before),
                after_state=self._build_role_audit(role_after),
                message_key=MessageKey.COMMON_OPERATION_SUCCESS,
                data=response,
            )

        return response

    async def set_role_active(self, *, context: AuthorizationContext,
                              role_id: str,
                              is_active: bool,
                              expected_version: int
                              ) -> RoleMutationResponse:
        """
            检查 roles:status:update（启停角色）、管理范围和版本后修改状态。
            还会检查全部角色持有者，避免间接修改无权管理的人；状态和审计一起提交。

        :param context: 当前操作者身份和审计上下文。
        :param role_id: 待启用或禁用的角色 ID。
        :param is_active: True 启用，False 停用但保留绑定；重复设置不增加版本。
        :param expected_version: 页面读到的版本号；与数据库不同时须刷新后再操作。
        :return: 提交后的角色信息；重复设置仍返回当前状态。
        :raises AppError: 身份或权限失效、目标不可见、管理策略拒绝或角色版本过期。
        """
        # 1. 选定本次是启用还是停用，以及对应的审计动作。
        operation = "enable" if is_active else "disable"
        action = RbacAuditAction.ENABLE_ROLE if is_active else RbacAuditAction.DISABLE_ROLE
        async with user_role_transaction(
            self._session_factory,
            context=context,
            action=action,
            target_role_id=role_id,
        ) as session:
            # 2. 锁住角色及持有者，重查管理范围和版本；停用角色也能在这里恢复。
            locked_role = await self._lock_role(
                session,
                context=context,
                role_id=role_id,
                required_permission=PermissionKey.ROLES_STATUS_UPDATE,
                include_inactive=True,
            )
            self._check_role_change(locked_role, operation=operation)
            role = locked_role.role
            self._check_role_version(role, expected_version)
            permissions_before = locked_role.role_info.permissions
            role_before = self._build_role_response(role, permissions_before)
            changed = role.is_active != is_active
            if changed:
                # 3. 状态变了才增加版本，不改已有绑定。
                role.is_active = is_active
                role.version += 1
            # 4. 整理结果和修改前后状态，随审计一起提交。
            role_after = self._build_role_response(role, permissions_before)
            response = RoleMutationResponse(role=role_after)
            if changed:
                reason_code = "role_enabled" if is_active else "role_disabled"
            else:
                reason_code = "role_status_unchanged"
            AuditService.audit_success(
                session,
                action=action,
                context=context,
                target_role_id=role_id,
                reason_code=reason_code,
                before_state=self._build_role_audit(role_before),
                after_state=self._build_role_audit(role_after),
                message_key=MessageKey.COMMON_OPERATION_SUCCESS,
                data=response,
            )

        return response

    async def delete_role(self, *, context: AuthorizationContext,
                          role_id: str,
                          expected_version: int
                          ) -> RoleMutationResponse:
        """
            检查 roles:delete（删除角色）、管理范围和版本后，软删除角色及其绑定。
            系统角色不能删除；删除、角色版本和审计一起保存。

        :param context: 当前操作者身份和审计上下文。
        :param role_id: 需要软删除的普通角色 ID。
        :param expected_version: 页面读到的版本号；与数据库不同时须刷新后再操作。
        :return: 已删除的角色信息，权限列表为空。
        :raises AppError: 身份或权限失效、目标不可见、系统/共享角色保护拒绝或角色版本过期。
        """
        # 1. 锁定角色和持有者，检查能否删除以及页面版本是否过期。
        action = RbacAuditAction.DELETE_ROLE
        async with user_role_transaction(
            self._session_factory,
            context=context,
            action=action,
            target_role_id=role_id,
        ) as session:
            locked_role = await self._lock_role(
                session,
                context=context,
                role_id=role_id,
                required_permission=PermissionKey.ROLES_DELETE,
                include_inactive=True,
            )
            self._check_role_change(locked_role, operation="delete")
            role = locked_role.role
            self._check_role_version(role, expected_version)
            role_before = self._build_role_response(role, locked_role.role_info.permissions)
            # 2. 给角色、用户绑定、权限绑定写上相同的删除时间和操作人，保留历史。
            deleted_at = datetime.now(UTC)
            role.is_active = False
            role.deleted_at = deleted_at
            role.deleted_by_user_id = locked_role.current_user.user_id
            await user_role_repository.unbind_roles(
                session,
                role_ids=frozenset({role_id}),
                deleted_at=deleted_at,
                deleted_by_user_id=locked_role.current_user.user_id,
            )
            await role_repository.unbind_permissions(
                session,
                role_id=role_id,
                deleted_at=deleted_at,
                deleted_by_user_id=locked_role.current_user.user_id,
            )
            # 3. 增加角色版本，记录删除前后状态，随审计一起提交。
            role.version += 1
            role_after = self._build_role_response(role, ())
            response = RoleMutationResponse(role=role_after)
            AuditService.audit_success(
                session,
                action=action,
                context=context,
                target_role_id=role_id,
                reason_code="role_soft_deleted",
                before_state=self._build_role_audit(role_before),
                after_state=self._build_role_audit(role_after),
                message_key=MessageKey.COMMON_OPERATION_SUCCESS,
                data=response,
            )

        return response

    async def change_role_permissions(self, *, context: AuthorizationContext,
                                      role_id: str,
                                      permission_ids: Iterable[str],
                                      operation: str,
                                      expected_version: int
                                      ) -> RoleMutationResponse:
        """
            bind 需要 roles:permissions:bind（给角色加权限），unbind 需要 roles:permissions:unbind（收回权限）。
            不能授予自己没有的权限，也不能借共享角色给自己或无权管理的人改权限。
            权限绑定、角色版本和审计一起提交。

        :param context: 当前操作者身份和审计上下文。
        :param role_id: 需要修改权限的角色 ID。
        :param permission_ids: 待绑定或解绑的权限 ID，不能为空；重复项去重，每项须是允许的未删除权限。
        :param operation: bind 表示绑定，unbind 表示软删除权限关系。
        :param expected_version: 页面读到的版本号；与数据库不同时须刷新后再操作。
        :return: 包含最终权限的角色信息；重复绑定或解绑不增加版本。
        :raises AppError: 权限集合无效、操作越权或角色版本过期。
        :raises ValueError: operation 不是 bind 或 unbind，在开启事务之前拒绝。
        """
        # 1. 检查绑定或解绑操作，去除重复 ID，拒绝空列表。
        check_role_operation(operation)
        requested_permission_ids = frozenset(permission_ids)
        if not requested_permission_ids:
            raise invalid_request_400("permission_ids_required",
                                      business_code=BusinessCode.PERMISSION_SELECTION_INVALID)
        # 绑定和解绑需要不同权限，也记录不同的审计动作，在这里一起选好。
        if operation == "bind":
            action = RbacAuditAction.BIND_ROLE_PERMISSIONS
            required_permission = PermissionKey.ROLES_PERMISSIONS_BIND
        else:
            action = RbacAuditAction.UNBIND_ROLE_PERMISSIONS
            required_permission = PermissionKey.ROLES_PERMISSIONS_UNBIND
        async with user_role_transaction(
            self._session_factory,
            context=context,
            action=action,
            target_role_id=role_id,
        ) as session:
            # 2. 加锁后重查本次所需权限和目标可见范围。
            locked_role = await self._lock_role(
                session,
                context=context,
                role_id=role_id,
                required_permission=required_permission,
            )
            role = locked_role.role
            # 保存加锁后读到的原权限，后面用来计算变化和避免重复绑定。
            permissions_before = locked_role.role_info.permissions
            # 3. 查询这些 ID 对应的权限标识；缺失或不在允许目录中的权限会被拒绝。
            permission_keys_by_id = await permission_repository.load_permission_keys(session, requested_permission_ids)
            # 必须全部找到，不能只处理有效部分。
            if set(permission_keys_by_id) != requested_permission_ids:
                raise invalid_request_400("unknown_permission_id",
                                          business_code=BusinessCode.PERMISSION_SELECTION_INVALID)
            requested_permission_keys = frozenset(permission_keys_by_id.values())
            if not requested_permission_keys <= SUPER_ADMIN_PERMISSION_KEYS:
                raise invalid_request_400(
                    "permission_outside_control_plane", business_code=BusinessCode.PERMISSION_SELECTION_INVALID,
                )

            # 4. 先算出修改后的权限，检查是否会让自己或其他持有者越权；此时还不写入。
            if operation == "bind":
                permission_keys_after = permissions_before | requested_permission_keys
            else:
                permission_keys_after = permissions_before - requested_permission_keys
            role_info_after = replace(locked_role.role_info, permissions=permission_keys_after)
            bound_users_after = tuple(user_info.with_role(role_info_after) for user_info in locked_role.bound_users)
            check_result = decide_role_permissions_change(
                operation=operation,
                current_user=locked_role.current_user,
                changed_role_before=locked_role.role_info,
                permission_keys_after=permission_keys_after,
                current_user_holds_role=locked_role.current_user.user_id in locked_role.bound_user_ids,
                affected_after=bound_users_after,
            )
            if not check_result.allowed:
                raise forbidden_403(check_result.reason_code)

            self._check_role_version(role, expected_version)
            role_before = self._build_role_response(role, permissions_before)
            changed = permissions_before != permission_keys_after
            # 5. 权限确实变了才修改绑定、增加版本，重复操作不改版本。
            if changed:
                if operation == "bind":
                    # 复用加锁后读取的权限，只新增尚未绑定的部分。
                    session.add_all(
                        RolePermission(
                            role_id=role_id,
                            permission_id=permission_id,
                            bound_by_user_id=locked_role.current_user.user_id,
                        )
                        for permission_id, permission_key in permission_keys_by_id.items()
                        if permission_key not in permissions_before
                    )
                else:
                    deleted_at = datetime.now(UTC)
                    await role_repository.unbind_permissions(
                        session,
                        role_id=role_id,
                        permission_ids=requested_permission_ids,
                        deleted_at=deleted_at,
                        deleted_by_user_id=locked_role.current_user.user_id,
                    )
                # 旧页面须刷新后再改，避免覆盖本次权限修改。
                role.version += 1

            # 6. 整理结果和修改前后状态，随审计一起提交。
            role_after = self._build_role_response(role, permission_keys_after)
            response = RoleMutationResponse(role=role_after)
            if not changed:
                reason_code = "role_permissions_unchanged"
            elif operation == "bind":
                reason_code = "role_permissions_bound"
            else:
                reason_code = "role_permissions_unbound"
            AuditService.audit_success(
                session,
                action=action,
                context=context,
                target_role_id=role_id,
                reason_code=reason_code,
                before_state=self._build_role_audit(role_before),
                after_state=self._build_role_audit(role_after),
                message_key=MessageKey.COMMON_OPERATION_SUCCESS,
                data=response,
            )

        return response


# 共享服务不保存当前用户、操作目标或数据库会话。
role_service = RoleService(SessionFactory)
