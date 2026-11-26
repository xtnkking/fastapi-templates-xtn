#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    查询角色、可见范围和角色权限，提供批量行锁；事务由业务层管理。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        展开角色与权限批量查询步骤，集中角色标识读取
# 2026/09/23    XTN       V1.002        解释查询范围、授权边界及初学者易混淆的数据语义
# 2026/09/23    XTN       V1.003        类方法参数逐行对齐，整理业务调用排版
# 2026/10/02    XTN       V1.004        使用已加载角色查询权限，删除重复角色读取及业务错误判断
# 2026/10/13    XTN       V1.005        说明批量锁的等待效果、空结果及授权快照冻结步骤
# 2026/10/16    XTN       V1.006        默认角色按编码一次查询并加锁，减少创建用户时的重复读取
# 2026/10/19    XTN       V1.007        精简角色查询、权限汇总和锁说明
# 2026/10/20    XTN       V1.008        角色查询及授权汇总统一读取 level
# 2026/10/22    XTN       V1.009        角色可见范围和分页查询统一放回角色仓储
# 2026/10/23    XTN       V1.010        权限汇总直接接收已加载角色，集中只读角色的字段转换
# 2026/10/24    XTN       V1.011        简化角色查询名称和变量，合并单个与批量权限读取
# 2026/10/26    XTN       V1.012        用户角色权限信息类型统一命名为 UserInfo
# 2026/10/26    XTN       V1.013        角色列表支持业务筛选及软删除记录，列表总数沿用相同条件
# 2026/10/26    XTN       V1.014        简化唯一角色读取和权限绑定行锁，按查询加锁解绑整理方法
# --------------------------------------------------------------------------------------------------


from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Select

from app.core.access.authorization import RoleGrant, UserInfo
from app.core.access.roles import SystemRoleKey
from app.models.postgres.permission import Permission
from app.models.postgres.role import Role, RolePermission


@dataclass(slots=True)
class RolePermissions:
    """
        保存一个角色和已收集的权限，再转成只读角色信息。
    """

    # 本次已查到的角色；转为只读信息时复制字段，不再查询数据库。
    role: Role
    # 用集合去重；default_factory 保证每个角色使用独立集合。
    permissions: set[str] = field(default_factory=set)

    def to_role_info(self) -> RoleGrant:
        """
            把汇总好的角色权限转成只读副本。

        :return: 含角色属性和权限集合的只读对象。
        """
        # 权限转成只读集合，避免业务层误改查询结果。
        return RoleGrant(
            role_id=self.role.id,
            key=self.role.key,
            level=self.role.level,
            permissions=frozenset(self.permissions),
            is_system=self.role.is_system,
            is_protected=self.role.is_protected,
            is_super_admin=self.role.is_super_admin,
        )


class RoleRepository:
    """
        查询可见角色、锁定角色、读取权限、写入解绑标记，事务由调用方管理。
        Service 负责操作权限和角色等级检查。
    """

    # -------------------- 角色查询与权限读取 --------------------

    def _build_role_query(self, *, current_user: UserInfo,
                          is_deleted: bool = False
                          ) -> Select[tuple[Role]]:
        """
            构造当前用户有权查看的角色查询，默认只查未删除角色，尚不执行 SQL。

        :param current_user: 当前操作者的完整权限信息，用于限制可见目标。
        :param is_deleted: False 只查未删除角色；True 仅供列表查看已软删除记录。
        :return: 带角色可见性条件的查询。
        """
        # 1. 默认只查未删除角色，列表可明确选择只查已软删除记录。
        role_query = select(Role)
        if is_deleted:
            role_query = role_query.where(Role.deleted_at.is_not(None))
        else:
            role_query = role_query.where(Role.deleted_at.is_(None))
        # 2. 超级管理员可查看所选删除状态下的全部角色；编码和专用标记必须同时匹配。
        if any(
            role.key == SystemRoleKey.SUPER_ADMIN.value and role.is_super_admin
            for role in current_user.roles
        ):
            return role_query
        # 3. 其他用户只能查看低于自己且未受保护的角色。
        return role_query.where(
            Role.level < current_user.role_level,
            Role.is_protected.is_(False),
            Role.is_super_admin.is_(False),
        )

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
                         ) -> tuple[tuple[Role, ...], int]:
        """
            按筛选条件查询当前用户有权查看的角色，返回当前页和相同条件的总数。

        :param session: 调用方管理生命周期和事务的 PostgreSQL 异步会话。
        :param current_user: 当前操作者的完整权限信息，用于限制可见目标。
        :param page: 从 1 开始的页码。
        :param page_size: 每页条数，HTTP 接口限制在 1 至 200。
        :param role_id: 角色 ID 精确匹配；None 不按 ID 筛选。
        :param key: 角色编码精确匹配；None 不按编码筛选。
        :param name: 名称包含的文字；None 不筛选，百分号和下划线按普通字符匹配。
        :param is_active: True 只查启用，False 只查禁用，None 不限制启用状态。
        :param is_system: True 只查系统角色，False 只查自定义角色，None 不限制类型。
        :param is_deleted: False 只查未删除角色，True 只查已软删除角色。
        :return: 当前页的角色对象元组及可见总数；本页无记录时元组为空。
        """
        # 1. 先限制能查看的角色，再用 AND 叠加每个已传条件；筛选不能放大查看范围。
        role_query = self._build_role_query(current_user=current_user, is_deleted=is_deleted)
        if role_id is not None:
            role_query = role_query.where(Role.id == role_id)
        if key is not None:
            role_query = role_query.where(Role.key == key)
        if name is not None:
            # 包含匹配交给数据库；自动转义 % 和 _，避免把用户文字当成通配符。
            role_query = role_query.where(Role.name.contains(name, autoescape=True))
        if is_active is not None:
            role_query = role_query.where(Role.is_active.is_(is_active))
        if is_system is not None:
            role_query = role_query.where(Role.is_system.is_(is_system))
        # 2. 总数从同一份查询计算，避免与列表条件不同或泄露隐藏角色数量。
        role_count_query = select(func.count()).select_from(role_query.subquery())
        total_roles = await session.scalar(role_count_query)
        # 3. 固定排序后由数据库分页，不先读取全表。
        role_page_query = (
            role_query
            .order_by(Role.key, Role.id)
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        role_page_result = await session.scalars(role_page_query)
        return tuple(role_page_result.all()), int(total_roles or 0)

    async def get_role_detail(self, session: AsyncSession, *,
                              current_user: UserInfo,
                              role_id: str
                              ) -> Role | None:
        """
            按 ID 查询角色，只返回当前操作者有权查看的未删除角色。

        :param session: 调用方管理生命周期和事务的 PostgreSQL 异步会话。
        :param current_user: 当前操作者的完整权限信息，用于限制可见目标。
        :param role_id: 目标角色的业务 ID。
        :return: 可见角色；不存在、已软删除或不可见时返回 None。
        """
        # 详情沿用列表的可见范围，不可见和不存在都返回 None。
        role_query = self._build_role_query(current_user=current_user).where(Role.id == role_id)
        role = await session.scalar(role_query)
        return role

    async def get_role_id_by_key(self, session: AsyncSession, *,
                                 key: str
                                 ) -> str | None:
        """
            按唯一角色编码读取 ID，已软删除角色也算占用。

        :param session: 调用方管理生命周期和事务的 PostgreSQL 异步会话。
        :param key: 需要精确匹配的角色编码。
        :return: 对应角色 ID；编码从未被使用时返回 None。
        """
        # 不排除软删除记录，避免重新使用旧角色的编码。
        role_id_query = select(Role.id).where(Role.key == key)
        # key 有数据库唯一约束，直接读取唯一角色的 ID。
        role_id: str | None = await session.scalar(role_id_query)
        return role_id

    async def get_role_permissions(self, session: AsyncSession, *,
                                   roles: Sequence[Role]
                                   ) -> dict[str, RoleGrant]:
        """
            一次查出角色权限，按角色 ID 返回只读角色信息。
            角色由调用方提供；这里只查权限，不重查角色或判断操作者能否查看。

        :param session: 调用方管理生命周期和事务的 PostgreSQL 异步会话。
        :param roles: 已查出或已锁定的角色；单个角色传 (role,)，空集合不查数据库。
        :return: “角色 ID → 只读角色信息”的映射；保留停用角色，没有权限时返回空权限集合。
        """
        # 1. 为每个角色准备结果，没有权限的角色也要保留。
        role_details_by_id = {
            role.id: RolePermissions(role=role)
            for role in roles
        }
        if not role_details_by_id:
            return {}

        # 2. 一次查询全部目标角色的未删除权限，避免逐个查询。
        # 这里只汇总成集合，不要求数据库排序；接口返回时由 Service 排序。
        role_permissions_query = (
            select(RolePermission.role_id, Permission.key.label("permission_key"))
            .join(Permission, (Permission.id == RolePermission.permission_id) & Permission.deleted_at.is_(None))
            .where(RolePermission.role_id.in_(role_details_by_id), RolePermission.deleted_at.is_(None))
        )
        role_permissions_result = await session.execute(role_permissions_query)
        # 3. 每行是一项角色权限，按角色汇总并去重。
        for role_permission in role_permissions_result.all():
            role_details_by_id[role_permission.role_id].permissions.add(role_permission.permission_key)

        # 转成只读副本，避免后续代码改动已经汇总的结果。
        return {
            role_id: role_details.to_role_info()
            for role_id, role_details in role_details_by_id.items()
        }

    # -------------------- 角色及权限绑定行锁 --------------------

    async def lock_role_by_key(self, session: AsyncSession, *,
                               key: str
                               ) -> Role | None:
        """
            按唯一角色编码查出并锁住未删除角色，业务层再判断能否分配。

        :param session: 调用方已开启事务的数据库会话，角色行锁保留到该事务提交或回滚。
        :param key: 精确匹配的角色编码，例如默认普通用户角色 user。
        :return: 已刷新并锁住的角色；角色不存在或已软删除时返回 None。
        """
        # 1. 一次查出角色 ID 和当前状态，排除软删除记录。
        role_lock_query = (
            select(Role)
            .where(Role.key == key, Role.deleted_at.is_(None))
            # 2. 加锁并刷新旧对象，锁到调用方提交或回滚才释放。
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        # key 有数据库唯一约束，直接读取这一个已锁定角色。
        role: Role | None = await session.scalar(role_lock_query)
        return role

    async def lock_roles(self, session: AsyncSession, *,
                         role_ids: set[str]
                         ) -> dict[str, Role]:
        """
            按 ID 固定顺序锁定未删除角色，并刷新会话中的已有实例。

        :param session: 调用方管理生命周期和事务的 PostgreSQL 异步会话。
        :param role_ids: 需要按固定 ID 顺序加锁的角色集合。
        :return: “角色 ID → 已锁定角色对象”的映射；不存在或已删除的不返回。
        """
        # 无目标就不查数据库，缺少的角色由调用方处理。
        if not role_ids:
            return {}
        # 按相同 ID 顺序加锁，减少死锁，并刷新旧对象。
        # 冲突写入会等待到调用方提交或回滚，普通查询不受此锁阻止。
        role_lock_query = (
            select(Role)
            .where(Role.id.in_(role_ids), Role.deleted_at.is_(None))
            .order_by(Role.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        locked_roles_result = await session.scalars(role_lock_query)
        return {role.id: role for role in locked_roles_result.all()}

    async def lock_permission_bindings(self, session: AsyncSession, *,
                                       role_id: str
                                       ) -> None:
        """
            按权限编码的顺序锁住角色尚未解绑的权限绑定，不锁权限目录本身。

        :param session: 调用方管理生命周期和事务的 PostgreSQL 异步会话。
        :param role_id: 目标角色的业务 ID。
        :return: 无返回值；绑定行锁保留到调用方提交或回滚，不加载绑定对象。
        """
        # 1. 只查询绑定 ID，排除已删除的权限和已解绑关系。
        binding_lock_query = (
            select(RolePermission.id)
            .join(Permission, (Permission.id == RolePermission.permission_id) & Permission.deleted_at.is_(None))
            .where(RolePermission.role_id == role_id, RolePermission.deleted_at.is_(None))
            # 2. 按权限编码固定加锁顺序，只锁绑定行，不锁权限目录。
            .order_by(Permission.key)
            .with_for_update(of=RolePermission)
        )
        # 3. 执行查询取得行锁即可；后续能否增删仍由 Service 判断。
        await session.execute(binding_lock_query)

    # -------------------- 权限解绑 --------------------

    async def unbind_permissions(self, session: AsyncSession, *,
                                 role_id: str,
                                 deleted_at: datetime,
                                 deleted_by_user_id: str,
                                 permission_ids: frozenset[str] | None = None
                                 ) -> None:
        """
            给角色权限绑定写入删除标记，可解绑指定权限或全部权限。
            调用方负责权限检查、加锁、角色版本和审计。

        :param session: 调用方管理生命周期和事务的 PostgreSQL 异步会话。
        :param role_id: 已通过业务校验并持锁的目标角色 ID。
        :param deleted_at: 外层事务统一采用的软删除时间。
        :param deleted_by_user_id: 已通过授权校验的操作者用户 ID。
        :param permission_ids: 可选权限 ID 集合；None 解除全部，空集合不写数据库。
        :return: 无返回值；记录变更由调用方统一提交或回滚。
        """
        # 空集表示不解绑，None 才表示解绑全部。
        if permission_ids == frozenset():
            return
        # 只处理尚未解绑的关系，保留以前解绑记录的时间和操作者。
        binding_update = update(RolePermission).where(
            RolePermission.role_id == role_id, RolePermission.deleted_at.is_(None))
        if permission_ids is not None:
            # 传了权限 ID 就只解绑这些权限。
            binding_update = binding_update.where(RolePermission.permission_id.in_(permission_ids))
        # 只写删除标记，由调用方将解绑、角色版本和审计一起提交。
        binding_update = binding_update.values(deleted_at=deleted_at, deleted_by_user_id=deleted_by_user_id)
        await session.execute(binding_update)


# 共享仓储不保存数据库会话或角色状态。
role_repository = RoleRepository()
