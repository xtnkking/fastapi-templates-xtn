#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    PostgreSQL 用户查询、角色权限、管理可见范围、用户加锁和密码保存。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        收回认证与创建流程的查询和密码持久化，展开查询执行步骤
# 2026/09/23    XTN       V1.002        解释查询范围、授权边界及初学者易混淆的数据语义
# 2026/09/23    XTN       V1.003        类方法参数逐行对齐，整理业务调用排版
# 2026/09/26    XTN       V1.004        用户占用检查改用具体字段名称
# 2026/09/30    XTN       V1.005        密码更新不再写入临时改密标记
# 2026/10/10    XTN       V1.006        统一用户 ID 与当前用户命名
# 2026/10/13    XTN       V1.007        补齐账号查询步骤并区分会话缓存、占用检查与密码待提交状态
# 2026/10/19    XTN       V1.008        精简用户查询和密码保存注释
# 2026/10/22    XTN       V1.009        合并用户及权限查询，统一 ID、用户名和状态筛选
# 2026/10/22    XTN       V1.010        查询和权限汇总变量按业务内容命名
# 2026/10/22    XTN       V1.011        用户可见范围直接排除受保护、同级和更高级的有效角色
# 2026/10/22    XTN       V1.012        密码保存方法统一命名为 update_password
# 2026/10/22    XTN       V1.013        统一查询名称，复用用户及角色读取，分清有效权限和角色保护
# 2026/10/23    XTN       V1.014        单个和批量权限统一入口，合并内部查询及汇总步骤
# 2026/10/23    XTN       V1.015        用大白话说明权限 SQL 连接、筛选和结果整理过程
# 2026/10/23    XTN       V1.016        每个角色只整理一次权限，再按用户绑定组合结果
# 2026/10/24    XTN       V1.017        用户列表支持 ID 和状态筛选，软删除记录只展示资料
# 2026/10/24    XTN       V1.018        页面信息直观命名，合并账号字段转换和展示结果组装
# 2026/10/24    XTN       V1.019        列表、详情和查询构造使用业务名称，保留操作者可查看范围
# 2026/10/24    XTN       V1.020        角色权限字段转换使用 RolePermissions 和 to_role_info
# 2026/10/24    XTN       V1.021        批量用户资料统一使用 get_users_info、UserDetails 和具体变量名
# 2026/10/26    XTN       V1.022        说明当前用户检查的通过条件、拒绝原因与权限边界
# 2026/10/26    XTN       V1.023        用户角色权限信息类型统一命名为 UserInfo
# 2026/10/26    XTN       V1.024        用户权限结果字段明确区分生效信息与含停用角色的信息
# --------------------------------------------------------------------------------------------------

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import cast

from sqlalchemy import false, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Select

from app.core.access.authorization import RoleGrant, UserInfo
from app.core.access.roles import SystemRoleKey
from app.core.exceptions import not_found_404, unauthenticated_401
from app.models.postgres.permission import Permission
from app.models.postgres.role import Role, RolePermission
from app.models.postgres.user import User, UserRole
from app.repositories.postgres.role_repository import RolePermissions


@dataclass(frozen=True, slots=True)
class UserPermissions:
    """
        同一用户的两份信息，分别按启用角色和包含停用角色计算。
    """

    # 只计算启用角色，用于判断用户当前能做什么；页面入口的结果仍受查看范围限制。
    user_info: UserInfo
    # 包含启用和停用角色，用于管理等级和保护判断，不能用这份信息授予接口权限。
    user_info_with_disabled_roles: UserInfo


@dataclass(frozen=True, slots=True)
class UserDetails:
    """
        用户的用户名、绑定角色和允许查看的权限信息。
        已过滤无权查看的角色，只用于返回资料，不能用于授权判断。
    """

    # 页面展示的目标用户名，不是发起查询的管理员用户名。
    user_name: str
    # 页面可见的未解绑角色 ID，包含停用角色。
    bound_role_ids: tuple[str, ...]
    # 只含页面可见范围内的权限，不能用作完整的授权依据。
    user_info: UserInfo


class UserRepository:
    """
        统一查询用户、角色权限和管理可见结果，调用方负责接口权限与事务提交。
    """

    # -------------------- 内部查询与信息整理 --------------------

    @staticmethod
    def _build_user_info(user: User, *, roles: tuple[RoleGrant, ...]) -> UserInfo:
        """
            把已查出的账号和指定角色整理为只读用户信息，不查询数据库。

        :param user: 已查询的账号，提供用户 ID、启用状态、保护标记和登录版本。
        :param roles: 本次需要保留的角色；有效权限传启用角色，管理检查传全部角色，删除记录传空元组。
        :return: 根据这些角色算出的权限和等级；完整信息与页面信息仍由调用方区分。
        """
        # 账号字段统一在这里复制；权限和等级由传入的角色计算，不会修改账号或角色。
        return UserInfo.build(
            user_id=user.user_id,
            user_is_active=user.is_active,
            user_is_protected=user.is_protected,
            token_version=user.token_version,
            roles=roles,
        )

    def _is_super_admin(self, current_user: UserInfo) -> bool:
        """
            检查操作者是否持有真正的超级管理员角色。

        :param current_user: 当前操作者的完整权限快照，用于限制可见目标。
        :return: 满足系统超级管理员条件时为 True。
        """
        # 角色名和专用标记必须同时匹配，不能只看名称或等级。
        return any(
            role.key == SystemRoleKey.SUPER_ADMIN.value and role.is_super_admin
            for role in current_user.roles
        )

    def _build_user_query(self, *, current_user: UserInfo,
                          is_deleted: bool = False
                          ) -> Select[tuple[User]]:
        """
            拼好所选删除状态下操作者可见的用户查询，尚不执行 SQL。

        :param current_user: 当前操作者的完整权限快照，用于限制可见目标。
        :param is_deleted: False 只查未删除用户；True 仅供列表查看软删除记录。
        :return: 带用户可见性条件的查询；普通管理员看不到自身及受保护目标。
        """
        # 1. 默认排除已删除用户；管理列表可明确选择只查软删除记录。
        user_query = select(User)
        if is_deleted:
            user_query = user_query.where(User.deleted_at.is_not(None))
        else:
            user_query = user_query.where(User.deleted_at.is_(None))
        if self._is_super_admin(current_user):
            return user_query
        # 没有角色按 0 级计算，所以 0 级操作者没有更低级的用户可看。
        if current_user.role_level <= 0:
            return user_query.where(false())

        # 2. 目标只要持有一个受保护、同级或更高级的有效角色，就不能显示。
        has_hidden_role = (
            select(UserRole.user_id)
            .select_from(UserRole)
            .join(Role, Role.id == UserRole.role_id)
            .where(
                UserRole.user_id == User.user_id,
                UserRole.deleted_at.is_(None),
                Role.is_active.is_(True),
                Role.deleted_at.is_(None),
                or_(Role.is_protected.is_(True), Role.level >= current_user.role_level),
            )
            .correlate(User)
            .exists()
        )
        # 3. 再排除本人和账号本身受保护的用户；这里只拼查询，不访问数据库。
        return user_query.where(
            User.user_id != current_user.user_id,
            User.is_protected.is_(False),
            ~has_hidden_role,
        )

    async def _load_user_permissions(self, session: AsyncSession, *,
                                     users: Sequence[User],
                                     current_user: UserInfo | None = None
                                     ) -> dict[str, UserPermissions]:
        """
            一次查询并整理用户的角色权限，供完整权限和页面展示两个入口复用。

        :param session: 调用方管理生命周期的数据库会话。
        :param users: 刚查到或已锁定的用户；没有角色也保留空权限结果。
        :param current_user: 页面查询传当前操作者以限制角色可见范围；完整权限入口固定不传。
        :return: 用户 ID 到两份权限结果的映射；空集合不查数据库。
        :raises AppError: 输入包含已软删除用户，不能继续读取其权限。
        """
        # 1. 按 ID 收好已查到的用户；空集合不查库，已删除用户不能加载完整权限。
        users_by_id = {user.user_id: user for user in users}
        if not users_by_id:
            return {}
        if any(user.deleted_at is not None for user in users_by_id.values()):
            raise not_found_404("user_not_found")

        # 2. 一次查齐“用户 → 角色 → 权限”。保留停用角色，后面还要用它检查管理范围。
        role_permissions_query = (
            # 每行是一名用户、一个角色和一个权限键；多个权限会让同一角色出现多行。
            select(UserRole.user_id, Role, Permission.key.label("permission_key"))
            .select_from(UserRole)
            # 只读未删除角色；左连接权限，保留尚未分配权限的角色。
            .join(Role, (Role.id == UserRole.role_id) & Role.deleted_at.is_(None))
            .outerjoin(
                RolePermission,
                (RolePermission.role_id == Role.id) & RolePermission.deleted_at.is_(None),
            )
            # 已解绑或已删除的权限不参与计算；没有权限时 permission_key 为 None。
            .outerjoin(
                Permission,
                (Permission.id == RolePermission.permission_id) & Permission.deleted_at.is_(None),
            )
            # 只读这些用户尚未解绑的角色，已解绑的历史记录不再参与。
            .where(UserRole.user_id.in_(users_by_id), UserRole.deleted_at.is_(None))
            .order_by(UserRole.user_id, Role.id, Permission.key)
            # 加锁后再次读取时也刷新角色对象，不能沿用会话里的旧等级或启用状态。
            .execution_options(populate_existing=True)
        )
        # 只有页面入口传入 current_user；完整权限入口不传，超级管理员也不限制角色范围。
        if current_user is not None and not self._is_super_admin(current_user):
            # 其他操作者只能看到低于自己、未受保护且不是超级管理员的角色。
            role_permissions_query = role_permissions_query.where(
                Role.level < current_user.role_level,
                Role.is_protected.is_(False),
                Role.is_super_admin.is_(False),
            )

        # 3. 分开记清“每个用户绑定哪些角色”和“每个角色有哪些权限”。
        # 多个用户共用同一角色时，角色权限只整理一份；用户没有角色也保留空结果。
        role_ids_by_user: dict[str, set[str]] = {user_id: set() for user_id in users_by_id}
        # 每个角色保存原角色资料及收集到的权限，供多个用户共用。
        role_details_by_id: dict[str, RolePermissions] = {}

        # 到这里才执行前面拼好的 SQL；整个批次只查一次数据库。
        role_permissions_result = await session.execute(role_permissions_query)
        for user_id, role, permission_key in role_permissions_result.all():
            role_ids_by_user[user_id].add(role.id)
            if role.id not in role_details_by_id:
                role_details_by_id[role.id] = RolePermissions(role=role)
            if permission_key is not None:
                # 一行只带一个权限，加入对应角色的集合；重复权限会自动去重。
                role_details_by_id[role.id].permissions.add(permission_key)

        # 4. 每个角色转成一份只读结果，再按用户的角色 ID 取用，不重复复制角色字段。
        role_info_by_id = {role_id: role_details.to_role_info() for role_id, role_details in role_details_by_id.items()}
        permissions_by_user_id: dict[str, UserPermissions] = {}
        for user_id, user in users_by_id.items():
            all_roles = tuple(role_info_by_id[role_id] for role_id in role_ids_by_user[user_id])
            # 停用角色仍参与管理保护判断，但不能提供当前有效权限。
            active_roles = tuple(
                role_info for role_info in all_roles
                if role_details_by_id[role_info.role_id].role.is_active
            )
            permissions_by_user_id[user_id] = UserPermissions(
                # 汇总启用角色的权限和等级；页面读取的结果只用于展示，不能代替完整鉴权。
                user_info=self._build_user_info(user, roles=active_roles),
                # 保留停用角色：完整读取供管理保护判断，页面读取供展示角色绑定。
                user_info_with_disabled_roles=self._build_user_info(user, roles=all_roles),
            )
        return permissions_by_user_id

    # -------------------- 单用户查询、用户名占用、用户锁和密码保存 --------------------

    async def get_user(self, session: AsyncSession, *,
                       user_id: str | None = None,
                       user_name: str | None = None,
                       is_active: bool | None = None,
                       is_deleted: bool | None = False
                       ) -> User | None:
        """
            按 ID 或用户名查询一个用户，可同时筛选启用和删除状态。
            默认只查未删除账号；不检查接口权限，也不加行锁。

        :param session: 调用方管理生命周期和事务的 PostgreSQL 异步会话。
        :param user_id: 用户 ID；与 user_name 至少填写一项，两项都填时必须同时匹配。
        :param user_name: 按项目规则规范化后的用户名；None 表示不按用户名筛选。
        :param is_active: True 只查启用账号，False 只查停用账号，None 不限制启用状态。
        :param is_deleted: False 只查未删除账号，True 只查已删除账号，None 包含两种状态。
        :return: 匹配的用户；不存在或不符合筛选条件时返回 None，并刷新会话中该用户的旧数据。
        :raises ValueError: ID 和用户名都未提供，不能把单用户查询变成无条件查询。
        """
        # 1. 必须明确查谁，不能不填 ID 和用户名就随便返回一个账号。
        if user_id is None and user_name is None:
            raise ValueError("user_id or user_name is required")
        user_query = select(User)
        if user_id is not None:
            user_query = user_query.where(User.user_id == user_id)
        if user_name is not None:
            user_query = user_query.where(User.user_name == user_name)

        # 2. 仅添加调用方选中的状态条件；None 表示这一项不限。
        if is_active is not None:
            user_query = user_query.where(User.is_active.is_(is_active))
        if is_deleted is False:
            user_query = user_query.where(User.deleted_at.is_(None))
        elif is_deleted is True:
            user_query = user_query.where(User.deleted_at.is_not(None))

        # 3. 每次读取数据库当前值，避免账号状态或登录版本沿用会话里的旧数据。
        user_query = user_query.execution_options(populate_existing=True)
        user = await session.scalar(user_query)
        return user

    async def user_name_exists(self, session: AsyncSession, *,
                               user_name: str
                               ) -> bool:
        """
            检查用户名是否已被占用，软删除记录仍保留原用户名。

        :param session: 调用方管理生命周期的 PostgreSQL 异步会话。
        :param user_name: 新用户准备使用的规范化用户名。
        :return: 用户名已存在时返回 True；并发最终仍由唯一约束保护。
        """
        # 取到 ID 就表示已占用；并发插入仍靠数据库唯一约束拦截。
        user_name_query = select(User.user_id).where(User.user_name == user_name).limit(1)
        existing_user_id = await session.scalar(user_name_query)
        return existing_user_id is not None

    async def lock_users(self, session: AsyncSession,
                         user_ids: set[str]
                         ) -> dict[str, User]:
        """
            按 ID 固定顺序锁定未删除用户，并刷新会话中的已有实例。

        :param session: 调用方管理生命周期和事务的 PostgreSQL 异步会话。
        :param user_ids: 需要按固定 ID 顺序加锁的用户集合。
        :return: 实际存在的用户 ID 到已锁定用户的映射；缺失目标不在结果中。
        """
        # 空目标不发起查询，也不持有任何行锁。
        if not user_ids:
            return {}
        # 按相同 ID 顺序加锁，减少并发请求互相等待造成的死锁。
        # 锁保留到调用方提交或回滚；缺少的用户由调用方判断。
        user_lock_query = select(User).where(User.user_id.in_(user_ids), User.deleted_at.is_(None))
        user_lock_query = (
            user_lock_query.order_by(User.user_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        locked_user_result = await session.scalars(user_lock_query)
        locked_users = locked_user_result.all()
        return {user.user_id: user for user in locked_users}

    async def update_password(self, session: AsyncSession, *,
                              user: User,
                              password_hash: str
                              ) -> None:
        """
            保存新密码哈希和改密时间，调用方需先锁住用户。
            Token 版本、审计和最终提交由业务层处理。

        :param session: 调用方持有用户锁的 PostgreSQL 异步事务会话。
        :param user: 当前事务内需要修改密码状态的用户模型。
        :param password_hash: 已经在锁外计算好的新密码哈希。
        :return: 无返回值，密码状态等待调用方事务提交。
        """
        # 取数据库当前语句的时间作为改密时间；仅升级哈希参数时不会调用这里。
        password_time_query = select(func.statement_timestamp())
        password_changed_at = await session.scalar(password_time_query)
        # 先更新会话对象，由调用方发送到数据库并提交；这里只保存哈希，不保存明文。
        user.password_hash = password_hash
        user.password_changed_at = cast(datetime, password_changed_at)

    # -------------------- 完整角色权限：用于鉴权和管理判断 --------------------

    async def check_current_user(self, session: AsyncSession, *,
                                 user_id: str,
                                 token_version: int
                                 ) -> UserInfo:
        """
            检查本次登录对应的账号是否仍可用，通过后读取当前有效角色和权限。
            通过条件：用户存在、未软删除、已启用，且数据库登录版本与本次登录版本一致。
            普通用户、管理员和超级管理员都按这些条件检查；没有接口权限也能通过此检查。
            不通过：用户不存在、已软删除、已禁用，或登录版本不一致，统一返回 HTTP 401。
            调用前应已验证 JWT 和 Redis 登录记录；具体接口所需权限仍由调用方另外检查。

        :param session: 调用方管理生命周期和事务的 PostgreSQL 异步会话。
        :param user_id: 已验证登录记录中的当前用户 ID，不使用客户端自选的目标用户 ID。
        :param token_version: Redis 登录记录保存的登录版本，用来与数据库当前值比较。
        :return: 当前用户及其有效角色、等级和权限的只读信息；权限可以为空，不是数据库用户对象。
        :raises AppError: 不满足上述账号或版本条件时返回 401，原因码为 user_no_longer_active。
        """
        # 1. 按用户 ID 读取数据库当前状态；get_user 默认排除软删除，所以不存在或已删除都得到 None。
        user = await self.get_user(session, user_id=user_id)
        # 2. 以下任意一项成立就拒绝：没查到用户、账号被禁用、本次登录版本已不是数据库当前版本。
        # 例如登录记录是版本 4，改密后数据库变成 5，这次旧登录就不能继续使用。
        if user is None or not user.is_active or user.token_version != token_version:
            raise unauthenticated_401("user_no_longer_active")
        # 3. 账号检查通过后，用刚查到的用户读取角色权限，不再重复查用户表。
        # 只返回启用角色带来的有效权限；停用角色不提供权限，权限为空也不在这里拒绝。
        permissions_by_user_id = await self.get_user_permissions(session, users=(user,))
        return permissions_by_user_id[user_id].user_info

    async def get_user_permissions(self, session: AsyncSession, *,
                                   users: Sequence[User]
                                   ) -> dict[str, UserPermissions]:
        """
            读取一个或多个用户的完整角色权限，始终按用户 ID 返回结果。

        :param session: 调用方管理生命周期和事务的 PostgreSQL 异步会话。
        :param users: 已查询的用户集合；一个用户传 (user,)，写操作传当前事务内已锁定的对象。
        :return: 用户 ID 到 UserPermissions 的映射；user_info 用于鉴权，user_info_with_disabled_roles 用于管理保护。
        :raises AppError: 输入包含已软删除用户。
        """
        # 完整权限固定不传页面操作者，不能误把展示范围当成真实权限范围。
        return await self._load_user_permissions(session, users=users)

    # -------------------- 管理页面：只返回操作者可见的用户和角色权限 --------------------

    async def list_users(self, session: AsyncSession, *,
                         current_user: UserInfo,
                         page: int,
                         page_size: int,
                         user_id: str | None = None,
                         user_name: str | None = None,
                         is_active: bool | None = None,
                         is_deleted: bool = False
                         ) -> tuple[tuple[User, ...], int]:
        """
            只查当前操作者有权查看的用户，按 ID、用户名和状态返回当前页及总数。

        :param session: 调用方管理生命周期和事务的 PostgreSQL 异步会话。
        :param current_user: 当前操作者的完整权限快照，用于限制可见目标。
        :param page: 从 1 开始的页码。
        :param page_size: 每页条数，HTTP 接口限制在 1 至 200。
        :param user_id: 用户 ID 精确匹配条件；None 表示不按 ID 筛选。
        :param user_name: 规范化后的用户名精确匹配条件；None 表示不按用户名筛选。
        :param is_active: True 只查启用，False 只查禁用，None 不限制启用状态。
        :param is_deleted: False 只查未删除用户，True 只查已软删除用户。
        :return: 当前页的用户对象元组及匹配总数；无匹配时返回空元组和 0。
        """
        # 1. 先选删除状态和可见范围，再把已传条件逐项叠加，必须同时匹配。
        user_query = self._build_user_query(current_user=current_user, is_deleted=is_deleted)
        if user_id is not None:
            user_query = user_query.where(User.user_id == user_id)
        if user_name is not None:
            user_query = user_query.where(User.user_name == user_name)
        if is_active is not None:
            user_query = user_query.where(User.is_active.is_(is_active))
        # 2. 总数和当前页共用上面的条件，避免筛选后页数与记录对不上。
        user_count_query = select(func.count()).select_from(user_query.subquery())
        total_users = await session.scalar(user_count_query)
        # 按唯一 ID 固定排序，让分页顺序稳定。
        user_page_query = (
            user_query
            .order_by(User.user_id)
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        user_page_result = await session.scalars(user_page_query)
        return tuple(user_page_result.all()), int(total_users or 0)

    async def get_user_detail(self, session: AsyncSession, *,
                              current_user: UserInfo,
                              user_id: str
                              ) -> User | None:
        """
            按 ID 查询用户，只返回当前操作者有权查看的未删除账号。

        :param session: 调用方管理生命周期和事务的 PostgreSQL 异步会话。
        :param current_user: 当前操作者的完整权限快照，用于限制可见目标。
        :param user_id: 目标用户的业务 ID。
        :return: 可见用户；不存在、已软删除或不可见时返回 None。
        """
        # 详情沿用列表的等级和保护限制，不可见和不存在都返回 None。
        user_query = self._build_user_query(current_user=current_user).where(User.user_id == user_id)
        user = await session.scalar(user_query)
        return user

    async def get_users_info(self, session: AsyncSession, *,
                             users: Sequence[User],
                             current_user: UserInfo
                             ) -> dict[str, UserDetails]:
        """
            给这批已查出的用户补齐用户名、绑定角色和允许查看的权限。
            停用角色仍展示绑定，但不计入有效权限。
            已软删除用户只展示账号资料，不恢复其角色和权限。

        :param session: 调用方管理生命周期和事务的 PostgreSQL 异步会话。
        :param users: 调用方已查出且允许查看的用户；这里不重新查询账号，空集合不查库。
        :param current_user: 当前操作者的完整权限信息，用于筛选允许返回的角色和权限。
        :return: “用户 ID → 用户资料”的映射；没有可见角色的用户仍返回，角色和权限为空。
        """
        # 1. 只给未删除用户加载权限；完整鉴权入口仍拒绝已删除用户，不能为页面放宽。
        not_deleted_users = tuple(user for user in users if user.deleted_at is None)
        permissions_by_user_id = await self._load_user_permissions(
            session,
            users=not_deleted_users,
            current_user=current_user,
        )
        # 2. 停用角色保留绑定，但不计入页面上的有效权限。
        user_details_by_id: dict[str, UserDetails] = {}
        for user in users:
            if user.deleted_at is not None:
                # 删除记录只供查看；即使还残留角色绑定，也不展示成当前权限。
                bound_role_ids: tuple[str, ...] = ()
                user_info = self._build_user_info(user, roles=())
            else:
                permissions = permissions_by_user_id[user.user_id]
                bound_role_ids = tuple(role.role_id for role in permissions.user_info_with_disabled_roles.roles)
                user_info = permissions.user_info
            user_details_by_id[user.user_id] = UserDetails(
                user_name=user.user_name,
                bound_role_ids=bound_role_ids,
                user_info=user_info,
            )
        return user_details_by_id


# 仓储不保存当前请求状态，数据库会话始终由调用方传入。
user_repository = UserRepository()
