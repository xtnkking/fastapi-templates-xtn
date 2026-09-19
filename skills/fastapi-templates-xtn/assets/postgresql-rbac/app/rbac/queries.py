import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import cast

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Select

from app.rbac.domain import AuthoritySnapshot, RoleGrant, SystemRoleKey
from app.rbac.errors import not_found, unauthenticated, unavailable
from app.rbac.models import (
    Permission,
    RbacState,
    Role,
    RolePermission,
    User,
    UserRole,
)


@dataclass(slots=True)
class _RoleAccumulator:
    role_id: uuid.UUID
    key: str
    management_tier: int
    is_system: bool
    is_protected: bool
    is_super_admin: bool
    permissions: set[str] = field(default_factory=set)

    def freeze(self) -> RoleGrant:
        return RoleGrant(
            role_id=self.role_id,
            key=self.key,
            management_tier=self.management_tier,
            permissions=frozenset(self.permissions),
            is_system=self.is_system,
            is_protected=self.is_protected,
            is_super_admin=self.is_super_admin,
        )


@dataclass(frozen=True, slots=True)
class UserAccessView:
    user_name: str
    assigned_role_ids: tuple[uuid.UUID, ...]
    authority: AuthoritySnapshot


def _actor_is_super_admin(actor: AuthoritySnapshot) -> bool:
    return any(
        role.key == SystemRoleKey.SUPER_ADMIN.value and role.is_super_admin
        for role in actor.roles
    )


async def load_role_grants_for_roles(
    session: AsyncSession,
    *,
    roles: Sequence[Role],
) -> dict[uuid.UUID, RoleGrant]:
    accumulators = {
        role.id: _RoleAccumulator(
            role_id=role.id,
            key=role.key,
            management_tier=role.management_tier,
            is_system=role.is_system,
            is_protected=role.is_protected,
            is_super_admin=role.is_super_admin,
        )
        for role in roles
    }
    if not accumulators:
        return {}

    rows = (
        await session.execute(
            select(
                RolePermission.role_id,
                Permission.key.label("permission_key"),
            )
            .join(
                Permission,
                (Permission.id == RolePermission.permission_id)
                & Permission.deleted_at.is_(None),
            )
            .where(
                RolePermission.role_id.in_(accumulators),
                RolePermission.deleted_at.is_(None),
            )
            .order_by(RolePermission.role_id, Permission.key)
        )
    ).all()
    for row in rows:
        accumulator = accumulators[row.role_id]
        accumulator.permissions.add(row.permission_key)

    return {
        role_id: accumulator.freeze() for role_id, accumulator in accumulators.items()
    }


async def load_user_access_views(
    session: AsyncSession,
    *,
    users: Sequence[User],
    actor: AuthoritySnapshot,
) -> dict[uuid.UUID, UserAccessView]:
    users_by_id = {user.id: user for user in users}
    if not users_by_id:
        return {}

    assigned_role_ids: dict[uuid.UUID, set[uuid.UUID]] = {
        user_id: set() for user_id in users_by_id
    }
    effective_roles: dict[uuid.UUID, dict[uuid.UUID, _RoleAccumulator]] = {
        user_id: {} for user_id in users_by_id
    }
    statement = (
        select(
            UserRole.user_id,
            Role.id.label("role_id"),
            Role.key,
            Role.management_tier,
            Role.is_active,
            Role.is_system,
            Role.is_protected,
            Role.is_super_admin,
            Permission.key.label("permission_key"),
        )
        .select_from(UserRole)
        .join(
            Role,
            (Role.id == UserRole.role_id) & Role.deleted_at.is_(None),
        )
        .outerjoin(
            RolePermission,
            (RolePermission.role_id == Role.id) & RolePermission.deleted_at.is_(None),
        )
        .outerjoin(
            Permission,
            (Permission.id == RolePermission.permission_id)
            & Permission.deleted_at.is_(None),
        )
        .where(
            UserRole.user_id.in_(users_by_id),
            UserRole.deleted_at.is_(None),
        )
    )
    if not _actor_is_super_admin(actor):
        statement = statement.where(
            Role.management_tier < actor.management_tier,
            Role.is_protected.is_(False),
            Role.is_super_admin.is_(False),
        )
    rows = (
        await session.execute(
            statement.order_by(UserRole.user_id, Role.id, Permission.key)
        )
    ).all()
    for row in rows:
        assigned_role_ids[row.user_id].add(row.role_id)
        if not row.is_active:
            continue
        accumulator = effective_roles[row.user_id].setdefault(
            row.role_id,
            _RoleAccumulator(
                role_id=row.role_id,
                key=row.key,
                management_tier=row.management_tier,
                is_system=row.is_system,
                is_protected=row.is_protected,
                is_super_admin=row.is_super_admin,
            ),
        )
        if row.permission_key is not None:
            accumulator.permissions.add(row.permission_key)

    return {
        user_id: UserAccessView(
            user_name=user.user_name,
            assigned_role_ids=tuple(sorted(assigned_role_ids[user_id], key=str)),
            authority=AuthoritySnapshot.build(
                user_id=user.id,
                user_is_active=user.is_active,
                user_is_protected=user.is_protected,
                token_version=user.token_version,
                authz_version=user.authz_version,
                roles=tuple(
                    accumulator.freeze()
                    for accumulator in effective_roles[user_id].values()
                ),
            ),
        )
        for user_id, user in users_by_id.items()
    }


def _select_visible_users(
    *,
    actor: AuthoritySnapshot,
) -> Select[tuple[User]]:
    statement = select(User).where(User.deleted_at.is_(None))
    if _actor_is_super_admin(actor):
        return statement

    active_authority = (
        select(
            UserRole.user_id.label("user_id"),
            func.max(Role.management_tier).label("management_tier"),
            func.bool_or(Role.is_protected).label("has_protected_role"),
        )
        .select_from(UserRole)
        .join(
            Role,
            (Role.id == UserRole.role_id)
            & Role.is_active.is_(True)
            & Role.deleted_at.is_(None),
        )
        .where(UserRole.deleted_at.is_(None))
        .group_by(UserRole.user_id)
        .subquery("active_user_authority")
    )
    return statement.outerjoin(
        active_authority,
        active_authority.c.user_id == User.id,
    ).where(
        User.id != actor.user_id,
        User.is_protected.is_(False),
        func.coalesce(active_authority.c.has_protected_role, False).is_(False),
        func.coalesce(active_authority.c.management_tier, 0) < actor.management_tier,
    )


def _select_visible_roles(
    *,
    actor: AuthoritySnapshot,
) -> Select[tuple[Role]]:
    statement = select(Role).where(Role.deleted_at.is_(None))
    if _actor_is_super_admin(actor):
        return statement
    return statement.where(
        Role.management_tier < actor.management_tier,
        Role.is_protected.is_(False),
        Role.is_super_admin.is_(False),
    )


async def list_visible_roles_page(
    session: AsyncSession,
    *,
    actor: AuthoritySnapshot,
    page: int,
    page_size: int,
) -> tuple[tuple[Role, ...], int]:
    visible_roles = _select_visible_roles(actor=actor)
    total = int(
        await session.scalar(select(func.count()).select_from(visible_roles.subquery()))
        or 0
    )
    roles = tuple(
        (
            await session.scalars(
                visible_roles.order_by(Role.key, Role.id)
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        ).all()
    )
    return roles, total


async def load_visible_role(
    session: AsyncSession,
    *,
    actor: AuthoritySnapshot,
    role_id: uuid.UUID,
) -> Role | None:
    return cast(
        Role | None,
        await session.scalar(
            _select_visible_roles(actor=actor).where(Role.id == role_id)
        ),
    )


async def list_visible_users_page(
    session: AsyncSession,
    *,
    actor: AuthoritySnapshot,
    page: int,
    page_size: int,
    user_name: str | None = None,
) -> tuple[tuple[User, ...], int]:
    visible_users = _select_visible_users(actor=actor)
    if user_name is not None:
        visible_users = visible_users.where(User.user_name == user_name)
    total = int(
        await session.scalar(select(func.count()).select_from(visible_users.subquery()))
        or 0
    )
    users = tuple(
        (
            await session.scalars(
                visible_users.order_by(User.id)
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        ).all()
    )
    return users, total


async def load_visible_user(
    session: AsyncSession,
    *,
    actor: AuthoritySnapshot,
    user_id: uuid.UUID,
) -> User | None:
    return cast(
        User | None,
        await session.scalar(
            _select_visible_users(actor=actor).where(User.id == user_id)
        ),
    )


async def load_role_grants_for_user(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    include_disabled_roles: bool,
) -> tuple[RoleGrant, ...]:
    statement = (
        select(
            Role.id.label("role_id"),
            Role.key,
            Role.management_tier,
            Role.is_system,
            Role.is_protected,
            Role.is_super_admin,
            Permission.key.label("permission_key"),
        )
        .select_from(UserRole)
        .join(
            Role,
            (Role.id == UserRole.role_id) & Role.deleted_at.is_(None),
        )
        .outerjoin(
            RolePermission,
            (RolePermission.role_id == Role.id) & RolePermission.deleted_at.is_(None),
        )
        .outerjoin(
            Permission,
            (Permission.id == RolePermission.permission_id)
            & Permission.deleted_at.is_(None),
        )
        .where(UserRole.user_id == user_id)
        .where(UserRole.deleted_at.is_(None))
        .order_by(Role.id, Permission.key)
    )
    if not include_disabled_roles:
        statement = statement.where(Role.is_active.is_(True))

    accumulators: dict[uuid.UUID, _RoleAccumulator] = {}
    for row in (await session.execute(statement)).all():
        accumulator = accumulators.setdefault(
            row.role_id,
            _RoleAccumulator(
                role_id=row.role_id,
                key=row.key,
                management_tier=row.management_tier,
                is_system=row.is_system,
                is_protected=row.is_protected,
                is_super_admin=row.is_super_admin,
            ),
        )
        if row.permission_key is not None:
            accumulator.permissions.add(row.permission_key)

    return tuple(item.freeze() for item in accumulators.values())


async def load_authority_snapshots_for_users(
    session: AsyncSession,
    *,
    users: Sequence[User],
    include_disabled_roles: bool = False,
) -> dict[uuid.UUID, AuthoritySnapshot]:
    """Load complete authority for already-loaded users with one role query."""
    users_by_id = {user.id: user for user in users}
    if not users_by_id:
        return {}

    effective_roles: dict[uuid.UUID, dict[uuid.UUID, _RoleAccumulator]] = {
        user_id: {} for user_id in users_by_id
    }
    statement = (
        select(
            UserRole.user_id,
            Role.id.label("role_id"),
            Role.key,
            Role.management_tier,
            Role.is_system,
            Role.is_protected,
            Role.is_super_admin,
            Permission.key.label("permission_key"),
        )
        .select_from(UserRole)
        .join(
            Role,
            (Role.id == UserRole.role_id) & Role.deleted_at.is_(None),
        )
        .outerjoin(
            RolePermission,
            (RolePermission.role_id == Role.id) & RolePermission.deleted_at.is_(None),
        )
        .outerjoin(
            Permission,
            (Permission.id == RolePermission.permission_id)
            & Permission.deleted_at.is_(None),
        )
        .where(
            UserRole.user_id.in_(users_by_id),
            UserRole.deleted_at.is_(None),
        )
    )
    if not include_disabled_roles:
        statement = statement.where(Role.is_active.is_(True))

    rows = (
        await session.execute(
            statement.order_by(UserRole.user_id, Role.id, Permission.key)
        )
    ).all()
    for row in rows:
        accumulator = effective_roles[row.user_id].setdefault(
            row.role_id,
            _RoleAccumulator(
                role_id=row.role_id,
                key=row.key,
                management_tier=row.management_tier,
                is_system=row.is_system,
                is_protected=row.is_protected,
                is_super_admin=row.is_super_admin,
            ),
        )
        if row.permission_key is not None:
            accumulator.permissions.add(row.permission_key)

    return {
        user_id: AuthoritySnapshot.build(
            user_id=user.id,
            user_is_active=user.is_active,
            user_is_protected=user.is_protected,
            token_version=user.token_version,
            authz_version=user.authz_version,
            roles=tuple(
                accumulator.freeze()
                for accumulator in effective_roles[user_id].values()
            ),
        )
        for user_id, user in users_by_id.items()
    }


async def count_live_user_roles(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
) -> int:
    count = await session.scalar(
        select(func.count(UserRole.id)).where(
            UserRole.user_id == user_id,
            UserRole.deleted_at.is_(None),
        )
    )
    return int(count or 0)


async def load_live_super_admin_holder_ids(
    session: AsyncSession,
) -> frozenset[uuid.UUID]:
    """Return the assignment set protected by the global RBAC write lock."""

    holder_ids = await session.scalars(
        select(UserRole.user_id)
        .join(
            Role,
            (Role.id == UserRole.role_id) & Role.deleted_at.is_(None),
        )
        .where(
            Role.key == SystemRoleKey.SUPER_ADMIN.value,
            UserRole.deleted_at.is_(None),
        )
        .order_by(UserRole.user_id)
    )
    return frozenset(holder_ids.all())


async def load_authority_snapshot(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    include_disabled_roles: bool = False,
) -> AuthoritySnapshot:
    user = await session.scalar(
        select(User)
        .where(User.id == user_id, User.deleted_at.is_(None))
        .execution_options(populate_existing=True)
    )
    if user is None:
        raise not_found("user_not_found")
    snapshots = await load_authority_snapshots_for_users(
        session,
        users=(user,),
        include_disabled_roles=include_disabled_roles,
    )
    return snapshots[user_id]


async def load_role_grant(
    session: AsyncSession,
    *,
    role_id: uuid.UUID,
    include_disabled: bool = False,
    include_deleted: bool = False,
) -> RoleGrant:
    statement = select(Role).where(Role.id == role_id)
    if not include_deleted:
        statement = statement.where(Role.deleted_at.is_(None))
    role = await session.scalar(statement.execution_options(populate_existing=True))
    if role is None or (not include_disabled and not role.is_active):
        raise not_found("role_not_found")

    rows = (
        await session.execute(
            select(Permission.key)
            .select_from(RolePermission)
            .join(
                Permission,
                (Permission.id == RolePermission.permission_id)
                & Permission.deleted_at.is_(None),
            )
            .where(
                RolePermission.role_id == role_id,
                RolePermission.deleted_at.is_(None),
            )
            .order_by(Permission.key)
        )
    ).all()
    permissions = frozenset(row.key for row in rows)
    return RoleGrant(
        role_id=role.id,
        key=role.key,
        management_tier=role.management_tier,
        permissions=permissions,
        is_system=role.is_system,
        is_protected=role.is_protected,
        is_super_admin=role.is_super_admin,
    )


async def lock_rbac_state(session: AsyncSession) -> RbacState:
    state = await session.scalar(
        select(RbacState)
        .where(RbacState.scope == "global")
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if state is None:
        raise unavailable("rbac_state_missing")
    return state


async def lock_users(
    session: AsyncSession, user_ids: set[uuid.UUID]
) -> dict[uuid.UUID, User]:
    if not user_ids:
        return {}
    users = (
        await session.scalars(
            select(User)
            .where(User.id.in_(user_ids), User.deleted_at.is_(None))
            .order_by(User.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).all()
    return {user.id: user for user in users}


async def lock_roles(
    session: AsyncSession,
    *,
    role_ids: set[uuid.UUID],
) -> dict[uuid.UUID, Role]:
    if not role_ids:
        return {}
    roles = (
        await session.scalars(
            select(Role)
            .where(Role.id.in_(role_ids), Role.deleted_at.is_(None))
            .order_by(Role.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).all()
    return {role.id: role for role in roles}


async def lock_role_permissions(
    session: AsyncSession,
    *,
    role_id: uuid.UUID,
) -> dict[str, RolePermission]:
    rows = (
        await session.execute(
            select(RolePermission, Permission.key.label("permission_key"))
            .join(
                Permission,
                (Permission.id == RolePermission.permission_id)
                & Permission.deleted_at.is_(None),
            )
            .where(
                RolePermission.role_id == role_id,
                RolePermission.deleted_at.is_(None),
            )
            .order_by(Permission.key)
            .with_for_update(of=RolePermission)
            .execution_options(populate_existing=True)
        )
    ).all()
    return {row.permission_key: row[0] for row in rows}


async def require_current_actor(
    session: AsyncSession,
    *,
    actor_user_id: uuid.UUID,
    token_version: int,
) -> AuthoritySnapshot:
    user = await session.scalar(
        select(User)
        .where(User.id == actor_user_id, User.deleted_at.is_(None))
        .execution_options(populate_existing=True)
    )
    if user is None or not user.is_active or user.token_version != token_version:
        raise unauthenticated("actor_no_longer_active")
    return await load_authority_snapshot(session, user_id=actor_user_id)


async def load_permission_ids(
    session: AsyncSession, permission_keys: frozenset[str]
) -> dict[str, uuid.UUID]:
    if not permission_keys:
        return {}
    rows = (
        await session.execute(
            select(Permission.key, Permission.id).where(
                Permission.key.in_(permission_keys),
                Permission.deleted_at.is_(None),
            )
        )
    ).all()
    return {row.key: row.id for row in rows}


async def load_permission_keys(
    session: AsyncSession,
    permission_ids: frozenset[uuid.UUID],
) -> dict[uuid.UUID, str]:
    if not permission_ids:
        return {}
    rows = (
        await session.execute(
            select(Permission.id, Permission.key).where(
                Permission.id.in_(permission_ids),
                Permission.deleted_at.is_(None),
            )
        )
    ).all()
    return {row.id: row.key for row in rows}
