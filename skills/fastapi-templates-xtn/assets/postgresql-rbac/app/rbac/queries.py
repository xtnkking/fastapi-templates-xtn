import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.rbac.domain import AuthoritySnapshot, RoleGrant
from app.rbac.errors import not_found, unauthenticated, unavailable
from app.rbac.models import (
    AuthorizationState,
    Permission,
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
    is_owner: bool
    permissions: set[str] = field(default_factory=set)
    delegable_permissions: set[str] = field(default_factory=set)

    def freeze(self) -> RoleGrant:
        return RoleGrant(
            role_id=self.role_id,
            key=self.key,
            management_tier=self.management_tier,
            permissions=frozenset(self.permissions),
            delegable_permissions=frozenset(self.delegable_permissions),
            is_system=self.is_system,
            is_protected=self.is_protected,
            is_owner=self.is_owner,
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
            Role.is_owner,
            Permission.key.label("permission_key"),
            RolePermission.can_delegate,
        )
        .select_from(UserRole)
        .join(Role, Role.id == UserRole.role_id)
        .outerjoin(RolePermission, RolePermission.role_id == Role.id)
        .outerjoin(Permission, Permission.id == RolePermission.permission_id)
        .where(UserRole.user_id == user_id)
        .where(Role.deleted_at.is_(None))
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
                is_owner=row.is_owner,
            ),
        )
        if row.permission_key is not None:
            accumulator.permissions.add(row.permission_key)
            if row.can_delegate:
                accumulator.delegable_permissions.add(row.permission_key)

    return tuple(item.freeze() for item in accumulators.values())


async def load_authority_snapshot(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    include_disabled_roles: bool = False,
) -> AuthoritySnapshot:
    user = await session.scalar(
        select(User).where(User.id == user_id).execution_options(populate_existing=True)
    )
    if user is None:
        raise not_found("user_not_found")
    roles = await load_role_grants_for_user(
        session,
        user_id=user_id,
        include_disabled_roles=include_disabled_roles,
    )
    return AuthoritySnapshot.build(
        user_id=user.id,
        user_is_active=user.is_active,
        user_is_protected=user.is_protected,
        authz_version=user.authz_version,
        roles=roles,
    )


async def load_role_grant(
    session: AsyncSession,
    *,
    role_id: uuid.UUID,
    include_disabled: bool = False,
    include_deleted: bool = False,
) -> RoleGrant:
    role = await session.scalar(
        select(Role).where(Role.id == role_id).execution_options(populate_existing=True)
    )
    if (
        role is None
        or (not include_disabled and not role.is_active)
        or (not include_deleted and role.deleted_at is not None)
    ):
        raise not_found("role_not_found")

    rows = (
        await session.execute(
            select(Permission.key, RolePermission.can_delegate)
            .select_from(RolePermission)
            .join(Permission, Permission.id == RolePermission.permission_id)
            .where(RolePermission.role_id == role_id)
            .order_by(Permission.key)
        )
    ).all()
    permissions = frozenset(row.key for row in rows)
    return RoleGrant(
        role_id=role.id,
        key=role.key,
        management_tier=role.management_tier,
        permissions=permissions,
        delegable_permissions=frozenset(row.key for row in rows if row.can_delegate),
        is_system=role.is_system,
        is_protected=role.is_protected,
        is_owner=role.is_owner,
    )


async def lock_authorization_state(session: AsyncSession) -> AuthorizationState:
    state = await session.scalar(
        select(AuthorizationState)
        .where(AuthorizationState.scope == "global")
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if state is None:
        raise unavailable("authorization_state_missing")
    return state


async def lock_users(
    session: AsyncSession, user_ids: set[uuid.UUID]
) -> dict[uuid.UUID, User]:
    if not user_ids:
        return {}
    users = (
        await session.scalars(
            select(User)
            .where(User.id.in_(user_ids))
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
            .where(Role.id.in_(role_ids))
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
            .join(Permission, Permission.id == RolePermission.permission_id)
            .where(RolePermission.role_id == role_id)
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
        .where(User.id == actor_user_id)
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
                Permission.key.in_(permission_keys)
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
                Permission.id.in_(permission_ids)
            )
        )
    ).all()
    return {row.id: row.key for row in rows}
