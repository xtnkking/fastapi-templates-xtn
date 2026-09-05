import uuid
from dataclasses import dataclass, field

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.rbac.domain import AuthoritySnapshot, RoleGrant
from app.rbac.errors import not_found, unauthenticated
from app.rbac.models import (
    Membership,
    MembershipRole,
    Permission,
    Role,
    RolePermission,
    Tenant,
    TenantAuthorizationState,
    User,
)


@dataclass(slots=True)
class _RoleAccumulator:
    role_id: uuid.UUID
    management_tier: int
    is_protected: bool
    is_owner: bool
    permissions: set[str] = field(default_factory=set)
    delegable_permissions: set[str] = field(default_factory=set)

    def freeze(self) -> RoleGrant:
        return RoleGrant(
            role_id=self.role_id,
            management_tier=self.management_tier,
            permissions=frozenset(self.permissions),
            delegable_permissions=frozenset(self.delegable_permissions),
            is_protected=self.is_protected,
            is_owner=self.is_owner,
        )


async def load_role_grants_for_membership(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    membership_id: uuid.UUID,
    include_disabled_roles: bool,
) -> tuple[RoleGrant, ...]:
    statement = (
        select(
            Role.id.label("role_id"),
            Role.management_tier,
            Role.is_protected,
            Role.is_owner,
            Permission.key.label("permission_key"),
            RolePermission.can_delegate,
        )
        .select_from(MembershipRole)
        .join(
            Role,
            and_(
                Role.id == MembershipRole.role_id,
                Role.tenant_id == MembershipRole.tenant_id,
            ),
        )
        .outerjoin(
            RolePermission,
            and_(
                RolePermission.tenant_id == Role.tenant_id,
                RolePermission.role_id == Role.id,
            ),
        )
        .outerjoin(Permission, Permission.id == RolePermission.permission_id)
        .where(
            MembershipRole.tenant_id == tenant_id,
            MembershipRole.membership_id == membership_id,
        )
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
                management_tier=row.management_tier,
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
    tenant_id: uuid.UUID,
    membership_id: uuid.UUID,
    include_disabled_roles: bool = False,
) -> AuthoritySnapshot:
    result = await session.execute(
        select(
            Membership,
            User.is_active.label("user_is_active"),
            User.is_protected.label("user_is_protected"),
        )
        .join(User, User.id == Membership.user_id)
        .where(
            Membership.tenant_id == tenant_id,
            Membership.id == membership_id,
        )
        .execution_options(populate_existing=True)
    )
    row = result.one_or_none()
    if row is None:
        raise not_found("membership_not_found")
    membership: Membership = row[0]
    roles = await load_role_grants_for_membership(
        session,
        tenant_id=tenant_id,
        membership_id=membership_id,
        include_disabled_roles=include_disabled_roles,
    )
    return AuthoritySnapshot.build(
        membership_id=membership.id,
        user_id=membership.user_id,
        membership_status=membership.status,
        membership_is_protected=membership.is_protected,
        user_is_protected=bool(row.user_is_protected),
        authz_version=membership.authz_version,
        roles=roles,
        user_is_active=bool(row.user_is_active),
    )


async def load_role_grant(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    role_id: uuid.UUID,
    include_disabled: bool = False,
) -> RoleGrant:
    role = await session.scalar(
        select(Role)
        .where(Role.tenant_id == tenant_id, Role.id == role_id)
        .execution_options(populate_existing=True)
    )
    if role is None or (not include_disabled and not role.is_active):
        raise not_found("role_not_found")

    rows = (
        await session.execute(
            select(Permission.key, RolePermission.can_delegate)
            .select_from(RolePermission)
            .join(Permission, Permission.id == RolePermission.permission_id)
            .where(
                RolePermission.tenant_id == tenant_id,
                RolePermission.role_id == role_id,
            )
            .order_by(Permission.key)
        )
    ).all()
    permissions = frozenset(row.key for row in rows)
    return RoleGrant(
        role_id=role.id,
        management_tier=role.management_tier,
        permissions=permissions,
        delegable_permissions=frozenset(row.key for row in rows if row.can_delegate),
        is_protected=role.is_protected,
        is_owner=role.is_owner,
    )


async def find_membership_for_user(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
) -> Membership | None:
    result = await session.scalars(
        select(Membership).where(
            Membership.tenant_id == tenant_id,
            Membership.user_id == user_id,
        )
    )
    return result.one_or_none()


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


async def lock_tenant_authorization_state(
    session: AsyncSession, tenant_id: uuid.UUID
) -> tuple[Tenant, TenantAuthorizationState]:
    state = await session.scalar(
        select(TenantAuthorizationState)
        .where(TenantAuthorizationState.tenant_id == tenant_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    tenant = await session.scalar(
        select(Tenant)
        .where(Tenant.id == tenant_id)
        .execution_options(populate_existing=True)
    )
    if state is None or tenant is None:
        raise not_found("tenant_not_found")
    return tenant, state


async def lock_memberships(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    membership_ids: set[uuid.UUID],
) -> dict[uuid.UUID, Membership]:
    if not membership_ids:
        return {}
    memberships = (
        await session.scalars(
            select(Membership)
            .where(
                Membership.tenant_id == tenant_id,
                Membership.id.in_(membership_ids),
            )
            .order_by(Membership.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).all()
    return {membership.id: membership for membership in memberships}


async def lock_roles(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    role_ids: set[uuid.UUID],
) -> dict[uuid.UUID, Role]:
    if not role_ids:
        return {}
    roles = (
        await session.scalars(
            select(Role)
            .where(Role.tenant_id == tenant_id, Role.id.in_(role_ids))
            .order_by(Role.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).all()
    return {role.id: role for role in roles}


async def lock_role_permissions(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    role_id: uuid.UUID,
) -> dict[str, RolePermission]:
    rows = (
        await session.execute(
            select(RolePermission, Permission.key.label("permission_key"))
            .join(Permission, Permission.id == RolePermission.permission_id)
            .where(
                RolePermission.tenant_id == tenant_id,
                RolePermission.role_id == role_id,
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
    tenant_id: uuid.UUID,
    actor_membership_id: uuid.UUID,
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
    actor = await load_authority_snapshot(
        session,
        tenant_id=tenant_id,
        membership_id=actor_membership_id,
    )
    if actor.user_id != actor_user_id or actor.membership_status != "active":
        raise unauthenticated("actor_membership_no_longer_active")
    return actor


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
