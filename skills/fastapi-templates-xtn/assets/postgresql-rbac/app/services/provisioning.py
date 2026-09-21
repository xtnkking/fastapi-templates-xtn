import uuid

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditSource
from app.core.errors import conflict, not_found
from app.core.security.domain import SYSTEM_ROLE_SPECS, SystemRoleKey
from app.core.security.identity import normalize_identity
from app.models.access import RbacAuditEvent, Role, User, UserRole
from app.repositories.access import lock_rbac_state, lock_roles, lock_users


def _new_user_id(value: uuid.UUID | None) -> uuid.UUID:
    user_id = value or uuid.uuid4()
    if user_id.version != 4:
        raise ValueError("user_id must be a UUIDv4 value")
    return user_id


async def create_user_with_default_role(
    session: AsyncSession,
    *,
    user_name: str,
    user_id: uuid.UUID | None = None,
    assigned_by_user_id: uuid.UUID | None = None,
    request_id: str = "user-provision",
) -> User:
    """Create one user and its mandatory base role without committing.

    The caller owns the transaction and must invoke this before taking any
    authorization locks of its own. Registration, invitations, and identity
    synchronization should all reuse this boundary. The identity is a user name
    and the operation never accepts a caller-selected role.
    """
    if not session.in_transaction():
        raise RuntimeError("caller must start the provisioning transaction")
    normalized_user_name = normalize_identity(user_name, field="user_name")
    new_user_id = _new_user_id(user_id)

    state = await lock_rbac_state(session)
    if assigned_by_user_id is not None:
        actors = await lock_users(session, {assigned_by_user_id})
        if assigned_by_user_id not in actors:
            raise not_found("provisioning_actor_not_found")

    identity_matches = [User.id == new_user_id, User.user_name == normalized_user_name]
    existing = await session.scalar(select(User.id).where(or_(*identity_matches)))
    if existing is not None:
        raise conflict("user_identity_exists")

    user = User(
        id=new_user_id,
        user_name=normalized_user_name,
        is_active=True,
        is_protected=False,
        token_version=0,
        authz_version=1,
    )
    session.add(user)
    await session.flush()

    user_role_id = await session.scalar(
        select(Role.id).where(Role.key == SystemRoleKey.USER.value)
    )
    if user_role_id is None:
        raise not_found("default_user_role_missing")
    locked_roles = await lock_roles(session, role_ids={user_role_id})
    user_role = locked_roles[user_role_id]
    spec = SYSTEM_ROLE_SPECS[SystemRoleKey.USER]
    if (
        not user_role.is_system
        or user_role.is_protected != spec.is_protected
        or user_role.is_super_admin
        or not user_role.is_active
        or user_role.management_tier != spec.management_tier
        or user_role.deleted_at is not None
    ):
        raise RuntimeError("default user role does not match the migrated contract")

    session.add(
        UserRole(
            user_id=user.id,
            role_id=user_role.id,
            assigned_by_user_id=assigned_by_user_id,
        )
    )
    state.epoch += 1
    session.add(
        RbacAuditEvent(
            actor_user_id=assigned_by_user_id or user.id,
            target_user_id=user.id,
            target_role_id=user_role.id,
            action="user.provision",
            decision="allowed",
            reason_code="default_user_role_assigned",
            source=AuditSource.SERVICE.value,
            before_state=None,
            after_state={
                "user_id": str(user.id),
                "default_role_id": str(user_role.id),
                "authz_version": user.authz_version,
            },
            request_id=request_id,
        )
    )
    return user
