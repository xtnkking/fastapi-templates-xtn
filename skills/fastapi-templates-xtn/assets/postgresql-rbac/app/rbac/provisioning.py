import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.rbac.domain import SYSTEM_ROLE_SPECS, SystemRoleKey
from app.rbac.errors import conflict, not_found
from app.rbac.models import AuthorizationAuditEvent, Role, User, UserRole
from app.rbac.queries import lock_authorization_state, lock_roles, lock_users


def _new_user_id(value: uuid.UUID | None) -> uuid.UUID:
    user_id = value or uuid.uuid4()
    if user_id.version != 4:
        raise ValueError("user_id must be a UUIDv4 value")
    return user_id


async def create_user_with_default_role(
    session: AsyncSession,
    *,
    email: str,
    user_id: uuid.UUID | None = None,
    assigned_by_user_id: uuid.UUID | None = None,
    request_id: str = "user-provision",
) -> User:
    """Create one user and its mandatory base role without committing.

    The caller owns the transaction and must invoke this before taking any
    authorization locks of its own. Registration, invitations, and identity
    synchronization should all reuse this boundary.
    """
    if not session.in_transaction():
        raise RuntimeError("caller must start the provisioning transaction")
    normalized_email = email.strip()
    if not normalized_email:
        raise ValueError("email must not be empty")
    new_user_id = _new_user_id(user_id)

    state = await lock_authorization_state(session)
    if assigned_by_user_id is not None:
        actors = await lock_users(session, {assigned_by_user_id})
        if assigned_by_user_id not in actors:
            raise not_found("provisioning_actor_not_found")

    existing = await session.scalar(
        select(User.id).where(
            (User.id == new_user_id) | (User.email == normalized_email)
        )
    )
    if existing is not None:
        raise conflict("user_identity_exists")

    user = User(id=new_user_id, email=normalized_email, authz_version=1)
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
        or user_role.is_owner
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
        AuthorizationAuditEvent(
            actor_user_id=assigned_by_user_id or user.id,
            target_user_id=user.id,
            target_role_id=user_role.id,
            action="user.provision",
            decision="allowed",
            reason_code="default_user_role_assigned",
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
