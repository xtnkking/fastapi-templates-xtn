import argparse
import asyncio
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import SessionFactory
from app.rbac.domain import (
    SUPER_ADMIN_DELEGABLE_PERMISSION_KEYS,
    SUPER_ADMIN_PERMISSION_KEYS,
    SYSTEM_ROLE_SPECS,
    SystemRoleKey,
)
from app.rbac.models import (
    AuthorizationAuditEvent,
    Permission,
    Role,
    RolePermission,
    User,
    UserRole,
)
from app.rbac.queries import lock_authorization_state, lock_roles, lock_users


def _require_system_role_shape(role: Role, *, key: SystemRoleKey) -> None:
    spec = SYSTEM_ROLE_SPECS[key]
    if (
        role.key != key.value
        or role.name != spec.name
        or role.description != spec.description
        or role.management_tier != spec.management_tier
        or not role.is_active
        or role.is_protected != spec.is_protected
        or not role.is_system
        or role.is_owner != spec.is_owner
        or role.deleted_at is not None
        or role.deleted_by_user_id is not None
    ):
        raise RuntimeError(
            f"system role {key.value!r} does not match the migrated contract"
        )


async def _require_super_admin_grants(
    *,
    session: AsyncSession,
    role_id: uuid.UUID,
) -> None:
    # The offline trust boundary verifies, rather than repairs, migration-owned
    # super-administrator grants.
    rows = (
        await session.execute(
            select(Permission.key, RolePermission.can_delegate)
            .select_from(RolePermission)
            .join(Permission, Permission.id == RolePermission.permission_id)
            .where(RolePermission.role_id == role_id)
            .order_by(Permission.key)
            .with_for_update(of=RolePermission)
        )
    ).all()
    permission_keys = frozenset(row.key for row in rows)
    delegable_keys = frozenset(row.key for row in rows if row.can_delegate)
    if permission_keys != SUPER_ADMIN_PERMISSION_KEYS:
        raise RuntimeError(
            "super_admin permission grants do not match the versioned allowlist"
        )
    if delegable_keys != SUPER_ADMIN_DELEGABLE_PERMISSION_KEYS:
        raise RuntimeError(
            "super_admin delegable grants do not match the versioned allowlist"
        )


async def bootstrap_super_admin(*, super_admin_email: str) -> User:
    """Atomically assign the sole pre-seeded super_admin role offline."""
    normalized_email = super_admin_email.strip()
    if not normalized_email:
        raise ValueError("super-admin email must not be empty")

    async with SessionFactory() as session:
        async with session.begin():
            state = await lock_authorization_state(session)

            role_candidates = (
                await session.scalars(
                    select(Role).where(
                        Role.key.in_(
                            [
                                SystemRoleKey.SUPER_ADMIN.value,
                                SystemRoleKey.USER.value,
                            ]
                        )
                    )
                )
            ).all()
            roles_by_key = {role.key: role for role in role_candidates}
            if set(roles_by_key) != {
                SystemRoleKey.SUPER_ADMIN.value,
                SystemRoleKey.USER.value,
            }:
                raise RuntimeError("system roles are missing; run Alembic upgrade head")

            super_admin_role = roles_by_key[SystemRoleKey.SUPER_ADMIN.value]
            user_role = roles_by_key[SystemRoleKey.USER.value]
            current_holder_ids = set(
                (
                    await session.scalars(
                        select(UserRole.user_id).where(
                            UserRole.role_id == super_admin_role.id
                        )
                    )
                ).all()
            )
            if len(current_holder_ids) > 1:
                raise RuntimeError(
                    "multiple super_admin assignments exist; bootstrap refused"
                )

            existing_candidate = await session.scalar(
                select(User).where(User.email == normalized_email)
            )
            users_to_lock = set(current_holder_ids)
            if existing_candidate is not None:
                users_to_lock.add(existing_candidate.id)
            locked_users = await lock_users(session, users_to_lock)
            locked_roles = await lock_roles(
                session,
                role_ids={super_admin_role.id, user_role.id},
            )
            super_admin_role = locked_roles[super_admin_role.id]
            user_role = locked_roles[user_role.id]
            _require_system_role_shape(
                super_admin_role,
                key=SystemRoleKey.SUPER_ADMIN,
            )
            _require_system_role_shape(user_role, key=SystemRoleKey.USER)
            await _require_super_admin_grants(
                session=session,
                role_id=super_admin_role.id,
            )

            candidate = (
                locked_users.get(existing_candidate.id)
                if existing_candidate is not None
                else None
            )
            if candidate is None:
                candidate = User(email=normalized_email)
                session.add(candidate)
                await session.flush()
            elif not candidate.is_active or candidate.is_protected:
                raise RuntimeError(
                    "existing super_admin identity is inactive or system-protected"
                )

            assignments = (
                await session.scalars(
                    select(UserRole)
                    .where(UserRole.role_id.in_({super_admin_role.id, user_role.id}))
                    .order_by(UserRole.user_id, UserRole.role_id)
                    .with_for_update()
                )
            ).all()
            current_holder_ids = {
                assignment.user_id
                for assignment in assignments
                if assignment.role_id == super_admin_role.id
            }
            if current_holder_ids and current_holder_ids != {candidate.id}:
                raise RuntimeError(
                    "a different super_admin already exists; bootstrap refused"
                )

            assigned_role_ids = {
                assignment.role_id
                for assignment in assignments
                if assignment.user_id == candidate.id
            }
            missing_role_ids = {
                super_admin_role.id,
                user_role.id,
            } - assigned_role_ids
            if missing_role_ids:
                session.add_all(
                    UserRole(
                        user_id=candidate.id,
                        role_id=role_id,
                        assigned_by_user_id=None,
                    )
                    for role_id in sorted(missing_role_ids, key=str)
                )
                candidate.authz_version += 1
                state.epoch += 1

            session.add(
                AuthorizationAuditEvent(
                    actor_user_id=candidate.id,
                    target_user_id=candidate.id,
                    target_role_id=super_admin_role.id,
                    action="super_admin.bootstrap",
                    decision="allowed",
                    reason_code=(
                        "explicit_super_admin_bootstrap"
                        if missing_role_ids
                        else "super_admin_already_bootstrapped"
                    ),
                    before_state=None,
                    after_state={
                        "super_admin_user_id": str(candidate.id),
                        "super_admin_role_id": str(super_admin_role.id),
                        "base_user_role_id": str(user_role.id),
                        "changed": bool(missing_role_ids),
                    },
                    request_id=f"bootstrap:super_admin:{candidate.id}",
                )
            )
        return candidate


async def bootstrap_owner(*, owner_email: str) -> User:
    """Compatibility wrapper for integrations using the v0.2 function name."""
    return await bootstrap_super_admin(super_admin_email=owner_email)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Assign the first and sole system super administrator."
    )
    parser.add_argument("--super-admin-email", required=True)
    args = parser.parse_args()
    super_admin = asyncio.run(
        bootstrap_super_admin(super_admin_email=args.super_admin_email)
    )
    print(f"super_admin_user_id={super_admin.id}")


if __name__ == "__main__":
    main()
