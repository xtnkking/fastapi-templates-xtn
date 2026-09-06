import argparse
import asyncio

from sqlalchemy import select

from app.database import SessionFactory
from app.rbac.domain import OWNER_DELEGABLE_PERMISSION_KEYS, OWNER_PERMISSION_KEYS
from app.rbac.models import (
    AuthorizationAuditEvent,
    Permission,
    Role,
    RolePermission,
    User,
    UserRole,
)
from app.rbac.queries import lock_authorization_state


async def bootstrap_owner(*, owner_email: str) -> User:
    """Create the single system Owner in an explicit transaction."""
    async with SessionFactory() as session:
        async with session.begin():
            state = await lock_authorization_state(session)
            existing_owner = await session.scalar(
                select(Role.id).where(Role.is_owner.is_(True))
            )
            if existing_owner is not None:
                raise RuntimeError("system Owner already exists; bootstrap refused")

            permission_rows = {
                permission.key: permission
                for permission in (
                    await session.scalars(
                        select(Permission)
                        .where(Permission.key.in_(OWNER_PERMISSION_KEYS))
                        .order_by(Permission.key)
                    )
                ).all()
            }
            missing_permissions = OWNER_PERMISSION_KEYS - set(permission_rows)
            if missing_permissions:
                missing = ", ".join(sorted(missing_permissions))
                raise RuntimeError(
                    f"permission catalog is incomplete ({missing}); run Alembic"
                )

            owner_user = await session.scalar(
                select(User).where(User.email == owner_email).with_for_update()
            )
            if owner_user is None:
                owner_user = User(email=owner_email)
                session.add(owner_user)
                await session.flush()
            elif not owner_user.is_active or owner_user.is_protected:
                raise RuntimeError(
                    "existing Owner identity is inactive or system-protected"
                )

            owner_role = Role(
                key="owner",
                name="Owner",
                management_tier=1000,
                is_active=True,
                is_protected=True,
                is_system=True,
                is_owner=True,
                version=1,
            )
            session.add(owner_role)
            await session.flush()
            session.add_all(
                RolePermission(
                    role_id=owner_role.id,
                    permission_id=permission.id,
                    can_delegate=(permission.key in OWNER_DELEGABLE_PERMISSION_KEYS),
                )
                for permission in permission_rows.values()
            )
            session.add(
                UserRole(
                    user_id=owner_user.id,
                    role_id=owner_role.id,
                    assigned_by_user_id=None,
                )
            )
            owner_user.authz_version += 1
            state.epoch += 1
            session.add(
                AuthorizationAuditEvent(
                    actor_user_id=owner_user.id,
                    target_user_id=owner_user.id,
                    target_role_id=owner_role.id,
                    action="system.bootstrap",
                    decision="allowed",
                    reason_code="explicit_owner_bootstrap",
                    before_state=None,
                    after_state={
                        "owner_user_id": str(owner_user.id),
                        "owner_role_id": str(owner_role.id),
                    },
                    request_id="bootstrap",
                )
            )
        return owner_user


def main() -> None:
    parser = argparse.ArgumentParser(description="Create the first system Owner.")
    parser.add_argument("--owner-email", required=True)
    args = parser.parse_args()
    owner = asyncio.run(bootstrap_owner(owner_email=args.owner_email))
    print(f"owner_user_id={owner.id}")


if __name__ == "__main__":
    main()
