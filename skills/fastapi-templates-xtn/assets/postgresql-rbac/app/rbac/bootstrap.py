import argparse
import asyncio

from sqlalchemy import select

from app.database import SessionFactory
from app.rbac.domain import (
    TENANT_OWNER_DELEGABLE_PERMISSION_KEYS,
    TENANT_OWNER_PERMISSION_KEYS,
)
from app.rbac.models import (
    AuthorizationAuditEvent,
    Membership,
    MembershipRole,
    Permission,
    Role,
    RolePermission,
    Tenant,
    TenantAuthorizationState,
    User,
)


async def bootstrap_tenant(
    *,
    owner_email: str,
    tenant_slug: str,
    tenant_name: str,
) -> tuple[Tenant, Membership]:
    """Create one tenant and its first owner in an explicit transaction."""
    async with SessionFactory() as session:
        async with session.begin():
            existing_tenant = await session.scalar(
                select(Tenant.id).where(Tenant.slug == tenant_slug)
            )
            if existing_tenant is not None:
                raise RuntimeError("tenant slug already exists; bootstrap refused")

            permission_rows = {
                permission.key: permission
                for permission in (
                    await session.scalars(
                        select(Permission)
                        .where(Permission.key.in_(TENANT_OWNER_PERMISSION_KEYS))
                        .order_by(Permission.key)
                    )
                ).all()
            }
            missing_permissions = TENANT_OWNER_PERMISSION_KEYS - set(permission_rows)
            if missing_permissions:
                missing = ", ".join(sorted(missing_permissions))
                raise RuntimeError(
                    f"tenant permission catalog is incomplete ({missing}); run Alembic"
                )

            owner_user = await session.scalar(
                select(User).where(User.email == owner_email)
            )
            if owner_user is None:
                owner_user = User(email=owner_email)
                session.add(owner_user)
            elif not owner_user.is_active or owner_user.is_protected:
                raise RuntimeError(
                    "existing owner identity is inactive or platform-protected"
                )

            tenant = Tenant(slug=tenant_slug, name=tenant_name)
            session.add(tenant)
            await session.flush()
            session.add(TenantAuthorizationState(tenant_id=tenant.id, epoch=1))

            membership = Membership(
                tenant_id=tenant.id,
                user_id=owner_user.id,
                status="active",
                authz_version=1,
            )
            owner_role = Role(
                tenant_id=tenant.id,
                key="owner",
                name="Owner",
                management_tier=1000,
                is_active=True,
                is_protected=True,
                is_system=True,
                is_owner=True,
                version=1,
            )
            session.add_all([membership, owner_role])
            await session.flush()

            session.add_all(
                RolePermission(
                    tenant_id=tenant.id,
                    role_id=owner_role.id,
                    permission_id=permission.id,
                    can_delegate=(
                        permission.key in TENANT_OWNER_DELEGABLE_PERMISSION_KEYS
                    ),
                )
                for permission in permission_rows.values()
            )
            session.add(
                MembershipRole(
                    tenant_id=tenant.id,
                    membership_id=membership.id,
                    role_id=owner_role.id,
                    assigned_by_membership_id=None,
                )
            )
            session.add(
                AuthorizationAuditEvent(
                    tenant_id=tenant.id,
                    actor_user_id=owner_user.id,
                    actor_membership_id=membership.id,
                    target_membership_id=membership.id,
                    target_role_id=owner_role.id,
                    action="tenant.bootstrap",
                    decision="allowed",
                    reason_code="explicit_owner_bootstrap",
                    before_state=None,
                    after_state={
                        "owner_membership_id": str(membership.id),
                        "owner_role_id": str(owner_role.id),
                    },
                    request_id="bootstrap",
                )
            )
        return tenant, membership


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create an explicitly named tenant and first owner."
    )
    parser.add_argument("--owner-email", required=True)
    parser.add_argument("--tenant-slug", required=True)
    parser.add_argument("--tenant-name", required=True)
    args = parser.parse_args()
    tenant, membership = asyncio.run(
        bootstrap_tenant(
            owner_email=args.owner_email,
            tenant_slug=args.tenant_slug,
            tenant_name=args.tenant_name,
        )
    )
    print(f"tenant_id={tenant.id}")
    print(f"owner_membership_id={membership.id}")


if __name__ == "__main__":
    main()
