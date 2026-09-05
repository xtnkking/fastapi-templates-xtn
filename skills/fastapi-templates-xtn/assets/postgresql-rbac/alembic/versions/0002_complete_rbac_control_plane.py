"""Complete the tenant RBAC administration control plane.

Downgrade is intentionally lossy: it removes control-plane grants and does not
restore role flags or tiers normalized during upgrade. Restore a pre-upgrade
backup when an exact rollback is required.

Revision ID: 0002_complete_rbac_control_plane
Revises: 0001_postgresql_rbac
"""

import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0002_complete_rbac_control_plane"
down_revision: str | None = "0001_postgresql_rbac"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PERMISSIONS: tuple[tuple[str, str], ...] = (
    ("roles:read", "Read tenant roles and their permission grants"),
    ("roles:create", "Create an unprotected tenant role"),
    ("roles:assign", "Assign an existing manageable role"),
    ("roles:revoke", "Revoke an existing manageable role"),
    (
        "roles:permissions:update",
        "Replace permission grants on a manageable tenant role",
    ),
    (
        "roles:delegation:update",
        "Replace delegable grants on a manageable tenant role",
    ),
    ("memberships:read", "Read visible tenant memberships"),
    ("memberships:create", "Create a membership for a known identity"),
    (
        "memberships:status:update",
        "Suspend or reactivate a manageable tenant membership",
    ),
    ("tenant_ownership:transfer", "Transfer tenant ownership atomically"),
    ("projects:read", "Read tenant projects"),
    ("projects:update", "Update tenant projects"),
)

OWNER_GRANTS: tuple[tuple[str, bool], ...] = (
    ("roles:delegation:update", False),
    ("memberships:create", True),
    ("memberships:status:update", True),
)


def _permission_id(key: str) -> uuid.UUID:
    return uuid.uuid5(uuid.NAMESPACE_URL, f"fastapi-rbac-permission:{key}")


def upgrade() -> None:
    permission_table = sa.table(
        "permissions",
        sa.column("id", postgresql.UUID(as_uuid=True)),
        sa.column("key", sa.String()),
        sa.column("description", sa.Text()),
    )
    role_table = sa.table(
        "roles",
        sa.column("id", postgresql.UUID(as_uuid=True)),
        sa.column("tenant_id", postgresql.UUID(as_uuid=True)),
        sa.column("management_tier", sa.Integer()),
        sa.column("is_owner", sa.Boolean()),
        sa.column("is_system", sa.Boolean()),
        sa.column("is_protected", sa.Boolean()),
        sa.column("version", sa.BigInteger()),
    )
    role_permission_table = sa.table(
        "role_permissions",
        sa.column("tenant_id", postgresql.UUID(as_uuid=True)),
        sa.column("role_id", postgresql.UUID(as_uuid=True)),
        sa.column("permission_id", postgresql.UUID(as_uuid=True)),
        sa.column("can_delegate", sa.Boolean()),
    )
    tenant_state_table = sa.table(
        "tenant_authorization_state",
        sa.column("tenant_id", postgresql.UUID(as_uuid=True)),
        sa.column("epoch", sa.BigInteger()),
    )

    insert_permissions = postgresql.insert(permission_table).values(
        [
            {"id": _permission_id(key), "key": key, "description": description}
            for key, description in PERMISSIONS
        ]
    )
    op.execute(
        insert_permissions.on_conflict_do_update(
            index_elements=[permission_table.c.key],
            set_={"description": insert_permissions.excluded.description},
        )
    )

    op.execute(
        role_table.update()
        .where(
            role_table.c.is_system.is_(True),
            role_table.c.is_protected.is_(False),
        )
        .values(is_protected=True)
    )
    op.drop_constraint(
        "protected_is_system",
        "roles",
        type_="check",
    )
    op.create_check_constraint(
        "system_protection_match",
        "roles",
        "is_system = is_protected",
    )

    legacy_owner_tier = role_table.c.management_tier == 1000
    non_owner_at_reserved_tier = legacy_owner_tier & role_table.c.is_owner.is_(False)

    for key, can_delegate in OWNER_GRANTS:
        owner_grant_rows = (
            sa.select(
                role_table.c.tenant_id,
                role_table.c.id,
                permission_table.c.id,
                sa.literal(can_delegate, type_=sa.Boolean()),
            )
            .select_from(
                role_table.join(permission_table, permission_table.c.key == key)
            )
            .where(role_table.c.is_owner.is_(True))
        )
        insert_owner_grant = postgresql.insert(role_permission_table).from_select(
            ["tenant_id", "role_id", "permission_id", "can_delegate"],
            owner_grant_rows,
        )
        op.execute(
            insert_owner_grant.on_conflict_do_update(
                index_elements=[
                    role_permission_table.c.tenant_id,
                    role_permission_table.c.role_id,
                    role_permission_table.c.permission_id,
                ],
                set_={"can_delegate": insert_owner_grant.excluded.can_delegate},
            )
        )

    affected_roles = (
        role_table.c.is_owner.is_(True)
        | role_table.c.is_system.is_(True)
        | non_owner_at_reserved_tier
    )
    affected_tenants = sa.select(role_table.c.tenant_id).where(affected_roles)
    op.execute(
        role_table.update()
        .where(affected_roles)
        .values(version=role_table.c.version + 1)
    )
    op.execute(
        tenant_state_table.update()
        .where(tenant_state_table.c.tenant_id.in_(affected_tenants))
        .values(epoch=tenant_state_table.c.epoch + 1)
    )
    op.execute(
        role_table.update()
        .where(non_owner_at_reserved_tier)
        .values(management_tier=999)
    )
    op.create_check_constraint(
        "owner_tier_reserved",
        "roles",
        "management_tier < 1000 OR is_owner",
    )


def downgrade() -> None:
    added_keys = tuple(key for key, _can_delegate in OWNER_GRANTS)
    permission_table = sa.table(
        "permissions",
        sa.column("id", postgresql.UUID(as_uuid=True)),
        sa.column("key", sa.String()),
    )
    role_permission_table = sa.table(
        "role_permissions",
        sa.column("permission_id", postgresql.UUID(as_uuid=True)),
    )

    added_permission_ids = sa.select(permission_table.c.id).where(
        permission_table.c.key.in_(added_keys)
    )
    op.execute(
        role_permission_table.delete().where(
            role_permission_table.c.permission_id.in_(added_permission_ids)
        )
    )
    op.execute(permission_table.delete().where(permission_table.c.key.in_(added_keys)))

    op.drop_constraint("owner_tier_reserved", "roles", type_="check")
    op.drop_constraint(
        "system_protection_match",
        "roles",
        type_="check",
    )
    op.create_check_constraint(
        "protected_is_system",
        "roles",
        "NOT is_protected OR is_system",
    )
