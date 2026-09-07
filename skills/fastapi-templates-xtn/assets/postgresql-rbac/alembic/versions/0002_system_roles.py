"""Add fixed system roles and role lifecycle metadata.

Revision ID: 0002_system_roles
Revises: 0001_single_project_rbac
"""

import uuid
from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0002_system_roles"
down_revision: str | None = "0001_single_project_rbac"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NEW_PERMISSIONS: tuple[tuple[str, str], ...] = (
    ("permissions:read", "Read the permission catalog"),
    ("roles:update", "Update a manageable role's public information"),
    ("roles:status:update", "Enable or disable a manageable role"),
    ("roles:delete", "Soft-delete a manageable role"),
    ("roles:permissions:bind", "Bind one permission to a manageable role"),
    ("roles:permissions:unbind", "Unbind one permission from a manageable role"),
    ("super_admin:transfer", "Transfer the sole super administrator atomically"),
)

SUPER_ADMIN_PERMISSION_KEYS = frozenset(
    {
        "permissions:read",
        "roles:read",
        "roles:create",
        "roles:update",
        "roles:status:update",
        "roles:delete",
        "roles:assign",
        "roles:revoke",
        "roles:permissions:bind",
        "roles:permissions:unbind",
        "roles:permissions:update",
        "roles:delegation:update",
        "users:read",
        "users:status:update",
        "super_admin:transfer",
        "system_owner:transfer",
        "projects:read",
        "projects:update",
    }
)
SUPER_ADMIN_DELEGABLE_PERMISSION_KEYS = SUPER_ADMIN_PERMISSION_KEYS - {
    "roles:delegation:update",
    "super_admin:transfer",
    "system_owner:transfer",
}
ADMIN_PERMISSION_KEYS = frozenset(
    {
        "permissions:read",
        "roles:read",
        "roles:create",
        "roles:update",
        "roles:status:update",
        "roles:assign",
        "roles:revoke",
        "roles:permissions:bind",
        "roles:permissions:unbind",
        "users:read",
        "users:status:update",
        "projects:read",
        "projects:update",
    }
)
ADMIN_DELEGABLE_PERMISSION_KEYS = frozenset({"projects:read", "projects:update"})
USER_PERMISSION_KEYS: frozenset[str] = frozenset()

SYSTEM_ROLE_SPECS: dict[str, dict[str, Any]] = {
    "super_admin": {
        "name": "Super administrator",
        "description": "Sole protected administrator for the application",
        "management_tier": 1000,
        "is_protected": True,
        "is_owner": True,
        "permissions": SUPER_ADMIN_PERMISSION_KEYS,
        "delegable_permissions": SUPER_ADMIN_DELEGABLE_PERMISSION_KEYS,
    },
    "admin": {
        "name": "Administrator",
        "description": "Built-in administrator for strictly lower authority",
        "management_tier": 500,
        "is_protected": False,
        "is_owner": False,
        "permissions": ADMIN_PERMISSION_KEYS,
        "delegable_permissions": ADMIN_DELEGABLE_PERMISSION_KEYS,
    },
    "user": {
        "name": "User",
        "description": "Mandatory lowest-authority role for every user",
        "management_tier": 0,
        "is_protected": False,
        "is_owner": False,
        "permissions": USER_PERMISSION_KEYS,
        "delegable_permissions": frozenset(),
    },
}


def _permission_id(key: str) -> uuid.UUID:
    return uuid.uuid5(uuid.NAMESPACE_URL, f"fastapi-rbac-permission:{key}")


def _system_role_id(key: str) -> uuid.UUID:
    return uuid.uuid5(uuid.NAMESPACE_URL, f"fastapi-rbac-system-role:{key}")


def _uuid_value(value: object) -> uuid.UUID:
    if not isinstance(value, uuid.UUID):
        raise RuntimeError("expected PostgreSQL UUID value while seeding system roles")
    return value


def _role_by_key(connection: sa.Connection, key: str) -> sa.RowMapping | None:
    return (
        connection.execute(
            sa.text(
                "SELECT id, key, name, management_tier, is_active, is_protected, "
                "is_system, is_owner FROM roles WHERE key = :key"
            ),
            {"key": key},
        )
        .mappings()
        .one_or_none()
    )


def _preflight_legacy_owner_assignment(connection: sa.Connection) -> None:
    owners = (
        connection.execute(
            sa.text("SELECT id, key FROM roles WHERE is_owner ORDER BY id")
        )
        .mappings()
        .all()
    )
    if not owners:
        return
    if len(owners) > 1:
        raise RuntimeError(
            "multiple Owner roles exist; repair authority before upgrading"
        )

    holder_count = connection.scalar(
        sa.text("SELECT count(*) FROM user_roles WHERE role_id = :role_id"),
        {"role_id": owners[0]["id"]},
    )
    if holder_count is None:
        raise RuntimeError("could not count legacy Owner assignments")
    if holder_count > 1:
        raise RuntimeError(
            "legacy Owner role has multiple holders; reduce it to exactly one "
            "before upgrading"
        )


def _insert_system_role(
    connection: sa.Connection,
    *,
    key: str,
    role_id: uuid.UUID,
) -> None:
    spec = SYSTEM_ROLE_SPECS[key]
    connection.execute(
        sa.text(
            "INSERT INTO roles "
            "(id, key, name, description, management_tier, is_active, "
            "is_protected, is_system, is_owner, version) VALUES "
            "(:id, :key, :name, :description, :management_tier, true, "
            ":is_protected, true, :is_owner, 0)"
        ),
        {
            "id": role_id,
            "key": key,
            "name": spec["name"],
            "description": spec["description"],
            "management_tier": spec["management_tier"],
            "is_protected": spec["is_protected"],
            "is_owner": spec["is_owner"],
        },
    )


def _ensure_non_owner_system_role(
    connection: sa.Connection,
    *,
    key: str,
) -> uuid.UUID:
    existing = _role_by_key(connection, key)
    if existing is None:
        role_id = _system_role_id(key)
        _insert_system_role(connection, key=key, role_id=role_id)
        return role_id

    spec = SYSTEM_ROLE_SPECS[key]
    expected = {
        "management_tier": spec["management_tier"],
        "is_active": True,
        "is_protected": spec["is_protected"],
        "is_system": True,
        "is_owner": False,
    }
    if any(existing[field] != value for field, value in expected.items()):
        raise RuntimeError(
            f"role key {key!r} already exists with a non-system shape; "
            "resolve the collision before upgrading"
        )
    connection.execute(
        sa.text(
            "UPDATE roles SET name = :name, description = :description "
            "WHERE id = :role_id"
        ),
        {
            "role_id": existing["id"],
            "name": spec["name"],
            "description": spec["description"],
        },
    )
    return _uuid_value(existing["id"])


def _ensure_super_admin_role(connection: sa.Connection) -> uuid.UUID:
    legacy = _role_by_key(connection, "owner")
    named = _role_by_key(connection, "super_admin")
    owners = (
        connection.execute(
            sa.text("SELECT id, key FROM roles WHERE is_owner ORDER BY id")
        )
        .mappings()
        .all()
    )
    if len(owners) > 1:
        raise RuntimeError(
            "multiple Owner roles exist; repair authority before upgrading"
        )
    if legacy is not None and not legacy["is_owner"]:
        raise RuntimeError(
            "role key 'owner' is occupied by a non-Owner role; resolve the "
            "collision before upgrading"
        )

    if owners:
        owner = owners[0]
        if owner["key"] not in {"owner", "super_admin"}:
            raise RuntimeError(
                "the Owner role has an unexpected key; resolve it before upgrading"
            )
        if named is not None and named["id"] != owner["id"]:
            raise RuntimeError(
                "role key 'super_admin' is already occupied; resolve the collision "
                "before upgrading"
            )
        role_id = _uuid_value(owner["id"])
        spec = SYSTEM_ROLE_SPECS["super_admin"]
        connection.execute(
            sa.text(
                "UPDATE roles SET key = 'super_admin', name = :name, "
                "description = :description, management_tier = 1000, "
                "is_active = true, is_protected = true, is_system = true, "
                "is_owner = true, deleted_at = NULL, deleted_by_user_id = NULL "
                "WHERE id = :role_id"
            ),
            {
                "role_id": role_id,
                "name": spec["name"],
                "description": spec["description"],
            },
        )
        return role_id

    if named is not None:
        raise RuntimeError(
            "role key 'super_admin' is occupied by a non-Owner role; resolve the "
            "collision before upgrading"
        )

    role_id = _system_role_id("super_admin")
    _insert_system_role(connection, key="super_admin", role_id=role_id)
    return role_id


def _replace_system_role_grants(
    connection: sa.Connection,
    *,
    role_id: uuid.UUID,
    permission_keys: frozenset[str],
    delegable_permission_keys: frozenset[str],
) -> None:
    rows = (
        connection.execute(
            sa.text("SELECT id, key FROM permissions WHERE key = ANY(:keys)"),
            {"keys": sorted(permission_keys)},
        )
        .mappings()
        .all()
    )
    permission_ids = {row["key"]: row["id"] for row in rows}
    missing = permission_keys - set(permission_ids)
    if missing:
        raise RuntimeError(
            "permission catalog is incomplete: " + ", ".join(sorted(missing))
        )

    connection.execute(
        sa.text("DELETE FROM role_permissions WHERE role_id = :role_id"),
        {"role_id": role_id},
    )
    if permission_keys:
        connection.execute(
            sa.text(
                "INSERT INTO role_permissions (role_id, permission_id, can_delegate) "
                "VALUES (:role_id, :permission_id, :can_delegate)"
            ),
            [
                {
                    "role_id": role_id,
                    "permission_id": permission_ids[key],
                    "can_delegate": key in delegable_permission_keys,
                }
                for key in sorted(permission_keys)
            ],
        )


def upgrade() -> None:
    connection = op.get_bind()
    connection.execute(
        sa.text(
            "SELECT scope FROM authorization_state WHERE scope = 'global' FOR UPDATE"
        )
    )
    _preflight_legacy_owner_assignment(connection)

    op.add_column(
        "roles",
        sa.Column(
            "description",
            sa.Text(),
            server_default=sa.text("''"),
            nullable=False,
        ),
    )
    op.add_column(
        "roles", sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "roles",
        sa.Column("deleted_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_roles_deleted_by_user_id_users",
        "roles",
        "users",
        ["deleted_by_user_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.drop_constraint("system_protection_match", "roles", type_="check")

    permission_table = sa.table(
        "permissions",
        sa.column("id", postgresql.UUID(as_uuid=True)),
        sa.column("key", sa.String()),
        sa.column("description", sa.Text()),
    )
    insert_permissions = postgresql.insert(permission_table).values(
        [
            {"id": _permission_id(key), "key": key, "description": description}
            for key, description in NEW_PERMISSIONS
        ]
    )
    connection.execute(
        insert_permissions.on_conflict_do_update(
            index_elements=[permission_table.c.key],
            set_={"description": insert_permissions.excluded.description},
        )
    )

    role_ids = {
        "super_admin": _ensure_super_admin_role(connection),
        "admin": _ensure_non_owner_system_role(connection, key="admin"),
        "user": _ensure_non_owner_system_role(connection, key="user"),
    }
    for key, role_id in role_ids.items():
        spec = SYSTEM_ROLE_SPECS[key]
        _replace_system_role_grants(
            connection,
            role_id=role_id,
            permission_keys=spec["permissions"],
            delegable_permission_keys=spec["delegable_permissions"],
        )

    inserted_user_ids = list(
        connection.scalars(
            sa.text(
                "INSERT INTO user_roles "
                "(user_id, role_id, assigned_by_user_id) "
                "SELECT users.id, :role_id, NULL FROM users "
                "ON CONFLICT (user_id, role_id) DO NOTHING RETURNING user_id"
            ),
            {"role_id": role_ids["user"]},
        ).all()
    )
    if inserted_user_ids:
        connection.execute(
            sa.text(
                "UPDATE users SET authz_version = authz_version + 1 "
                "WHERE id = ANY(:user_ids)"
            ),
            {"user_ids": inserted_user_ids},
        )
    connection.execute(
        sa.text(
            "UPDATE authorization_state SET epoch = epoch + 1 WHERE scope = 'global'"
        )
    )

    op.create_check_constraint(
        "custom_role_tier_range",
        "roles",
        "is_system OR (management_tier >= 1 AND management_tier <= 999)",
    )
    op.create_check_constraint(
        "legacy_owner_role_key_reserved",
        "roles",
        "key <> 'owner'",
    )
    op.create_check_constraint(
        "protected_role_is_system", "roles", "NOT is_protected OR is_system"
    )
    op.create_check_constraint(
        "system_role_always_available",
        "roles",
        "NOT is_system OR (is_active AND deleted_at IS NULL)",
    )
    op.create_check_constraint(
        "deleted_role_inactive", "roles", "deleted_at IS NULL OR NOT is_active"
    )
    op.create_check_constraint(
        "deleted_role_actor_requires_timestamp",
        "roles",
        "deleted_by_user_id IS NULL OR deleted_at IS NOT NULL",
    )
    op.drop_constraint("owner_shape", "roles", type_="check")
    op.create_check_constraint(
        "owner_shape",
        "roles",
        "NOT is_owner OR (is_system AND is_protected AND is_active "
        "AND management_tier = 1000 AND key = 'super_admin' "
        "AND deleted_at IS NULL)",
    )
    op.create_check_constraint(
        "super_admin_role_shape",
        "roles",
        "key <> 'super_admin' OR (is_system AND is_protected AND is_owner "
        "AND is_active AND management_tier = 1000 AND deleted_at IS NULL)",
    )
    op.create_check_constraint(
        "admin_role_shape",
        "roles",
        "key <> 'admin' OR (is_system AND NOT is_protected AND NOT is_owner "
        "AND is_active AND management_tier = 500 AND deleted_at IS NULL)",
    )
    op.create_check_constraint(
        "user_role_shape",
        "roles",
        "key <> 'user' OR (is_system AND NOT is_protected AND NOT is_owner "
        "AND is_active AND management_tier = 0 AND deleted_at IS NULL)",
    )

    op.execute(
        """
        CREATE FUNCTION protect_system_role_definition() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF TG_OP = 'DELETE' AND OLD.is_system THEN
                RAISE EXCEPTION 'system roles cannot be deleted'
                    USING ERRCODE = '23514';
            END IF;
            IF TG_OP = 'UPDATE' AND OLD.is_system AND (
                NEW.key IS DISTINCT FROM OLD.key OR
                NEW.name IS DISTINCT FROM OLD.name OR
                NEW.description IS DISTINCT FROM OLD.description OR
                NEW.management_tier IS DISTINCT FROM OLD.management_tier OR
                NEW.is_active IS DISTINCT FROM OLD.is_active OR
                NEW.is_protected IS DISTINCT FROM OLD.is_protected OR
                NEW.is_system IS DISTINCT FROM OLD.is_system OR
                NEW.is_owner IS DISTINCT FROM OLD.is_owner OR
                NEW.deleted_at IS DISTINCT FROM OLD.deleted_at OR
                NEW.deleted_by_user_id IS DISTINCT FROM OLD.deleted_by_user_id
            ) THEN
                RAISE EXCEPTION 'system role definitions are immutable'
                    USING ERRCODE = '23514';
            END IF;
            IF TG_OP = 'DELETE' THEN
                RETURN OLD;
            END IF;
            RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER tr_roles_protect_system_definition
        BEFORE UPDATE OR DELETE ON roles
        FOR EACH ROW EXECUTE FUNCTION protect_system_role_definition()
        """
    )
    op.execute(
        """
        CREATE FUNCTION protect_system_role_permissions() RETURNS trigger
        LANGUAGE plpgsql AS $$
        DECLARE
            protected_role_id uuid;
        BEGIN
            IF TG_OP IN ('UPDATE', 'DELETE') AND EXISTS (
                SELECT 1 FROM roles
                WHERE id = OLD.role_id AND is_system
            ) THEN
                protected_role_id := OLD.role_id;
            END IF;
            IF TG_OP IN ('INSERT', 'UPDATE') AND EXISTS (
                SELECT 1 FROM roles
                WHERE id = NEW.role_id AND is_system
            ) THEN
                protected_role_id := NEW.role_id;
            END IF;
            IF protected_role_id IS NOT NULL THEN
                RAISE EXCEPTION 'system role permission grants are immutable'
                    USING ERRCODE = '23514';
            END IF;
            IF TG_OP = 'DELETE' THEN
                RETURN OLD;
            END IF;
            RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER tr_role_permissions_protect_system_roles
        BEFORE INSERT OR UPDATE OR DELETE ON role_permissions
        FOR EACH ROW EXECUTE FUNCTION protect_system_role_permissions()
        """
    )
    op.execute(
        """
        CREATE FUNCTION assert_user_has_base_role(candidate_user_id uuid)
        RETURNS void LANGUAGE plpgsql AS $$
        BEGIN
            PERFORM scope FROM authorization_state
            WHERE scope = 'global' FOR UPDATE;
            IF EXISTS (SELECT 1 FROM users WHERE id = candidate_user_id)
               AND NOT EXISTS (
                   SELECT 1 FROM user_roles ur
                   JOIN roles r ON r.id = ur.role_id
                   WHERE ur.user_id = candidate_user_id AND r.key = 'user'
               ) THEN
                RAISE EXCEPTION 'every user must retain the user system role'
                    USING ERRCODE = '23514';
            END IF;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE FUNCTION enforce_user_base_role() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF TG_TABLE_NAME = 'users' THEN
                PERFORM assert_user_has_base_role(NEW.id);
            ELSE
                IF TG_OP IN ('UPDATE', 'DELETE') THEN
                    PERFORM assert_user_has_base_role(OLD.user_id);
                END IF;
                IF TG_OP IN ('INSERT', 'UPDATE') THEN
                    PERFORM assert_user_has_base_role(NEW.user_id);
                END IF;
            END IF;
            RETURN NULL;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE CONSTRAINT TRIGGER ct_users_require_base_role
        AFTER INSERT OR UPDATE ON users
        DEFERRABLE INITIALLY DEFERRED
        FOR EACH ROW EXECUTE FUNCTION enforce_user_base_role()
        """
    )
    op.execute(
        """
        CREATE CONSTRAINT TRIGGER ct_user_roles_require_base_role
        AFTER INSERT OR UPDATE OR DELETE ON user_roles
        DEFERRABLE INITIALLY DEFERRED
        FOR EACH ROW EXECUTE FUNCTION enforce_user_base_role()
        """
    )
    op.execute(
        """
        CREATE FUNCTION enforce_exactly_one_super_admin() RETURNS trigger
        LANGUAGE plpgsql AS $$
        DECLARE
            super_admin_role_id uuid;
            holder_count integer;
            assignment_changed boolean := false;
        BEGIN
            SELECT id INTO STRICT super_admin_role_id
            FROM roles WHERE key = 'super_admin';

            IF TG_OP IN ('UPDATE', 'DELETE') THEN
                IF OLD.role_id = super_admin_role_id THEN
                    assignment_changed := true;
                END IF;
            END IF;
            IF TG_OP IN ('INSERT', 'UPDATE') THEN
                IF NEW.role_id = super_admin_role_id THEN
                    assignment_changed := true;
                END IF;
            END IF;
            IF NOT assignment_changed THEN
                RETURN NULL;
            END IF;

            PERFORM scope FROM authorization_state
            WHERE scope = 'global' FOR UPDATE;

            SELECT count(*) INTO holder_count
            FROM user_roles WHERE role_id = super_admin_role_id;
            IF holder_count = 0 THEN
                RAISE EXCEPTION 'the final super_admin assignment cannot be removed'
                    USING ERRCODE = '23514';
            END IF;
            IF holder_count > 1 THEN
                RAISE EXCEPTION 'only one super_admin assignment is allowed'
                    USING ERRCODE = '23505';
            END IF;
            RETURN NULL;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE CONSTRAINT TRIGGER ct_user_roles_exactly_one_super_admin
        AFTER INSERT OR UPDATE OR DELETE ON user_roles
        DEFERRABLE INITIALLY DEFERRED
        FOR EACH ROW EXECUTE FUNCTION enforce_exactly_one_super_admin()
        """
    )


def downgrade() -> None:
    connection = op.get_bind()
    connection.execute(
        sa.text(
            "SELECT scope FROM authorization_state WHERE scope = 'global' FOR UPDATE"
        )
    )

    op.execute(
        "DROP TRIGGER IF EXISTS ct_user_roles_exactly_one_super_admin ON user_roles"
    )
    op.execute("DROP FUNCTION IF EXISTS enforce_exactly_one_super_admin()")
    op.execute("DROP TRIGGER IF EXISTS ct_user_roles_require_base_role ON user_roles")
    op.execute("DROP TRIGGER IF EXISTS ct_users_require_base_role ON users")
    op.execute("DROP FUNCTION IF EXISTS enforce_user_base_role()")
    op.execute("DROP FUNCTION IF EXISTS assert_user_has_base_role(uuid)")
    op.execute("DROP TRIGGER IF EXISTS tr_roles_protect_system_definition ON roles")
    op.execute("DROP FUNCTION IF EXISTS protect_system_role_definition()")
    op.execute(
        "DROP TRIGGER IF EXISTS tr_role_permissions_protect_system_roles "
        "ON role_permissions"
    )
    op.execute("DROP FUNCTION IF EXISTS protect_system_role_permissions()")

    for name in (
        "user_role_shape",
        "admin_role_shape",
        "super_admin_role_shape",
        "owner_shape",
        "legacy_owner_role_key_reserved",
        "deleted_role_actor_requires_timestamp",
        "deleted_role_inactive",
        "system_role_always_available",
        "protected_role_is_system",
        "custom_role_tier_range",
    ):
        op.drop_constraint(name, "roles", type_="check")

    connection.execute(
        sa.text(
            "DELETE FROM user_roles USING roles "
            "WHERE user_roles.role_id = roles.id AND roles.key IN ('admin', 'user')"
        )
    )
    connection.execute(
        sa.text(
            "DELETE FROM role_permissions USING roles "
            "WHERE role_permissions.role_id = roles.id "
            "AND roles.key IN ('admin', 'user')"
        )
    )
    connection.execute(sa.text("DELETE FROM roles WHERE key IN ('admin', 'user')"))
    connection.execute(
        sa.text(
            "DELETE FROM role_permissions USING permissions "
            "WHERE role_permissions.permission_id = permissions.id "
            "AND permissions.key = ANY(:keys)"
        ),
        {"keys": [key for key, _description in NEW_PERMISSIONS]},
    )
    connection.execute(
        sa.text("DELETE FROM permissions WHERE key = ANY(:keys)"),
        {"keys": [key for key, _description in NEW_PERMISSIONS]},
    )
    connection.execute(
        sa.text(
            "UPDATE roles SET key = 'owner', name = 'Owner' "
            "WHERE key = 'super_admin' AND is_owner"
        )
    )

    op.create_check_constraint(
        "owner_shape",
        "roles",
        "NOT is_owner OR (is_system AND is_protected AND is_active "
        "AND management_tier = 1000)",
    )
    op.create_check_constraint(
        "system_protection_match", "roles", "is_system = is_protected"
    )
    op.drop_constraint("fk_roles_deleted_by_user_id_users", "roles", type_="foreignkey")
    op.drop_column("roles", "deleted_by_user_id")
    op.drop_column("roles", "deleted_at")
    op.drop_column("roles", "description")
