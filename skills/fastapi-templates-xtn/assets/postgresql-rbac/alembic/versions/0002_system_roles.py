#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    保留第二版固定系统角色历史迁移，说明角色生命周期、初始授权和数据库保护规则。
#    迁移执行与回退由项目使用者管理，不自动运行或重新生成此历史版本。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/13    XTN       V1.000        完善历史系统角色迁移函数的通俗说明与步骤注释
# --------------------------------------------------------------------------------------------------

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
    ("users:sessions:revoke", "End every login of a strictly lower user"),
    ("users:create", "Create a user with the mandatory base role"),
    ("registration:configure", "Change the public registration switch"),
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
        "users:read",
        "users:create",
        "users:status:update",
        "users:sessions:revoke",
        "registration:configure",
        "projects:read",
        "projects:update",
    }
)
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
        "users:create",
        "users:status:update",
        "users:sessions:revoke",
        "projects:read",
        "projects:update",
    }
)
USER_PERMISSION_KEYS: frozenset[str] = frozenset()

SYSTEM_ROLE_SPECS: dict[str, dict[str, Any]] = {
    "super_admin": {
        "name": "Super administrator",
        "description": "Sole protected administrator for the application",
        "management_tier": 1000,
        "is_protected": True,
        "is_super_admin": True,
        "permissions": SUPER_ADMIN_PERMISSION_KEYS,
    },
    "admin": {
        "name": "Administrator",
        "description": "Built-in administrator for strictly lower authority",
        "management_tier": 500,
        "is_protected": False,
        "is_super_admin": False,
        "permissions": ADMIN_PERMISSION_KEYS,
    },
    "user": {
        "name": "User",
        "description": "Mandatory lowest-authority role for every user",
        "management_tier": 0,
        "is_protected": False,
        "is_super_admin": False,
        "permissions": USER_PERMISSION_KEYS,
    },
}


def _permission_id(key: str) -> uuid.UUID:
    """
        根据权限键计算固定权限 ID，让第二版新增目录与第一版使用同一套标识规则。

    :param key: 要加入权限目录的完整权限键。
    :return: 由权限专用前缀和固定命名空间生成的 UUID，不读取数据库。
    """
    # 保持权限 ID 计算规则不变，同一权限键在各历史迁移中仍对应相同 ID。
    return uuid.uuid5(uuid.NAMESPACE_URL, f"fastapi-rbac-permission:{key}")


def _system_role_id(key: str) -> uuid.UUID:
    """
        为固定系统角色计算可重复的 ID，避免每次初始写入产生不同标识。

    :param key: 系统角色键，取自本版本的 SYSTEM_ROLE_SPECS。
    :return: 由角色专用前缀和固定命名空间生成的 UUID，不读取数据库。
    """
    # 用不同于权限 ID 的前缀，区分两类对象的固定标识。
    return uuid.uuid5(uuid.NAMESPACE_URL, f"fastapi-rbac-system-role:{key}")


def _uuid_value(value: object) -> uuid.UUID:
    """
        确认数据库返回的系统角色 ID 是 UUID，防止错误结果继续参与初始授权。

    :param value: PostgreSQL 查询结果中的角色 ID 原值。
    :return: 已确认类型的原始 UUID，不转换字符串或其他类型。
    :raises RuntimeError: 查询结果不是 UUID，无法继续安全使用角色 ID。
    """
    # 对驱动返回值作明确类型检查，不静默猜测或重新生成角色 ID。
    if not isinstance(value, uuid.UUID):
        raise RuntimeError("expected PostgreSQL UUID value while seeding system roles")
    return value


def _role_by_key(connection: sa.Connection, key: str) -> sa.RowMapping | None:
    """
        按角色键读取已有定义，供迁移判断系统角色是否存在或发生键冲突。
        查询不加软删除过滤，也不提交事务，使用外层 Alembic 的连接。

    :param connection: 当前迁移事务使用的 SQLAlchemy 同步连接。
    :param key: 要精确匹配的角色键。
    :return: 已有角色的字段映射；没有同键角色时返回 None。
    """
    # 初始迁移要识别任何同键定义，所以只按键匹配，不把冲突角色隐藏掉。
    return (
        connection.execute(
            sa.text(
                "SELECT id, key, name, management_tier, is_active, is_protected, "
                "is_system, is_super_admin FROM roles WHERE key = :key"
            ),
            {"key": key},
        )
        .mappings()
        .one_or_none()
    )


def _insert_system_role(connection: sa.Connection, *, key: str, role_id: uuid.UUID) -> None:
    """
        将一项固定系统角色写入当前迁移事务，名称、等级和保护标记来自本版本定义。
        不自行提交事务，迁移失败时由外层事务决定回滚。

    :param connection: 当前迁移事务使用的 SQLAlchemy 同步连接。
    :param key: 本版本已定义的系统角色键。
    :param role_id: 由调用方计算的系统角色固定 ID。
    :return: 无返回值；角色已通过当前连接写入，事务尚由外层管理。
    """
    # 从同一份固定定义取字段，避免系统角色等级和保护标记在初始数据中彼此不一致。
    spec = SYSTEM_ROLE_SPECS[key]
    connection.execute(
        sa.text(
            "INSERT INTO roles "
            "(id, key, name, description, management_tier, is_active, "
            "is_protected, is_system, is_super_admin, version) VALUES "
            "(:id, :key, :name, :description, :management_tier, true, "
            ":is_protected, true, :is_super_admin, 0)"
        ),
        {
            "id": role_id,
            "key": key,
            "name": spec["name"],
            "description": spec["description"],
            "management_tier": spec["management_tier"],
            "is_protected": spec["is_protected"],
            "is_super_admin": spec["is_super_admin"],
        },
    )


def _ensure_system_role(connection: sa.Connection, *, key: str) -> uuid.UUID:
    """
        为固定系统角色创建缺失记录，或确认已有定义符合系统角色要求后更新展示文本。
        同键普通角色不会被悄悄改成系统角色；使用外层迁移事务，不自行提交。

    :param connection: 当前迁移事务使用的 SQLAlchemy 同步连接。
    :param key: 本版本已定义的系统角色键。
    :return: 新建或已经存在的系统角色 UUID。
    :raises RuntimeError: 同键角色的等级、启用或保护标记不符合固定定义，或已有 ID 不是 UUID。
    """
    # 先查同键记录；没有时用固定 ID 创建，有时继续验证其身份而不是直接覆盖。
    existing = _role_by_key(connection, key)
    if existing is None:
        role_id = _system_role_id(key)
        _insert_system_role(connection, key=key, role_id=role_id)
        return role_id

    # 已有记录必须与系统身份一致；只有名称和说明允许在此迁移中更新。
    spec = SYSTEM_ROLE_SPECS[key]
    expected = {
        "management_tier": spec["management_tier"],
        "is_active": True,
        "is_protected": spec["is_protected"],
        "is_system": True,
        "is_super_admin": spec["is_super_admin"],
    }
    if any(existing[field] != value for field, value in expected.items()):
        raise RuntimeError(
            f"role key {key!r} already exists with a non-system shape; "
            "resolve the collision before upgrading"
        )
    # 核验通过后同步可展示文本，保留原角色 ID 和权限版本。
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


def _replace_system_role_grants(connection: sa.Connection, *, role_id: uuid.UUID,
                                permission_keys: frozenset[str]) -> None:
    """
        把系统角色的有效授权调整为指定权限全集，先确认目录齐全再撤销多余授权并补齐缺失授权。
        被撤销的关系保留软删除历史；本函数使用迁移事务，不自行提交。

    :param connection: 当前迁移事务使用的 SQLAlchemy 同步连接。
    :param role_id: 要写入固定授权的系统角色 ID。
    :param permission_keys: 角色应拥有的完整权限键集合；空集合表示撤销全部有效授权。
    :return: 无返回值；有效授权已在当前事务中调整为指定集合。
    :raises RuntimeError: 指定权限键在未删除的权限目录中有缺失，不能继续调整授权。
    """
    # 一次读取所需的未删除权限；先发现缺失，避免只写入一部分固定授权。
    rows = (
        connection.execute(
            sa.text(
                "SELECT id, key FROM permissions "
                "WHERE key = ANY(:keys) AND deleted_at IS NULL"
            ),
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

    # 先软删除集合之外的有效关系；空集合走单独分支，把所有有效授权撤掉。
    desired_permission_ids = list(permission_ids.values())
    if desired_permission_ids:
        connection.execute(
            sa.text(
                "UPDATE role_permissions "
                "SET deleted_at = now(), deleted_by_user_id = NULL "
                "WHERE role_id = :role_id AND deleted_at IS NULL "
                "AND NOT (permission_id = ANY(:permission_ids))"
            ),
            {
                "role_id": role_id,
                "permission_ids": desired_permission_ids,
            },
        )
    else:
        connection.execute(
            sa.text(
                "UPDATE role_permissions "
                "SET deleted_at = now(), deleted_by_user_id = NULL "
                "WHERE role_id = :role_id AND deleted_at IS NULL"
            ),
            {"role_id": role_id},
        )
    # 按稳定顺序补齐应有授权，部分唯一约束冲突时保留已有有效关系。
    if permission_keys:
        connection.execute(
            sa.text(
                "INSERT INTO role_permissions (role_id, permission_id) "
                "VALUES (:role_id, :permission_id) "
                "ON CONFLICT (role_id, permission_id) WHERE deleted_at IS NULL "
                "DO NOTHING"
            ),
            [
                {
                    "role_id": role_id,
                    "permission_id": permission_ids[key],
                }
                for key in sorted(permission_keys)
            ],
        )


def upgrade() -> None:
    """
        应用第二版历史迁移，加入固定系统角色、角色软删除信息和用户基础角色保护。
        先锁全局授权状态，完成初始数据调整后再安装不可变定义和延迟检查触发器。

    :return: 无返回值；成功时本版本的角色结构、固定授权、基础角色关系与数据库保护已建立。
    :raises RuntimeError: 系统角色键发生不兼容冲突，或固定授权所需的权限目录不完整。
    """
    # 先复用 Alembic 连接并锁全局状态，避免初始授权写入与其他授权变更交错。
    connection = op.get_bind()
    connection.execute(
        sa.text("SELECT scope FROM rbac_state WHERE scope = 'global' FOR UPDATE")
    )

    # 补齐角色说明和软删除信息，移除旧版把系统身份与保护标记强行等同的约束。
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
    op.create_index("ix_roles_deleted_at", "roles", ["deleted_at"])
    op.drop_constraint("system_protection_match", "roles", type_="check")

    # 写入新增权限，遇到已有同键记录时更新说明并恢复为有效目录项。
    permission_table = sa.table(
        "permissions",
        sa.column("id", postgresql.UUID(as_uuid=True)),
        sa.column("key", sa.String()),
        sa.column("description", sa.Text()),
        sa.column("deleted_at", sa.DateTime(timezone=True)),
        sa.column("deleted_by_user_id", postgresql.UUID(as_uuid=True)),
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
            set_={
                "description": insert_permissions.excluded.description,
                "deleted_at": None,
                "deleted_by_user_id": None,
            },
        )
    )

    # 确认三个固定系统角色的定义，再逐个把有效授权调整为该版本规定的全集。
    role_ids = {
        key: _ensure_system_role(connection, key=key) for key in SYSTEM_ROLE_SPECS
    }
    for key, role_id in role_ids.items():
        spec = SYSTEM_ROLE_SPECS[key]
        _replace_system_role_grants(
            connection,
            role_id=role_id,
            permission_keys=spec["permissions"],
        )

    # 给所有未删除用户补基础 user 角色；只给实际新增了关系的用户提升权限版本。
    inserted_user_ids = list(
        connection.scalars(
            sa.text(
                "INSERT INTO user_roles "
                "(user_id, role_id, assigned_by_user_id) "
                "SELECT users.id, :role_id, NULL FROM users "
                "WHERE users.deleted_at IS NULL "
                "ON CONFLICT (user_id, role_id) WHERE deleted_at IS NULL "
                "DO NOTHING RETURNING user_id"
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
        sa.text("UPDATE rbac_state SET epoch = epoch + 1 WHERE scope = 'global'")
    )

    # 初始数据就绪后安装角色等级、可用性和各固定角色形状的数据库约束。
    op.create_check_constraint(
        "custom_role_tier_range",
        "roles",
        "is_system OR (management_tier >= 1 AND management_tier <= 999)",
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
    op.drop_constraint("super_admin_flag_shape", "roles", type_="check")
    op.create_check_constraint(
        "super_admin_flag_shape",
        "roles",
        "NOT is_super_admin OR (is_system AND is_protected AND is_active "
        "AND management_tier = 1000 AND key = 'super_admin' "
        "AND deleted_at IS NULL)",
    )
    op.create_check_constraint(
        "super_admin_role_shape",
        "roles",
        "key <> 'super_admin' OR (is_system AND is_protected AND is_super_admin "
        "AND is_active AND management_tier = 1000 AND deleted_at IS NULL)",
    )
    op.create_check_constraint(
        "admin_role_shape",
        "roles",
        "key <> 'admin' OR (is_system AND NOT is_protected AND NOT is_super_admin "
        "AND is_active AND management_tier = 500 AND deleted_at IS NULL)",
    )
    op.create_check_constraint(
        "user_role_shape",
        "roles",
        "key <> 'user' OR (is_system AND NOT is_protected AND NOT is_super_admin "
        "AND is_active AND management_tier = 0 AND deleted_at IS NULL)",
    )

    # 固定角色定义和授权不可由普通更新改写；下面的触发器在直接数据库写入时也生效。
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
                NEW.is_super_admin IS DISTINCT FROM OLD.is_super_admin OR
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
    # 基础角色检查延迟到事务末，让创建用户和分配 user 角色可以在同一事务完成。
    op.execute(
        """
        CREATE FUNCTION assert_user_has_base_role(candidate_user_id uuid)
        RETURNS void LANGUAGE plpgsql AS $$
        BEGIN
            PERFORM scope FROM rbac_state
            WHERE scope = 'global' FOR UPDATE;
            IF EXISTS (
                SELECT 1 FROM users
                WHERE id = candidate_user_id AND deleted_at IS NULL
            )
               AND NOT EXISTS (
                   SELECT 1 FROM user_roles ur
                   JOIN roles r ON r.id = ur.role_id
                   WHERE ur.user_id = candidate_user_id
                     AND ur.deleted_at IS NULL
                     AND r.key = 'user'
                     AND r.deleted_at IS NULL
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
    # 超管关系变动在事务末检查，既禁止移除最后一位持有人，也禁止同时保留多位。
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
            FROM roles
            WHERE key = 'super_admin' AND deleted_at IS NULL;

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

            PERFORM scope FROM rbac_state
            WHERE scope = 'global' FOR UPDATE;

            SELECT count(*) INTO holder_count
            FROM user_roles
            WHERE role_id = super_admin_role_id AND deleted_at IS NULL;
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
    """
        回退第二版历史迁移，移除系统角色保护、固定角色及新增权限，再恢复第一版角色结构。
        会删除本版本角色及其授权关系；执行和事务管理仍由项目使用者的 Alembic 命令负责。

    :return: 无返回值；成功时本版本的初始数据、数据库保护和新增角色字段已移除。
    """
    # 先锁全局状态并结算待处理的用户基础角色检查，再拆除会阻止回退的触发器。
    connection = op.get_bind()
    connection.execute(
        sa.text("SELECT scope FROM rbac_state WHERE scope = 'global' FOR UPDATE")
    )
    connection.execute(sa.text("SET CONSTRAINTS ct_users_require_base_role IMMEDIATE"))

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

    # 移除第二版固定形状及软删除约束，后续清理数据和字段时不再受这些检查阻挡。
    for name in (
        "user_role_shape",
        "admin_role_shape",
        "super_admin_role_shape",
        "super_admin_flag_shape",
        "deleted_role_actor_requires_timestamp",
        "deleted_role_inactive",
        "system_role_always_available",
        "protected_role_is_system",
        "custom_role_tier_range",
    ):
        op.drop_constraint(name, "roles", type_="check")

    op.drop_index("ix_roles_deleted_at", table_name="roles")

    # 先清理引用系统角色的关系，再删除角色；新增权限也先清理关系后删除目录项。
    connection.execute(
        sa.text(
            "DELETE FROM user_roles USING roles "
            "WHERE user_roles.role_id = roles.id "
            "AND roles.key IN ('super_admin', 'admin', 'user')"
        )
    )
    connection.execute(
        sa.text(
            "DELETE FROM role_permissions USING roles "
            "WHERE role_permissions.role_id = roles.id "
            "AND roles.key IN ('super_admin', 'admin', 'user')"
        )
    )
    connection.execute(
        sa.text("DELETE FROM roles WHERE key IN ('super_admin', 'admin', 'user')")
    )
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
    # 恢复第一版角色约束后，移除第二版增加的外键和三个字段。
    op.create_check_constraint(
        "super_admin_flag_shape",
        "roles",
        "NOT is_super_admin OR (is_system AND is_protected AND is_active "
        "AND management_tier = 1000)",
    )
    op.create_check_constraint(
        "system_protection_match", "roles", "is_system = is_protected"
    )
    op.drop_constraint("fk_roles_deleted_by_user_id_users", "roles", type_="foreignkey")
    op.drop_column("roles", "deleted_by_user_id")
    op.drop_column("roles", "deleted_at")
    op.drop_column("roles", "description")
