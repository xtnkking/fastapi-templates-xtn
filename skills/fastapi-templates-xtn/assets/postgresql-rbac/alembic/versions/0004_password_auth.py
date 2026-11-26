#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    保留第四版本地密码和账号安全审计历史迁移，说明密码状态、审计保护及重置权限变更。
#    历史注册开关和字段命名保持原文，迁移执行与回退仍由项目使用者管理。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/13    XTN       V1.000        完善历史密码迁移函数的通俗说明与步骤注释
# --------------------------------------------------------------------------------------------------

"""Add user-local password state and account-security audit.

Revision ID: 0004_password_auth
Revises: 0003_business_audit
"""

import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0004_password_auth"
down_revision: str | None = "0003_business_audit"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PASSWORD_RESET_PERMISSION_KEY = "users:password:reset"
PASSWORD_RESET_PERMISSION_DESCRIPTION = (
    "Reset the local password of a strictly lower user"
)
PASSWORD_RESET_SYSTEM_ROLES = ("admin", "super_admin")


def _permission_id(key: str) -> uuid.UUID:
    """
        沿用历史权限 ID 规则，为密码重置权限计算稳定标识。

    :param key: 完整权限键，本版本用于 users:password:reset。
    :return: 固定命名空间和权限前缀计算出的 UUID，不访问数据库。
    """
    # 相同权限键始终得到同一个 ID，便于按键更新已有目录记录。
    return uuid.uuid5(uuid.NAMESPACE_URL, f"fastapi-rbac-permission:{key}")


def upgrade() -> None:
    """
        应用第四版历史迁移，增加本地密码状态、账号安全审计及管理员密码重置权限。
        保留这个版本当时的注册开关和字段定义；变更使用 Alembic 外层事务，不自行提交。

    :return: 无返回值；成功时密码字段、审计表及保护、重置授权和关联权限版本已更新。
    """
    # 先锁全局授权状态，后续授予固定角色新权限和提升版本在同一迁移事务中完成。
    connection = op.get_bind()
    connection.execute(
        sa.text("SELECT scope FROM rbac_state WHERE scope = 'global' FOR UPDATE")
    )

    # 这是历史版本的注册开关字段，保留其原始定义，不推断当前产品仍有此开关。
    op.add_column(
        "rbac_state",
        sa.Column(
            "public_registration_enabled",
            sa.Boolean(),
            server_default=sa.text("true"),
            nullable=False,
        ),
    )

    # 给已有用户增加可为空的密码状态，再限制密码散列格式、时间一致性和删除后清空密码。
    op.add_column("users", sa.Column("password_hash", sa.String(512), nullable=True))
    op.add_column(
        "users",
        sa.Column(
            "must_change_password",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
    )
    op.add_column("users", sa.Column("password_changed_at", sa.DateTime(timezone=True)))
    op.create_check_constraint(
        op.f("ck_users_password_hash_shape"),
        "users",
        "password_hash IS NULL OR password_hash ~ "
        "'^\\$argon2id\\$v=19\\$m=[1-9][0-9]*,t=[1-9][0-9]*,"
        "p=[1-9][0-9]*\\$[A-Za-z0-9+/]{16,}\\$"
        "[A-Za-z0-9+/]{16,}$'",
    )
    op.create_check_constraint(
        op.f("ck_users_password_state_coherent"),
        "users",
        "(password_hash IS NULL AND password_changed_at IS NULL "
        "AND NOT must_change_password) OR "
        "(password_hash IS NOT NULL AND password_changed_at IS NOT NULL)",
    )
    op.create_check_constraint(
        op.f("ck_users_deleted_user_no_password"),
        "users",
        "deleted_at IS NULL OR password_hash IS NULL",
    )

    # 创建账号安全审计，约束操作、来源和操作者字段，防止不完整记录混入审计数据。
    op.create_table(
        "account_security_audit_events",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("action", sa.String(length=120), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("reason_code", sa.String(length=80), nullable=False),
        sa.Column("actor_type", sa.String(length=16), nullable=False),
        sa.Column("actor_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("target_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column(
            "schema_version",
            sa.SmallInteger(),
            server_default=sa.text("1"),
            nullable=False,
        ),
        sa.Column("request_id", sa.String(length=128), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("statement_timestamp()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "id::text ~ "
            "'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'",
            name=op.f("ck_account_security_audit_events_id_uuid4"),
        ),
        sa.CheckConstraint(
            "char_length(action) BETWEEN 20 AND 120 AND action ~ "
            "'^account_security\\.[a-z][a-z0-9_]*"
            "(\\.[a-z][a-z0-9_]*)+$'",
            name=op.f("ck_account_security_audit_events_action_format"),
        ),
        sa.CheckConstraint(
            "outcome IN ('succeeded', 'failed', 'denied')",
            name=op.f("ck_account_security_audit_events_outcome_valid"),
        ),
        sa.CheckConstraint(
            "char_length(reason_code) BETWEEN 2 AND 80 AND reason_code ~ "
            "'^[a-z][a-z0-9_]*$'",
            name=op.f("ck_account_security_audit_events_reason_code_format"),
        ),
        sa.CheckConstraint(
            "actor_type IN ('anonymous', 'user', 'operator', 'system')",
            name=op.f("ck_account_security_audit_events_actor_type_valid"),
        ),
        sa.CheckConstraint(
            "(actor_type = 'user' AND actor_user_id IS NOT NULL) OR "
            "(actor_type <> 'user' AND actor_user_id IS NULL)",
            name=op.f("ck_account_security_audit_events_actor_user_shape"),
        ),
        sa.CheckConstraint(
            "source IN ('http', 'service', 'job', 'operator', 'migration')",
            name=op.f("ck_account_security_audit_events_source_valid"),
        ),
        sa.CheckConstraint(
            "schema_version = 1",
            name=op.f("ck_account_security_audit_events_schema_version_one"),
        ),
        sa.CheckConstraint(
            "char_length(request_id) BETWEEN 1 AND 128 AND request_id ~ "
            "'^[A-Za-z0-9][A-Za-z0-9:._-]*$'",
            name=op.f("ck_account_security_audit_events_request_id_format"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_account_security_audit_events")),
    )
    # 为按时间、操作者、目标用户、请求和事件结果检索审计建立索引。
    op.create_index(
        "ix_account_security_audit_created",
        "account_security_audit_events",
        ["created_at", "id"],
    )
    op.create_index(
        "ix_account_security_audit_actor_created",
        "account_security_audit_events",
        ["actor_user_id", "created_at"],
        postgresql_where=sa.text("actor_user_id IS NOT NULL"),
    )
    op.create_index(
        "ix_account_security_audit_target_created",
        "account_security_audit_events",
        ["target_user_id", "created_at"],
        postgresql_where=sa.text("target_user_id IS NOT NULL"),
    )
    op.create_index(
        "ix_account_security_audit_request_id",
        "account_security_audit_events",
        ["request_id"],
    )
    op.create_index(
        "ix_account_security_audit_action_outcome_created",
        "account_security_audit_events",
        ["action", "outcome", "created_at"],
    )
    # 账号安全审计只追加，数据库触发器分别拦住改删已有记录和整表清空。
    op.execute(
        """
        CREATE FUNCTION reject_account_security_audit_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION 'account security audit events are append-only'
                USING ERRCODE = '55000';
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_account_security_audit_no_update_delete
        BEFORE UPDATE OR DELETE ON account_security_audit_events
        FOR EACH ROW
        EXECUTE FUNCTION reject_account_security_audit_mutation()
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_account_security_audit_no_truncate
        BEFORE TRUNCATE ON account_security_audit_events
        FOR EACH STATEMENT
        EXECUTE FUNCTION reject_account_security_audit_mutation()
        """
    )

    # 写入或恢复密码重置权限目录项，再把它授予本版本指定的两个系统管理角色。
    permission_table = sa.table(
        "permissions",
        sa.column("id", postgresql.UUID(as_uuid=True)),
        sa.column("key", sa.String()),
        sa.column("description", sa.Text()),
        sa.column("deleted_at", sa.DateTime(timezone=True)),
        sa.column("deleted_by_user_id", postgresql.UUID(as_uuid=True)),
    )
    insert_permission = postgresql.insert(permission_table).values(
        id=_permission_id(PASSWORD_RESET_PERMISSION_KEY),
        key=PASSWORD_RESET_PERMISSION_KEY,
        description=PASSWORD_RESET_PERMISSION_DESCRIPTION,
        deleted_at=None,
        deleted_by_user_id=None,
    )
    connection.execute(
        insert_permission.on_conflict_do_update(
            index_elements=[permission_table.c.key],
            set_={
                "description": insert_permission.excluded.description,
                "deleted_at": None,
                "deleted_by_user_id": None,
            },
        )
    )

    # 系统角色授权平时不可修改；迁移在本事务内暂时停用保护，补授权后立即恢复。
    op.execute(
        "ALTER TABLE role_permissions DISABLE TRIGGER "
        "tr_role_permissions_protect_system_roles"
    )
    connection.execute(
        sa.text(
            "INSERT INTO role_permissions "
            "(role_id, permission_id, assigned_by_user_id) "
            "SELECT roles.id, permissions.id, NULL "
            "FROM roles CROSS JOIN permissions "
            "WHERE roles.key = ANY(:role_keys) "
            "AND roles.is_system AND roles.deleted_at IS NULL "
            "AND permissions.key = :permission_key "
            "AND permissions.deleted_at IS NULL "
            "ON CONFLICT (role_id, permission_id) WHERE deleted_at IS NULL "
            "DO NOTHING"
        ),
        {
            "role_keys": list(PASSWORD_RESET_SYSTEM_ROLES),
            "permission_key": PASSWORD_RESET_PERMISSION_KEY,
        },
    )
    op.execute(
        "ALTER TABLE role_permissions ENABLE TRIGGER "
        "tr_role_permissions_protect_system_roles"
    )
    # 固定角色及相关用户的权限已变，提升各自版本并推进全局 epoch，标记旧授权状态过期。
    connection.execute(
        sa.text(
            "UPDATE roles SET version = version + 1 "
            "WHERE key = ANY(:role_keys) AND is_system AND deleted_at IS NULL"
        ),
        {"role_keys": list(PASSWORD_RESET_SYSTEM_ROLES)},
    )
    connection.execute(
        sa.text(
            "UPDATE users SET authz_version = authz_version + 1 "
            "WHERE deleted_at IS NULL AND EXISTS ("
            "SELECT 1 FROM user_roles JOIN roles ON roles.id = user_roles.role_id "
            "WHERE user_roles.user_id = users.id "
            "AND user_roles.deleted_at IS NULL "
            "AND roles.key = ANY(:role_keys) AND roles.deleted_at IS NULL)"
        ),
        {"role_keys": list(PASSWORD_RESET_SYSTEM_ROLES)},
    )
    connection.execute(
        sa.text("UPDATE rbac_state SET epoch = epoch + 1 WHERE scope = 'global'")
    )


def downgrade() -> None:
    """
        回退第四版历史迁移，移除密码状态、密码重置授权和账号安全审计结构。
        回退会丢弃密码字段及账号安全审计表内的数据；事务由 Alembic 外层管理。

    :return: 无返回值；成功时本版本字段、权限关系和审计保护已移除，关联权限版本已提升。
    """
    # 先锁全局状态，再拆除密码约束和字段；避免先变更用户数据产生延迟触发器待处理事件。
    connection = op.get_bind()
    connection.execute(
        sa.text("SELECT scope FROM rbac_state WHERE scope = 'global' FOR UPDATE")
    )
    # ALTER TABLE 放在后面的用户版本更新之前，保留历史迁移原有的执行顺序。
    op.drop_constraint(
        op.f("ck_users_deleted_user_no_password"), "users", type_="check"
    )
    op.drop_constraint(op.f("ck_users_password_state_coherent"), "users", type_="check")
    op.drop_constraint(op.f("ck_users_password_hash_shape"), "users", type_="check")
    op.drop_column("users", "password_changed_at")
    op.drop_column("users", "must_change_password")
    op.drop_column("users", "password_hash")
    op.drop_column("rbac_state", "public_registration_enabled")
    # 撤销重置能力前提升相关用户和固定角色的权限版本，让旧权限状态失效。
    connection.execute(
        sa.text(
            "UPDATE users SET authz_version = authz_version + 1 "
            "WHERE deleted_at IS NULL AND EXISTS ("
            "SELECT 1 FROM user_roles JOIN roles ON roles.id = user_roles.role_id "
            "WHERE user_roles.user_id = users.id "
            "AND user_roles.deleted_at IS NULL "
            "AND roles.key = ANY(:role_keys) AND roles.deleted_at IS NULL)"
        ),
        {"role_keys": list(PASSWORD_RESET_SYSTEM_ROLES)},
    )
    connection.execute(
        sa.text(
            "UPDATE roles SET version = version + 1 "
            "WHERE key = ANY(:role_keys) AND is_system AND deleted_at IS NULL"
        ),
        {"role_keys": list(PASSWORD_RESET_SYSTEM_ROLES)},
    )
    # 暂时停用系统角色授权保护，只删除本版本重置权限的关系，然后恢复保护并删除目录项。
    op.execute(
        "ALTER TABLE role_permissions DISABLE TRIGGER "
        "tr_role_permissions_protect_system_roles"
    )
    connection.execute(
        sa.text(
            "DELETE FROM role_permissions USING permissions "
            "WHERE role_permissions.permission_id = permissions.id "
            "AND permissions.key = :permission_key"
        ),
        {"permission_key": PASSWORD_RESET_PERMISSION_KEY},
    )
    op.execute(
        "ALTER TABLE role_permissions ENABLE TRIGGER "
        "tr_role_permissions_protect_system_roles"
    )
    connection.execute(
        sa.text("DELETE FROM permissions WHERE key = :permission_key"),
        {"permission_key": PASSWORD_RESET_PERMISSION_KEY},
    )
    connection.execute(
        sa.text("UPDATE rbac_state SET epoch = epoch + 1 WHERE scope = 'global'")
    )

    # 最后按触发器、保护函数、审计表的依赖顺序移除账号安全审计结构。
    op.execute(
        "DROP TRIGGER IF EXISTS trg_account_security_audit_no_truncate "
        "ON account_security_audit_events"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS trg_account_security_audit_no_update_delete "
        "ON account_security_audit_events"
    )
    op.execute("DROP FUNCTION IF EXISTS reject_account_security_audit_mutation()")
    op.drop_table("account_security_audit_events")
