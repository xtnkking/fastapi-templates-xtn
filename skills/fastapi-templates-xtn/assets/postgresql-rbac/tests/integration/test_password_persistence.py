#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    集成验证密码哈希在用户表中的保存、删除与状态约束。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/30    XTN       V1.000        补充文件记录并移除临时密码状态测试
# 2026/10/10    XTN       V1.001        统一用户 ID 与当前用户命名
# 2026/10/22    XTN       V1.002        密码保存方法统一命名为 update_password
# --------------------------------------------------------------------------------------------------

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from app.core.ids import new_audit_id
from app.core.security.passwords import DUMMY_PASSWORD_HASH
from app.db.postgres_db import SessionFactory
from app.models.postgres.operation_audit import OperationAuditEvent
from app.models.postgres.user import User, UserRole
from app.repositories.postgres.user_repository import user_repository
from tests.integration.conftest import World

pytestmark = pytest.mark.postgresql


async def test_passwordless_user_has_no_password_state(world: World) -> None:
    async with SessionFactory() as session:
        user = await session.get(User, world.users["lower"].user_id)
    assert user is not None
    assert user.password_hash is None
    assert user.password_changed_at is None


async def test_rotation_updates_same_user_row(world: World) -> None:
    user_id = world.users["lower"].user_id
    initial_token_version = world.users["lower"].token_version
    async with SessionFactory() as session:
        async with session.begin():
            user = await session.get(User, user_id, with_for_update=True)
            assert user is not None
            await user_repository.update_password(
                session,
                user=user,
                password_hash=DUMMY_PASSWORD_HASH,
            )

    async with SessionFactory() as session:
        user = await session.get(User, user_id)
    assert user is not None
    assert user.password_hash == DUMMY_PASSWORD_HASH
    assert user.password_changed_at is not None
    assert user.token_version == initial_token_version


async def test_deleted_user_cannot_retain_password_hash(world: World) -> None:
    user_id = world.users["lower"].user_id
    changed_at = datetime.now(UTC)
    async with SessionFactory() as session:
        async with session.begin():
            user = await session.get(User, user_id, with_for_update=True)
            assert user is not None
            user.password_hash = DUMMY_PASSWORD_HASH
            user.password_changed_at = changed_at

    with pytest.raises(DBAPIError) as caught:
        async with SessionFactory() as session:
            async with session.begin():
                await session.execute(
                    text(
                        "UPDATE users SET deleted_at = :deleted_at, is_active = false "
                        "WHERE id = :user_id"
                    ),
                    {"deleted_at": changed_at, "user_id": user_id},
                )
    assert "ck_users_deleted_user_no_password" in str(caught.value)

    async with SessionFactory() as session:
        async with session.begin():
            await session.execute(
                text("SELECT scope FROM rbac_state WHERE scope = 'global' FOR UPDATE")
            )
            user = await session.get(User, user_id, with_for_update=True)
            assert user is not None
            user.password_hash = None
            user.password_changed_at = None
            user.is_active = False
            user.deleted_at = changed_at
            user.token_version += 1
            await session.execute(
                text(
                    "UPDATE user_roles SET deleted_at = :deleted_at, "
                    "deleted_by_user_id = :deleting_user_id "
                    "WHERE user_id = :user_id AND deleted_at IS NULL"
                ),
                {
                    "deleted_at": changed_at,
                    "deleting_user_id": world.users["super_admin"].user_id,
                    "user_id": user_id,
                },
            )

    async with SessionFactory() as session:
        deleted = await session.get(User, user_id)
        assert deleted is not None
        assert deleted.deleted_at is not None
        assert deleted.password_hash is None
        assert deleted.password_changed_at is None
        previous_bindings = (
            await session.scalars(select(UserRole).where(UserRole.user_id == user_id))
        ).all()
        assert {binding.role_id for binding in previous_bindings} == {
            world.roles["user"].id,
            world.roles["viewer"].id,
        }
        assert all(binding.deleted_at is not None for binding in previous_bindings)

    async with SessionFactory() as session:
        async with session.begin():
            await session.execute(
                text("SELECT scope FROM rbac_state WHERE scope = 'global' FOR UPDATE")
            )
            deleted = await session.get(User, user_id, with_for_update=True)
            assert deleted is not None
            deleted.deleted_at = None
            deleted.is_active = True
            session.add(UserRole(user_id=user_id, role_id=world.roles["user"].id))

    async with SessionFactory() as session:
        restored = await session.get(User, user_id)
    assert restored is not None
    assert restored.password_hash is None
    async with SessionFactory() as session:
        live_bindings = (
            await session.scalars(
                select(UserRole).where(
                    UserRole.user_id == user_id,
                    UserRole.deleted_at.is_(None),
                )
            )
        ).all()
    assert len(live_bindings) == 1
    assert live_bindings[0].role_id == world.roles["user"].id
    assert live_bindings[0].id not in {item.id for item in previous_bindings}


@pytest.mark.parametrize(
    "values",
    [
        {
            "password_hash": "not-an-argon2id-hash",
            "password_changed_at": datetime.now(UTC),
        },
        {
            "password_hash": DUMMY_PASSWORD_HASH,
            "password_changed_at": None,
        },
        {
            "password_hash": None,
            "password_changed_at": datetime.now(UTC),
        },
    ],
)
async def test_user_password_fields_reject_invalid_shapes(world: World, values: dict[str, object]) -> None:
    with pytest.raises(DBAPIError):
        async with SessionFactory() as session:
            async with session.begin():
                await session.execute(
                    text(
                        "UPDATE users SET password_hash = :password_hash, "
                        "password_changed_at = :password_changed_at "
                        "WHERE id = :user_id"
                    ),
                    {
                        "user_id": world.users["lower"].user_id,
                        "password_hash": values["password_hash"],
                        "password_changed_at": values["password_changed_at"],
                    },
                )


async def test_account_security_audit_rows_are_append_only(world: World) -> None:
    event_id = new_audit_id("OA")
    request_id = str(uuid.uuid4())
    async with SessionFactory() as session:
        async with session.begin():
            session.add(
                OperationAuditEvent(
                    id=event_id,
                    action="account_security.password.changed",
                    outcome="succeeded",
                    reason_code="password_changed",
                    category="account",
                    user_id=world.users["lower"].user_id,
                    target_user_id=world.users["lower"].user_id,
                    source="http",
                    request_id=request_id,
                )
            )

    for statement in (
        "UPDATE operation_audit_events SET reason_code = 'rewritten' "
        "WHERE id = :event_id",
        "DELETE FROM operation_audit_events WHERE id = :event_id",
        "TRUNCATE TABLE operation_audit_events",
    ):
        with pytest.raises(DBAPIError):
            async with SessionFactory() as session:
                async with session.begin():
                    parameters = (
                        {"event_id": event_id} if ":event_id" in statement else {}
                    )
                    await session.execute(text(statement), parameters)

    async with SessionFactory() as session:
        persisted = await session.get(OperationAuditEvent, event_id)
    assert persisted is not None
    assert persisted.request_id == request_id
