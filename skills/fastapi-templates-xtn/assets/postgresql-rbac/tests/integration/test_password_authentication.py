#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    在已准备的 PostgreSQL 和 Redis 中验证本地密码认证流程
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/29    XTN       V1.000        补充文件记录并使集成测试密码符合可见 ASCII 规则
# 2026/09/30    XTN       V1.001        管理员重置与线下恢复改为直接登录密码
# 2026/10/02    XTN       V1.002        线下恢复改用仅供维护命令调用的服务
# 2026/10/09    XTN       V1.003        现行注册集成测试名称统一使用 register
# 2026/10/10    XTN       V1.004        统一用户 ID 与当前用户命名
# 2026/10/16    XTN       V1.005        登录集成调用统一使用 AuthService.login 业务名称
# 2026/10/16    XTN       V1.006        并发哈希升级只允许首个登录成功，其余直接拒绝
# 2026/10/16    XTN       V1.007        直接登录调用传入 Redis 与配置并校验返回令牌
# 2026/10/24    XTN       V1.008        验证码场景名称明确具体用户操作
# --------------------------------------------------------------------------------------------------

import asyncio
import secrets
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import cast

import pytest
from argon2 import PasswordHasher
from argon2.low_level import Type
from httpx import AsyncClient
from sqlalchemy import select, text

from app.commands.operator_password_service import OperatorPasswordService
from app.core.config import get_settings
from app.core.exceptions import AppError, InvalidLoginCredentialsError
from app.core.security.passwords import PasswordManager, password_manager
from app.db.postgres_db import SessionFactory
from app.main import app
from app.models.postgres.operation_audit import OperationAuditEvent
from app.models.postgres.role import Role
from app.models.postgres.user import User, UserRole
from app.services.auth_service import AuthService
from tests.integration.conftest import World

PASSWORD = "correct-horse-battery-staple-47"
NEW_PASSWORD = "quiet-river-lantern-mountain-82"
ADMIN_PASSWORD = "meadow-compass-stone-63"
pytestmark = pytest.mark.postgresql


@pytest.fixture(autouse=True)
def known_captcha_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(secrets, "choice", lambda _alphabet: "A")


async def _captcha(client: AsyncClient, scene: str, token: str | None = None) -> dict[str, str]:
    endpoint = "/api/v1/auth/captcha" if token is None else "/api/v1/me/captcha"
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    response = await client.post(endpoint, json={"scene": scene}, headers=headers)
    assert response.status_code == 200, response.text
    return {
        "captcha_id": response.json()["data"]["captcha_id"],
        "captcha_answer": "AAAAA",
    }


class _ConcurrentRehashPasswordManager(PasswordManager):
    def __init__(self) -> None:
        super().__init__()
        self._rehash_barrier = asyncio.Barrier(2)
        self.rehash_calls = 0

    async def hash_verified_password(self, password: str) -> str:
        replacement = await super().hash_verified_password(password)
        self.rehash_calls += 1
        await self._rehash_barrier.wait()
        return replacement


async def _register(client: AsyncClient, user_name: str, password: str) -> uuid.UUID:
    response = await client.post(
        "/api/v1/auth/register",
        json={
            "user_name": user_name,
            "password": password,
            **await _captcha(client, "register"),
        },
    )
    assert response.status_code == 201, response.text
    return uuid.UUID(cast(str, response.json()["data"]["user_id"]))


async def _login(client: AsyncClient, user_name: str, password: str) -> str:
    response = await client.post(
        "/api/v1/auth/login",
        json={
            "user_name": user_name,
            "password": password,
            **await _captcha(client, "login"),
        },
    )
    assert response.status_code == 200, response.text
    return cast(str, response.json()["data"]["access_token"])


async def _enroll_existing_user(user: User, *, user_name: str, password: str) -> None:
    password_hash = await password_manager.hash_new_password(
        password,
        user_name=user_name,
    )
    async with SessionFactory() as session:
        async with session.begin():
            stored = await session.scalar(
                select(User).where(User.user_id == user.user_id).with_for_update()
            )
            assert stored is not None
            stored.user_name = user_name
            stored.password_hash = password_hash
            stored.password_changed_at = datetime.now(UTC)


async def _replace_live_super_admin_holders(world: World, holder_names: tuple[str, ...]) -> None:
    """Create a deliberately corrupt holder set to exercise the operator guard."""

    role_id = world.roles["super_admin"].id
    user_id = world.users["super_admin"].user_id
    async with SessionFactory() as session:
        async with session.begin():
            await session.execute(
                text(
                    "ALTER TABLE user_roles DISABLE TRIGGER "
                    "ct_user_roles_exactly_one_super_admin"
                )
            )
    try:
        async with SessionFactory() as session:
            async with session.begin():
                await session.execute(
                    text(
                        "UPDATE user_roles "
                        "SET deleted_at = statement_timestamp(), "
                        "deleted_by_user_id = :user_id "
                        "WHERE role_id = :role_id AND deleted_at IS NULL"
                    ),
                    {"user_id": user_id, "role_id": role_id},
                )
                session.add_all(
                    UserRole(
                        user_id=world.users[name].user_id,
                        role_id=role_id,
                        bound_by_user_id=user_id,
                    )
                    for name in holder_names
                )
    finally:
        # PostgreSQL cannot alter the table after queued trigger events in the
        # same transaction; restore protection even when the corrupt setup fails.
        async with SessionFactory() as session:
            async with session.begin():
                await session.execute(
                    text(
                        "ALTER TABLE user_roles ENABLE TRIGGER "
                        "ct_user_roles_exactly_one_super_admin"
                    )
                )


async def test_register_and_login_persist_complete_local_identity(client: AsyncClient) -> None:
    user_id = await _register(client, "  Alice  ", PASSWORD)
    access_token = await _login(client, "Alice", PASSWORD)

    assert access_token
    async with SessionFactory() as session:
        user = await session.scalar(select(User).where(User.user_id == user_id))
        assert user is not None
        assert user.user_name == "Alice"
        assert user.password_hash is not None
        assert user.password_hash.startswith("$argon2id$")
        assert user.password_changed_at is not None
        role_key = await session.scalar(
            select(Role.key)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(
                UserRole.user_id == user.user_id,
                UserRole.deleted_at.is_(None),
            )
        )
        assert role_key == "user"
        account_event = await session.scalar(
            select(OperationAuditEvent).where(
                OperationAuditEvent.target_user_id == user.user_id
            )
        )
        assert account_event is not None
        assert account_event.action == "account_security.registration.completed"


async def test_concurrent_legacy_hash_upgrade_rejects_the_conflicting_login(world: World,
                                                                            client: AsyncClient) -> None:
    user_id = world.users["lower"].user_id
    user_name = "concurrent_rehash"
    legacy_hasher = PasswordHasher(
        time_cost=2,
        memory_cost=32_768,
        parallelism=2,
        hash_len=32,
        salt_len=16,
        type=Type.ID,
    )
    legacy_hash = await asyncio.to_thread(legacy_hasher.hash, PASSWORD)
    changed_at = datetime.now(UTC)

    async with SessionFactory() as session:
        async with session.begin():
            user = await session.get(User, user_id, with_for_update=True)
            assert user is not None
            user.user_name = user_name
            token_version = user.token_version
            user.password_hash = legacy_hash
            user.password_changed_at = changed_at

    manager = _ConcurrentRehashPasswordManager()
    service = AuthService(SessionFactory, manager)
    async with asyncio.timeout(30):
        results = await asyncio.gather(
            service.login(
                redis=app.state.redis,
                settings=get_settings(),
                user_name=user_name,
                password=PASSWORD,
            ),
            service.login(
                redis=app.state.redis,
                settings=get_settings(),
                user_name=user_name,
                password=PASSWORD,
            ),
            return_exceptions=True,
        )

    # 两次请求都在锁外完成旧密码校验；首个保存升级结果，后一个发现哈希已变就拒绝。
    successes = [result for result in results if not isinstance(result, BaseException)]
    failures = [result for result in results if isinstance(result, BaseException)]
    assert len(successes) == len(failures) == 1
    assert successes[0].user_id == user_id
    assert successes[0].access_token
    assert successes[0].expires_in == get_settings().jwt_access_token_ttl_seconds
    assert isinstance(failures[0], InvalidLoginCredentialsError)
    assert manager.rehash_calls == 2
    async with SessionFactory() as session:
        user = await session.get(User, user_id)
    assert user is not None
    assert user.password_changed_at == changed_at
    assert user.token_version == token_version
    assert user.password_hash is not None
    assert user.password_hash != legacy_hash
    verification = await password_manager.verify_or_dummy(
        PASSWORD,
        user.password_hash,
    )
    assert verification.verified is True
    assert verification.needs_rehash is False


async def test_unknown_wrong_and_passwordless_logins_share_one_response(client: AsyncClient, world: World) -> None:
    await _register(client, "alice", PASSWORD)
    responses = [
        await client.post(
            "/api/v1/auth/login",
            json={
                "user_name": "alice",
                "password": NEW_PASSWORD,
                **await _captcha(client, "login"),
            },
        ),
        await client.post(
            "/api/v1/auth/login",
            json={
                "user_name": "unknown",
                "password": NEW_PASSWORD,
                **await _captcha(client, "login"),
            },
        ),
        await client.post(
            "/api/v1/auth/login",
            json={
                "user_name": "passwordless",
                "password": NEW_PASSWORD,
                **await _captcha(client, "login"),
            },
        ),
    ]
    async with SessionFactory() as session:
        passwordless = await session.get(User, world.users["blank"].user_id)
        assert passwordless is not None
        passwordless.user_name = "passwordless"
        await session.commit()

    # Re-run after the passwordless identity exists; it must still look unknown.
    responses[-1] = await client.post(
        "/api/v1/auth/login",
        json={
            "user_name": "passwordless",
            "password": NEW_PASSWORD,
            **await _captcha(client, "login"),
        },
    )
    public_shapes = []
    for response in responses:
        assert response.status_code == 401
        body = response.json()
        assert body["code"] == 40110
        assert body["data"] is None
        assert response.headers["WWW-Authenticate"] == "Bearer"
        public_shapes.append((body["code"], body["message"], body["data"]))
    assert len(set(public_shapes)) == 1


async def test_self_password_change_updates_user_and_revokes_old_token(client: AsyncClient) -> None:
    user_id = await _register(client, "alice", PASSWORD)
    old_token = await _login(client, "alice", PASSWORD)
    async with SessionFactory() as session:
        before = await session.get(User, user_id)
        assert before is not None
        old_hash = before.password_hash
        old_changed_at = before.password_changed_at
        old_token_version = before.token_version

    changed = await client.post(
        "/api/v1/me/password/change",
        headers={"Authorization": f"Bearer {old_token}"},
        json={
            "current_password": PASSWORD,
            "new_password": NEW_PASSWORD,
            **await _captcha(client, "user_change_password", old_token),
        },
    )
    assert changed.status_code == 200, changed.text
    assert changed.json()["data"] is None

    revoked = await client.get(
        "/api/v1/me/user_info",
        headers={"Authorization": f"Bearer {old_token}"},
    )
    assert revoked.status_code == 401
    wrong_old = await client.post(
        "/api/v1/auth/login",
        json={
            "user_name": "alice",
            "password": PASSWORD,
            **await _captcha(client, "login"),
        },
    )
    assert wrong_old.status_code == 401
    assert await _login(client, "alice", NEW_PASSWORD)

    async with SessionFactory() as session:
        after = await session.get(User, user_id)
        assert after is not None
        assert after.password_hash is not None
        assert after.password_hash != old_hash
        assert after.password_changed_at is not None
        assert old_changed_at is not None
        assert after.password_changed_at >= old_changed_at
        assert after.token_version == old_token_version + 1


async def test_admin_reset_sets_a_directly_usable_password(
    client: AsyncClient,
    world: World,
    access_token: Callable[[User], Awaitable[str]],
) -> None:
    manager_password = "silver-orchard-window-planet-94"
    await _enroll_existing_user(
        world.users["manager"],
        user_name="manager",
        password=manager_password,
    )
    manager_token = await access_token(world.users["manager"])
    target_id = await _register(client, "target", PASSWORD)
    old_target_token = await _login(client, "target", PASSWORD)
    try:
        missing_captcha = await client.post(
            '/api/v1/users/password/reset',
            headers={"Authorization": f"Bearer {manager_token}"},
            json={"user_id": str(target_id), "new_password": ADMIN_PASSWORD},
        )
        assert missing_captcha.status_code == 422
        assert await _login(client, "target", PASSWORD)

        reset = await client.post(
            '/api/v1/users/password/reset',
            headers={"Authorization": f"Bearer {manager_token}"},
            json={"user_id": str(target_id),
                  "new_password": ADMIN_PASSWORD,
                  **await _captcha(client, "admin_reset_user_password", manager_token),
                  },
        )
        assert reset.status_code == 200, reset.text
        assert reset.json()["message"] == "密码重置成功"
        async with SessionFactory() as session:
            reset_user = await session.get(User, target_id)
            reset_event = await session.scalar(
                select(OperationAuditEvent).where(
                    OperationAuditEvent.target_user_id == target_id,
                    OperationAuditEvent.action
                    == "account_security.password.admin_reset",
                )
            )
        assert reset_user is not None
        assert reset_user.password_hash is not None
        assert reset_user.password_changed_at is not None
        assert reset_event is not None
        assert reset_event.reason_code == "permanent_password_set"

        old_token_is_revoked = await client.get(
            "/api/v1/me/user_info",
            headers={"Authorization": f"Bearer {old_target_token}"},
        )
        assert old_token_is_revoked.status_code == 401

        assert await _login(client, "target", ADMIN_PASSWORD)

        hidden_peer = await client.post(
            '/api/v1/users/password/reset',
            headers={"Authorization": f"Bearer {manager_token}"},
            json={"user_id": str(world.users['peer'].user_id),
                  "new_password": ADMIN_PASSWORD,
                  **await _captcha(client, "admin_reset_user_password", manager_token),
                  },
        )
        assert hidden_peer.status_code == 404
    finally:
        app.dependency_overrides.pop(get_settings, None)


@pytest.mark.parametrize(
    "holder_names",
    [(), ("manager",), ("super_admin", "manager")],
    ids=["no-holder", "different-sole-holder", "multiple-holders"],
)
async def test_operator_reset_rejects_every_non_exact_holder_set(world: World, holder_names: tuple[str, ...],
                                                                 audit_request_context: str) -> None:
    await _replace_live_super_admin_holders(world, holder_names)
    target_id = world.users["super_admin"].user_id
    token_version_before = world.users["super_admin"].token_version
    request_id = audit_request_context
    service = OperatorPasswordService(SessionFactory, password_manager)

    with pytest.raises(AppError) as caught:
        await service.reset_super_admin_password(
            user_id=target_id,
            new_password=ADMIN_PASSWORD,
        )

    assert caught.value.status_code == 409
    assert caught.value.reason_code == "operator_reset_requires_sole_super_admin"
    async with SessionFactory() as session:
        target = await session.get(User, target_id)
        event = await session.scalar(
            select(OperationAuditEvent).where(
                OperationAuditEvent.request_id == request_id
            )
        )
    assert target is not None and target.token_version == token_version_before
    assert target.password_hash is None
    assert target.password_changed_at is None
    assert event is None


async def test_operator_reset_rotates_the_correct_sole_holder_atomically(
    world: World, audit_request_context: str,
) -> None:
    target_id = world.users["super_admin"].user_id
    token_version_before = world.users["super_admin"].token_version
    request_id = audit_request_context
    service = OperatorPasswordService(SessionFactory, password_manager)

    changed = await service.reset_super_admin_password(
        user_id=target_id,
        new_password=ADMIN_PASSWORD,
    )

    assert changed is True
    async with SessionFactory() as session:
        target = await session.get(User, target_id)
        event = await session.scalar(
            select(OperationAuditEvent).where(
                OperationAuditEvent.request_id == request_id
            )
        )
    assert target is not None and target.token_version == token_version_before + 1
    assert target.password_changed_at is not None
    assert target.password_hash is not None
    assert target.password_hash != ADMIN_PASSWORD
    assert event is not None
    assert event.action == "account_security.password.operator_reset"
    assert event.reason_code == "permanent_password_set"
    assert event.target_user_id == target_id
