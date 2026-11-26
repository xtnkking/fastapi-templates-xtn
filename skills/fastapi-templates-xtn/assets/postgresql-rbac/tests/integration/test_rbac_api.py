#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    PostgreSQL RBAC 接口集成测试。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/29    XTN       V1.000        补充文件职责并改用普通类型别名写法
# 2026/09/30    XTN       V1.001        覆盖管理员会话查询的可见范围和强制退出新路径
# 2026/10/10    XTN       V1.002        统一用户 ID 与当前用户命名
# 2026/10/15    XTN       V1.003        移除用户权限版本并保留登录撤销与实时授权验证
# 2026/10/16    XTN       V1.004        移除运行时权限版本预期，保留协调锁与历史迁移契约
# 2026/10/24    XTN       V1.005        审计失败测试对齐 user_role_transaction 模块
# 2026/10/26    XTN       V1.006        权限结果字段明确区分有效用户信息与包含停用角色的信息
# --------------------------------------------------------------------------------------------------

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from app.core.access.authorization import AuthorizationContext, LoginInfo
from app.core.access.permissions import PermissionKey
from app.core.access.roles import SystemRoleKey
from app.core.exceptions import AppError
from app.core.ids import new_entity_id
from app.db.postgres_db import SessionFactory
from app.models.postgres.operation_audit import OperationAuditEvent
from app.models.postgres.permission import Permission
from app.models.postgres.rbac_state import RbacState
from app.models.postgres.role import Role, RolePermission
from app.models.postgres.user import User, UserRole
from app.repositories.postgres.rbac_state_repository import rbac_state_repository
from app.repositories.postgres.user_repository import user_repository
from app.services.audit_service import AuditService
from app.services.role_service import RoleService
from app.services.user_service import UserService
from tests.integration.conftest import World

pytestmark = [pytest.mark.postgresql, pytest.mark.usefixtures("audit_request_context")]
AccessToken = Callable[[User], Awaitable[str]]


async def headers(access_token: AccessToken, world: World, user_name: str) -> dict[str, str]:
    token = await access_token(world.users[user_name])
    return {"Authorization": f"Bearer {token}"}


def role_version(role: Role) -> int:
    return role.version


async def context_for(world: World, user_name: str) -> AuthorizationContext:
    async with SessionFactory() as session:
        user = await user_repository.get_user(session, user_id=world.users[user_name].user_id)
        assert user is not None
        user_info = (await user_repository.get_user_permissions(session, users=(user,)))[user.user_id].user_info
    return AuthorizationContext(
        login_info=LoginInfo(
            user_id=world.users[user_name].user_id,
            token_version=world.users[user_name].token_version,
            token_id=uuid.uuid4(),
            issued_at=0,
            expires_at=1,
        ),
        user_info=user_info,
    )


async def increment_token_version(user_id: str) -> None:
    async with SessionFactory() as session:
        async with session.begin():
            user = await session.get(User, user_id, with_for_update=True)
            assert user is not None
            user.token_version += 1


async def remove_rbac_state_for_test() -> None:
    async with SessionFactory() as session:
        async with session.begin():
            await session.execute(
                text("ALTER TABLE rbac_state DISABLE TRIGGER trg_rbac_state_no_delete")
            )
            await session.execute(text("DELETE FROM rbac_state WHERE scope = 'global'"))
            await session.execute(
                text("ALTER TABLE rbac_state ENABLE TRIGGER trg_rbac_state_no_delete")
            )


async def create_role(client: AsyncClient, world: World, access_token: AccessToken, *,
                      current_user: str = "super_admin", key: str = "report-reader",
                      tier: int = 10) -> tuple[dict[str, object], int]:
    response = await client.post(
        '/api/v1/roles/create',
        json={
            "key": key,
            "name": key.replace("-", " ").title(),
            "description": "Integration-test role",
            "level": tier,
        },
        headers=await headers(access_token, world, current_user),
    )
    assert response.status_code == 201, response.text
    role = response.json()["data"]["role"]
    return role, int(role["version"])


async def test_stale_current_user_cannot_probe_missing_user(world: World) -> None:
    context = await context_for(world, "manager")
    await increment_token_version(world.users["manager"].user_id)

    with pytest.raises(AppError) as caught:
        await UserService(SessionFactory).update_user_status(
            context=context,
            target_user_id=new_entity_id("U"),
            is_active=False,
        )

    assert caught.value.status_code == 401


async def test_stale_current_user_cannot_probe_missing_session_revoke_target(world: World) -> None:
    context = await context_for(world, "manager")
    await increment_token_version(world.users["manager"].user_id)

    with pytest.raises(AppError) as caught:
        await UserService(SessionFactory).revoke_user_sessions(
            context=context,
            target_user_id=new_entity_id("U"),
        )

    assert caught.value.status_code == 401


async def test_stale_current_user_cannot_probe_missing_role(world: World) -> None:
    context = await context_for(world, "super_admin")
    await increment_token_version(world.users["super_admin"].user_id)

    with pytest.raises(AppError) as caught:
        await RoleService(SessionFactory).change_role_permissions(
            context=context,
            role_id=new_entity_id("R"),
            permission_ids=(world.permissions[PermissionKey.PROJECTS_READ.value].id,),
            operation="bind",
            expected_version=0,
        )

    assert caught.value.status_code == 401


async def test_unprivileged_current_user_cannot_probe_missing_role(world: World) -> None:
    context = await context_for(world, "blank")

    with pytest.raises(AppError) as caught:
        await RoleService(SessionFactory).change_role_permissions(
            context=context,
            role_id=new_entity_id("R"),
            permission_ids=(world.permissions[PermissionKey.PROJECTS_READ.value].id,),
            operation="bind",
            expected_version=0,
        )

    assert caught.value.status_code == 403
    assert caught.value.reason_code == "missing_operation_permission"


async def test_unprivileged_current_user_cannot_probe_missing_user(world: World) -> None:
    context = await context_for(world, "blank")
    service = UserService(SessionFactory)

    with pytest.raises(AppError) as status_error:
        await service.update_user_status(
            context=context,
            target_user_id=new_entity_id("U"),
            is_active=False,
        )
    with pytest.raises(AppError) as role_error:
        await service.change_user_roles(
            context=context,
            target_user_id=new_entity_id("U"),
            role_ids=(world.roles["viewer"].id,),
            operation="bind",
        )
    with pytest.raises(AppError) as sessions_error:
        await service.revoke_user_sessions(
            context=context,
            target_user_id=new_entity_id("U"),
        )

    assert status_error.value.status_code == 403
    assert status_error.value.reason_code == "missing_operation_permission"
    assert role_error.value.status_code == 403
    assert role_error.value.reason_code == "missing_operation_permission"
    assert sessions_error.value.status_code == 403
    assert sessions_error.value.reason_code == "missing_operation_permission"


async def test_authority_uses_all_active_roles(client: AsyncClient, world: World, access_token: AccessToken) -> None:
    response = await client.get(
        "/api/v1/me/user_info",
        headers=await headers(access_token, world, "hidden_higher"),
    )

    assert response.status_code == 200
    body = response.json()["data"]
    assert body["user_id"] == str(world.users["hidden_higher"].user_id)
    assert body["role_level"] == 700
    assert body["permissions"] == ["projects:read"]
    assert "authorization_epoch" not in body


async def test_user_role_has_no_management_access(client: AsyncClient, world: World, access_token: AccessToken) -> None:
    response = await client.get(
        '/api/v1/users/list',
        headers=await headers(access_token, world, "blank"),
    )

    assert response.status_code == 403
    assert response.json()["code"] == 40301


async def test_admin_binds_lower_role_atomically_and_audits(client: AsyncClient, world: World,
                                                            access_token: AccessToken) -> None:
    response = await client.post(
        '/api/v1/users/roles/bind',
        json={"user_id": str(world.users['blank'].user_id), "role_ids": [str(world.roles["viewer"].id)]},
        headers={
            **(await headers(access_token, world, "manager")),
            "X-Request-ID": "bind-lower",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert set(body["data"]) == {"user"}
    assert body["request_id"] != "bind-lower"
    assert response.headers["X-Request-ID"] == body["request_id"]
    async with SessionFactory() as session:
        assignment = await session.scalar(
            select(UserRole).where(
                UserRole.user_id == world.users["blank"].user_id,
                UserRole.role_id == world.roles["viewer"].id,
                UserRole.deleted_at.is_(None),
            )
        )
        audit = await session.scalar(
            select(OperationAuditEvent).where(
                OperationAuditEvent.request_id == body["request_id"]
            )
        )
    assert assignment is not None
    assert audit is not None
    assert audit.action == "user.roles.bind"
    assert audit.outcome == "succeeded"
    assert audit.source == "http"


async def test_user_role_unbind_then_rebind_preserves_history(client: AsyncClient, world: World,
                                                              access_token: AccessToken) -> None:
    user_id = world.users["blank"].user_id
    role_id = world.roles["viewer"].id
    manager_headers = await headers(access_token, world, "manager")
    endpoint = "/api/v1/users/roles"
    body = {"user_id": str(user_id), "role_ids": [str(role_id)]}

    bound = await client.post(f"{endpoint}/bind", json=body, headers=manager_headers)
    unbound = await client.post(
        f"{endpoint}/unbind", json=body, headers=manager_headers
    )
    async with SessionFactory() as session:
        user = await user_repository.get_user(session, user_id=user_id)
        assert user is not None
        after_unbind = (await user_repository.get_user_permissions(session, users=(user,)))[user.user_id].user_info
    rebound = await client.post(f"{endpoint}/bind", json=body, headers=manager_headers)

    assert bound.status_code == 200
    assert unbound.status_code == 200
    assert rebound.status_code == 200
    assert set(bound.json()["data"]) == {"user"}
    assert set(unbound.json()["data"]) == {"user"}
    assert set(rebound.json()["data"]) == {"user"}
    assert PermissionKey.PROJECTS_READ.value not in after_unbind.permissions

    async with SessionFactory() as session:
        history = (
            await session.scalars(
                select(UserRole).where(
                    UserRole.user_id == user_id,
                    UserRole.role_id == role_id,
                )
            )
        ).all()
        user = await user_repository.get_user(session, user_id=user_id)
        assert user is not None
        after_rebind = (await user_repository.get_user_permissions(session, users=(user,)))[user.user_id].user_info
    assert len(history) == 2
    assert sum(item.deleted_at is None for item in history) == 1
    tombstone = next(item for item in history if item.deleted_at is not None)
    assert tombstone.deleted_by_user_id == world.users["manager"].user_id
    assert PermissionKey.PROJECTS_READ.value in after_rebind.permissions


async def test_junior_admin_can_manage_a_strictly_lower_user(client: AsyncClient, world: World,
                                                             access_token: AccessToken) -> None:
    response = await client.post(
        '/api/v1/users/roles/bind',
        json={"user_id": str(world.users['blank'].user_id), "role_ids": [str(world.roles["viewer"].id)]},
        headers=await headers(access_token, world, "junior"),
    )

    assert response.status_code == 200
    assert set(response.json()["data"]) == {"user"}


@pytest.mark.parametrize(
    ("current_user", "target", "expected_status"),
    [
        pytest.param("junior", "manager", 404, id="hidden-higher-target"),
        pytest.param("lower", "blank", 403, id="missing-management-capability"),
    ],
)
async def test_lower_authority_cannot_manage_users(client: AsyncClient, world: World, access_token: AccessToken,
                                                   current_user: str, target: str, expected_status: int) -> None:
    response = await client.post(
        '/api/v1/users/roles/bind',
        json={"user_id": str(world.users[target].user_id), "role_ids": [str(world.roles["viewer"].id)]},
        headers=await headers(access_token, world, current_user),
    )

    assert response.status_code == expected_status


async def test_admin_user_writes_conceal_self_peer_higher_and_protected_targets(client: AsyncClient, world: World,
                                                                                access_token: AccessToken) -> None:
    async with SessionFactory() as session:
        async with session.begin():
            protected_user = await session.get(User, world.users["newcomer"].user_id)
            assert protected_user is not None
            protected_user.is_protected = True

    manager_headers = await headers(access_token, world, "manager")
    missing = await client.post(
        '/api/v1/users/roles/unbind',
        json={"user_id": str(uuid.uuid4()), "role_ids": [str(world.roles["viewer"].id)]},
        headers=manager_headers,
    )
    assert missing.status_code == 404
    missing_body = missing.json()

    for target_name in (
        "manager",
        "peer",
        "higher",
        "hidden_higher",
        "super_admin",
        "newcomer",
    ):
        response = await client.post(
            '/api/v1/users/roles/unbind',
            json={"user_id": str(world.users[target_name].user_id), "role_ids": [str(world.roles["viewer"].id)]},
            headers=manager_headers,
        )
        assert response.status_code == 404
        for field in ("code", "message", "data"):
            assert response.json()[field] == missing_body[field]


async def test_admin_role_writes_conceal_peer_higher_and_protected_roles(client: AsyncClient, world: World,
                                                                         access_token: AccessToken) -> None:
    manager_headers = await headers(access_token, world, "manager")
    permission_id = world.permissions[PermissionKey.PROJECTS_READ.value].id
    missing = await client.post(
        '/api/v1/roles/permissions/bind',
        json={"role_id": str(uuid.uuid4()), "expected_version": 0, "permission_ids": [str(permission_id)]},
        headers=manager_headers,
    )
    assert missing.status_code == 404
    missing_body = missing.json()

    for role_name in ("admin", "higher", "super_admin"):
        response = await client.post(
            '/api/v1/roles/permissions/bind',
            json={"role_id": str(world.roles[role_name].id),
                  "expected_version": role_version(world.roles[role_name]),
                  "permission_ids": [str(permission_id)],
                  },
            headers=manager_headers,
        )
        assert response.status_code == 404
        for field in ("code", "message", "data"):
            assert response.json()[field] == missing_body[field]


async def test_user_role_batch_conceals_hidden_role_and_remains_atomic(client: AsyncClient, world: World,
                                                                       access_token: AccessToken) -> None:
    manager_headers = await headers(access_token, world, "manager")
    target_id = world.users["blank"].user_id
    missing = await client.post(
        '/api/v1/users/roles/bind',
        json={"user_id": str(target_id), "role_ids": [str(uuid.uuid4())]},
        headers=manager_headers,
    )
    assert missing.status_code == 404
    missing_body = missing.json()

    response = await client.post(
        '/api/v1/users/roles/bind',
        json={"user_id": str(target_id),
              "role_ids": [
            str(world.roles["viewer"].id),
            str(world.roles["admin"].id),
        ]
        },
        headers=manager_headers,
    )

    assert response.status_code == 404
    for field in ("code", "message", "data"):
        assert response.json()[field] == missing_body[field]
    async with SessionFactory() as session:
        partial_assignment = await session.scalar(
            select(UserRole).where(
                UserRole.user_id == target_id,
                UserRole.role_id == world.roles["viewer"].id,
                UserRole.deleted_at.is_(None),
            )
        )
    assert partial_assignment is None


async def test_admin_can_assign_lower_role_with_permissions_in_its_ceiling(client: AsyncClient, world: World,
                                                                           access_token: AccessToken) -> None:
    response = await client.post(
        '/api/v1/users/roles/bind',
        json={"user_id": str(world.users['blank'].user_id), "role_ids": [str(world.roles["auditor"].id)]},
        headers=await headers(access_token, world, "manager"),
    )

    assert response.status_code == 200


async def test_system_roles_reject_lifecycle_and_permission_changes(client: AsyncClient, world: World,
                                                                    access_token: AccessToken) -> None:
    super_admin_headers = await headers(access_token, world, "super_admin")
    permission_id = world.permissions[PermissionKey.PROJECTS_READ.value].id
    for role_name in ("super_admin", "admin", "user"):
        role = world.roles[role_name]
        expected_version = role_version(role)
        requests = (
            (
                "/api/v1/roles/update",
                {"role_id": str(role.id), "name": "Changed", "expected_version": expected_version},
            ),
            (
                "/api/v1/roles/disable",
                {"role_id": str(role.id), "expected_version": expected_version},
            ),
            (
                "/api/v1/roles/delete",
                {"role_id": str(role.id), "expected_version": expected_version},
            ),
            (
                "/api/v1/roles/permissions/unbind",
                {
                    "role_id": str(role.id),
                    "expected_version": expected_version,
                    "permission_ids": [str(permission_id)],
                },
            ),
        )
        for path, body in requests:
            response = await client.post(path, json=body, headers=super_admin_headers)
            assert response.status_code == 403, (path, response.text)


async def test_role_creation_starts_empty_and_cannot_elevate_creator(client: AsyncClient, world: World,
                                                                     access_token: AccessToken) -> None:
    created, _version = await create_role(
        client,
        world,
        access_token,
        current_user="manager",
    )

    assert created["permissions"] == []
    assignment = await client.post(
        '/api/v1/users/roles/bind',
        json={"user_id": str(world.users['manager'].user_id), "role_ids": [created["id"]]},
        headers=await headers(access_token, world, "manager"),
    )
    assert assignment.status_code == 404


async def test_owner_role_key_is_available_for_a_custom_role(client: AsyncClient, world: World,
                                                             access_token: AccessToken) -> None:
    response = await client.post(
        '/api/v1/roles/create',
        json={
            "key": "owner",
            "name": "Custom owner label",
            "level": 10,
        },
        headers=await headers(access_token, world, "super_admin"),
    )

    assert response.status_code == 201
    role = response.json()["data"]["role"]
    assert role["key"] == "owner"
    assert role["is_system"] is False
    assert role["is_protected"] is False


async def test_role_writes_require_current_expected_version(client: AsyncClient, world: World,
                                                            access_token: AccessToken) -> None:
    created, version = await create_role(
        client,
        world,
        access_token,
        key="versioned-role",
    )
    role_id = created["id"]

    missing = await client.post(
        '/api/v1/roles/update',
        json={"role_id": str(role_id), "name": "Version one"},
        headers=await headers(access_token, world, "super_admin"),
    )
    first = await client.post(
        '/api/v1/roles/update',
        json={"role_id": str(role_id), "name": "Version one", "expected_version": version},
        headers=await headers(access_token, world, "super_admin"),
    )
    stale = await client.post(
        '/api/v1/roles/update',
        json={"role_id": str(role_id), "description": "stale write", "expected_version": version},
        headers=await headers(access_token, world, "super_admin"),
    )

    assert missing.status_code == 422
    assert missing.json()["code"] == 42201
    assert first.status_code == 200
    assert first.json()["data"]["role"]["version"] == version + 1
    assert stale.status_code == 409
    assert stale.json()["code"] == 40931


async def test_policy_denial_precedes_stale_role_version(client: AsyncClient, world: World,
                                                         access_token: AccessToken) -> None:
    role = world.roles["admin"]
    permission_id = world.permissions[PermissionKey.PROJECTS_READ.value].id
    stale_version = role_version(role) + 999
    super_admin_headers = await headers(access_token, world, "super_admin")
    requests = (
        (
            "/api/v1/roles/update",
            {"role_id": str(role.id), "name": "Forbidden", "expected_version": stale_version},
        ),
        (
            "/api/v1/roles/disable",
            {"role_id": str(role.id), "expected_version": stale_version},
        ),
        (
            "/api/v1/roles/delete",
            {"role_id": str(role.id), "expected_version": stale_version},
        ),
        (
            "/api/v1/roles/permissions/bind",
            {
                "role_id": str(role.id),
                "permission_ids": [str(permission_id)],
                "expected_version": stale_version,
            },
        ),
    )

    for path, body in requests:
        response = await client.post(path, json=body, headers=super_admin_headers)
        assert response.status_code == 403, (path, response.text)
        response_body = response.json()
        assert response_body["code"] == 40301
        async with SessionFactory() as session:
            audit = await session.scalar(
                select(OperationAuditEvent).where(
                    OperationAuditEvent.request_id == response_body["request_id"]
                )
            )
        assert audit is not None
        assert audit.outcome == "denied"
        assert audit.source == "http"
        assert audit.reason_code != "stale_role_version"


async def test_unknown_permission_is_a_semantically_invalid_request(client: AsyncClient, world: World,
                                                                    access_token: AccessToken) -> None:
    response = await client.post(
        '/api/v1/roles/permissions/bind',
        json={"role_id": str(world.roles['viewer'].id),
              "permission_ids": [str(uuid.uuid4())],
              "expected_version": role_version(world.roles["viewer"]),
              },
        headers=await headers(access_token, world, "super_admin"),
    )

    assert response.status_code == 400
    assert response.json()["code"] == 40040


async def test_incremental_permission_changes_are_idempotent(client: AsyncClient, world: World,
                                                             access_token: AccessToken) -> None:
    created, version = await create_role(
        client,
        world,
        access_token,
        key="permission-delta-role",
    )
    role_id = created["id"]
    read_id = world.permissions[PermissionKey.PROJECTS_READ.value].id
    update_id = world.permissions[PermissionKey.PROJECTS_UPDATE.value].id
    super_admin_headers = await headers(access_token, world, "super_admin")

    bound = await client.post(
        '/api/v1/roles/permissions/bind',
        json={"role_id": str(role_id), "permission_ids": [str(read_id)], "expected_version": version},
        headers=super_admin_headers,
    )
    assert bound.status_code == 200
    assert set(bound.json()["data"]) == {"role"}
    version = bound.json()["data"]["role"]["version"]

    duplicate = await client.post(
        '/api/v1/roles/permissions/bind',
        json={"role_id": str(role_id), "permission_ids": [str(read_id)], "expected_version": version},
        headers=super_admin_headers,
    )
    assert duplicate.status_code == 200
    assert duplicate.json()["data"] == bound.json()["data"]
    assert duplicate.json()["data"]["role"]["version"] == version

    obsolete_delegation = await client.post(
        '/api/v1/roles/delegable-permissions/bind',
        json={"role_id": str(role_id), "permission_ids": [str(read_id)], "expected_version": version},
        headers=super_admin_headers,
    )
    assert obsolete_delegation.status_code == 404

    second_permission = await client.post(
        '/api/v1/roles/permissions/bind',
        json={"role_id": str(role_id), "permission_ids": [str(update_id)], "expected_version": version},
        headers=super_admin_headers,
    )
    assert second_permission.status_code == 200
    assert set(second_permission.json()["data"]["role"]["permissions"]) == {
        PermissionKey.PROJECTS_READ.value,
        PermissionKey.PROJECTS_UPDATE.value,
    }
    version = second_permission.json()["data"]["role"]["version"]

    removed = await client.post(
        '/api/v1/roles/permissions/unbind',
        json={"role_id": str(role_id), "permission_ids": [str(read_id)], "expected_version": version},
        headers=super_admin_headers,
    )
    assert removed.status_code == 200
    assert removed.json()["data"]["role"]["permissions"] == [
        PermissionKey.PROJECTS_UPDATE.value
    ]
    version = removed.json()["data"]["role"]["version"]

    rebound = await client.post(
        '/api/v1/roles/permissions/bind',
        json={"role_id": str(role_id), "permission_ids": [str(read_id)], "expected_version": version},
        headers=super_admin_headers,
    )
    assert rebound.status_code == 200
    assert set(rebound.json()["data"]) == {"role"}

    async with SessionFactory() as session:
        history = (
            await session.scalars(
                select(RolePermission).where(
                    RolePermission.role_id == uuid.UUID(str(role_id)),
                    RolePermission.permission_id == read_id,
                )
            )
        ).all()
    assert len(history) == 2
    assert sum(item.deleted_at is None for item in history) == 1
    tombstone = next(item for item in history if item.deleted_at is not None)
    assert tombstone.deleted_by_user_id == world.users["super_admin"].user_id


async def test_role_disable_enable_and_soft_delete_revoke_effective_access(client: AsyncClient, world: World,
                                                                           access_token: AccessToken) -> None:
    created, version = await create_role(
        client,
        world,
        access_token,
        key="lifecycle-role",
    )
    role_id = created["id"]
    read_id = world.permissions[PermissionKey.PROJECTS_READ.value].id
    super_admin_headers = await headers(access_token, world, "super_admin")

    bound_permission = await client.post(
        '/api/v1/roles/permissions/bind',
        json={"role_id": str(role_id), "permission_ids": [str(read_id)], "expected_version": version},
        headers=super_admin_headers,
    )
    version = bound_permission.json()["data"]["role"]["version"]
    bound_user = await client.post(
        '/api/v1/users/roles/bind',
        json={"user_id": str(world.users['blank'].user_id), "role_ids": [role_id]},
        headers=super_admin_headers,
    )
    assert bound_user.status_code == 200

    disabled = await client.post(
        '/api/v1/roles/disable',
        json={"role_id": str(role_id), "expected_version": version},
        headers=super_admin_headers,
    )
    assert disabled.status_code == 200
    version = disabled.json()["data"]["role"]["version"]
    async with SessionFactory() as session:
        user = await user_repository.get_user(session, user_id=world.users["blank"].user_id)
        assert user is not None
        after_disable = (await user_repository.get_user_permissions(session, users=(user,)))[user.user_id].user_info
    assert PermissionKey.PROJECTS_READ.value not in after_disable.permissions

    enabled = await client.post(
        '/api/v1/roles/enable',
        json={"role_id": str(role_id), "expected_version": version},
        headers=super_admin_headers,
    )
    assert enabled.status_code == 200
    version = enabled.json()["data"]["role"]["version"]

    deleted = await client.post(
        '/api/v1/roles/delete',
        json={"role_id": str(role_id), "expected_version": version},
        headers=super_admin_headers,
    )
    assert deleted.status_code == 200
    assert deleted.json()["data"]["role"]["deleted_at"] is not None
    missing = await client.get(
        f'/api/v1/roles/detail?role_id={role_id}',
        headers=super_admin_headers,
    )
    assert missing.status_code == 404

    async with SessionFactory() as session:
        assignments = (
            await session.scalars(
                select(UserRole).where(
                    UserRole.user_id == world.users["blank"].user_id,
                    UserRole.role_id == uuid.UUID(str(role_id)),
                )
            )
        ).all()
        grants = (
            await session.scalars(
                select(RolePermission).where(
                    RolePermission.role_id == uuid.UUID(str(role_id))
                )
            )
        ).all()
        user = await user_repository.get_user(session, user_id=world.users["blank"].user_id)
        assert user is not None
        after_delete = (await user_repository.get_user_permissions(session, users=(user,)))[user.user_id].user_info
    assert assignments and all(item.deleted_at is not None for item in assignments)
    assert all(
        item.deleted_by_user_id == world.users["super_admin"].user_id for item in assignments
    )
    assert grants and all(item.deleted_at is not None for item in grants)
    assert all(
        item.deleted_by_user_id == world.users["super_admin"].user_id for item in grants
    )
    assert PermissionKey.PROJECTS_READ.value not in after_delete.permissions


async def test_admin_cannot_delete_even_a_lower_custom_role(client: AsyncClient, world: World,
                                                            access_token: AccessToken) -> None:
    created, version = await create_role(
        client,
        world,
        access_token,
        current_user="manager",
        key="admin-created-role",
    )

    response = await client.post(
        '/api/v1/roles/delete',
        json={"role_id": str(created['id']), "expected_version": version},
        headers=await headers(access_token, world, "manager"),
    )

    assert response.status_code == 403


async def test_system_role_assignment_rules_and_mandatory_user_role(client: AsyncClient, world: World,
                                                                    access_token: AccessToken) -> None:
    blank_id = world.users["blank"].user_id
    manager_headers = await headers(access_token, world, "manager")
    super_admin_headers = await headers(access_token, world, "super_admin")

    user_unbind = await client.post(
        '/api/v1/users/roles/unbind',
        json={"user_id": str(blank_id), "role_ids": [str(world.roles["user"].id)]},
        headers=manager_headers,
    )
    admin_by_admin = await client.post(
        '/api/v1/users/roles/bind',
        json={"user_id": str(blank_id), "role_ids": [str(world.roles["admin"].id)]},
        headers=manager_headers,
    )
    super_admin_by_super_admin = await client.post(
        '/api/v1/users/roles/bind',
        json={"user_id": str(blank_id), "role_ids": [str(world.roles["super_admin"].id)]},
        headers=super_admin_headers,
    )
    admin_by_super_admin = await client.post(
        '/api/v1/users/roles/bind',
        json={"user_id": str(blank_id), "role_ids": [str(world.roles["admin"].id)]},
        headers=super_admin_headers,
    )

    assert user_unbind.status_code == 403
    assert admin_by_admin.status_code == 404
    assert super_admin_by_super_admin.status_code == 403
    assert admin_by_super_admin.status_code == 200

    async with SessionFactory() as session:
        user_assignment = await session.scalar(
            select(UserRole).where(
                UserRole.user_id == blank_id,
                UserRole.role_id == world.roles["user"].id,
                UserRole.deleted_at.is_(None),
            )
        )
    assert user_assignment is not None


async def test_super_admin_transfer_route_is_absent(client: AsyncClient, world: World,
                                                    access_token: AccessToken) -> None:
    response = await client.post(
        "/api/v1/system/super-admin/transfer",
        json={"target_user_id": str(world.users["blank"].user_id)},
        headers=await headers(access_token, world, "super_admin"),
    )

    assert response.status_code == 404
    async with SessionFactory() as session:
        role_id = world.roles["super_admin"].id
        holders = (
            await session.scalars(
                select(UserRole.user_id).where(
                    UserRole.role_id == role_id,
                    UserRole.deleted_at.is_(None),
                )
            )
        ).all()
    assert holders == [world.users["super_admin"].user_id]


async def test_status_change_invalidates_old_token_after_reactivation(client: AsyncClient, world: World,
                                                                      access_token: AccessToken) -> None:
    old_token = await access_token(world.users["lower"])
    user_id = world.users["lower"].user_id
    admin_headers = await headers(access_token, world, "manager")

    disabled = await client.post(
        '/api/v1/users/disable', json={"user_id": str(user_id)},
        headers=admin_headers,
    )
    assert disabled.status_code == 200
    rejected = await client.get(
        "/api/v1/me/user_info",
        headers={"Authorization": f"Bearer {old_token}"},
    )
    assert rejected.status_code == 401

    enabled = await client.post(
        '/api/v1/users/enable', json={"user_id": str(user_id)},
        headers=admin_headers,
    )
    assert enabled.status_code == 200
    rejected_again = await client.get(
        "/api/v1/me/user_info",
        headers={"Authorization": f"Bearer {old_token}"},
    )
    assert rejected_again.status_code == 401

    async with SessionFactory() as session:
        user = await session.get(User, user_id)
    assert user is not None
    assert user.token_version == 2


async def test_logout_revokes_only_the_presented_access_token(client: AsyncClient, world: World,
                                                              access_token: AccessToken) -> None:
    first_token = await access_token(world.users["lower"])
    second_token = await access_token(world.users["lower"])

    logged_out = await client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {first_token}"},
    )
    first_rejected = await client.get(
        "/api/v1/me/user_info",
        headers={"Authorization": f"Bearer {first_token}"},
    )
    second_accepted = await client.get(
        "/api/v1/me/user_info",
        headers={"Authorization": f"Bearer {second_token}"},
    )

    assert logged_out.status_code == 200
    assert logged_out.json()["data"] is None
    assert first_rejected.status_code == 401
    assert second_accepted.status_code == 200


async def test_administrator_lists_only_visible_users_sessions(client: AsyncClient, world: World,
                                                               access_token: AccessToken) -> None:
    """
        验证管理员能查看下级在线登录，但不能通过用户 ID 探测本人、同级或上级。

    :param client: 已连接隔离数据库和 Redis 的 API 客户端。
    :param world: 包含不同管理等级测试用户的数据。
    :param access_token: 为测试用户签发有效登录的工厂。
    :return: 无返回值，断言权限与目标可见性边界。
    """
    await access_token(world.users["lower"])
    manager_headers = await headers(access_token, world, "manager")
    visible = await client.get(
        "/api/v1/users/sessions/list",
        params={"user_id": str(world.users["lower"].user_id)},
        headers=manager_headers,
    )
    assert visible.status_code == 200
    assert visible.json()["data"]["active_count"] >= 1

    unknown = await client.get(
        "/api/v1/users/sessions/list",
        params={"user_id": str(uuid.uuid4())},
        headers=manager_headers,
    )
    for name in ("manager", "peer", "higher", "super_admin"):
        hidden = await client.get(
            "/api/v1/users/sessions/list",
            params={"user_id": str(world.users[name].user_id)},
            headers=manager_headers,
        )
        assert hidden.status_code == unknown.status_code == 404
        assert hidden.json()["code"] == unknown.json()["code"] == 40401

    ordinary = await client.get(
        "/api/v1/users/sessions/list",
        params={"user_id": str(world.users["lower"].user_id)},
        headers=await headers(access_token, world, "lower"),
    )
    assert ordinary.status_code == 403
    assert (await client.get("/api/v1/me/sessions/list", headers=manager_headers)).status_code == 404


async def test_administrator_can_revoke_only_strictly_lower_users_sessions(client: AsyncClient, world: World,
                                                                           access_token: AccessToken) -> None:
    user = world.users["lower"]
    first_token = await access_token(user)
    second_token = await access_token(user)
    previous_token_version = user.token_version

    admin_token = await access_token(world.users["manager"])
    revoked = await client.post(
        '/api/v1/users/sessions/logout-all', json={"user_id": str(user.user_id)},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    first_rejected = await client.get(
        "/api/v1/me/user_info",
        headers={"Authorization": f"Bearer {first_token}"},
    )
    second_rejected = await client.get(
        "/api/v1/me/user_info",
        headers={"Authorization": f"Bearer {second_token}"},
    )

    async with SessionFactory() as session:
        persisted_user = await session.get(User, user.user_id)

    assert revoked.status_code == 200
    assert revoked.json()["data"] is None
    assert first_rejected.status_code == 401
    assert second_rejected.status_code == 401
    assert persisted_user is not None
    assert persisted_user.token_version == previous_token_version + 1
    assert (
        await client.get(
            "/api/v1/me/user_info",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
    ).status_code == 200
    async with SessionFactory() as session:
        audit = await session.scalar(
            select(OperationAuditEvent).where(
                OperationAuditEvent.action == "user.sessions.revoke",
                OperationAuditEvent.target_user_id == user.user_id,
                OperationAuditEvent.outcome == "succeeded",
            )
        )
    assert audit is not None
    assert audit.user_id == world.users["manager"].user_id
    assert audit.before_state == {"token_version": previous_token_version}
    assert audit.after_state == {"token_version": previous_token_version + 1}


async def test_session_revocation_conceals_self_peer_and_higher_users(client: AsyncClient, world: World,
                                                                      access_token: AccessToken) -> None:
    manager_headers = await headers(access_token, world, "manager")
    unknown = await client.post(
        '/api/v1/users/sessions/logout-all', json={"user_id": str(uuid.uuid4())},
        headers=manager_headers,
    )
    for name in ("manager", "peer", "higher", "super_admin"):
        response = await client.post(
            '/api/v1/users/sessions/logout-all', json={"user_id": str(world.users[name].user_id)},
            headers=manager_headers,
        )
        assert response.status_code == unknown.status_code == 404
        assert response.json()["code"] == unknown.json()["code"] == 40401

    ordinary_user = await client.post(
        '/api/v1/users/sessions/logout-all', json={"user_id": str(world.users['lower'].user_id)},
        headers=await headers(access_token, world, "lower"),
    )
    assert ordinary_user.status_code == 403
    assert ordinary_user.json()["code"] == 40301
    assert (
        await client.post(
            "/api/v1/auth/logout-all",
            headers=await headers(access_token, world, "lower"),
        )
    ).status_code == 404


async def test_audit_failure_rolls_back_authorization_mutation(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    context = await context_for(world, "manager")
    service = UserService(SessionFactory)

    def invalid_audit(**_kwargs: object) -> OperationAuditEvent:
        return OperationAuditEvent(
            user_id=world.users["manager"].user_id,
            target_user_id=world.users["blank"].user_id,
            target_role_id=world.roles["viewer"].id,
            action="user.roles.bind",
            category="permission",
            outcome="invalid",
            reason_code="forced_failure",
            request_id="audit-must-rollback",
        )

    monkeypatch.setattr(AuditService, "_build_event", invalid_audit)
    with pytest.raises(IntegrityError):
        await service.change_user_roles(
            context=context,
            target_user_id=world.users["blank"].user_id,
            role_ids=(world.roles["viewer"].id,),
            operation="bind",
        )

    async with SessionFactory() as session:
        assignment = await session.scalar(
            select(UserRole).where(
                UserRole.user_id == world.users["blank"].user_id,
                UserRole.role_id == world.roles["viewer"].id,
            )
        )
    assert assignment is None


async def test_missing_authoritative_state_returns_503(client: AsyncClient, world: World,
                                                       access_token: AccessToken) -> None:
    await remove_rbac_state_for_test()

    try:
        response = await client.get(
            "/api/v1/me/user_info",
            headers=await headers(access_token, world, "manager"),
        )
        assert response.status_code == 503
        assert response.json()["code"] == 50301
    finally:
        async with SessionFactory() as session:
            session.add(RbacState(scope="global"))
            await session.commit()


async def test_missing_state_does_not_write_false_denial(world: World, audit_request_context: str) -> None:
    request_id = audit_request_context
    context = await context_for(world, "manager")
    await remove_rbac_state_for_test()

    try:
        with pytest.raises(AppError) as caught:
            await UserService(SessionFactory).change_user_roles(
                context=context,
                target_user_id=world.users["blank"].user_id,
                role_ids=(world.roles["viewer"].id,),
                operation="bind",
            )
        assert caught.value.status_code == 503

        async with SessionFactory() as session:
            audit = await session.scalar(
                select(OperationAuditEvent).where(OperationAuditEvent.request_id == request_id)
            )
        assert audit is None
    finally:
        async with SessionFactory() as session:
            session.add(RbacState(scope="global"))
            await session.commit()


async def test_privileged_requests_reject_mass_assignment(client: AsyncClient, world: World,
                                                          access_token: AccessToken) -> None:
    response = await client.post(
        '/api/v1/roles/update',
        json={"role_id": str(world.roles['viewer'].id),
              "name": "Changed",
              "is_system": True,
              "expected_version": role_version(world.roles["viewer"]),
              },
        headers=await headers(access_token, world, "manager"),
    )

    assert response.status_code == 422


async def test_permission_list_and_detail_use_uuid_identifiers(client: AsyncClient, world: World,
                                                               access_token: AccessToken) -> None:
    super_admin_headers = await headers(access_token, world, "super_admin")
    listed = await client.get('/api/v1/permissions/list', headers=super_admin_headers)
    permission = world.permissions[PermissionKey.USERS_SESSIONS_REVOKE.value]
    detailed = await client.get(
        f'/api/v1/permissions/detail?permission_id={permission.id}',
        headers=super_admin_headers,
    )

    assert listed.status_code == 200
    page = listed.json()["data"]
    assert set(page) == {"items", "page", "page_size", "total"}
    assert all(uuid.UUID(item["id"]) for item in page["items"])
    assert detailed.status_code == 200
    assert detailed.json()["data"]["key"] == PermissionKey.USERS_SESSIONS_REVOKE.value


async def test_user_soft_delete_and_restore_never_revive_old_roles(client: AsyncClient, world: World,
                                                                   access_token: AccessToken) -> None:
    target_id = world.users["lower"].user_id
    user_id = world.users["super_admin"].user_id
    super_admin_headers = await headers(access_token, world, "super_admin")
    original_assignment_ids: set[str]
    async with SessionFactory() as session:
        async with session.begin():
            await rbac_state_repository.lock_rbac_state(session)
            user = await session.scalar(
                select(User).where(User.user_id == target_id).with_for_update()
            )
            assert user is not None
            assignments = tuple(
                (
                    await session.scalars(
                        select(UserRole)
                        .where(
                            UserRole.user_id == target_id,
                            UserRole.deleted_at.is_(None),
                        )
                        .order_by(UserRole.id)
                        .with_for_update()
                    )
                ).all()
            )
            original_assignment_ids = {item.id for item in assignments}
            assert len(original_assignment_ids) >= 2
            deleted_at = datetime.now(UTC)
            user.is_active = False
            user.deleted_at = deleted_at
            user.deleted_by_user_id = user_id
            user.token_version += 1
            for assignment in assignments:
                assignment.deleted_at = deleted_at
                assignment.deleted_by_user_id = user_id

    detailed = await client.get(
        f'/api/v1/users/detail?user_id={target_id}', headers=super_admin_headers
    )
    listed = await client.get(
        "/api/v1/users/list?page_size=200", headers=super_admin_headers
    )
    assert detailed.status_code == 404
    assert listed.status_code == 200
    assert str(target_id) not in {item["user_id"] for item in listed.json()["data"]["items"]}
    async with SessionFactory() as session:
        assert await user_repository.get_user(session, user_id=target_id) is None
        tombstones = tuple(
            (
                await session.scalars(
                    select(UserRole)
                    .where(UserRole.user_id == target_id)
                    .order_by(UserRole.id)
                )
            ).all()
        )
    assert {item.id for item in tombstones} == original_assignment_ids
    assert all(item.deleted_at is not None for item in tombstones)

    async with SessionFactory() as session:
        async with session.begin():
            await rbac_state_repository.lock_rbac_state(session)
            user = await session.scalar(
                select(User).where(User.user_id == target_id).with_for_update()
            )
            assert user is not None
            live_assignment = await session.scalar(
                select(UserRole.id).where(
                    UserRole.user_id == target_id,
                    UserRole.deleted_at.is_(None),
                )
            )
            assert live_assignment is None
            base_role = await session.scalar(
                select(Role)
                .where(
                    Role.key == SystemRoleKey.USER.value,
                    Role.deleted_at.is_(None),
                )
                .with_for_update()
            )
            assert base_role is not None
            user.deleted_at = None
            user.deleted_by_user_id = None
            restored_assignment = UserRole(
                user_id=target_id,
                role_id=base_role.id,
                bound_by_user_id=user_id,
            )
            session.add(restored_assignment)
            await session.flush()
            restored_assignment_id = restored_assignment.id

    async with SessionFactory() as session:
        user = await user_repository.get_user(session, user_id=target_id)
        assert user is not None
        restored = (
            await user_repository.get_user_permissions(session, users=(user,))
        )[user.user_id].user_info_with_disabled_roles
        all_assignments = tuple(
            (
                await session.scalars(
                    select(UserRole)
                    .where(UserRole.user_id == target_id)
                    .order_by(UserRole.id)
                )
            ).all()
        )
    assert restored.user_is_active is False
    assert {role.key for role in restored.roles} == {SystemRoleKey.USER.value}
    assert restored.permissions == frozenset()
    assert restored_assignment_id not in original_assignment_ids
    assert {item.id for item in all_assignments if item.deleted_at is None} == {
        restored_assignment_id
    }
    assert original_assignment_ids <= {
        item.id for item in all_assignments if item.deleted_at is not None
    }


async def test_permission_catalog_retirement_and_restore_require_new_grants(client: AsyncClient, world: World,
                                                                            access_token: AccessToken) -> None:
    permission_key = "projects:temporary-read"
    permission_id = uuid.uuid4()
    user_id = world.users["super_admin"].user_id
    role_id = world.roles["viewer"].id
    super_admin_headers = await headers(access_token, world, "super_admin")
    async with SessionFactory() as session:
        async with session.begin():
            await rbac_state_repository.lock_rbac_state(session)
            affected_users = tuple(
                (
                    await session.scalars(
                        select(User)
                        .join(UserRole, UserRole.user_id == User.user_id)
                        .where(
                            UserRole.role_id == role_id,
                            UserRole.deleted_at.is_(None),
                            User.deleted_at.is_(None),
                        )
                        .order_by(User.user_id)
                        .with_for_update()
                    )
                ).all()
            )
            role = await session.scalar(
                select(Role).where(Role.id == role_id).with_for_update()
            )
            assert role is not None
            permission = Permission(
                id=permission_id,
                key=permission_key,
                description="Temporary integration-test permission",
            )
            original_grant = RolePermission(
                role_id=role_id,
                permission_id=permission_id,
                bound_by_user_id=user_id,
            )
            session.add_all((permission, original_grant))
            role.version += 1
            assert all(user.deleted_at is None for user in affected_users)
            await session.flush()
            original_grant_id = original_grant.id

    async with SessionFactory() as session:
        async with session.begin():
            await rbac_state_repository.lock_rbac_state(session)
            affected_users = tuple(
                (
                    await session.scalars(
                        select(User)
                        .join(UserRole, UserRole.user_id == User.user_id)
                        .where(
                            UserRole.role_id == role_id,
                            UserRole.deleted_at.is_(None),
                            User.deleted_at.is_(None),
                        )
                        .order_by(User.user_id)
                        .with_for_update()
                    )
                ).all()
            )
            role = await session.scalar(
                select(Role).where(Role.id == role_id).with_for_update()
            )
            locked_permission = await session.scalar(
                select(Permission)
                .where(Permission.id == permission_id)
                .with_for_update()
            )
            grant = await session.scalar(
                select(RolePermission)
                .where(
                    RolePermission.id == original_grant_id,
                    RolePermission.deleted_at.is_(None),
                )
                .with_for_update()
            )
            assert role is not None
            assert locked_permission is not None
            assert grant is not None
            deleted_at = datetime.now(UTC)
            grant.deleted_at = deleted_at
            grant.deleted_by_user_id = user_id
            locked_permission.deleted_at = deleted_at
            locked_permission.deleted_by_user_id = user_id
            role.version += 1
            assert all(user.deleted_at is None for user in affected_users)

    detailed = await client.get(
        f'/api/v1/permissions/detail?permission_id={permission_id}', headers=super_admin_headers
    )
    listed = await client.get(
        "/api/v1/permissions/list?page_size=200", headers=super_admin_headers
    )
    async with SessionFactory() as session:
        user = await user_repository.get_user(session, user_id=world.users["lower"].user_id)
        assert user is not None
        authority_after_delete = (
            await user_repository.get_user_permissions(session, users=(user,))
        )[user.user_id].user_info
        old_grant = await session.get(RolePermission, original_grant_id)
        live_grant = await session.scalar(
            select(RolePermission).where(
                RolePermission.role_id == role_id,
                RolePermission.permission_id == permission_id,
                RolePermission.deleted_at.is_(None),
            )
        )
    assert detailed.status_code == 404
    assert listed.status_code == 200
    assert str(permission_id) not in {
        item["id"] for item in listed.json()["data"]["items"]
    }
    assert permission_key not in authority_after_delete.permissions
    assert old_grant is not None and old_grant.deleted_at is not None
    assert live_grant is None

    async with SessionFactory() as session:
        async with session.begin():
            await rbac_state_repository.lock_rbac_state(session)
            locked_permission = await session.scalar(
                select(Permission)
                .where(Permission.id == permission_id)
                .with_for_update()
            )
            assert locked_permission is not None
            locked_permission.deleted_at = None
            locked_permission.deleted_by_user_id = None

    async with SessionFactory() as session:
        user = await user_repository.get_user(session, user_id=world.users["lower"].user_id)
        assert user is not None
        authority_after_restore = (
            await user_repository.get_user_permissions(session, users=(user,))
        )[user.user_id].user_info
        live_grant = await session.scalar(
            select(RolePermission).where(
                RolePermission.role_id == role_id,
                RolePermission.permission_id == permission_id,
                RolePermission.deleted_at.is_(None),
            )
        )
    assert permission_key not in authority_after_restore.permissions
    assert live_grant is None

    async with SessionFactory() as session:
        async with session.begin():
            await rbac_state_repository.lock_rbac_state(session)
            affected_users = tuple(
                (
                    await session.scalars(
                        select(User)
                        .join(UserRole, UserRole.user_id == User.user_id)
                        .where(
                            UserRole.role_id == role_id,
                            UserRole.deleted_at.is_(None),
                            User.deleted_at.is_(None),
                        )
                        .order_by(User.user_id)
                        .with_for_update()
                    )
                ).all()
            )
            role = await session.scalar(
                select(Role).where(Role.id == role_id).with_for_update()
            )
            assert role is not None
            replacement_grant = RolePermission(
                role_id=role_id,
                permission_id=permission_id,
                bound_by_user_id=user_id,
            )
            session.add(replacement_grant)
            role.version += 1
            assert all(user.deleted_at is None for user in affected_users)
            await session.flush()
            replacement_grant_id = replacement_grant.id

    async with SessionFactory() as session:
        user = await user_repository.get_user(session, user_id=world.users["lower"].user_id)
        assert user is not None
        authority_after_rebind = (
            await user_repository.get_user_permissions(session, users=(user,))
        )[user.user_id].user_info
        old_grant = await session.get(RolePermission, original_grant_id)
    assert permission_key in authority_after_rebind.permissions
    assert replacement_grant_id != original_grant_id
    assert old_grant is not None and old_grant.deleted_at is not None
