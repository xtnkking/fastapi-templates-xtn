import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from app.database import SessionFactory
from app.rbac.domain import (
    AuthorizationContext,
    PermissionKey,
    Principal,
    SystemRoleKey,
)
from app.rbac.errors import RbacError
from app.rbac.models import (
    Permission,
    RbacAuditEvent,
    RbacState,
    Role,
    RolePermission,
    User,
    UserRole,
)
from app.rbac.queries import load_authority_snapshot, lock_rbac_state
from app.rbac.schemas import UserStatusUpdateRequest
from app.rbac.service import RbacService
from tests.integration.conftest import World

pytestmark = pytest.mark.postgresql
type AccessToken = Callable[[User], Awaitable[str]]


async def headers(
    access_token: AccessToken,
    world: World,
    user_name: str,
) -> dict[str, str]:
    token = await access_token(world.users[user_name])
    return {"Authorization": f"Bearer {token}"}


def role_version(role: Role) -> int:
    return role.version


async def context_for(
    world: World,
    user_name: str,
    request_id: str,
) -> AuthorizationContext:
    async with SessionFactory() as session:
        authority = await load_authority_snapshot(
            session,
            user_id=world.users[user_name].id,
        )
        state = await session.get(RbacState, "global")
        assert state is not None
    return AuthorizationContext(
        principal=Principal(
            user_id=world.users[user_name].id,
            token_version=world.users[user_name].token_version,
            token_id=uuid.uuid4(),
            issued_at=0,
            expires_at=1,
        ),
        authorization_epoch=state.epoch,
        authority=authority,
        request_id=request_id,
    )


async def increment_token_version(user_id: uuid.UUID) -> None:
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


async def create_role(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
    *,
    actor: str = "super_admin",
    key: str = "report-reader",
    tier: int = 10,
) -> tuple[dict[str, object], int]:
    response = await client.post(
        "/api/v1/roles",
        json={
            "key": key,
            "name": key.replace("-", " ").title(),
            "description": "Integration-test role",
            "management_tier": tier,
        },
        headers=await headers(access_token, world, actor),
    )
    assert response.status_code == 201, response.text
    role = response.json()["data"]["role"]
    return role, int(role["version"])


async def test_stale_actor_cannot_probe_missing_user(world: World) -> None:
    context = await context_for(world, "manager", "stale-actor-missing-user")
    await increment_token_version(world.users["manager"].id)

    with pytest.raises(RbacError) as caught:
        await RbacService(SessionFactory).update_user_status(
            context=context,
            target_user_id=uuid.uuid4(),
            request=UserStatusUpdateRequest(is_active=False),
        )

    assert caught.value.status_code == 401


async def test_stale_actor_cannot_probe_missing_super_admin_transfer_target(
    world: World,
) -> None:
    context = await context_for(world, "super_admin", "stale-super-admin-missing-user")
    await increment_token_version(world.users["super_admin"].id)

    with pytest.raises(RbacError) as caught:
        await RbacService(SessionFactory).transfer_super_admin(
            context=context,
            target_user_id=uuid.uuid4(),
        )

    assert caught.value.status_code == 401


async def test_stale_actor_cannot_probe_missing_role(world: World) -> None:
    context = await context_for(world, "super_admin", "stale-super-admin-missing-role")
    await increment_token_version(world.users["super_admin"].id)

    with pytest.raises(RbacError) as caught:
        await RbacService(SessionFactory).change_role_permissions(
            context=context,
            role_id=uuid.uuid4(),
            permission_ids=(world.permissions[PermissionKey.PROJECTS_READ.value].id,),
            operation="bind",
            expected_version=0,
        )

    assert caught.value.status_code == 401


async def test_unprivileged_actor_cannot_probe_missing_role(world: World) -> None:
    context = await context_for(world, "blank", "unprivileged-missing-role")

    with pytest.raises(RbacError) as caught:
        await RbacService(SessionFactory).change_role_permissions(
            context=context,
            role_id=uuid.uuid4(),
            permission_ids=(world.permissions[PermissionKey.PROJECTS_READ.value].id,),
            operation="bind",
            expected_version=0,
        )

    assert caught.value.status_code == 403
    assert caught.value.reason_code == "missing_operation_permission"


async def test_unprivileged_actor_cannot_probe_missing_user(world: World) -> None:
    context = await context_for(world, "blank", "unprivileged-missing-user")
    service = RbacService(SessionFactory)

    with pytest.raises(RbacError) as status_error:
        await service.update_user_status(
            context=context,
            target_user_id=uuid.uuid4(),
            request=UserStatusUpdateRequest(is_active=False),
        )
    with pytest.raises(RbacError) as role_error:
        await service.change_user_roles(
            context=context,
            target_user_id=uuid.uuid4(),
            role_ids=(world.roles["viewer"].id,),
            operation="bind",
        )
    with pytest.raises(RbacError) as transfer_error:
        await service.transfer_super_admin(
            context=context,
            target_user_id=uuid.uuid4(),
        )

    assert status_error.value.status_code == 403
    assert status_error.value.reason_code == "missing_operation_permission"
    assert role_error.value.status_code == 403
    assert role_error.value.reason_code == "missing_operation_permission"
    assert transfer_error.value.status_code == 403
    assert transfer_error.value.reason_code == "actor_is_not_super_admin"


async def test_authority_uses_all_active_roles(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    response = await client.get(
        "/api/v1/me/access",
        headers=await headers(access_token, world, "hidden_higher"),
    )

    assert response.status_code == 200
    body = response.json()["data"]
    assert body["user_id"] == str(world.users["hidden_higher"].id)
    assert body["management_tier"] == 700
    assert body["permissions"] == ["projects:read"]
    assert "authorization_epoch" in body


async def test_user_role_has_no_management_access(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    response = await client.get(
        "/api/v1/users",
        headers=await headers(access_token, world, "blank"),
    )

    assert response.status_code == 403
    assert response.json()["code"] == 403001


async def test_admin_binds_lower_role_atomically_and_audits(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    response = await client.post(
        f"/api/v1/users/{world.users['blank'].id}/roles/bind",
        json={"role_ids": [str(world.roles["viewer"].id)]},
        headers={
            **(await headers(access_token, world, "manager")),
            "X-Request-ID": "bind-lower",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["data"]["changed"] is True
    assert body["request_id"] != "bind-lower"
    assert response.headers["X-Request-ID"] == body["request_id"]
    async with SessionFactory() as session:
        assignment = await session.scalar(
            select(UserRole).where(
                UserRole.user_id == world.users["blank"].id,
                UserRole.role_id == world.roles["viewer"].id,
                UserRole.deleted_at.is_(None),
            )
        )
        audit = await session.scalar(
            select(RbacAuditEvent).where(
                RbacAuditEvent.request_id == body["request_id"]
            )
        )
    assert assignment is not None
    assert audit is not None
    assert audit.action == "user.roles.bind"
    assert audit.decision == "allowed"
    assert audit.source == "http"
    assert audit.schema_version == 1


async def test_user_role_unbind_then_rebind_preserves_history(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    user_id = world.users["blank"].id
    role_id = world.roles["viewer"].id
    manager_headers = await headers(access_token, world, "manager")
    endpoint = f"/api/v1/users/{user_id}/roles"
    body = {"role_ids": [str(role_id)]}

    bound = await client.post(f"{endpoint}/bind", json=body, headers=manager_headers)
    unbound = await client.post(
        f"{endpoint}/unbind", json=body, headers=manager_headers
    )
    async with SessionFactory() as session:
        after_unbind = await load_authority_snapshot(session, user_id=user_id)
    rebound = await client.post(f"{endpoint}/bind", json=body, headers=manager_headers)

    assert bound.status_code == 200
    assert unbound.status_code == 200
    assert rebound.status_code == 200
    assert bound.json()["data"]["changed"] is True
    assert unbound.json()["data"]["changed"] is True
    assert rebound.json()["data"]["changed"] is True
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
        after_rebind = await load_authority_snapshot(session, user_id=user_id)
    assert len(history) == 2
    assert sum(item.deleted_at is None for item in history) == 1
    tombstone = next(item for item in history if item.deleted_at is not None)
    assert tombstone.deleted_by_user_id == world.users["manager"].id
    assert PermissionKey.PROJECTS_READ.value in after_rebind.permissions


async def test_delegated_junior_admin_can_manage_a_strictly_lower_user(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    response = await client.post(
        f"/api/v1/users/{world.users['blank'].id}/roles/bind",
        json={"role_ids": [str(world.roles["viewer"].id)]},
        headers=await headers(access_token, world, "junior"),
    )

    assert response.status_code == 200
    assert response.json()["data"]["changed"] is True


@pytest.mark.parametrize(
    ("actor", "target", "expected_status"),
    [
        pytest.param("junior", "manager", 404, id="hidden-higher-target"),
        pytest.param("lower", "blank", 403, id="missing-management-capability"),
    ],
)
async def test_lower_authority_cannot_manage_users(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
    actor: str,
    target: str,
    expected_status: int,
) -> None:
    response = await client.post(
        f"/api/v1/users/{world.users[target].id}/roles/bind",
        json={"role_ids": [str(world.roles["viewer"].id)]},
        headers=await headers(access_token, world, actor),
    )

    assert response.status_code == expected_status


async def test_admin_user_writes_conceal_self_peer_higher_and_protected_targets(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    async with SessionFactory() as session:
        async with session.begin():
            protected_user = await session.get(User, world.users["newcomer"].id)
            assert protected_user is not None
            protected_user.is_protected = True

    manager_headers = await headers(access_token, world, "manager")
    missing = await client.post(
        f"/api/v1/users/{uuid.uuid4()}/roles/unbind",
        json={"role_ids": [str(world.roles["viewer"].id)]},
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
            f"/api/v1/users/{world.users[target_name].id}/roles/unbind",
            json={"role_ids": [str(world.roles["viewer"].id)]},
            headers=manager_headers,
        )
        assert response.status_code == 404
        for field in ("code", "message", "data"):
            assert response.json()[field] == missing_body[field]


async def test_admin_role_writes_conceal_peer_higher_and_protected_roles(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    manager_headers = await headers(access_token, world, "manager")
    permission_id = world.permissions[PermissionKey.PROJECTS_READ.value].id
    missing = await client.post(
        f"/api/v1/roles/{uuid.uuid4()}/permissions/bind",
        json={"expected_version": 0, "permission_ids": [str(permission_id)]},
        headers=manager_headers,
    )
    assert missing.status_code == 404
    missing_body = missing.json()

    for role_name in ("admin", "higher", "super_admin"):
        response = await client.post(
            f"/api/v1/roles/{world.roles[role_name].id}/permissions/bind",
            json={
                "expected_version": role_version(world.roles[role_name]),
                "permission_ids": [str(permission_id)],
            },
            headers=manager_headers,
        )
        assert response.status_code == 404
        for field in ("code", "message", "data"):
            assert response.json()[field] == missing_body[field]


async def test_user_role_batch_conceals_hidden_role_and_remains_atomic(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    manager_headers = await headers(access_token, world, "manager")
    target_id = world.users["blank"].id
    missing = await client.post(
        f"/api/v1/users/{target_id}/roles/bind",
        json={"role_ids": [str(uuid.uuid4())]},
        headers=manager_headers,
    )
    assert missing.status_code == 404
    missing_body = missing.json()

    response = await client.post(
        f"/api/v1/users/{target_id}/roles/bind",
        json={
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


async def test_possession_does_not_imply_delegation(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    response = await client.post(
        f"/api/v1/users/{world.users['blank'].id}/roles/bind",
        json={"role_ids": [str(world.roles["nondelegable"].id)]},
        headers=await headers(access_token, world, "manager"),
    )

    assert response.status_code == 403


async def test_system_roles_reject_lifecycle_and_permission_changes(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    super_admin_headers = await headers(access_token, world, "super_admin")
    permission_id = world.permissions[PermissionKey.PROJECTS_READ.value].id
    for role_name in ("super_admin", "admin", "user"):
        role = world.roles[role_name]
        expected_version = role_version(role)
        requests = (
            (
                f"/api/v1/roles/{role.id}/update",
                {"name": "Changed", "expected_version": expected_version},
            ),
            (
                f"/api/v1/roles/{role.id}/disable",
                {"expected_version": expected_version},
            ),
            (
                f"/api/v1/roles/{role.id}/delete",
                {"expected_version": expected_version},
            ),
            (
                f"/api/v1/roles/{role.id}/permissions/unbind",
                {
                    "expected_version": expected_version,
                    "permission_ids": [str(permission_id)],
                },
            ),
        )
        for path, body in requests:
            response = await client.post(path, json=body, headers=super_admin_headers)
            assert response.status_code == 403, (path, response.text)


async def test_role_creation_starts_empty_and_cannot_elevate_creator(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    created, _version = await create_role(
        client,
        world,
        access_token,
        actor="manager",
    )

    assert created["permissions"] == []
    assert created["delegable_permissions"] == []
    assignment = await client.post(
        f"/api/v1/users/{world.users['manager'].id}/roles/bind",
        json={"role_ids": [created["id"]]},
        headers=await headers(access_token, world, "manager"),
    )
    assert assignment.status_code == 404


async def test_owner_role_key_is_available_for_a_custom_role(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    response = await client.post(
        "/api/v1/roles",
        json={
            "key": "owner",
            "name": "Custom owner label",
            "management_tier": 10,
        },
        headers=await headers(access_token, world, "super_admin"),
    )

    assert response.status_code == 201
    role = response.json()["data"]["role"]
    assert role["key"] == "owner"
    assert role["is_system"] is False
    assert role["is_protected"] is False


async def test_role_writes_require_current_expected_version(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    created, version = await create_role(
        client,
        world,
        access_token,
        key="versioned-role",
    )
    role_id = created["id"]

    missing = await client.post(
        f"/api/v1/roles/{role_id}/update",
        json={"name": "Version one"},
        headers=await headers(access_token, world, "super_admin"),
    )
    first = await client.post(
        f"/api/v1/roles/{role_id}/update",
        json={"name": "Version one", "expected_version": version},
        headers=await headers(access_token, world, "super_admin"),
    )
    stale = await client.post(
        f"/api/v1/roles/{role_id}/update",
        json={"description": "stale write", "expected_version": version},
        headers=await headers(access_token, world, "super_admin"),
    )

    assert missing.status_code == 422
    assert missing.json()["code"] == 422001
    assert first.status_code == 200
    assert first.json()["data"]["role"]["version"] == version + 1
    assert stale.status_code == 409
    assert stale.json()["code"] == 409002


async def test_policy_denial_precedes_stale_role_version(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    role = world.roles["admin"]
    permission_id = world.permissions[PermissionKey.PROJECTS_READ.value].id
    stale_version = role_version(role) + 999
    super_admin_headers = await headers(access_token, world, "super_admin")
    requests = (
        (
            f"/api/v1/roles/{role.id}/update",
            {"name": "Forbidden", "expected_version": stale_version},
        ),
        (
            f"/api/v1/roles/{role.id}/disable",
            {"expected_version": stale_version},
        ),
        (
            f"/api/v1/roles/{role.id}/delete",
            {"expected_version": stale_version},
        ),
        (
            f"/api/v1/roles/{role.id}/permissions/bind",
            {
                "permission_ids": [str(permission_id)],
                "expected_version": stale_version,
            },
        ),
        (
            f"/api/v1/roles/{role.id}/delegable-permissions/bind",
            {
                "permission_ids": [str(permission_id)],
                "expected_version": stale_version,
            },
        ),
    )

    for path, body in requests:
        response = await client.post(path, json=body, headers=super_admin_headers)
        assert response.status_code == 403, (path, response.text)
        response_body = response.json()
        assert response_body["code"] == 403001
        async with SessionFactory() as session:
            audit = await session.scalar(
                select(RbacAuditEvent).where(
                    RbacAuditEvent.request_id == response_body["request_id"]
                )
            )
        assert audit is not None
        assert audit.decision == "denied"
        assert audit.source == "http"
        assert audit.schema_version == 1
        assert audit.reason_code != "stale_role_version"


async def test_unknown_permission_is_a_semantically_invalid_request(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    response = await client.post(
        f"/api/v1/roles/{world.roles['viewer'].id}/permissions/bind",
        json={
            "permission_ids": [str(uuid.uuid4())],
            "expected_version": role_version(world.roles["viewer"]),
        },
        headers=await headers(access_token, world, "super_admin"),
    )

    assert response.status_code == 400
    assert response.json()["code"] == 400001


async def test_incremental_permission_and_delegation_changes_are_idempotent(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
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
        f"/api/v1/roles/{role_id}/permissions/bind",
        json={"permission_ids": [str(read_id)], "expected_version": version},
        headers=super_admin_headers,
    )
    assert bound.status_code == 200
    assert bound.json()["data"]["changed"] is True
    version = bound.json()["data"]["role"]["version"]

    duplicate = await client.post(
        f"/api/v1/roles/{role_id}/permissions/bind",
        json={"permission_ids": [str(read_id)], "expected_version": version},
        headers=super_admin_headers,
    )
    assert duplicate.status_code == 200
    assert duplicate.json()["data"]["changed"] is False
    assert duplicate.json()["data"]["role"]["version"] == version

    delegated = await client.post(
        f"/api/v1/roles/{role_id}/delegable-permissions/bind",
        json={"permission_ids": [str(read_id)], "expected_version": version},
        headers=super_admin_headers,
    )
    assert delegated.status_code == 200
    version = delegated.json()["data"]["role"]["version"]

    second_permission = await client.post(
        f"/api/v1/roles/{role_id}/permissions/bind",
        json={"permission_ids": [str(update_id)], "expected_version": version},
        headers=super_admin_headers,
    )
    assert second_permission.status_code == 200
    assert second_permission.json()["data"]["role"]["delegable_permissions"] == [
        PermissionKey.PROJECTS_READ.value
    ]
    version = second_permission.json()["data"]["role"]["version"]

    removed = await client.post(
        f"/api/v1/roles/{role_id}/permissions/unbind",
        json={"permission_ids": [str(read_id)], "expected_version": version},
        headers=super_admin_headers,
    )
    assert removed.status_code == 200
    assert removed.json()["data"]["role"]["delegable_permissions"] == []
    version = removed.json()["data"]["role"]["version"]

    rebound = await client.post(
        f"/api/v1/roles/{role_id}/permissions/bind",
        json={"permission_ids": [str(read_id)], "expected_version": version},
        headers=super_admin_headers,
    )
    assert rebound.status_code == 200
    assert rebound.json()["data"]["changed"] is True

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
    assert tombstone.deleted_by_user_id == world.users["super_admin"].id


async def test_role_disable_enable_and_soft_delete_revoke_effective_access(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
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
        f"/api/v1/roles/{role_id}/permissions/bind",
        json={"permission_ids": [str(read_id)], "expected_version": version},
        headers=super_admin_headers,
    )
    version = bound_permission.json()["data"]["role"]["version"]
    bound_user = await client.post(
        f"/api/v1/users/{world.users['blank'].id}/roles/bind",
        json={"role_ids": [role_id]},
        headers=super_admin_headers,
    )
    assert bound_user.status_code == 200

    disabled = await client.post(
        f"/api/v1/roles/{role_id}/disable",
        json={"expected_version": version},
        headers=super_admin_headers,
    )
    assert disabled.status_code == 200
    version = disabled.json()["data"]["role"]["version"]
    async with SessionFactory() as session:
        after_disable = await load_authority_snapshot(
            session,
            user_id=world.users["blank"].id,
        )
    assert PermissionKey.PROJECTS_READ.value not in after_disable.permissions

    enabled = await client.post(
        f"/api/v1/roles/{role_id}/enable",
        json={"expected_version": version},
        headers=super_admin_headers,
    )
    assert enabled.status_code == 200
    version = enabled.json()["data"]["role"]["version"]

    deleted = await client.post(
        f"/api/v1/roles/{role_id}/delete",
        json={"expected_version": version},
        headers=super_admin_headers,
    )
    assert deleted.status_code == 200
    assert deleted.json()["data"]["role"]["deleted_at"] is not None
    missing = await client.get(
        f"/api/v1/roles/{role_id}",
        headers=super_admin_headers,
    )
    assert missing.status_code == 404

    async with SessionFactory() as session:
        assignments = (
            await session.scalars(
                select(UserRole).where(
                    UserRole.user_id == world.users["blank"].id,
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
        after_delete = await load_authority_snapshot(
            session,
            user_id=world.users["blank"].id,
        )
    assert assignments and all(item.deleted_at is not None for item in assignments)
    assert all(
        item.deleted_by_user_id == world.users["super_admin"].id for item in assignments
    )
    assert grants and all(item.deleted_at is not None for item in grants)
    assert all(
        item.deleted_by_user_id == world.users["super_admin"].id for item in grants
    )
    assert PermissionKey.PROJECTS_READ.value not in after_delete.permissions


async def test_admin_cannot_delete_even_a_lower_custom_role(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    created, version = await create_role(
        client,
        world,
        access_token,
        actor="manager",
        key="admin-created-role",
    )

    response = await client.post(
        f"/api/v1/roles/{created['id']}/delete",
        json={"expected_version": version},
        headers=await headers(access_token, world, "manager"),
    )

    assert response.status_code == 403


async def test_system_role_assignment_rules_and_mandatory_user_role(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    blank_id = world.users["blank"].id
    manager_headers = await headers(access_token, world, "manager")
    super_admin_headers = await headers(access_token, world, "super_admin")

    user_unbind = await client.post(
        f"/api/v1/users/{blank_id}/roles/unbind",
        json={"role_ids": [str(world.roles["user"].id)]},
        headers=manager_headers,
    )
    admin_by_admin = await client.post(
        f"/api/v1/users/{blank_id}/roles/bind",
        json={"role_ids": [str(world.roles["admin"].id)]},
        headers=manager_headers,
    )
    super_admin_by_super_admin = await client.post(
        f"/api/v1/users/{blank_id}/roles/bind",
        json={"role_ids": [str(world.roles["super_admin"].id)]},
        headers=super_admin_headers,
    )
    admin_by_super_admin = await client.post(
        f"/api/v1/users/{blank_id}/roles/bind",
        json={"role_ids": [str(world.roles["admin"].id)]},
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


async def test_super_admin_transfer_is_atomic(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    response = await client.post(
        "/api/v1/system/super-admin/transfer",
        json={"target_user_id": str(world.users["blank"].id)},
        headers=await headers(access_token, world, "super_admin"),
    )

    assert response.status_code == 200
    async with SessionFactory() as session:
        role = world.roles["super_admin"]
        assignments = (
            await session.scalars(
                select(UserRole).where(
                    UserRole.role_id == role.id,
                    UserRole.deleted_at.is_(None),
                )
            )
        ).all()
        old_super_admin_assignment = await session.scalar(
            select(UserRole).where(
                UserRole.user_id == world.users["super_admin"].id,
                UserRole.role_id == role.id,
            )
        )
        old_super_admin = await session.get(User, world.users["super_admin"].id)
        new_super_admin = await session.get(User, world.users["blank"].id)
        old_base = await session.scalar(
            select(UserRole).where(
                UserRole.user_id == world.users["super_admin"].id,
                UserRole.role_id == world.roles["user"].id,
                UserRole.deleted_at.is_(None),
            )
        )
    assert [item.user_id for item in assignments] == [world.users["blank"].id]
    assert old_super_admin is not None and old_super_admin.authz_version == 1
    assert new_super_admin is not None and new_super_admin.authz_version == 1
    assert old_base is not None
    assert old_super_admin_assignment is not None
    assert old_super_admin_assignment.deleted_at is not None
    assert (
        old_super_admin_assignment.deleted_by_user_id == world.users["super_admin"].id
    )


async def test_status_change_invalidates_old_token_after_reactivation(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    old_token = await access_token(world.users["lower"])
    user_id = world.users["lower"].id
    admin_headers = await headers(access_token, world, "manager")

    disabled = await client.post(
        f"/api/v1/users/{user_id}/disable",
        headers=admin_headers,
    )
    assert disabled.status_code == 200
    rejected = await client.get(
        "/api/v1/me/access",
        headers={"Authorization": f"Bearer {old_token}"},
    )
    assert rejected.status_code == 401

    enabled = await client.post(
        f"/api/v1/users/{user_id}/enable",
        headers=admin_headers,
    )
    assert enabled.status_code == 200
    rejected_again = await client.get(
        "/api/v1/me/access",
        headers={"Authorization": f"Bearer {old_token}"},
    )
    assert rejected_again.status_code == 401

    async with SessionFactory() as session:
        user = await session.get(User, user_id)
    assert user is not None
    assert user.token_version == 2
    assert user.authz_version == 2


async def test_logout_revokes_only_the_presented_access_token(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    first_token = await access_token(world.users["lower"])
    second_token = await access_token(world.users["lower"])

    logged_out = await client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {first_token}"},
    )
    first_rejected = await client.get(
        "/api/v1/me/access",
        headers={"Authorization": f"Bearer {first_token}"},
    )
    second_accepted = await client.get(
        "/api/v1/me/access",
        headers={"Authorization": f"Bearer {second_token}"},
    )

    assert logged_out.status_code == 200
    assert logged_out.json()["data"] == {"changed": True}
    assert first_rejected.status_code == 401
    assert second_accepted.status_code == 200


async def test_logout_all_revokes_every_access_token_for_the_current_user(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    user = world.users["lower"]
    first_token = await access_token(user)
    second_token = await access_token(user)
    previous_token_version = user.token_version

    logged_out = await client.post(
        "/api/v1/auth/logout-all",
        headers={"Authorization": f"Bearer {first_token}"},
    )
    first_rejected = await client.get(
        "/api/v1/me/access",
        headers={"Authorization": f"Bearer {first_token}"},
    )
    second_rejected = await client.get(
        "/api/v1/me/access",
        headers={"Authorization": f"Bearer {second_token}"},
    )

    async with SessionFactory() as session:
        persisted_user = await session.get(User, user.id)

    assert logged_out.status_code == 200
    assert logged_out.json()["data"] == {"changed": True}
    assert first_rejected.status_code == 401
    assert second_rejected.status_code == 401
    assert persisted_user is not None
    assert persisted_user.token_version == previous_token_version + 1


async def test_audit_failure_rolls_back_authorization_mutation(world: World) -> None:
    context = await context_for(world, "manager", "audit-must-rollback")
    service = RbacService(SessionFactory)

    def invalid_audit(**_kwargs: object) -> RbacAuditEvent:
        return RbacAuditEvent(
            actor_user_id=world.users["manager"].id,
            target_user_id=world.users["blank"].id,
            target_role_id=world.roles["viewer"].id,
            action="user.roles.bind",
            decision="invalid",
            reason_code="forced_failure",
            request_id="audit-must-rollback",
        )

    service._audit_event = invalid_audit  # type: ignore[method-assign]
    with pytest.raises(IntegrityError):
        await service.change_user_roles(
            context=context,
            target_user_id=world.users["blank"].id,
            role_ids=(world.roles["viewer"].id,),
            operation="bind",
        )

    async with SessionFactory() as session:
        assignment = await session.scalar(
            select(UserRole).where(
                UserRole.user_id == world.users["blank"].id,
                UserRole.role_id == world.roles["viewer"].id,
            )
        )
    assert assignment is None


async def test_missing_authoritative_state_returns_503(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    await remove_rbac_state_for_test()

    try:
        response = await client.get(
            "/api/v1/me/access",
            headers=await headers(access_token, world, "manager"),
        )
        assert response.status_code == 503
        assert response.json()["code"] == 503001
    finally:
        async with SessionFactory() as session:
            session.add(RbacState(scope="global", epoch=0))
            await session.commit()


async def test_missing_state_does_not_write_false_denial(world: World) -> None:
    request_id = "missing-state-is-not-a-policy-denial"
    context = await context_for(world, "manager", request_id)
    await remove_rbac_state_for_test()

    try:
        with pytest.raises(RbacError) as caught:
            await RbacService(SessionFactory).change_user_roles(
                context=context,
                target_user_id=world.users["blank"].id,
                role_ids=(world.roles["viewer"].id,),
                operation="bind",
            )
        assert caught.value.status_code == 503

        async with SessionFactory() as session:
            audit = await session.scalar(
                select(RbacAuditEvent).where(RbacAuditEvent.request_id == request_id)
            )
        assert audit is None
    finally:
        async with SessionFactory() as session:
            session.add(RbacState(scope="global", epoch=0))
            await session.commit()


async def test_privileged_requests_reject_mass_assignment(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    response = await client.post(
        f"/api/v1/roles/{world.roles['viewer'].id}/update",
        json={
            "name": "Changed",
            "is_system": True,
            "expected_version": role_version(world.roles["viewer"]),
        },
        headers=await headers(access_token, world, "manager"),
    )

    assert response.status_code == 422


async def test_permission_list_and_detail_use_uuid_identifiers(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    super_admin_headers = await headers(access_token, world, "super_admin")
    listed = await client.get("/api/v1/permissions", headers=super_admin_headers)
    permission = world.permissions[PermissionKey.SUPER_ADMIN_TRANSFER.value]
    detailed = await client.get(
        f"/api/v1/permissions/{permission.id}",
        headers=super_admin_headers,
    )

    assert listed.status_code == 200
    page = listed.json()["data"]
    assert set(page) == {"items", "page", "page_size", "total"}
    assert all(uuid.UUID(item["id"]) for item in page["items"])
    assert detailed.status_code == 200
    assert detailed.json()["data"]["key"] == PermissionKey.SUPER_ADMIN_TRANSFER.value


async def test_user_soft_delete_and_restore_never_revive_old_roles(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    target_id = world.users["lower"].id
    actor_id = world.users["super_admin"].id
    super_admin_headers = await headers(access_token, world, "super_admin")
    original_assignment_ids: set[uuid.UUID]
    async with SessionFactory() as session:
        async with session.begin():
            state = await lock_rbac_state(session)
            user = await session.scalar(
                select(User).where(User.id == target_id).with_for_update()
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
            user.deleted_by_user_id = actor_id
            user.token_version += 1
            user.authz_version += 1
            for assignment in assignments:
                assignment.deleted_at = deleted_at
                assignment.deleted_by_user_id = actor_id
            state.epoch += 1

    detailed = await client.get(
        f"/api/v1/users/{target_id}", headers=super_admin_headers
    )
    listed = await client.get(
        "/api/v1/users?page_size=200", headers=super_admin_headers
    )
    assert detailed.status_code == 404
    assert listed.status_code == 200
    assert str(target_id) not in {item["id"] for item in listed.json()["data"]["items"]}
    async with SessionFactory() as session:
        with pytest.raises(RbacError) as caught:
            await load_authority_snapshot(session, user_id=target_id)
        tombstones = tuple(
            (
                await session.scalars(
                    select(UserRole)
                    .where(UserRole.user_id == target_id)
                    .order_by(UserRole.id)
                )
            ).all()
        )
    assert caught.value.reason_code == "user_not_found"
    assert {item.id for item in tombstones} == original_assignment_ids
    assert all(item.deleted_at is not None for item in tombstones)

    async with SessionFactory() as session:
        async with session.begin():
            state = await lock_rbac_state(session)
            user = await session.scalar(
                select(User).where(User.id == target_id).with_for_update()
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
            user.authz_version += 1
            restored_assignment = UserRole(
                user_id=target_id,
                role_id=base_role.id,
                assigned_by_user_id=actor_id,
            )
            session.add(restored_assignment)
            state.epoch += 1
            await session.flush()
            restored_assignment_id = restored_assignment.id

    async with SessionFactory() as session:
        restored = await load_authority_snapshot(
            session,
            user_id=target_id,
            include_disabled_roles=True,
        )
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


async def test_permission_catalog_retirement_and_restore_require_new_grants(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    permission_key = "projects:temporary-read"
    permission_id = uuid.uuid4()
    actor_id = world.users["super_admin"].id
    role_id = world.roles["viewer"].id
    super_admin_headers = await headers(access_token, world, "super_admin")
    async with SessionFactory() as session:
        async with session.begin():
            state = await lock_rbac_state(session)
            affected_users = tuple(
                (
                    await session.scalars(
                        select(User)
                        .join(UserRole, UserRole.user_id == User.id)
                        .where(
                            UserRole.role_id == role_id,
                            UserRole.deleted_at.is_(None),
                            User.deleted_at.is_(None),
                        )
                        .order_by(User.id)
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
                assigned_by_user_id=actor_id,
            )
            session.add_all((permission, original_grant))
            role.version += 1
            for user in affected_users:
                user.authz_version += 1
            state.epoch += 1
            await session.flush()
            original_grant_id = original_grant.id

    async with SessionFactory() as session:
        async with session.begin():
            state = await lock_rbac_state(session)
            affected_users = tuple(
                (
                    await session.scalars(
                        select(User)
                        .join(UserRole, UserRole.user_id == User.id)
                        .where(
                            UserRole.role_id == role_id,
                            UserRole.deleted_at.is_(None),
                            User.deleted_at.is_(None),
                        )
                        .order_by(User.id)
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
            grant.deleted_by_user_id = actor_id
            locked_permission.deleted_at = deleted_at
            locked_permission.deleted_by_user_id = actor_id
            role.version += 1
            for user in affected_users:
                user.authz_version += 1
            state.epoch += 1

    detailed = await client.get(
        f"/api/v1/permissions/{permission_id}", headers=super_admin_headers
    )
    listed = await client.get(
        "/api/v1/permissions?page_size=200", headers=super_admin_headers
    )
    async with SessionFactory() as session:
        authority_after_delete = await load_authority_snapshot(
            session,
            user_id=world.users["lower"].id,
        )
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
            state = await lock_rbac_state(session)
            locked_permission = await session.scalar(
                select(Permission)
                .where(Permission.id == permission_id)
                .with_for_update()
            )
            assert locked_permission is not None
            locked_permission.deleted_at = None
            locked_permission.deleted_by_user_id = None
            state.epoch += 1

    async with SessionFactory() as session:
        authority_after_restore = await load_authority_snapshot(
            session,
            user_id=world.users["lower"].id,
        )
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
            state = await lock_rbac_state(session)
            affected_users = tuple(
                (
                    await session.scalars(
                        select(User)
                        .join(UserRole, UserRole.user_id == User.id)
                        .where(
                            UserRole.role_id == role_id,
                            UserRole.deleted_at.is_(None),
                            User.deleted_at.is_(None),
                        )
                        .order_by(User.id)
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
                assigned_by_user_id=actor_id,
            )
            session.add(replacement_grant)
            role.version += 1
            for user in affected_users:
                user.authz_version += 1
            state.epoch += 1
            await session.flush()
            replacement_grant_id = replacement_grant.id

    async with SessionFactory() as session:
        authority_after_rebind = await load_authority_snapshot(
            session,
            user_id=world.users["lower"].id,
        )
        old_grant = await session.get(RolePermission, original_grant_id)
    assert permission_key in authority_after_rebind.permissions
    assert replacement_grant_id != original_grant_id
    assert old_grant is not None and old_grant.deleted_at is not None
