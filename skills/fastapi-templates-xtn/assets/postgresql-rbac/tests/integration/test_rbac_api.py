import uuid
from collections.abc import Callable

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.database import SessionFactory
from app.rbac.domain import AuthorizationContext, PermissionKey, Principal
from app.rbac.errors import RbacError
from app.rbac.models import (
    AuthorizationAuditEvent,
    AuthorizationState,
    Role,
    RolePermission,
    User,
    UserRole,
)
from app.rbac.queries import load_authority_snapshot
from app.rbac.schemas import UserStatusUpdateRequest
from app.rbac.service import RbacService
from tests.integration.conftest import World

pytestmark = pytest.mark.postgresql
type AccessToken = Callable[[User], str]


def headers(access_token: AccessToken, world: World, user_name: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token(world.users[user_name])}"}


def role_etag(role: Role) -> str:
    return f'"role:{role.id}:v{role.version}"'


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
        state = await session.get(AuthorizationState, "global")
        assert state is not None
    return AuthorizationContext(
        principal=Principal(
            user_id=world.users[user_name].id,
            token_version=world.users[user_name].token_version,
            token_id=uuid.uuid4(),
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


async def create_role(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
    *,
    actor: str = "owner",
    key: str = "report-reader",
    tier: int = 10,
) -> tuple[dict[str, object], str]:
    response = await client.post(
        "/api/v1/roles",
        json={
            "key": key,
            "name": key.replace("-", " ").title(),
            "description": "Integration-test role",
            "management_tier": tier,
        },
        headers=headers(access_token, world, actor),
    )
    assert response.status_code == 201, response.text
    return response.json()["role"], response.headers["etag"]


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
    context = await context_for(world, "owner", "stale-owner-missing-user")
    await increment_token_version(world.users["owner"].id)

    with pytest.raises(RbacError) as caught:
        await RbacService(SessionFactory).transfer_ownership(
            context=context,
            target_user_id=uuid.uuid4(),
        )

    assert caught.value.status_code == 401


async def test_stale_actor_cannot_probe_missing_role(world: World) -> None:
    context = await context_for(world, "owner", "stale-owner-missing-role")
    await increment_token_version(world.users["owner"].id)

    with pytest.raises(RbacError) as caught:
        await RbacService(SessionFactory).change_role_permissions(
            context=context,
            role_id=uuid.uuid4(),
            permission_ids=(
                world.permissions[PermissionKey.PROJECTS_READ.value].id,
            ),
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
            permission_ids=(
                world.permissions[PermissionKey.PROJECTS_READ.value].id,
            ),
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
        await service.transfer_ownership(
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
        headers=headers(access_token, world, "hidden_higher"),
    )

    assert response.status_code == 200
    body = response.json()
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
        headers=headers(access_token, world, "blank"),
    )

    assert response.status_code == 403
    assert response.json() == {"detail": {"code": "access_forbidden"}}


async def test_admin_binds_lower_role_atomically_and_audits(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    response = await client.post(
        f"/api/v1/users/{world.users['blank'].id}/roles/bind",
        json={"role_ids": [str(world.roles["viewer"].id)]},
        headers={
            **headers(access_token, world, "manager"),
            "X-Request-ID": "bind-lower",
        },
    )

    assert response.status_code == 200
    assert response.json()["changed"] is True
    async with SessionFactory() as session:
        assignment = await session.get(
            UserRole,
            (world.users["blank"].id, world.roles["viewer"].id),
        )
        audit = await session.scalar(
            select(AuthorizationAuditEvent).where(
                AuthorizationAuditEvent.request_id == "bind-lower"
            )
        )
    assert assignment is not None
    assert audit is not None
    assert audit.action == "user.roles.bind"
    assert audit.decision == "allowed"


async def test_delegated_junior_admin_can_manage_a_strictly_lower_user(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    response = await client.post(
        f"/api/v1/users/{world.users['blank'].id}/roles/bind",
        json={"role_ids": [str(world.roles["viewer"].id)]},
        headers=headers(access_token, world, "junior"),
    )

    assert response.status_code == 200
    assert response.json()["changed"] is True


@pytest.mark.parametrize(
    ("actor", "target"),
    [
        pytest.param("junior", "manager", id="lower-tier-actor"),
        pytest.param("lower", "blank", id="missing-management-capability"),
    ],
)
async def test_lower_authority_cannot_manage_users(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
    actor: str,
    target: str,
) -> None:
    response = await client.post(
        f"/api/v1/users/{world.users[target].id}/roles/bind",
        json={"role_ids": [str(world.roles["viewer"].id)]},
        headers=headers(access_token, world, actor),
    )

    assert response.status_code == 403


async def test_admin_cannot_manage_peer_or_hidden_higher_user(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    for target_name in ("peer", "hidden_higher"):
        response = await client.post(
            f"/api/v1/users/{world.users[target_name].id}/roles/unbind",
            json={"role_ids": [str(world.roles["viewer"].id)]},
            headers=headers(access_token, world, "manager"),
        )
        assert response.status_code == 403


async def test_direct_and_indirect_self_elevation_are_denied(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    direct = await client.post(
        f"/api/v1/users/{world.users['manager'].id}/roles/bind",
        json={"role_ids": [str(world.roles["viewer"].id)]},
        headers=headers(access_token, world, "manager"),
    )
    indirect = await client.post(
        f"/api/v1/roles/{world.roles['admin'].id}/permissions/bind",
        json={
            "permission_ids": [
                str(world.permissions[PermissionKey.PROJECTS_READ.value].id)
            ]
        },
        headers={
            **headers(access_token, world, "manager"),
            "If-Match": role_etag(world.roles["admin"]),
        },
    )

    assert direct.status_code == 403
    assert indirect.status_code == 403


async def test_possession_does_not_imply_delegation(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    response = await client.post(
        f"/api/v1/users/{world.users['blank'].id}/roles/bind",
        json={"role_ids": [str(world.roles["nondelegable"].id)]},
        headers=headers(access_token, world, "manager"),
    )

    assert response.status_code == 403


async def test_system_roles_reject_lifecycle_and_permission_changes(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    owner_headers = headers(access_token, world, "owner")
    permission_id = world.permissions[PermissionKey.PROJECTS_READ.value].id
    for role_name in ("super_admin", "admin", "user"):
        role = world.roles[role_name]
        etag = role_etag(role)
        requests = (
            (f"/api/v1/roles/{role.id}/update", {"name": "Changed"}),
            (f"/api/v1/roles/{role.id}/disable", None),
            (f"/api/v1/roles/{role.id}/delete", None),
            (
                f"/api/v1/roles/{role.id}/permissions/unbind",
                {"permission_ids": [str(permission_id)]},
            ),
        )
        for path, body in requests:
            request_headers = {**owner_headers, "If-Match": etag}
            response = await client.post(path, json=body, headers=request_headers)
            assert response.status_code == 403, (path, response.text)


async def test_role_creation_starts_empty_and_cannot_elevate_creator(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    created, _etag = await create_role(
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
        headers=headers(access_token, world, "manager"),
    )
    assert assignment.status_code == 403


async def test_legacy_owner_role_key_is_reserved(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    response = await client.post(
        "/api/v1/roles",
        json={
            "key": "owner",
            "name": "Legacy owner collision",
            "management_tier": 10,
        },
        headers=headers(access_token, world, "owner"),
    )

    assert response.status_code == 409
    assert response.json() == {"detail": {"code": "authorization_conflict"}}


async def test_role_writes_require_current_etag(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    created, etag_v0 = await create_role(
        client,
        world,
        access_token,
        key="etag-role",
    )
    role_id = created["id"]

    missing = await client.post(
        f"/api/v1/roles/{role_id}/update",
        json={"name": "Version one"},
        headers=headers(access_token, world, "owner"),
    )
    first = await client.post(
        f"/api/v1/roles/{role_id}/update",
        json={"name": "Version one"},
        headers={
            **headers(access_token, world, "owner"),
            "If-Match": etag_v0,
        },
    )
    stale = await client.post(
        f"/api/v1/roles/{role_id}/update",
        json={"description": "stale write"},
        headers={
            **headers(access_token, world, "owner"),
            "If-Match": etag_v0,
        },
    )

    assert missing.status_code == 428
    assert first.status_code == 200
    assert first.headers["etag"].endswith(":v1\"")
    assert stale.status_code == 412


async def test_incremental_permission_and_delegation_changes_are_idempotent(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    created, etag = await create_role(
        client,
        world,
        access_token,
        key="permission-delta-role",
    )
    role_id = created["id"]
    read_id = world.permissions[PermissionKey.PROJECTS_READ.value].id
    update_id = world.permissions[PermissionKey.PROJECTS_UPDATE.value].id
    owner_headers = headers(access_token, world, "owner")

    bound = await client.post(
        f"/api/v1/roles/{role_id}/permissions/bind",
        json={"permission_ids": [str(read_id)]},
        headers={**owner_headers, "If-Match": etag},
    )
    assert bound.status_code == 200
    assert bound.json()["changed"] is True
    etag = bound.headers["etag"]

    duplicate = await client.post(
        f"/api/v1/roles/{role_id}/permissions/bind",
        json={"permission_ids": [str(read_id)]},
        headers={**owner_headers, "If-Match": etag},
    )
    assert duplicate.status_code == 200
    assert duplicate.json()["changed"] is False
    assert duplicate.headers["etag"] == etag

    delegated = await client.post(
        f"/api/v1/roles/{role_id}/delegable-permissions/bind",
        json={"permission_ids": [str(read_id)]},
        headers={**owner_headers, "If-Match": etag},
    )
    assert delegated.status_code == 200
    etag = delegated.headers["etag"]

    second_permission = await client.post(
        f"/api/v1/roles/{role_id}/permissions/bind",
        json={"permission_ids": [str(update_id)]},
        headers={**owner_headers, "If-Match": etag},
    )
    assert second_permission.status_code == 200
    assert second_permission.json()["role"]["delegable_permissions"] == [
        PermissionKey.PROJECTS_READ.value
    ]
    etag = second_permission.headers["etag"]

    removed = await client.post(
        f"/api/v1/roles/{role_id}/permissions/unbind",
        json={"permission_ids": [str(read_id)]},
        headers={**owner_headers, "If-Match": etag},
    )
    assert removed.status_code == 200
    assert removed.json()["role"]["delegable_permissions"] == []


async def test_role_disable_enable_and_soft_delete_revoke_effective_access(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    created, etag = await create_role(
        client,
        world,
        access_token,
        key="lifecycle-role",
    )
    role_id = created["id"]
    read_id = world.permissions[PermissionKey.PROJECTS_READ.value].id
    owner_headers = headers(access_token, world, "owner")

    bound_permission = await client.post(
        f"/api/v1/roles/{role_id}/permissions/bind",
        json={"permission_ids": [str(read_id)]},
        headers={**owner_headers, "If-Match": etag},
    )
    etag = bound_permission.headers["etag"]
    bound_user = await client.post(
        f"/api/v1/users/{world.users['blank'].id}/roles/bind",
        json={"role_ids": [role_id]},
        headers=owner_headers,
    )
    assert bound_user.status_code == 200

    disabled = await client.post(
        f"/api/v1/roles/{role_id}/disable",
        headers={**owner_headers, "If-Match": etag},
    )
    assert disabled.status_code == 200
    etag = disabled.headers["etag"]
    async with SessionFactory() as session:
        after_disable = await load_authority_snapshot(
            session,
            user_id=world.users["blank"].id,
        )
    assert PermissionKey.PROJECTS_READ.value not in after_disable.permissions

    enabled = await client.post(
        f"/api/v1/roles/{role_id}/enable",
        headers={**owner_headers, "If-Match": etag},
    )
    assert enabled.status_code == 200
    etag = enabled.headers["etag"]

    deleted = await client.post(
        f"/api/v1/roles/{role_id}/delete",
        headers={**owner_headers, "If-Match": etag},
    )
    assert deleted.status_code == 200
    assert deleted.json()["role"]["deleted_at"] is not None
    missing = await client.get(
        f"/api/v1/roles/{role_id}",
        headers=owner_headers,
    )
    assert missing.status_code == 404

    async with SessionFactory() as session:
        assignment = await session.get(
            UserRole,
            (world.users["blank"].id, uuid.UUID(str(role_id))),
        )
        grant = await session.scalar(
            select(RolePermission).where(RolePermission.role_id == role_id)
        )
        after_delete = await load_authority_snapshot(
            session,
            user_id=world.users["blank"].id,
        )
    assert assignment is not None
    assert grant is not None
    assert PermissionKey.PROJECTS_READ.value not in after_delete.permissions


async def test_admin_cannot_delete_even_a_lower_custom_role(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    created, etag = await create_role(
        client,
        world,
        access_token,
        actor="manager",
        key="admin-created-role",
    )

    response = await client.post(
        f"/api/v1/roles/{created['id']}/delete",
        headers={
            **headers(access_token, world, "manager"),
            "If-Match": etag,
        },
    )

    assert response.status_code == 403


async def test_system_role_assignment_rules_and_mandatory_user_role(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    blank_id = world.users["blank"].id
    manager_headers = headers(access_token, world, "manager")
    owner_headers = headers(access_token, world, "owner")

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
    super_admin_by_owner = await client.post(
        f"/api/v1/users/{blank_id}/roles/bind",
        json={"role_ids": [str(world.roles["super_admin"].id)]},
        headers=owner_headers,
    )
    admin_by_owner = await client.post(
        f"/api/v1/users/{blank_id}/roles/bind",
        json={"role_ids": [str(world.roles["admin"].id)]},
        headers=owner_headers,
    )

    assert user_unbind.status_code == 403
    assert admin_by_admin.status_code == 403
    assert super_admin_by_owner.status_code == 403
    assert admin_by_owner.status_code == 200

    async with SessionFactory() as session:
        user_assignment = await session.get(
            UserRole,
            (blank_id, world.roles["user"].id),
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
        headers=headers(access_token, world, "owner"),
    )

    assert response.status_code == 200
    async with SessionFactory() as session:
        role = world.roles["super_admin"]
        assignments = (
            await session.scalars(select(UserRole).where(UserRole.role_id == role.id))
        ).all()
        old_owner = await session.get(User, world.users["owner"].id)
        new_owner = await session.get(User, world.users["blank"].id)
        old_base = await session.get(
            UserRole,
            (world.users["owner"].id, world.roles["user"].id),
        )
    assert [item.user_id for item in assignments] == [world.users["blank"].id]
    assert old_owner is not None and old_owner.authz_version == 1
    assert new_owner is not None and new_owner.authz_version == 1
    assert old_base is not None


async def test_status_change_invalidates_old_token_after_reactivation(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    old_token = access_token(world.users["lower"])
    user_id = world.users["lower"].id
    admin_headers = headers(access_token, world, "manager")

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


async def test_audit_failure_rolls_back_authorization_mutation(world: World) -> None:
    context = await context_for(world, "manager", "audit-must-rollback")
    service = RbacService(SessionFactory)

    def invalid_audit(**_kwargs: object) -> AuthorizationAuditEvent:
        return AuthorizationAuditEvent(
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
        assignment = await session.get(
            UserRole,
            (world.users["blank"].id, world.roles["viewer"].id),
        )
    assert assignment is None


async def test_missing_authoritative_state_returns_503(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    async with SessionFactory() as session:
        state = await session.get(AuthorizationState, "global")
        assert state is not None
        await session.delete(state)
        await session.commit()

    try:
        response = await client.get(
            "/api/v1/me/access",
            headers=headers(access_token, world, "manager"),
        )
        assert response.status_code == 503
        assert response.json() == {"detail": {"code": "authorization_unavailable"}}
    finally:
        async with SessionFactory() as session:
            session.add(AuthorizationState(scope="global", epoch=0))
            await session.commit()


async def test_missing_state_does_not_write_false_denial(world: World) -> None:
    request_id = "missing-state-is-not-a-policy-denial"
    context = await context_for(world, "manager", request_id)
    async with SessionFactory() as session:
        state = await session.get(AuthorizationState, "global")
        assert state is not None
        await session.delete(state)
        await session.commit()

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
                select(AuthorizationAuditEvent).where(
                    AuthorizationAuditEvent.request_id == request_id
                )
            )
        assert audit is None
    finally:
        async with SessionFactory() as session:
            session.add(AuthorizationState(scope="global", epoch=0))
            await session.commit()


async def test_privileged_requests_reject_mass_assignment(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    response = await client.post(
        f"/api/v1/roles/{world.roles['viewer'].id}/update",
        json={"name": "Changed", "is_system": True},
        headers={
            **headers(access_token, world, "manager"),
            "If-Match": role_etag(world.roles["viewer"]),
        },
    )

    assert response.status_code == 422


async def test_permission_list_and_detail_use_uuid_identifiers(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    owner_headers = headers(access_token, world, "owner")
    listed = await client.get("/api/v1/permissions", headers=owner_headers)
    permission = world.permissions[PermissionKey.SUPER_ADMIN_TRANSFER.value]
    detailed = await client.get(
        f"/api/v1/permissions/{permission.id}",
        headers=owner_headers,
    )

    assert listed.status_code == 200
    assert all(uuid.UUID(item["id"]) for item in listed.json())
    assert detailed.status_code == 200
    assert detailed.json()["key"] == PermissionKey.SUPER_ADMIN_TRANSFER.value
