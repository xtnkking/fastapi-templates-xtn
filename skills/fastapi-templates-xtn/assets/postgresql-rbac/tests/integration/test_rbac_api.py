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
    Permission,
    RolePermission,
    User,
    UserRole,
)
from app.rbac.queries import load_authority_snapshot
from app.rbac.schemas import RolePermissionsReplaceRequest, UserStatusUpdateRequest
from app.rbac.service import RbacService
from tests.integration.conftest import World

pytestmark = pytest.mark.postgresql
type AccessToken = Callable[[User], str]


def headers(access_token: AccessToken, world: World, user_name: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token(world.users[user_name])}"}


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


async def test_stale_actor_cannot_probe_missing_owner_transfer_target(
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


async def test_stale_actor_cannot_probe_missing_shared_role(world: World) -> None:
    context = await context_for(world, "owner", "stale-owner-missing-role")
    await increment_token_version(world.users["owner"].id)

    with pytest.raises(RbacError) as caught:
        await RbacService(SessionFactory).replace_role_permissions(
            context=context,
            role_id=uuid.uuid4(),
            request=RolePermissionsReplaceRequest(permissions=[]),
        )

    assert caught.value.status_code == 401


async def test_authority_uses_all_active_roles(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    response = await client.get(
        "/rbac/me",
        headers=headers(access_token, world, "hidden_higher"),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["user_id"] == str(world.users["hidden_higher"].id)
    assert body["management_tier"] == 700
    assert body["permissions"] == ["projects:read"]
    assert "authorization_epoch" in body


async def test_normal_permission_dependency_defaults_to_deny(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    response = await client.get(
        "/rbac/users",
        headers=headers(access_token, world, "lower"),
    )

    assert response.status_code == 403
    assert response.json() == {"detail": {"code": "rbac_forbidden"}}


async def test_manager_assigns_lower_role_and_audits(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    response = await client.put(
        f"/rbac/users/{world.users['blank'].id}/roles/{world.roles['viewer'].id}",
        headers={
            **headers(access_token, world, "manager"),
            "X-Request-ID": "assign-lower",
        },
    )

    assert response.status_code == 204
    async with SessionFactory() as session:
        assignment = await session.get(
            UserRole,
            (world.users["blank"].id, world.roles["viewer"].id),
        )
        audit = await session.scalar(
            select(AuthorizationAuditEvent).where(
                AuthorizationAuditEvent.request_id == "assign-lower"
            )
        )
        user = await session.get(User, world.users["blank"].id)
    assert assignment is not None
    assert assignment.assigned_by_user_id == world.users["manager"].id
    assert audit is not None and audit.decision == "allowed"
    assert user is not None and user.authz_version == 1


@pytest.mark.parametrize(
    ("actor", "target"),
    [("junior", "higher"), ("manager", "peer")],
)
async def test_lower_and_peer_cannot_manage_target(
    actor: str,
    target: str,
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    response = await client.put(
        f"/rbac/users/{world.users[target].id}/roles/{world.roles['viewer'].id}",
        headers=headers(access_token, world, actor),
    )

    assert response.status_code == 403


async def test_hidden_higher_role_prevents_management(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    response = await client.delete(
        f"/rbac/users/{world.users['hidden_higher'].id}/roles/"
        f"{world.roles['viewer'].id}",
        headers=headers(access_token, world, "manager"),
    )

    assert response.status_code == 403


async def test_direct_self_assignment_is_denied(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    response = await client.put(
        f"/rbac/users/{world.users['manager'].id}/roles/{world.roles['viewer'].id}",
        headers=headers(access_token, world, "manager"),
    )

    assert response.status_code == 403


async def test_possession_does_not_imply_delegation(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    response = await client.put(
        f"/rbac/users/{world.users['blank'].id}/roles/{world.roles['nondelegable'].id}",
        headers=headers(access_token, world, "manager"),
    )

    assert response.status_code == 403


async def test_actor_cannot_edit_role_it_holds(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    response = await client.put(
        f"/rbac/roles/{world.roles['manager'].id}/permissions",
        json={"permissions": ["projects:read"]},
        headers=headers(access_token, world, "manager"),
    )

    assert response.status_code == 403


async def test_shared_role_edit_checks_every_assignee_role(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    response = await client.put(
        f"/rbac/roles/{world.roles['viewer'].id}/permissions",
        json={"permissions": ["projects:read", "projects:update"]},
        headers=headers(access_token, world, "manager"),
    )

    assert response.status_code == 403


async def test_role_creation_starts_non_delegable_and_cannot_elevate_creator(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    created = await client.post(
        "/rbac/roles",
        json={
            "key": "report-reader",
            "name": "Report reader",
            "management_tier": 10,
            "permissions": ["projects:read"],
        },
        headers=headers(access_token, world, "manager"),
    )

    assert created.status_code == 201
    assert created.json()["delegable_permissions"] == []
    assignment = await client.put(
        f"/rbac/users/{world.users['manager'].id}/roles/{created.json()['id']}",
        headers=headers(access_token, world, "manager"),
    )
    assert assignment.status_code == 403


async def test_owner_transfer_is_atomic(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    response = await client.post(
        f"/rbac/ownership/transfer/{world.users['blank'].id}",
        headers=headers(access_token, world, "owner"),
    )

    assert response.status_code == 204
    async with SessionFactory() as session:
        owner_role = world.roles["owner"]
        assignments = (
            await session.scalars(
                select(UserRole).where(UserRole.role_id == owner_role.id)
            )
        ).all()
        old_owner = await session.get(User, world.users["owner"].id)
        new_owner = await session.get(User, world.users["blank"].id)
    assert [item.user_id for item in assignments] == [world.users["blank"].id]
    assert old_owner is not None and old_owner.authz_version == 1
    assert new_owner is not None and new_owner.authz_version == 1


async def test_status_change_invalidates_old_token_even_after_reactivation(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    old_token = access_token(world.users["lower"])
    url = f"/rbac/users/{world.users['lower'].id}/status"
    admin_headers = headers(access_token, world, "manager")

    disabled = await client.patch(
        url,
        json={"is_active": False},
        headers=admin_headers,
    )
    assert disabled.status_code == 200
    assert not disabled.json()["is_active"]
    rejected = await client.get(
        "/rbac/me",
        headers={"Authorization": f"Bearer {old_token}"},
    )
    assert rejected.status_code == 401

    enabled = await client.patch(
        url,
        json={"is_active": True},
        headers=admin_headers,
    )
    assert enabled.status_code == 200
    rejected_again = await client.get(
        "/rbac/me",
        headers={"Authorization": f"Bearer {old_token}"},
    )
    assert rejected_again.status_code == 401

    async with SessionFactory() as session:
        user = await session.get(User, world.users["lower"].id)
    assert user is not None
    assert user.token_version == 2
    assert user.authz_version == 2


async def test_owner_replaces_delegation_and_noop_does_not_bump_versions(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    url = f"/rbac/roles/{world.roles['viewer'].id}/delegable-permissions"
    request = {"delegable_permissions": ["projects:read"]}

    first = await client.put(
        url,
        json=request,
        headers=headers(access_token, world, "owner"),
    )
    assert first.status_code == 200
    assert first.json()["version"] == 1

    async with SessionFactory() as session:
        state_before = await session.get(AuthorizationState, "global")
        assert state_before is not None
        epoch_before = state_before.epoch

    second = await client.put(
        url,
        json=request,
        headers=headers(access_token, world, "owner"),
    )
    assert second.status_code == 200
    assert second.json()["version"] == 1
    async with SessionFactory() as session:
        state_after = await session.get(AuthorizationState, "global")
    assert state_after is not None and state_after.epoch == epoch_before


async def test_permission_replace_preserves_retained_delegation(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    owner_headers = headers(access_token, world, "owner")
    role_id = world.roles["viewer"].id
    delegated = await client.put(
        f"/rbac/roles/{role_id}/delegable-permissions",
        json={"delegable_permissions": ["projects:read"]},
        headers=owner_headers,
    )
    assert delegated.status_code == 200

    replaced = await client.put(
        f"/rbac/roles/{role_id}/permissions",
        json={"permissions": ["projects:read", "projects:update"]},
        headers=owner_headers,
    )
    assert replaced.status_code == 200
    assert replaced.json()["delegable_permissions"] == ["projects:read"]


async def test_audit_failure_rolls_back_authorization_mutation(world: World) -> None:
    context = await context_for(world, "manager", "audit-must-rollback")
    service = RbacService(SessionFactory)

    def invalid_audit(**_kwargs: object) -> AuthorizationAuditEvent:
        return AuthorizationAuditEvent(
            actor_user_id=world.users["manager"].id,
            target_user_id=world.users["blank"].id,
            target_role_id=world.roles["viewer"].id,
            action="role.assign",
            decision="invalid",
            reason_code="forced_failure",
            request_id="audit-must-rollback",
        )

    service._audit_event = invalid_audit  # type: ignore[method-assign]
    with pytest.raises(IntegrityError):
        await service.assign_role(
            context=context,
            target_user_id=world.users["blank"].id,
            role_id=world.roles["viewer"].id,
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
            "/rbac/me",
            headers=headers(access_token, world, "manager"),
        )
        assert response.status_code == 503
        assert response.json() == {"detail": {"code": "authorization_unavailable"}}
    finally:
        async with SessionFactory() as session:
            session.add(AuthorizationState(scope="global", epoch=0))
            await session.commit()


async def test_missing_authoritative_state_does_not_write_false_denial(
    world: World,
) -> None:
    request_id = "missing-state-is-not-a-policy-denial"
    context = await context_for(world, "manager", request_id)
    async with SessionFactory() as session:
        state = await session.get(AuthorizationState, "global")
        assert state is not None
        await session.delete(state)
        await session.commit()

    try:
        with pytest.raises(RbacError) as caught:
            await RbacService(SessionFactory).assign_role(
                context=context,
                target_user_id=world.users["blank"].id,
                role_id=world.roles["viewer"].id,
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


async def test_privileged_request_models_reject_mass_assignment(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    response = await client.patch(
        f"/rbac/users/{world.users['lower'].id}/status",
        json={"is_active": False, "is_protected": True},
        headers=headers(access_token, world, "manager"),
    )

    assert response.status_code == 422


async def test_role_permission_rows_use_expected_global_keys(world: World) -> None:
    async with SessionFactory() as session:
        keys = set(
            (
                await session.scalars(
                    select(Permission.key)
                    .select_from(RolePermission)
                    .join(Permission, Permission.id == RolePermission.permission_id)
                    .where(RolePermission.role_id == world.roles["owner"].id)
                )
            ).all()
        )

    assert PermissionKey.SYSTEM_OWNER_TRANSFER.value in keys
    assert "system_owner:transfer" in keys
