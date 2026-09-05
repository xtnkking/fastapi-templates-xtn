import uuid
from collections.abc import Callable

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import SessionFactory
from app.rbac.domain import AuthorizationContext, PermissionKey, Principal
from app.rbac.errors import RbacError, forbidden
from app.rbac.models import (
    AuthorizationAuditEvent,
    MembershipRole,
    Permission,
    Role,
    RolePermission,
    Tenant,
    TenantAuthorizationState,
    User,
)
from app.rbac.queries import load_authority_snapshot
from app.rbac.service import RbacService, _MutationOutcome
from tests.integration.conftest import World

pytestmark = pytest.mark.postgresql
type AccessToken = Callable[[User, Tenant], str]


def headers(access_token: AccessToken, world: World, user_name: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {access_token(world.users[user_name], world.tenant)}",
        "X-Request-ID": f"test-{user_name}",
    }


async def test_authority_uses_all_active_roles(
    client: AsyncClient,
    access_token: AccessToken,
    world: World,
) -> None:
    response = await client.get(
        f"/tenants/{world.tenant.id}/rbac/me",
        headers=headers(access_token, world, "hidden_higher"),
    )

    assert response.status_code == 200
    assert response.json()["management_tier"] == 700
    assert response.json()["permissions"] == ["projects:read"]


async def test_normal_permission_dependency_defaults_to_deny(
    client: AsyncClient,
    access_token: AccessToken,
    world: World,
) -> None:
    allowed = await client.get(
        f"/tenants/{world.tenant.id}/rbac/roles",
        headers=headers(access_token, world, "manager"),
    )
    denied = await client.get(
        f"/tenants/{world.tenant.id}/rbac/roles",
        headers=headers(access_token, world, "blank"),
    )

    assert allowed.status_code == 200
    assert denied.status_code == 403


async def test_manager_assigns_lower_role_and_audits(
    client: AsyncClient,
    access_token: AccessToken,
    world: World,
) -> None:
    response = await client.put(
        f"/tenants/{world.tenant.id}/rbac/memberships/"
        f"{world.memberships['blank'].id}/roles/{world.roles['viewer'].id}",
        headers=headers(access_token, world, "manager"),
    )

    assert response.status_code == 204
    async with SessionFactory() as session:
        assignment = await session.scalar(
            select(MembershipRole).where(
                MembershipRole.membership_id == world.memberships["blank"].id,
                MembershipRole.role_id == world.roles["viewer"].id,
            )
        )
        audit = await session.scalar(
            select(AuthorizationAuditEvent).where(
                AuthorizationAuditEvent.request_id == "test-manager"
            )
        )
    assert assignment is not None
    assert audit is not None
    assert audit.decision == "allowed"


@pytest.mark.parametrize("actor,target", [("junior", "higher"), ("manager", "peer")])
async def test_lower_and_peer_cannot_manage_target(
    client: AsyncClient,
    access_token: AccessToken,
    world: World,
    actor: str,
    target: str,
) -> None:
    response = await client.put(
        f"/tenants/{world.tenant.id}/rbac/memberships/"
        f"{world.memberships[target].id}/roles/{world.roles['viewer'].id}",
        headers=headers(access_token, world, actor),
    )

    assert response.status_code == 403
    assert response.json() == {"detail": {"code": "rbac_forbidden"}}


async def test_hidden_higher_role_prevents_management(
    client: AsyncClient,
    access_token: AccessToken,
    world: World,
) -> None:
    response = await client.delete(
        f"/tenants/{world.tenant.id}/rbac/memberships/"
        f"{world.memberships['hidden_higher'].id}/roles/"
        f"{world.roles['viewer'].id}",
        headers=headers(access_token, world, "manager"),
    )

    assert response.status_code == 403


async def test_direct_self_assignment_is_denied(
    client: AsyncClient,
    access_token: AccessToken,
    world: World,
) -> None:
    response = await client.put(
        f"/tenants/{world.tenant.id}/rbac/memberships/"
        f"{world.memberships['manager'].id}/roles/{world.roles['viewer'].id}",
        headers=headers(access_token, world, "manager"),
    )

    assert response.status_code == 403


async def test_missing_operation_permission_is_denied_and_audited(
    client: AsyncClient,
    access_token: AccessToken,
    world: World,
) -> None:
    response = await client.put(
        f"/tenants/{world.tenant.id}/rbac/memberships/"
        f"{world.memberships['lower'].id}/roles/{world.roles['viewer'].id}",
        headers=headers(access_token, world, "blank"),
    )

    assert response.status_code == 403
    async with SessionFactory() as session:
        audit = await session.scalar(
            select(AuthorizationAuditEvent).where(
                AuthorizationAuditEvent.request_id == "test-blank"
            )
        )
    assert audit is not None
    assert audit.decision == "denied"
    assert audit.reason_code == "missing_operation_permission"


async def test_possession_does_not_imply_delegation(
    client: AsyncClient,
    access_token: AccessToken,
    world: World,
) -> None:
    response = await client.put(
        f"/tenants/{world.tenant.id}/rbac/memberships/"
        f"{world.memberships['blank'].id}/roles/"
        f"{world.roles['nondelegable'].id}",
        headers=headers(access_token, world, "manager"),
    )

    assert response.status_code == 403


async def test_cross_tenant_membership_is_concealed(
    client: AsyncClient,
    access_token: AccessToken,
    world: World,
) -> None:
    response = await client.put(
        f"/tenants/{world.tenant.id}/rbac/memberships/"
        f"{world.memberships['outsider'].id}/roles/{world.roles['viewer'].id}",
        headers=headers(access_token, world, "manager"),
    )

    assert response.status_code == 404
    assert response.json() == {"detail": {"code": "not_found"}}


async def test_actor_cannot_edit_role_it_holds(
    client: AsyncClient,
    access_token: AccessToken,
    world: World,
) -> None:
    response = await client.put(
        f"/tenants/{world.tenant.id}/rbac/roles/"
        f"{world.roles['manager'].id}/permissions",
        headers=headers(access_token, world, "manager"),
        json={"permissions": ["projects:read"]},
    )

    assert response.status_code == 403


async def test_shared_role_edit_checks_every_assignee_role(
    client: AsyncClient,
    access_token: AccessToken,
    world: World,
) -> None:
    response = await client.put(
        f"/tenants/{world.tenant.id}/rbac/roles/{world.roles['viewer'].id}/permissions",
        headers=headers(access_token, world, "manager"),
        json={"permissions": ["projects:read", "projects:update"]},
    )

    # hidden_higher also holds viewer, so the equal-looking shared role is unsafe.
    assert response.status_code == 403


async def test_role_creation_never_creates_delegable_grants(
    client: AsyncClient,
    access_token: AccessToken,
    world: World,
) -> None:
    response = await client.post(
        f"/tenants/{world.tenant.id}/rbac/roles",
        headers=headers(access_token, world, "manager"),
        json={
            "key": "report-reader",
            "name": "Report reader",
            "management_tier": 40,
            "permissions": ["projects:read"],
        },
    )

    assert response.status_code == 201
    role_id = uuid.UUID(response.json()["id"])
    async with SessionFactory() as session:
        grants = (
            await session.scalars(
                select(RolePermission).where(RolePermission.role_id == role_id)
            )
        ).all()
    assert grants
    assert not any(grant.can_delegate for grant in grants)

    replace_response = await client.put(
        f"/tenants/{world.tenant.id}/rbac/roles/{role_id}/permissions",
        headers=headers(access_token, world, "manager"),
        json={"permissions": ["projects:update"]},
    )
    assert replace_response.status_code == 200
    assert replace_response.json()["permissions"] == ["projects:update"]


async def test_owner_transfer_is_atomic_and_ordinary_assignment_cannot_add_owner(
    client: AsyncClient,
    access_token: AccessToken,
    world: World,
) -> None:
    ordinary_response = await client.put(
        f"/tenants/{world.tenant.id}/rbac/memberships/"
        f"{world.memberships['blank'].id}/roles/{world.roles['owner'].id}",
        headers=headers(access_token, world, "manager"),
    )
    assert ordinary_response.status_code == 403

    transfer_response = await client.post(
        f"/tenants/{world.tenant.id}/rbac/ownership/transfer/"
        f"{world.memberships['blank'].id}",
        headers=headers(access_token, world, "owner"),
    )
    assert transfer_response.status_code == 204

    async with SessionFactory() as session:
        owner_assignments = (
            await session.scalars(
                select(MembershipRole).where(
                    MembershipRole.tenant_id == world.tenant.id,
                    MembershipRole.role_id == world.roles["owner"].id,
                )
            )
        ).all()
    assert [item.membership_id for item in owner_assignments] == [
        world.memberships["blank"].id
    ]


async def test_manager_can_create_suspend_and_reactivate_lower_membership(
    client: AsyncClient,
    access_token: AccessToken,
    world: World,
) -> None:
    create_response = await client.post(
        f"/tenants/{world.tenant.id}/rbac/memberships",
        headers=headers(access_token, world, "manager"),
        json={"user_id": str(world.users["newcomer"].id)},
    )

    assert create_response.status_code == 201
    created = create_response.json()
    assert created["user_id"] == str(world.users["newcomer"].id)
    assert created["permissions"] == []
    membership_id = created["id"]

    suspend_response = await client.patch(
        f"/tenants/{world.tenant.id}/rbac/memberships/{membership_id}/status",
        headers=headers(access_token, world, "manager"),
        json={"status": "suspended"},
    )
    assert suspend_response.status_code == 200
    assert suspend_response.json()["status"] == "suspended"

    suspended_access = await client.get(
        f"/tenants/{world.tenant.id}/rbac/me",
        headers={
            "Authorization": (
                f"Bearer {access_token(world.users['newcomer'], world.tenant)}"
            )
        },
    )
    assert suspended_access.status_code == 404

    reactivate_response = await client.patch(
        f"/tenants/{world.tenant.id}/rbac/memberships/{membership_id}/status",
        headers=headers(access_token, world, "manager"),
        json={"status": "active"},
    )
    assert reactivate_response.status_code == 200
    assert reactivate_response.json()["status"] == "active"


async def test_membership_management_rejects_inactive_and_peer_targets(
    client: AsyncClient,
    access_token: AccessToken,
    world: World,
) -> None:
    inactive_response = await client.post(
        f"/tenants/{world.tenant.id}/rbac/memberships",
        headers=headers(access_token, world, "manager"),
        json={"user_id": str(world.users["disabled"].id)},
    )
    peer_response = await client.patch(
        f"/tenants/{world.tenant.id}/rbac/memberships/"
        f"{world.memberships['peer'].id}/status",
        headers=headers(access_token, world, "manager"),
        json={"status": "suspended"},
    )

    assert inactive_response.status_code == 403
    assert peer_response.status_code == 403


async def test_owner_replaces_delegation_and_noop_does_not_bump_versions(
    client: AsyncClient,
    access_token: AccessToken,
    world: World,
) -> None:
    url = (
        f"/tenants/{world.tenant.id}/rbac/roles/"
        f"{world.roles['manager'].id}/delegable-permissions"
    )
    first = await client.put(
        url,
        headers=headers(access_token, world, "owner"),
        json={"delegable_permissions": ["projects:read"]},
    )
    second = await client.put(
        url,
        headers=headers(access_token, world, "owner"),
        json={"delegable_permissions": ["projects:read"]},
    )

    assert first.status_code == 200
    assert first.json()["delegable_permissions"] == ["projects:read"]
    assert second.status_code == 200
    async with SessionFactory() as session:
        role = await session.get(Role, world.roles["manager"].id)
        state = await session.get(TenantAuthorizationState, world.tenant.id)
        audits = (
            await session.scalars(
                select(AuthorizationAuditEvent)
                .where(AuthorizationAuditEvent.action == "role.delegation.replace")
                .order_by(AuthorizationAuditEvent.created_at)
            )
        ).all()
    assert role is not None
    assert state is not None
    assert role.version == 1
    assert state.epoch == 1
    assert [audit.reason_code for audit in audits] == [
        "role_delegation_replaced",
        "role_delegation_unchanged",
    ]


async def test_permission_replace_preserves_retained_delegation(
    client: AsyncClient,
    access_token: AccessToken,
    world: World,
) -> None:
    response = await client.put(
        f"/tenants/{world.tenant.id}/rbac/roles/"
        f"{world.roles['manager'].id}/permissions",
        headers=headers(access_token, world, "owner"),
        json={
            "permissions": [
                "memberships:read",
                "projects:read",
                "roles:read",
            ]
        },
    )

    assert response.status_code == 200
    assert response.json()["delegable_permissions"] == ["projects:read"]


async def test_non_owner_cannot_use_delegation_control_even_with_permission(
    client: AsyncClient,
    access_token: AccessToken,
    world: World,
) -> None:
    async with SessionFactory() as session:
        permission = await session.scalar(
            select(Permission).where(
                Permission.key == PermissionKey.ROLES_DELEGATION_UPDATE.value
            )
        )
        assert permission is not None
        session.add(
            RolePermission(
                tenant_id=world.tenant.id,
                role_id=world.roles["junior_admin"].id,
                permission_id=permission.id,
                can_delegate=False,
            )
        )
        await session.commit()

    response = await client.put(
        f"/tenants/{world.tenant.id}/rbac/roles/"
        f"{world.roles['viewer'].id}/delegable-permissions",
        headers=headers(access_token, world, "junior"),
        json={"delegable_permissions": ["projects:read"]},
    )

    assert response.status_code == 403


async def test_delegation_rejects_non_role_and_control_permissions(
    client: AsyncClient,
    access_token: AccessToken,
    world: World,
) -> None:
    url = (
        f"/tenants/{world.tenant.id}/rbac/roles/"
        f"{world.roles['manager'].id}/delegable-permissions"
    )
    missing_role_permission = await client.put(
        url,
        headers=headers(access_token, world, "owner"),
        json={"delegable_permissions": ["tenant_ownership:transfer"]},
    )
    assert missing_role_permission.status_code == 422

    async with SessionFactory() as session:
        permission = await session.scalar(
            select(Permission).where(
                Permission.key == PermissionKey.TENANT_OWNERSHIP_TRANSFER.value
            )
        )
        assert permission is not None
        session.add(
            RolePermission(
                tenant_id=world.tenant.id,
                role_id=world.roles["manager"].id,
                permission_id=permission.id,
                can_delegate=False,
            )
        )
        await session.commit()

    protected_permission = await client.put(
        url,
        headers=headers(access_token, world, "owner"),
        json={"delegable_permissions": ["tenant_ownership:transfer"]},
    )
    assert protected_permission.status_code == 403


async def test_create_then_assign_to_self_is_denied(
    client: AsyncClient,
    access_token: AccessToken,
    world: World,
) -> None:
    created = await client.post(
        f"/tenants/{world.tenant.id}/rbac/roles",
        headers=headers(access_token, world, "manager"),
        json={
            "key": "self-escalation-attempt",
            "name": "Self escalation attempt",
            "management_tier": 40,
            "permissions": ["projects:read"],
        },
    )
    assert created.status_code == 201

    assignment = await client.put(
        f"/tenants/{world.tenant.id}/rbac/memberships/"
        f"{world.memberships['manager'].id}/roles/{created.json()['id']}",
        headers=headers(access_token, world, "manager"),
    )
    assert assignment.status_code == 403


async def test_role_create_does_not_reveal_platform_permission_catalog(
    client: AsyncClient,
    access_token: AccessToken,
    world: World,
) -> None:
    async with SessionFactory() as session:
        session.add(
            Permission(
                id=uuid.uuid4(),
                key="platform:break_glass",
                description="Platform-only emergency capability",
            )
        )
        await session.commit()

    url = f"/tenants/{world.tenant.id}/rbac/roles"
    responses = [
        await client.post(
            url,
            headers=headers(access_token, world, "owner"),
            json={
                "key": role_key,
                "name": "Unavailable permission role",
                "management_tier": 10,
                "permissions": [permission_key],
            },
        )
        for role_key, permission_key in (
            ("platform-probe", "platform:break_glass"),
            ("unknown-probe", "unknown:capability"),
        )
    ]

    assert [response.status_code for response in responses] == [422, 422]
    assert (
        responses[0].json()
        == responses[1].json()
        == {"detail": {"code": "invalid_request"}}
    )


async def test_disabled_role_assignment_can_be_safely_revoked(
    client: AsyncClient,
    access_token: AccessToken,
    world: World,
) -> None:
    async with SessionFactory() as session:
        role = await session.get(Role, world.roles["viewer"].id)
        assert role is not None
        role.is_active = False
        await session.commit()

    response = await client.delete(
        f"/tenants/{world.tenant.id}/rbac/memberships/"
        f"{world.memberships['lower'].id}/roles/{world.roles['viewer'].id}",
        headers=headers(access_token, world, "manager"),
    )

    assert response.status_code == 204
    async with SessionFactory() as session:
        assignment = await session.scalar(
            select(MembershipRole).where(
                MembershipRole.membership_id == world.memberships["lower"].id,
                MembershipRole.role_id == world.roles["viewer"].id,
            )
        )
    assert assignment is None


async def test_denied_operation_rolls_back_mutation_before_audit(world: World) -> None:
    async with SessionFactory() as session:
        authority = await load_authority_snapshot(
            session,
            tenant_id=world.tenant.id,
            membership_id=world.memberships["manager"].id,
        )
        state = await session.get(TenantAuthorizationState, world.tenant.id)
        assert state is not None
        original_epoch = state.epoch

    context = AuthorizationContext(
        principal=Principal(
            user_id=world.users["manager"].id,
            token_tenant_id=world.tenant.id,
            token_version=world.users["manager"].token_version,
            token_id=str(uuid.uuid4()),
        ),
        tenant_id=world.tenant.id,
        tenant_authz_epoch=original_epoch,
        authority=authority,
        request_id="test-mutate-then-deny",
    )
    service = RbacService(SessionFactory)

    async def mutate_then_deny(
        session: AsyncSession,
    ) -> _MutationOutcome[None]:
        mutable_state = await session.get(TenantAuthorizationState, world.tenant.id)
        assert mutable_state is not None
        mutable_state.epoch += 100
        await session.flush()
        raise forbidden("forced_denial_after_flush")

    with pytest.raises(RbacError):
        await service._run_audited(
            context=context,
            action="test.mutate_then_deny",
            target_membership_id=None,
            target_role_id=None,
            operation=mutate_then_deny,
        )

    async with SessionFactory() as session:
        persisted_state = await session.get(TenantAuthorizationState, world.tenant.id)
        audit = await session.scalar(
            select(AuthorizationAuditEvent).where(
                AuthorizationAuditEvent.request_id == "test-mutate-then-deny"
            )
        )
    assert persisted_state is not None
    assert persisted_state.epoch == original_epoch
    assert audit is not None
    assert audit.decision == "denied"
    assert audit.reason_code == "forced_denial_after_flush"


async def test_direct_service_call_rejects_token_tenant_mismatch(world: World) -> None:
    async with SessionFactory() as session:
        authority = await load_authority_snapshot(
            session,
            tenant_id=world.second_tenant.id,
            membership_id=world.memberships["outsider"].id,
        )
        state = await session.get(TenantAuthorizationState, world.second_tenant.id)
        assert state is not None
        original_epoch = state.epoch

    context = AuthorizationContext(
        principal=Principal(
            user_id=world.users["outsider"].id,
            token_tenant_id=world.tenant.id,
            token_version=world.users["outsider"].token_version,
            token_id=str(uuid.uuid4()),
        ),
        tenant_id=world.second_tenant.id,
        tenant_authz_epoch=original_epoch,
        authority=authority,
        request_id="test-direct-service-cross-tenant",
    )
    service = RbacService(SessionFactory)

    async def forbidden_cross_tenant_operation(
        session: AsyncSession,
    ) -> _MutationOutcome[None]:
        mutable_state = await session.get(
            TenantAuthorizationState, world.second_tenant.id
        )
        assert mutable_state is not None
        mutable_state.epoch += 1
        return _MutationOutcome(value=None, reason_code="must_not_run")

    with pytest.raises(RbacError) as caught:
        await service._run_audited(
            context=context,
            action="test.cross_tenant_service_call",
            target_membership_id=None,
            target_role_id=None,
            operation=forbidden_cross_tenant_operation,
        )

    assert caught.value.status_code == 404
    async with SessionFactory() as session:
        persisted_state = await session.get(
            TenantAuthorizationState, world.second_tenant.id
        )
        audit = await session.scalar(
            select(AuthorizationAuditEvent).where(
                AuthorizationAuditEvent.request_id == "test-direct-service-cross-tenant"
            )
        )
    assert persisted_state is not None
    assert persisted_state.epoch == original_epoch
    assert audit is not None
    assert audit.decision == "denied"
    assert audit.reason_code == "tenant_not_visible"


async def test_privileged_request_models_reject_mass_assignment(
    client: AsyncClient,
    access_token: AccessToken,
    world: World,
) -> None:
    response = await client.post(
        f"/tenants/{world.tenant.id}/rbac/roles",
        headers=headers(access_token, world, "manager"),
        json={
            "key": "mass-assignment",
            "name": "Mass assignment",
            "management_tier": 40,
            "permissions": ["projects:read"],
            "is_protected": True,
        },
    )

    assert response.status_code == 422
