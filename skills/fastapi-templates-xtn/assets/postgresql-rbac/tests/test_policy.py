import uuid

from app.rbac.domain import AuthoritySnapshot, PermissionKey, RoleGrant
from app.rbac.policy import (
    decide_membership_create,
    decide_membership_status_change,
    decide_role_change,
    decide_role_create,
    decide_role_delegation_replace,
    decide_role_permissions_replace,
)


def role(
    *,
    tier: int,
    permissions: set[str],
    delegable: set[str] | None = None,
    protected: bool = False,
    owner: bool = False,
) -> RoleGrant:
    return RoleGrant(
        role_id=uuid.uuid4(),
        management_tier=tier,
        permissions=frozenset(permissions),
        delegable_permissions=frozenset(delegable or set()),
        is_protected=protected,
        is_owner=owner,
    )


def authority(
    *roles: RoleGrant,
    user_id: uuid.UUID | None = None,
    membership_protected: bool = False,
    membership_status: str = "active",
    user_is_active: bool = True,
) -> AuthoritySnapshot:
    return AuthoritySnapshot.build(
        membership_id=uuid.uuid4(),
        user_id=user_id or uuid.uuid4(),
        membership_status=membership_status,
        membership_is_protected=membership_protected,
        user_is_protected=False,
        authz_version=1,
        roles=roles,
        user_is_active=user_is_active,
    )


def administrative_actor(*, tier: int = 500) -> AuthoritySnapshot:
    return authority(
        role(
            tier=tier,
            permissions={
                PermissionKey.ROLES_ASSIGN.value,
                PermissionKey.ROLES_REVOKE.value,
                PermissionKey.ROLES_PERMISSIONS_UPDATE.value,
                PermissionKey.PROJECTS_READ.value,
            },
            delegable={PermissionKey.PROJECTS_READ.value},
        )
    )


def test_multi_role_snapshot_uses_union_and_maximum_tier() -> None:
    snapshot = authority(
        role(tier=20, permissions={PermissionKey.PROJECTS_READ.value}),
        role(tier=700, permissions={PermissionKey.PROJECTS_UPDATE.value}),
    )

    assert snapshot.management_tier == 700
    assert snapshot.permissions == {
        PermissionKey.PROJECTS_READ.value,
        PermissionKey.PROJECTS_UPDATE.value,
    }


def test_higher_actor_can_assign_lower_delegable_role() -> None:
    actor = administrative_actor()
    target = authority()
    changed_role = role(
        tier=20,
        permissions={PermissionKey.PROJECTS_READ.value},
    )

    decision = decide_role_change(
        operation="assign",
        actor=actor,
        target_before=target,
        target_after=target.with_role(changed_role),
        changed_role=changed_role,
    )

    assert decision.allowed


def test_lower_actor_cannot_change_higher_target() -> None:
    actor = administrative_actor(tier=100)
    target = authority(role(tier=700, permissions={PermissionKey.PROJECTS_READ.value}))
    changed_role = role(
        tier=20,
        permissions={PermissionKey.PROJECTS_READ.value},
    )

    decision = decide_role_change(
        operation="revoke",
        actor=actor,
        target_before=target,
        target_after=target.without_role(changed_role.role_id),
        changed_role=changed_role,
    )

    assert not decision.allowed
    assert decision.reason_code == "target_not_strictly_lower"


def test_peer_cannot_change_peer() -> None:
    actor = administrative_actor(tier=500)
    target = authority(role(tier=500, permissions={PermissionKey.PROJECTS_READ.value}))
    changed_role = role(
        tier=20,
        permissions={PermissionKey.PROJECTS_READ.value},
    )

    decision = decide_role_change(
        operation="assign",
        actor=actor,
        target_before=target,
        target_after=target.with_role(changed_role),
        changed_role=changed_role,
    )

    assert not decision.allowed
    assert decision.reason_code == "target_not_strictly_lower"


def test_direct_self_assignment_is_denied() -> None:
    user_id = uuid.uuid4()
    actor = administrative_actor()
    actor = AuthoritySnapshot.build(
        membership_id=actor.membership_id,
        user_id=user_id,
        membership_status=actor.membership_status,
        membership_is_protected=False,
        user_is_protected=False,
        authz_version=actor.authz_version,
        roles=actor.roles,
    )
    changed_role = role(
        tier=20,
        permissions={PermissionKey.PROJECTS_READ.value},
    )

    decision = decide_role_change(
        operation="assign",
        actor=actor,
        target_before=actor,
        target_after=actor.with_role(changed_role),
        changed_role=changed_role,
    )

    assert not decision.allowed
    assert decision.reason_code == "self_management_forbidden"


def test_permission_possession_does_not_imply_delegation() -> None:
    actor = administrative_actor()
    target = authority()
    changed_role = role(
        tier=20,
        permissions={PermissionKey.MEMBERSHIPS_READ.value},
    )

    decision = decide_role_change(
        operation="assign",
        actor=actor,
        target_before=target,
        target_after=target.with_role(changed_role),
        changed_role=changed_role,
    )

    assert not decision.allowed
    assert decision.reason_code == "delegation_ceiling_exceeded"


def test_actor_cannot_edit_a_shared_role_it_holds() -> None:
    shared_role = role(
        tier=100,
        permissions={PermissionKey.PROJECTS_READ.value},
    )
    actor = authority(
        role(
            tier=500,
            permissions={PermissionKey.ROLES_PERMISSIONS_UPDATE.value},
            delegable={PermissionKey.PROJECTS_READ.value},
        ),
        shared_role,
    )

    decision = decide_role_permissions_replace(
        actor=actor,
        changed_role_before=shared_role,
        permission_keys=frozenset({PermissionKey.PROJECTS_READ.value}),
        actor_holds_role=True,
        affected_before_after=((actor, actor),),
    )

    assert not decision.allowed
    assert decision.reason_code == "indirect_self_change_forbidden"


def test_disabled_actor_is_denied_by_reusable_policy() -> None:
    actor = administrative_actor()
    actor = AuthoritySnapshot.build(
        membership_id=actor.membership_id,
        user_id=actor.user_id,
        membership_status="active",
        membership_is_protected=False,
        user_is_protected=False,
        authz_version=actor.authz_version,
        roles=actor.roles,
        user_is_active=False,
    )
    target = authority()
    changed_role = role(
        tier=20,
        permissions={PermissionKey.PROJECTS_READ.value},
    )

    decision = decide_role_change(
        operation="assign",
        actor=actor,
        target_before=target,
        target_after=target.with_role(changed_role),
        changed_role=changed_role,
    )

    assert not decision.allowed
    assert decision.reason_code == "actor_inactive"


def test_only_owner_can_replace_delegation() -> None:
    managed_role = role(
        tier=100,
        permissions={PermissionKey.PROJECTS_READ.value},
    )
    target_before = authority(managed_role)
    target_after = target_before.with_role(
        RoleGrant(
            role_id=managed_role.role_id,
            management_tier=managed_role.management_tier,
            permissions=managed_role.permissions,
            delegable_permissions=frozenset({PermissionKey.PROJECTS_READ.value}),
            is_protected=False,
            is_owner=False,
        )
    )
    non_owner = authority(
        role(
            tier=900,
            permissions={PermissionKey.ROLES_DELEGATION_UPDATE.value},
            delegable={PermissionKey.PROJECTS_READ.value},
        )
    )

    denied = decide_role_delegation_replace(
        actor=non_owner,
        changed_role_before=managed_role,
        delegable_permission_keys=frozenset({PermissionKey.PROJECTS_READ.value}),
        actor_holds_role=False,
        affected_before_after=((target_before, target_after),),
    )

    assert not denied.allowed
    assert denied.reason_code == "owner_control_plane_required"


def test_owner_cannot_make_control_permission_delegable() -> None:
    owner = authority(
        role(
            tier=1000,
            permissions={
                PermissionKey.ROLES_DELEGATION_UPDATE.value,
                PermissionKey.TENANT_OWNERSHIP_TRANSFER.value,
            },
            protected=True,
            owner=True,
        )
    )
    managed_role = role(
        tier=100,
        permissions={PermissionKey.TENANT_OWNERSHIP_TRANSFER.value},
    )

    decision = decide_role_delegation_replace(
        actor=owner,
        changed_role_before=managed_role,
        delegable_permission_keys=frozenset(
            {PermissionKey.TENANT_OWNERSHIP_TRANSFER.value}
        ),
        actor_holds_role=False,
        affected_before_after=(),
    )

    assert not decision.allowed
    assert decision.reason_code == "protected_delegation_forbidden"


def test_membership_management_requires_strictly_lower_non_self_target() -> None:
    actor = authority(
        role(
            tier=500,
            permissions={
                PermissionKey.MEMBERSHIPS_CREATE.value,
                PermissionKey.MEMBERSHIPS_STATUS_UPDATE.value,
                PermissionKey.PROJECTS_READ.value,
            },
            delegable={PermissionKey.PROJECTS_READ.value},
        )
    )
    lower = authority(role(tier=20, permissions={PermissionKey.PROJECTS_READ.value}))
    peer = authority(role(tier=500, permissions={PermissionKey.PROJECTS_READ.value}))

    create_decision = decide_membership_create(
        actor=actor,
        target_user_id=uuid.uuid4(),
        target_user_is_active=True,
        target_user_is_protected=False,
    )
    lower_decision = decide_membership_status_change(
        actor=actor,
        target_before=lower,
        proposed_status="suspended",
    )
    peer_decision = decide_membership_status_change(
        actor=actor,
        target_before=peer,
        proposed_status="suspended",
    )

    assert create_decision.allowed
    assert lower_decision.allowed
    assert not peer_decision.allowed
    assert peer_decision.reason_code == "target_not_strictly_lower"


def test_tenant_actor_cannot_propagate_unknown_platform_permission() -> None:
    platform_permission = "platform:break_glass"
    actor = authority(
        role(
            tier=1000,
            permissions={PermissionKey.ROLES_CREATE.value, platform_permission},
            delegable={platform_permission},
        )
    )

    decision = decide_role_create(
        actor=actor,
        management_tier=10,
        permission_keys=frozenset({platform_permission}),
    )

    assert not decision.allowed
    assert decision.reason_code == "permission_outside_tenant_control_plane"
