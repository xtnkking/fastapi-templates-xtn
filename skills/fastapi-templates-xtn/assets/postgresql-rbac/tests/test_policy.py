import uuid

from app.rbac.domain import (
    OWNER_PERMISSION_KEYS,
    AuthoritySnapshot,
    PermissionKey,
    RoleGrant,
)
from app.rbac.policy import (
    decide_ownership_transfer,
    decide_role_change,
    decide_role_create,
    decide_role_delegation_replace,
    decide_role_permissions_replace,
    decide_user_status_change,
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
    user_protected: bool = False,
    user_is_active: bool = True,
) -> AuthoritySnapshot:
    return AuthoritySnapshot.build(
        user_id=user_id or uuid.uuid4(),
        user_is_active=user_is_active,
        user_is_protected=user_protected,
        authz_version=1,
        roles=roles,
    )


def administrative_actor(*, tier: int = 500) -> AuthoritySnapshot:
    return authority(
        role(
            tier=tier,
            permissions={
                PermissionKey.ROLES_ASSIGN.value,
                PermissionKey.ROLES_REVOKE.value,
                PermissionKey.ROLES_PERMISSIONS_UPDATE.value,
                PermissionKey.USERS_STATUS_UPDATE.value,
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
    changed_role = role(tier=20, permissions={PermissionKey.PROJECTS_READ.value})

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
    changed_role = role(tier=20, permissions={PermissionKey.PROJECTS_READ.value})

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
    changed_role = role(tier=20, permissions={PermissionKey.PROJECTS_READ.value})

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
    actor = administrative_actor()
    changed_role = role(tier=20, permissions={PermissionKey.PROJECTS_READ.value})

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
    changed_role = role(tier=20, permissions={PermissionKey.USERS_READ.value})

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
    shared_role = role(tier=100, permissions={PermissionKey.PROJECTS_READ.value})
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


def test_actor_cannot_rewrite_unassigned_role_above_delegation_ceiling() -> None:
    actor = administrative_actor()
    inaccessible_role = role(
        tier=100,
        permissions={PermissionKey.PROJECTS_UPDATE.value},
    )

    decision = decide_role_permissions_replace(
        actor=actor,
        changed_role_before=inaccessible_role,
        permission_keys=frozenset({PermissionKey.PROJECTS_READ.value}),
        actor_holds_role=False,
        affected_before_after=(),
    )

    assert not decision.allowed
    assert decision.reason_code == "delegation_ceiling_exceeded"


def test_disabled_actor_is_denied_by_reusable_policy() -> None:
    actor = administrative_actor()
    actor = AuthoritySnapshot.build(
        user_id=actor.user_id,
        user_is_active=False,
        user_is_protected=False,
        authz_version=actor.authz_version,
        roles=actor.roles,
    )
    target = authority()
    changed_role = role(tier=20, permissions={PermissionKey.PROJECTS_READ.value})

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
    managed_role = role(tier=100, permissions={PermissionKey.PROJECTS_READ.value})
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
                PermissionKey.SYSTEM_OWNER_TRANSFER.value,
            },
            protected=True,
            owner=True,
        )
    )
    managed_role = role(
        tier=100,
        permissions={PermissionKey.SYSTEM_OWNER_TRANSFER.value},
    )

    decision = decide_role_delegation_replace(
        actor=owner,
        changed_role_before=managed_role,
        delegable_permission_keys=frozenset(
            {PermissionKey.SYSTEM_OWNER_TRANSFER.value}
        ),
        actor_holds_role=False,
        affected_before_after=(),
    )

    assert not decision.allowed
    assert decision.reason_code == "protected_delegation_forbidden"


def test_owner_cannot_rewrite_delegation_on_invalid_unassigned_role() -> None:
    owner = authority(
        role(
            tier=1000,
            permissions=set(OWNER_PERMISSION_KEYS),
            delegable=set(OWNER_PERMISSION_KEYS)
            - {PermissionKey.SYSTEM_OWNER_TRANSFER.value},
            protected=True,
            owner=True,
        )
    )
    invalid_role = role(
        tier=100,
        permissions={PermissionKey.SYSTEM_OWNER_TRANSFER.value},
    )

    decision = decide_role_delegation_replace(
        actor=owner,
        changed_role_before=invalid_role,
        delegable_permission_keys=frozenset(),
        actor_holds_role=False,
        affected_before_after=(),
    )

    assert not decision.allowed
    assert decision.reason_code == "delegation_ceiling_exceeded"


def test_user_status_change_requires_lower_non_self_target() -> None:
    actor = administrative_actor()
    lower = authority(role(tier=20, permissions={PermissionKey.PROJECTS_READ.value}))
    peer = authority(role(tier=500, permissions={PermissionKey.PROJECTS_READ.value}))

    lower_decision = decide_user_status_change(
        actor=actor,
        target_before=lower,
        proposed_is_active=False,
    )
    peer_decision = decide_user_status_change(
        actor=actor,
        target_before=peer,
        proposed_is_active=False,
    )
    self_decision = decide_user_status_change(
        actor=actor,
        target_before=actor,
        proposed_is_active=False,
    )

    assert lower_decision.allowed
    assert not peer_decision.allowed
    assert peer_decision.reason_code == "target_not_strictly_lower"
    assert not self_decision.allowed
    assert self_decision.reason_code == "self_management_forbidden"


def test_owner_transfer_rejects_self_and_inactive_target() -> None:
    owner = authority(
        role(
            tier=1000,
            permissions={PermissionKey.SYSTEM_OWNER_TRANSFER.value},
            protected=True,
            owner=True,
        )
    )
    inactive = authority(user_is_active=False)

    self_decision = decide_ownership_transfer(actor=owner, target_before=owner)
    inactive_decision = decide_ownership_transfer(
        actor=owner,
        target_before=inactive,
    )

    assert self_decision.reason_code == "self_transfer_forbidden"
    assert inactive_decision.reason_code == "target_inactive"


def test_owner_allowlist_is_explicit_and_rejects_unknown_control_key() -> None:
    platform_permission = "platform:break_glass"
    assert platform_permission not in OWNER_PERMISSION_KEYS

    actor = authority(
        role(
            tier=1000,
            permissions={PermissionKey.ROLES_CREATE.value, platform_permission},
            delegable={platform_permission},
            protected=True,
            owner=True,
        )
    )
    decision = decide_role_create(
        actor=actor,
        management_tier=10,
        permission_keys=frozenset({platform_permission}),
    )

    assert not decision.allowed
    assert decision.reason_code == "permission_outside_rbac_control_plane"
