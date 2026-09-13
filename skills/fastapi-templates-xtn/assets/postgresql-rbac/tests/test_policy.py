import uuid

from app.rbac.domain import (
    ADMIN_PERMISSION_KEYS,
    SUPER_ADMIN_PERMISSION_KEYS,
    AuthoritySnapshot,
    PermissionKey,
    RoleGrant,
    SystemRoleKey,
)
from app.rbac.policy import (
    decide_role_administration,
    decide_role_change,
    decide_role_create,
    decide_role_permissions_change,
    decide_user_password_reset,
    decide_user_sessions_revoke,
    decide_user_status_change,
    is_administrative_role_visible,
    is_administrative_user_visible,
)


def role(
    number: int,
    *,
    key: str,
    tier: int,
    permissions: frozenset[str] = frozenset(),
    system: bool = False,
    protected: bool = False,
    super_admin: bool = False,
) -> RoleGrant:
    return RoleGrant(
        role_id=uuid.UUID(int=number),
        key=key,
        management_tier=tier,
        permissions=permissions,
        is_system=system,
        is_protected=protected,
        is_super_admin=super_admin,
    )


def authority(
    number: int,
    *roles: RoleGrant,
    active: bool = True,
    protected: bool = False,
) -> AuthoritySnapshot:
    return AuthoritySnapshot.build(
        user_id=uuid.UUID(int=number),
        user_is_active=active,
        user_is_protected=protected,
        authz_version=0,
        roles=roles,
    )


SUPER_ADMIN = role(
    1,
    key=SystemRoleKey.SUPER_ADMIN.value,
    tier=1000,
    permissions=SUPER_ADMIN_PERMISSION_KEYS,
    system=True,
    protected=True,
    super_admin=True,
)
ADMIN = role(
    2,
    key=SystemRoleKey.ADMIN.value,
    tier=500,
    permissions=ADMIN_PERMISSION_KEYS,
    system=True,
)
USER = role(3, key=SystemRoleKey.USER.value, tier=0, system=True)
VIEWER = role(
    4,
    key="viewer",
    tier=20,
    permissions=frozenset({PermissionKey.PROJECTS_READ.value}),
)


def test_administrative_user_visibility_is_strictly_downward_for_admin() -> None:
    admin = authority(10, ADMIN)

    assert is_administrative_user_visible(
        actor=admin,
        target=authority(11, USER),
    )
    for hidden in (
        admin,
        authority(12, USER, ADMIN),
        authority(13, USER, role(5, key="higher", tier=700)),
        authority(14, USER, protected=True),
    ):
        assert not is_administrative_user_visible(actor=admin, target=hidden)


def test_super_admin_can_see_every_non_deleted_administrative_user() -> None:
    super_admin = authority(10, SUPER_ADMIN)

    for target in (
        super_admin,
        authority(11, USER, ADMIN),
        authority(12, USER, protected=True),
    ):
        assert is_administrative_user_visible(actor=super_admin, target=target)


def test_administrative_role_visibility_is_strictly_downward_for_admin() -> None:
    admin = authority(10, ADMIN)

    assert is_administrative_role_visible(actor=admin, role=VIEWER)
    for hidden in (
        ADMIN,
        role(5, key="higher", tier=700),
        SUPER_ADMIN,
    ):
        assert not is_administrative_role_visible(actor=admin, role=hidden)
        assert is_administrative_role_visible(
            actor=authority(11, SUPER_ADMIN),
            role=hidden,
        )


def test_admin_can_bind_a_lower_role_whose_permissions_it_holds() -> None:
    actor = authority(10, ADMIN)
    target_before = authority(11, USER)
    target_after = target_before.with_role(VIEWER)

    decision = decide_role_change(
        operation="bind",
        actor=actor,
        target_before=target_before,
        target_after=target_after,
        changed_roles=(VIEWER,),
    )

    assert decision.allowed


def test_admin_cannot_manage_a_peer_or_bind_admin() -> None:
    actor = authority(10, ADMIN)
    peer = authority(11, USER, ADMIN)

    decision = decide_role_change(
        operation="bind",
        actor=actor,
        target_before=peer,
        target_after=peer,
        changed_roles=(ADMIN,),
    )

    assert not decision.allowed
    assert decision.reason_code in {
        "super_admin_required",
        "target_not_strictly_lower",
    }


def test_super_admin_can_bind_admin_to_a_lower_user() -> None:
    actor = authority(10, SUPER_ADMIN)
    target_before = authority(11, USER)

    decision = decide_role_change(
        operation="bind",
        actor=actor,
        target_before=target_before,
        target_after=target_before.with_role(ADMIN),
        changed_roles=(ADMIN,),
    )

    assert decision.allowed


def test_super_admin_role_cannot_use_the_ordinary_bind_path() -> None:
    actor = authority(10, SUPER_ADMIN)
    target_before = authority(11, USER)

    decision = decide_role_change(
        operation="bind",
        actor=actor,
        target_before=target_before,
        target_after=target_before.with_role(SUPER_ADMIN),
        changed_roles=(SUPER_ADMIN,),
    )

    assert not decision.allowed
    assert decision.reason_code == "super_admin_assignment_offline_only"


def test_mandatory_user_role_cannot_be_unbound() -> None:
    actor = authority(10, ADMIN)
    target_before = authority(11, USER)

    decision = decide_role_change(
        operation="unbind",
        actor=actor,
        target_before=target_before,
        target_after=target_before.without_role(USER.role_id),
        changed_roles=(USER,),
    )

    assert not decision.allowed
    assert decision.reason_code == "default_user_role_required"


def test_direct_self_assignment_is_denied() -> None:
    actor = authority(10, ADMIN)

    decision = decide_role_change(
        operation="bind",
        actor=actor,
        target_before=actor,
        target_after=actor.with_role(VIEWER),
        changed_roles=(VIEWER,),
    )

    assert not decision.allowed
    assert decision.reason_code == "self_management_forbidden"


def test_hidden_higher_role_prevents_lower_admin_management() -> None:
    actor = authority(10, ADMIN)
    hidden_higher = role(5, key="higher", tier=700)
    target = authority(11, USER, VIEWER, hidden_higher)

    decision = decide_role_change(
        operation="unbind",
        actor=actor,
        target_before=target,
        target_after=target.without_role(VIEWER.role_id),
        changed_roles=(VIEWER,),
    )

    assert not decision.allowed
    assert decision.reason_code == "target_not_strictly_lower"


def test_role_creation_requires_a_strictly_lower_nonzero_tier() -> None:
    admin = authority(10, ADMIN)

    assert decide_role_create(actor=admin, management_tier=499).allowed
    assert not decide_role_create(actor=admin, management_tier=500).allowed
    assert not decide_role_create(actor=admin, management_tier=0).allowed
    assert not decide_role_create(
        actor=authority(11, USER),
        management_tier=1,
    ).allowed


def test_every_system_role_is_immutable_through_role_administration() -> None:
    actor = authority(10, SUPER_ADMIN)

    for operation in ("update", "enable", "disable", "delete"):
        decision = decide_role_administration(
            operation=operation,
            actor=actor,
            changed_role=ADMIN,
            actor_holds_role=False,
            affected=(),
        )
        assert not decision.allowed
        assert decision.reason_code == "system_role_immutable"


def test_admin_lacks_role_delete_even_for_a_lower_role() -> None:
    actor = authority(10, ADMIN)

    decision = decide_role_administration(
        operation="delete",
        actor=actor,
        changed_role=VIEWER,
        actor_holds_role=False,
        affected=(),
    )

    assert not decision.allowed
    assert decision.reason_code == "missing_operation_permission"


def test_actor_cannot_change_permissions_of_a_role_it_holds() -> None:
    actor = authority(10, SUPER_ADMIN, VIEWER)

    decision = decide_role_permissions_change(
        operation="bind",
        actor=actor,
        changed_role_before=VIEWER,
        permission_keys_after=frozenset(
            {PermissionKey.PROJECTS_READ.value, PermissionKey.PROJECTS_UPDATE.value}
        ),
        actor_holds_role=True,
        affected_after=(),
    )

    assert not decision.allowed
    assert decision.reason_code == "indirect_self_change_forbidden"


def test_system_role_permissions_cannot_be_changed() -> None:
    actor = authority(10, SUPER_ADMIN)

    decision = decide_role_permissions_change(
        operation="unbind",
        actor=actor,
        changed_role_before=ADMIN,
        permission_keys_after=frozenset(),
        actor_holds_role=False,
        affected_after=(),
    )

    assert not decision.allowed
    assert decision.reason_code == "system_role_immutable"


def test_cannot_grant_permission_actor_does_not_have() -> None:
    admin = authority(10, ADMIN)
    denied = decide_role_permissions_change(
        operation="bind",
        actor=admin,
        changed_role_before=VIEWER,
        permission_keys_after=frozenset({PermissionKey.ROLES_DELETE.value}),
        actor_holds_role=False,
        affected_after=(),
    )

    allowed = decide_role_permissions_change(
        operation="bind",
        actor=admin,
        changed_role_before=VIEWER,
        permission_keys_after=frozenset({PermissionKey.PROJECTS_READ.value}),
        actor_holds_role=False,
        affected_after=(),
    )

    assert not denied.allowed
    assert denied.reason_code == "permission_ceiling_exceeded"
    assert allowed.allowed


def test_registration_switch_capability_is_reserved_for_the_system_role() -> None:
    decision = decide_role_permissions_change(
        operation="bind",
        actor=authority(10, SUPER_ADMIN),
        changed_role_before=VIEWER,
        permission_keys_after=frozenset({PermissionKey.REGISTRATION_CONFIGURE.value}),
        actor_holds_role=False,
        affected_after=(),
    )
    assert not decision.allowed
    assert decision.reason_code == "system_only_permission"


def test_admin_can_change_status_only_for_a_strictly_lower_user() -> None:
    actor = authority(10, ADMIN)
    lower = authority(11, USER)
    peer = authority(12, USER, ADMIN)

    assert decide_user_status_change(
        actor=actor,
        target_before=lower,
        proposed_is_active=False,
    ).allowed
    assert not decide_user_status_change(
        actor=actor,
        target_before=peer,
        proposed_is_active=False,
    ).allowed


def test_password_reset_requires_capability_and_strictly_lower_target() -> None:
    admin = authority(10, ADMIN)
    lower = authority(11, USER)
    peer = authority(12, USER, ADMIN)

    assert decide_user_password_reset(actor=admin, target_before=lower).allowed
    assert not decide_user_password_reset(actor=admin, target_before=admin).allowed
    assert not decide_user_password_reset(actor=admin, target_before=peer).allowed
    assert not decide_user_password_reset(
        actor=authority(13, USER),
        target_before=lower,
    ).allowed


def test_super_admin_cannot_reset_own_password_through_management_api() -> None:
    super_admin = authority(10, SUPER_ADMIN)

    decision = decide_user_password_reset(
        actor=super_admin,
        target_before=super_admin,
    )

    assert not decision.allowed
    assert decision.reason_code == "self_management_forbidden"


def test_admin_revokes_only_strictly_lower_users_sessions() -> None:
    admin = authority(10, ADMIN)
    assert decide_user_sessions_revoke(
        actor=admin, target_before=authority(11, USER)
    ).allowed
    assert not decide_user_sessions_revoke(actor=admin, target_before=admin).allowed
    assert not decide_user_sessions_revoke(
        actor=admin, target_before=authority(12, ADMIN)
    ).allowed
    assert not decide_user_sessions_revoke(
        actor=authority(13, USER), target_before=authority(11, USER)
    ).allowed
