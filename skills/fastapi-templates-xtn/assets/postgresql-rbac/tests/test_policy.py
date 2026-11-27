#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    验证角色管理和用户管理策略的权限、等级与目标保护边界。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/29    XTN       V1.000        明确角色与用户策略所属模块，保留现有行为测试
# 2026/09/29    XTN       V1.001        验证两种角色变更共享目标边界并拒绝未知操作
# 2026/10/10    XTN       V1.002        统一用户 ID 与当前用户命名
# 2026/10/15    XTN       V1.003        移除用户权限版本并保留登录撤销与实时授权验证
# 2026/10/26    XTN       V1.004        用户权限信息类型统一使用 UserInfo，保持原有验证行为
# 2026/10/26    XTN       V1.005        普通用户策略用例使用实际基础权限集合
# 2026/11/26    XTN       V1.006        管理能力用例补齐基础权限并采用业务字符串 ID
# 2026/11/26    XTN       V1.007        补齐角色绑定权限上限、共享角色影响范围及拒绝优先级矩阵
# 2026/11/27    XTN       V1.008        管理员改为自定义测试角色，仅保留两个系统角色的保护
# --------------------------------------------------------------------------------------------------

from collections.abc import Callable
from dataclasses import replace

import pytest

from app.core.access.authorization import RoleGrant, UserInfo
from app.core.access.authorization_policy import PolicyDecision
from app.core.access.permissions import PermissionKey
from app.core.access.role_policy import (
    decide_role_administration,
    decide_role_create,
    decide_role_permissions_change,
    is_administrative_role_visible,
)
from app.core.access.roles import (
    SUPER_ADMIN_PERMISSION_KEYS,
    USER_PERMISSION_KEYS,
    SystemRoleKey,
)
from app.core.access.user_policy import (
    decide_role_change,
    decide_user_password_reset,
    decide_user_sessions_revoke,
    decide_user_status_change,
    is_administrative_user_visible,
)


def role(number: int, *, key: str, tier: int, permissions: frozenset[str] = frozenset(), system: bool = False,
         protected: bool = False, super_admin: bool = False) -> RoleGrant:
    return RoleGrant(
        role_id=f"R{number:014d}",
        key=key,
        level=tier,
        permissions=permissions,
        is_system=system,
        is_protected=protected,
        is_super_admin=super_admin,
    )


def authority(number: int, *roles: RoleGrant, active: bool = True, protected: bool = False) -> UserInfo:
    return UserInfo.build(
        user_id=f"U{number:014d}",
        user_is_active=active,
        user_is_protected=protected,
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
    key="admin",
    tier=500,
    # 这里只给测试中的自定义管理员配置权限，生产默认角色不再包含 admin。
    permissions=SUPER_ADMIN_PERMISSION_KEYS - {PermissionKey.ROLES_DELETE.value},
)
USER = role(3, key=SystemRoleKey.USER.value, tier=0, permissions=USER_PERMISSION_KEYS, system=True)
VIEWER = role(
    4,
    key="viewer",
    tier=20,
    permissions=frozenset({PermissionKey.PROJECTS_READ.value}),
)


def test_administrative_user_visibility_is_strictly_downward_for_admin() -> None:
    admin = authority(10, ADMIN)

    assert is_administrative_user_visible(
        current_user=admin,
        target=authority(11, USER),
    )
    for hidden in (
        admin,
        authority(12, USER, ADMIN),
        authority(13, USER, role(5, key="higher", tier=700)),
        authority(14, USER, protected=True),
    ):
        assert not is_administrative_user_visible(current_user=admin, target=hidden)


def test_super_admin_can_see_every_non_deleted_administrative_user() -> None:
    super_admin = authority(10, SUPER_ADMIN)

    for target in (
        super_admin,
        authority(11, USER, ADMIN),
        authority(12, USER, protected=True),
    ):
        assert is_administrative_user_visible(current_user=super_admin, target=target)


def test_administrative_role_visibility_is_strictly_downward_for_admin() -> None:
    admin = authority(10, ADMIN)

    assert is_administrative_role_visible(current_user=admin, role=VIEWER)
    for hidden in (
        ADMIN,
        role(5, key="higher", tier=700),
        SUPER_ADMIN,
    ):
        assert not is_administrative_role_visible(current_user=admin, role=hidden)
        assert is_administrative_role_visible(
            current_user=authority(11, SUPER_ADMIN),
            role=hidden,
        )


def test_admin_can_bind_a_lower_role_whose_permissions_it_holds() -> None:
    current_user = authority(10, ADMIN)
    target_before = authority(11, USER)
    target_after = target_before.with_role(VIEWER)

    decision = decide_role_change(
        operation="bind",
        current_user=current_user,
        target_before=target_before,
        target_after=target_after,
        changed_roles=(VIEWER,),
    )

    assert decision.allowed


def test_admin_cannot_manage_a_peer_or_bind_a_same_level_role() -> None:
    current_user = authority(10, ADMIN)
    peer = authority(11, USER, ADMIN)

    decision = decide_role_change(
        operation="bind",
        current_user=current_user,
        target_before=peer,
        target_after=peer,
        changed_roles=(ADMIN,),
    )

    assert not decision.allowed
    assert decision.reason_code == "role_not_strictly_lower"


def test_super_admin_can_bind_admin_to_a_lower_user() -> None:
    current_user = authority(10, SUPER_ADMIN)
    target_before = authority(11, USER)

    decision = decide_role_change(
        operation="bind",
        current_user=current_user,
        target_before=target_before,
        target_after=target_before.with_role(ADMIN),
        changed_roles=(ADMIN,),
    )

    assert decision.allowed


@pytest.mark.parametrize("operation", ["bind", "unbind"])
def test_higher_custom_manager_can_bind_or_unbind_a_custom_admin_role(operation: str) -> None:
    """admin 已是普通角色，有权限且等级更高的自定义管理者也可绑定或解绑。"""
    current_user = authority(10, role(68, key="manager", tier=800, permissions=SUPER_ADMIN_PERMISSION_KEYS))
    target = authority(11, USER)
    with_admin = target.with_role(ADMIN)

    decision = decide_role_change(
        operation=operation,
        current_user=current_user,
        target_before=target if operation == "bind" else with_admin,
        target_after=with_admin if operation == "bind" else target,
        changed_roles=(ADMIN,),
    )

    assert decision.allowed


@pytest.mark.parametrize("operation", ["bind", "unbind"])
@pytest.mark.parametrize(
    ("current_user", "reason"),
    [
        (authority(10, USER), "missing_operation_permission"),
        (authority(10, role(69, key="peer_manager", tier=500, permissions=SUPER_ADMIN_PERMISSION_KEYS)),
         "role_not_strictly_lower"),
        (authority(10, role(70, key="lower_manager", tier=400, permissions=SUPER_ADMIN_PERMISSION_KEYS)),
         "role_not_strictly_lower"),
    ],
    ids=["ordinary-user", "peer-manager", "lower-manager"],
)
def test_custom_admin_role_still_requires_permission_and_a_higher_level(
    operation: str, current_user: UserInfo, reason: str,
) -> None:
    """取消 admin 的特殊限制，不会让无权限、同级或更低级的用户越权分配它。"""
    target = authority(11, USER)
    with_admin = target.with_role(ADMIN)

    decision = decide_role_change(
        operation=operation,
        current_user=current_user,
        target_before=target if operation == "bind" else with_admin,
        target_after=with_admin if operation == "bind" else target,
        changed_roles=(ADMIN,),
    )

    assert not decision.allowed
    assert decision.reason_code == reason


def test_super_admin_role_cannot_use_the_ordinary_bind_path() -> None:
    current_user = authority(10, SUPER_ADMIN)
    target_before = authority(11, USER)

    decision = decide_role_change(
        operation="bind",
        current_user=current_user,
        target_before=target_before,
        target_after=target_before.with_role(SUPER_ADMIN),
        changed_roles=(SUPER_ADMIN,),
    )

    assert not decision.allowed
    assert decision.reason_code == "super_admin_assignment_offline_only"


def test_mandatory_user_role_cannot_be_unbound() -> None:
    current_user = authority(10, ADMIN)
    target_before = authority(11, USER)

    decision = decide_role_change(
        operation="unbind",
        current_user=current_user,
        target_before=target_before,
        target_after=target_before.without_role(USER.role_id),
        changed_roles=(USER,),
    )

    assert not decision.allowed
    assert decision.reason_code == "default_user_role_required"


def test_direct_self_assignment_is_denied() -> None:
    current_user = authority(10, ADMIN)

    decision = decide_role_change(
        operation="bind",
        current_user=current_user,
        target_before=current_user,
        target_after=current_user.with_role(VIEWER),
        changed_roles=(VIEWER,),
    )

    assert not decision.allowed
    assert decision.reason_code == "self_management_forbidden"


def test_hidden_higher_role_prevents_lower_admin_management() -> None:
    current_user = authority(10, ADMIN)
    hidden_higher = role(5, key="higher", tier=700)
    target = authority(11, USER, VIEWER, hidden_higher)

    decision = decide_role_change(
        operation="unbind",
        current_user=current_user,
        target_before=target,
        target_after=target.without_role(VIEWER.role_id),
        changed_roles=(VIEWER,),
    )

    assert not decision.allowed
    assert decision.reason_code == "target_not_strictly_lower"


def test_role_creation_requires_a_strictly_lower_nonzero_tier() -> None:
    admin = authority(10, ADMIN)

    assert decide_role_create(current_user=admin, level=499).allowed
    assert not decide_role_create(current_user=admin, level=500).allowed
    assert not decide_role_create(current_user=admin, level=0).allowed
    assert not decide_role_create(
        current_user=authority(11, USER),
        level=1,
    ).allowed


@pytest.mark.parametrize("changed_role", [SUPER_ADMIN, USER])
def test_every_system_role_is_immutable_through_role_administration(changed_role: RoleGrant) -> None:
    current_user = authority(10, SUPER_ADMIN)

    for operation in ("update", "enable", "disable", "delete"):
        decision = decide_role_administration(
            operation=operation,
            current_user=current_user,
            changed_role=changed_role,
            current_user_holds_role=False,
            affected=(),
        )
        assert not decision.allowed
        assert decision.reason_code == "system_role_immutable"


@pytest.mark.parametrize("operation", ["update", "enable", "disable", "delete"])
def test_custom_admin_role_has_no_system_immutability(operation: str) -> None:
    decision = decide_role_administration(
        operation=operation,
        current_user=authority(10, SUPER_ADMIN),
        changed_role=ADMIN,
        current_user_holds_role=False,
        affected=(),
    )

    assert decision.allowed


def test_admin_name_alone_grants_no_management_permissions() -> None:
    named_admin = role(67, key="admin", tier=500)
    current_user = authority(10, USER, named_admin)

    assert current_user.permissions == USER_PERMISSION_KEYS
    assert not current_user.is_super_admin
    assert not decide_role_create(current_user=current_user, level=100).allowed


def test_level_500_is_available_to_a_custom_role() -> None:
    assert decide_role_create(current_user=authority(10, SUPER_ADMIN), level=500).allowed


def test_admin_lacks_role_delete_even_for_a_lower_role() -> None:
    current_user = authority(10, ADMIN)

    decision = decide_role_administration(
        operation="delete",
        current_user=current_user,
        changed_role=VIEWER,
        current_user_holds_role=False,
        affected=(),
    )

    assert not decision.allowed
    assert decision.reason_code == "missing_operation_permission"


def test_current_user_cannot_change_permissions_of_a_role_it_holds() -> None:
    current_user = authority(10, SUPER_ADMIN, VIEWER)

    decision = decide_role_permissions_change(
        operation="bind",
        current_user=current_user,
        changed_role_before=VIEWER,
        permission_keys_after=frozenset(
            {PermissionKey.PROJECTS_READ.value, PermissionKey.PROJECTS_UPDATE.value}
        ),
        current_user_holds_role=True,
        affected_after=(),
    )

    assert not decision.allowed
    assert decision.reason_code == "indirect_self_change_forbidden"


@pytest.mark.parametrize("changed_role", [SUPER_ADMIN, USER])
def test_system_role_permissions_cannot_be_changed(changed_role: RoleGrant) -> None:
    current_user = authority(10, SUPER_ADMIN)

    decision = decide_role_permissions_change(
        operation="unbind",
        current_user=current_user,
        changed_role_before=changed_role,
        permission_keys_after=frozenset(),
        current_user_holds_role=False,
        affected_after=(),
    )

    assert not decision.allowed
    assert decision.reason_code == "system_role_immutable"


def test_cannot_grant_permission_current_user_does_not_have() -> None:
    admin = authority(10, ADMIN)
    denied = decide_role_permissions_change(
        operation="bind",
        current_user=admin,
        changed_role_before=VIEWER,
        permission_keys_after=frozenset({PermissionKey.ROLES_DELETE.value}),
        current_user_holds_role=False,
        affected_after=(),
    )

    allowed = decide_role_permissions_change(
        operation="bind",
        current_user=admin,
        changed_role_before=VIEWER,
        permission_keys_after=frozenset({PermissionKey.PROJECTS_READ.value}),
        current_user_holds_role=False,
        affected_after=(),
    )

    assert not denied.allowed
    assert denied.reason_code == "permission_ceiling_exceeded"
    assert allowed.allowed


@pytest.mark.parametrize(
    ("current_user", "changed_role", "current_user_holds_role", "reason"),
    [
        (authority(10, SUPER_ADMIN), USER, False, "system_role_immutable"),
        (authority(10, SUPER_ADMIN), VIEWER, True, "indirect_self_change_forbidden"),
        (authority(10, ADMIN), role(20, key="peer", tier=500), False, "role_not_strictly_lower"),
        (authority(10, ADMIN), role(21, key="outside", tier=20,
                                    permissions=frozenset({PermissionKey.ROLES_DELETE.value})),
         False, "permission_ceiling_exceeded"),
    ],
)
def test_role_mutation_paths_keep_the_same_existing_role_boundary(current_user: UserInfo,
                                                                  changed_role: RoleGrant,
                                                                  current_user_holds_role: bool,
                                                                  reason: str) -> None:
    """
        角色资料变更与权限变更先经过相同的系统角色、本人、等级和权限上限检查。

    :param current_user: 本次变更的操作者授权快照。
    :param changed_role: 被管理的角色及其变更前权限。
    :param current_user_holds_role: 操作者是否持有该角色。
    :param reason: 两条操作都应返回的首个拒绝原因。
    :return: 无返回值；两条策略的边界或错误顺序分叉时断言失败。
    """
    administration = decide_role_administration(
        operation="update",
        current_user=current_user,
        changed_role=changed_role,
        current_user_holds_role=current_user_holds_role,
        affected=(),
    )
    permissions = decide_role_permissions_change(
        operation="bind",
        current_user=current_user,
        changed_role_before=changed_role,
        permission_keys_after=changed_role.permissions,
        current_user_holds_role=current_user_holds_role,
        affected_after=(),
    )

    assert administration.reason_code == reason
    assert permissions.reason_code == reason


def test_unknown_role_operations_are_rejected_before_permission_selection() -> None:
    """
        非法内部操作不能落入解绑分支，从而错用较低权限继续执行。

    :return: 无返回值；未知操作没有被明确拒绝时断言失败。
    """
    current_user = authority(10, SUPER_ADMIN)
    target = authority(11, USER)
    with pytest.raises(ValueError, match="unsupported user role operation"):
        decide_role_change(
            operation="replace",
            current_user=current_user,
            target_before=target,
            target_after=target,
            changed_roles=(VIEWER,),
        )
    with pytest.raises(ValueError, match="unsupported role permission operation"):
        decide_role_permissions_change(
            operation="replace",
            current_user=current_user,
            changed_role_before=VIEWER,
            permission_keys_after=VIEWER.permissions,
            current_user_holds_role=False,
            affected_after=(),
        )
    with pytest.raises(ValueError, match="unsupported role administration operation"):
        decide_role_administration(
            operation="replace",
            current_user=current_user,
            changed_role=VIEWER,
            current_user_holds_role=False,
            affected=(),
        )


@pytest.mark.parametrize(
    ("policy", "required_permission"),
    [
        (decide_user_status_change, PermissionKey.USERS_STATUS_UPDATE),
        (decide_user_password_reset, PermissionKey.USERS_PASSWORD_RESET),
        (decide_user_sessions_revoke, PermissionKey.USERS_SESSIONS_REVOKE),
    ],
)
def test_user_administration_keeps_each_operations_exact_capability(policy: Callable[..., PolicyDecision],
                                                                    required_permission: PermissionKey) -> None:
    current_user = authority(
        10,
        role(
            20,
            key="operator",
            tier=500,
            permissions=USER_PERMISSION_KEYS | {required_permission.value},
        ),
    )
    for active in (True, False):
        assert policy(
            current_user=current_user, target_before=authority(11, USER, active=active)
        ).allowed

    wrong_capability_current_user = authority(
        10,
        replace(ADMIN, permissions=ADMIN.permissions - {required_permission.value}),
    )
    for target in (authority(11, USER), wrong_capability_current_user):
        decision = policy(current_user=wrong_capability_current_user, target_before=target)
        assert not decision.allowed
        assert decision.reason_code == "missing_operation_permission"


@pytest.mark.parametrize(
    "policy",
    [
        decide_user_status_change,
        decide_user_password_reset,
        decide_user_sessions_revoke,
    ],
)
@pytest.mark.parametrize(
    ("current_user", "target", "reason"),
    [
        (authority(10, ADMIN, active=False), authority(11, USER), "user_inactive"),
        (authority(10, ADMIN), authority(10, ADMIN), "self_management_forbidden"),
        (
            authority(10, SUPER_ADMIN),
            authority(10, SUPER_ADMIN),
            "self_management_forbidden",
        ),
        (
            authority(10, ADMIN),
            authority(11, USER, protected=True),
            "protected_subject",
        ),
        (
            authority(10, ADMIN),
            authority(11, USER, VIEWER, ADMIN),
            "target_not_strictly_lower",
        ),
        (
            authority(10, ADMIN),
            authority(11, USER, role(20, key="higher", tier=700)),
            "target_not_strictly_lower",
        ),
        (
            authority(
                10, replace(ADMIN, permissions=ADMIN.permissions - VIEWER.permissions)
            ),
            authority(11, USER, VIEWER),
            "permission_ceiling_exceeded",
        ),
        (
            authority(
                10, replace(ADMIN, permissions=ADMIN.permissions | {"private:read"})
            ),
            authority(11, replace(VIEWER, permissions=frozenset({"private:read"}))),
            "permission_ceiling_exceeded",
        ),
    ],
)
def test_user_administration_preserves_complete_target_security_boundary(policy: Callable[..., PolicyDecision],
                                                                         current_user: UserInfo,
                                                                         target: UserInfo,
                                                                         reason: str) -> None:
    decision = policy(current_user=current_user, target_before=target)

    assert not decision.allowed
    assert decision.reason_code == reason


@pytest.mark.parametrize("operation", ["bind", "unbind"])
@pytest.mark.parametrize("outside_system", [False, True], ids=["outside-current-user", "outside-system"])
@pytest.mark.parametrize("outside_location", ["changed_role", "target_before", "target_after"])
def test_user_role_change_checks_every_permission_ceiling(operation: str,
                                                          outside_system: bool,
                                                          outside_location: str) -> None:
    """待变更角色、原用户和预测用户分别越界时，都不能借低等级绕过权限上限。"""
    outside_permission = "private:read" if outside_system else PermissionKey.PROJECTS_UPDATE.value
    current_user = authority(10, replace(
        ADMIN,
        permissions=(ADMIN.permissions - {PermissionKey.PROJECTS_UPDATE.value}) | {"private:read"},
    ))
    outside_role = role(60, key="outside", tier=10, permissions=frozenset({outside_permission}))
    changed_role = VIEWER
    target_before = authority(11, USER)
    target_after = target_before.with_role(VIEWER)
    if operation == "unbind":
        target_before, target_after = target_after, target_before

    # 三份输入分别单独越界，确保不能只检查本次角色，或只检查变更前后的其中一份快照。
    if outside_location == "changed_role":
        changed_role = outside_role
    elif outside_location == "target_before":
        target_before = target_before.with_role(outside_role)
    else:
        target_after = target_after.with_role(outside_role)

    decision = decide_role_change(
        operation=operation,
        current_user=current_user,
        target_before=target_before,
        target_after=target_after,
        changed_roles=(changed_role,),
    )

    assert not decision.allowed
    assert decision.reason_code == "permission_ceiling_exceeded"


@pytest.mark.parametrize("operation", ["bind", "unbind"])
def test_user_role_change_allows_held_permissions_in_both_directions(operation: str) -> None:
    """对应的正向操作可以成功，避免权限上限测试被一律拒绝的错误实现蒙混过去。"""
    target = authority(11, USER)
    with_viewer = target.with_role(VIEWER)
    decision = decide_role_change(
        operation=operation,
        current_user=authority(10, ADMIN),
        target_before=target if operation == "bind" else with_viewer,
        target_after=with_viewer if operation == "bind" else target,
        changed_roles=(VIEWER,),
    )

    assert decision.allowed
    assert decision.reason_code == "allowed"


@pytest.mark.parametrize("operation", ["bind", "unbind"])
@pytest.mark.parametrize("level", [500, 700], ids=["peer", "higher"])
def test_user_role_change_rechecks_complete_predicted_level(operation: str, level: int) -> None:
    """即使待变更角色很低级，也不能忽略预测快照中的其他同级或上级角色。"""
    before = authority(11, USER, VIEWER)
    after = before.with_role(role(61, key="other_role", tier=level))
    decision = decide_role_change(
        operation=operation,
        current_user=authority(10, ADMIN),
        target_before=before,
        target_after=after,
        changed_roles=(VIEWER,),
    )

    assert not decision.allowed
    assert decision.reason_code == "target_not_strictly_lower"


SHARED_ROLE_OPERATIONS = ("update", "enable", "disable", "delete", "bind_permissions", "unbind_permissions")


def shared_role_decision(operation: str, *, current_user: UserInfo,
                         affected: tuple[UserInfo, ...], changed_role: RoleGrant = VIEWER,
                         current_user_holds_role: bool = False) -> PolicyDecision:
    """让同一组共享角色边界分别经过六种实际策略入口，保留各自的操作权限要求。"""
    if operation in {"bind_permissions", "unbind_permissions"}:
        return decide_role_permissions_change(
            operation="bind" if operation == "bind_permissions" else "unbind",
            current_user=current_user,
            changed_role_before=changed_role,
            permission_keys_after=(VIEWER.permissions | {PermissionKey.ACCOUNT_READ.value}
                                   if operation == "bind_permissions" else frozenset()),
            current_user_holds_role=current_user_holds_role,
            affected_after=affected,
        )
    return decide_role_administration(
        operation=operation,
        current_user=current_user,
        changed_role=changed_role,
        current_user_holds_role=current_user_holds_role,
        affected=affected,
    )


@pytest.mark.parametrize("operation", SHARED_ROLE_OPERATIONS)
@pytest.mark.parametrize("blocked_first", [False, True], ids=["allowed-user-first", "blocked-user-first"])
@pytest.mark.parametrize(("affected_user", "reason"), [
    (authority(10, USER), "affected_subject_not_manageable"),
    (authority(12, USER, protected=True), "affected_subject_not_manageable"),
    (authority(12, USER, replace(VIEWER, is_protected=True)), "affected_subject_not_manageable"),
    (authority(12, USER, role(62, key="peer", tier=500)), "affected_subject_not_strictly_lower"),
    (authority(12, USER, role(63, key="higher", tier=700)), "affected_subject_not_strictly_lower"),
    (authority(12, USER, role(64, key="outside", tier=10,
                              permissions=frozenset({PermissionKey.PROJECTS_UPDATE.value}))),
     "permission_ceiling_exceeded"),
    (authority(12, USER, role(65, key="outside_system", tier=10,
                              permissions=frozenset({"private:read"}))),
     "permission_ceiling_exceeded"),
], ids=["self", "protected-user", "protected-role", "peer", "higher", "outside-current-user", "outside-system"])
def test_shared_role_change_rejects_any_unmanageable_holder(operation: str,
                                                            blocked_first: bool,
                                                            affected_user: UserInfo,
                                                            reason: str) -> None:
    """共享角色只要影响到一个不可管理用户就拒绝，不受用户返回顺序影响。"""
    current_user = authority(10, role(
        66,
        key="manager",
        tier=500,
        permissions=(SUPER_ADMIN_PERMISSION_KEYS - {PermissionKey.PROJECTS_UPDATE.value}) | {"private:read"},
    ))
    manageable_user = authority(11, USER, VIEWER)
    affected = ((affected_user, manageable_user) if blocked_first else (manageable_user, affected_user))
    decision = shared_role_decision(operation, current_user=current_user, affected=affected)

    assert not decision.allowed
    assert decision.reason_code == reason


@pytest.mark.parametrize("operation", SHARED_ROLE_OPERATIONS)
def test_shared_role_change_allows_multiple_manageable_holders(operation: str) -> None:
    """持有人全部为权限范围内的普通下级时，六类共享角色操作都允许继续。"""
    current_user = authority(10, role(66, key="manager", tier=500, permissions=SUPER_ADMIN_PERMISSION_KEYS))
    decision = shared_role_decision(
        operation,
        current_user=current_user,
        affected=(authority(11, USER, VIEWER), authority(12, USER, VIEWER)),
    )

    assert decision.allowed
    assert decision.reason_code == "allowed"


@pytest.mark.parametrize("operation", SHARED_ROLE_OPERATIONS)
@pytest.mark.parametrize(("has_permission", "active", "reason"), [
    (False, True, "missing_operation_permission"),
    (False, False, "missing_operation_permission"),
    (True, False, "user_inactive"),
], ids=["no-capability", "inactive-and-no-capability", "inactive"])
def test_shared_role_change_checks_current_user_before_targets(operation: str,
                                                               has_permission: bool,
                                                               active: bool,
                                                               reason: str) -> None:
    """无权限或已停用的操作者先被拒绝，不因系统角色、自身或目标保护状态而改变错误。"""
    required_permissions = {
        "update": PermissionKey.ROLES_UPDATE,
        "enable": PermissionKey.ROLES_STATUS_UPDATE,
        "disable": PermissionKey.ROLES_STATUS_UPDATE,
        "delete": PermissionKey.ROLES_DELETE,
        "bind_permissions": PermissionKey.ROLES_PERMISSIONS_BIND,
        "unbind_permissions": PermissionKey.ROLES_PERMISSIONS_UNBIND,
    }
    permissions = SUPER_ADMIN_PERMISSION_KEYS
    if not has_permission:
        permissions = permissions - {required_permissions[operation].value}
    current_user = authority(10, role(66, key="manager", tier=500, permissions=permissions), active=active)
    decision = shared_role_decision(
        operation,
        current_user=current_user,
        changed_role=SUPER_ADMIN,
        current_user_holds_role=True,
        affected=(current_user, authority(11, USER, protected=True)),
    )

    assert not decision.allowed
    assert decision.reason_code == reason


@pytest.mark.parametrize("operation", ["bind", "unbind"])
@pytest.mark.parametrize(("has_permission", "active", "reason"), [
    (False, True, "missing_operation_permission"),
    (False, False, "missing_operation_permission"),
    (True, False, "user_inactive"),
], ids=["no-capability", "inactive-and-no-capability", "inactive"])
def test_user_role_change_checks_current_user_before_target_and_roles(operation: str,
                                                                      has_permission: bool,
                                                                      active: bool,
                                                                      reason: str) -> None:
    """用户角色操作同样先拒绝无权或停用操作者，再检查本人、超级管理员角色等目标信息。"""
    required = PermissionKey.ROLES_BIND if operation == "bind" else PermissionKey.ROLES_UNBIND
    permissions = ADMIN.permissions if has_permission else ADMIN.permissions - {required.value}
    current_user = authority(10, replace(ADMIN, permissions=permissions), active=active)
    decision = decide_role_change(
        operation=operation,
        current_user=current_user,
        target_before=current_user,
        target_after=current_user.with_role(SUPER_ADMIN),
        changed_roles=(SUPER_ADMIN,),
    )

    assert not decision.allowed
    assert decision.reason_code == reason
