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
    ADMIN_PERMISSION_KEYS,
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
    key=SystemRoleKey.ADMIN.value,
    tier=500,
    permissions=ADMIN_PERMISSION_KEYS,
    system=True,
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


def test_admin_cannot_manage_a_peer_or_bind_admin() -> None:
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
    assert decision.reason_code in {
        "super_admin_required",
        "target_not_strictly_lower",
    }


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


def test_every_system_role_is_immutable_through_role_administration() -> None:
    current_user = authority(10, SUPER_ADMIN)

    for operation in ("update", "enable", "disable", "delete"):
        decision = decide_role_administration(
            operation=operation,
            current_user=current_user,
            changed_role=ADMIN,
            current_user_holds_role=False,
            affected=(),
        )
        assert not decision.allowed
        assert decision.reason_code == "system_role_immutable"


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


def test_system_role_permissions_cannot_be_changed() -> None:
    current_user = authority(10, SUPER_ADMIN)

    decision = decide_role_permissions_change(
        operation="unbind",
        current_user=current_user,
        changed_role_before=ADMIN,
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
        (authority(10, SUPER_ADMIN), ADMIN, False, "system_role_immutable"),
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
