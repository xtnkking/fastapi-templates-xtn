from dataclasses import dataclass
from typing import Literal

from app.rbac.domain import (
    NON_DELEGABLE_CONTROL_PERMISSIONS,
    SUPER_ADMIN_PERMISSION_KEYS,
    AuthoritySnapshot,
    PermissionKey,
    RoleGrant,
    SystemRoleKey,
)


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    allowed: bool
    reason_code: str


def allow() -> PolicyDecision:
    return PolicyDecision(allowed=True, reason_code="allowed")


def deny(reason_code: str) -> PolicyDecision:
    return PolicyDecision(allowed=False, reason_code=reason_code)


def _target_is_within_delegation(
    actor: AuthoritySnapshot,
    target: AuthoritySnapshot,
) -> bool:
    return (
        target.permissions <= SUPER_ADMIN_PERMISSION_KEYS
        and target.delegable_permissions <= SUPER_ADMIN_PERMISSION_KEYS
        and target.permissions <= actor.delegable_permissions
        and target.delegable_permissions <= actor.delegable_permissions
    )


def _role_is_within_delegation(
    actor: AuthoritySnapshot,
    role: RoleGrant,
) -> bool:
    return (
        role.permissions <= SUPER_ADMIN_PERMISSION_KEYS
        and role.delegable_permissions <= SUPER_ADMIN_PERMISSION_KEYS
        and role.permissions <= actor.delegable_permissions
        and role.delegable_permissions <= actor.delegable_permissions
    )


def _basic_actor_check(
    actor: AuthoritySnapshot,
    required: PermissionKey,
) -> PolicyDecision | None:
    if required.value not in actor.permissions:
        return deny("missing_operation_permission")
    if not actor.user_is_active:
        return deny("actor_inactive")
    return None


def _affected_subjects_are_manageable(
    *,
    actor: AuthoritySnapshot,
    affected: tuple[AuthoritySnapshot, ...],
) -> PolicyDecision:
    for subject in affected:
        if subject.is_protected or actor.user_id == subject.user_id:
            return deny("affected_subject_not_manageable")
        if actor.management_tier <= subject.management_tier:
            return deny("affected_subject_not_strictly_lower")
        if not _target_is_within_delegation(actor, subject):
            return deny("delegation_ceiling_exceeded")
    return allow()


def decide_role_change(
    *,
    operation: Literal["bind", "unbind"],
    actor: AuthoritySnapshot,
    target_before: AuthoritySnapshot,
    target_after: AuthoritySnapshot,
    changed_roles: tuple[RoleGrant, ...],
) -> PolicyDecision:
    required = (
        PermissionKey.ROLES_ASSIGN
        if operation == "bind"
        else PermissionKey.ROLES_REVOKE
    )
    basic = _basic_actor_check(actor, required)
    if basic is not None:
        return basic
    if actor.user_id == target_before.user_id:
        return deny("self_management_forbidden")
    if operation == "bind" and not target_before.user_is_active:
        return deny("target_inactive")
    if target_before.is_protected:
        return deny("protected_subject")

    for role in changed_roles:
        if role.key == SystemRoleKey.SUPER_ADMIN.value or role.is_protected:
            return deny("super_admin_requires_transfer")
        if operation == "unbind" and role.key == SystemRoleKey.USER.value:
            return deny("default_user_role_required")
        if role.key == SystemRoleKey.ADMIN.value and not actor.is_owner:
            return deny("super_admin_required")
        if not _role_is_within_delegation(actor, role):
            return deny("delegation_ceiling_exceeded")
        if actor.management_tier <= role.management_tier:
            return deny("role_not_strictly_lower")

    if actor.management_tier <= target_before.management_tier:
        return deny("target_not_strictly_lower")
    if actor.management_tier <= target_after.management_tier:
        return deny("target_not_strictly_lower")
    if not _target_is_within_delegation(actor, target_before):
        return deny("delegation_ceiling_exceeded")
    if not _target_is_within_delegation(actor, target_after):
        return deny("delegation_ceiling_exceeded")
    return allow()


def decide_role_create(
    *,
    actor: AuthoritySnapshot,
    management_tier: int,
) -> PolicyDecision:
    basic = _basic_actor_check(actor, PermissionKey.ROLES_CREATE)
    if basic is not None:
        return basic
    if management_tier < 1 or management_tier >= 1000:
        return deny("custom_role_tier_out_of_range")
    if actor.management_tier <= management_tier:
        return deny("role_not_strictly_lower")
    return allow()


def decide_role_administration(
    *,
    operation: Literal["update", "enable", "disable", "delete"],
    actor: AuthoritySnapshot,
    changed_role: RoleGrant,
    actor_holds_role: bool,
    affected: tuple[AuthoritySnapshot, ...],
) -> PolicyDecision:
    required = {
        "update": PermissionKey.ROLES_UPDATE,
        "enable": PermissionKey.ROLES_STATUS_UPDATE,
        "disable": PermissionKey.ROLES_STATUS_UPDATE,
        "delete": PermissionKey.ROLES_DELETE,
    }[operation]
    basic = _basic_actor_check(actor, required)
    if basic is not None:
        return basic
    if changed_role.is_system:
        return deny("system_role_immutable")
    if actor_holds_role:
        return deny("indirect_self_change_forbidden")
    if actor.management_tier <= changed_role.management_tier:
        return deny("role_not_strictly_lower")
    if not _role_is_within_delegation(actor, changed_role):
        return deny("delegation_ceiling_exceeded")
    return _affected_subjects_are_manageable(actor=actor, affected=affected)


def decide_role_permissions_change(
    *,
    operation: Literal["bind", "unbind"],
    actor: AuthoritySnapshot,
    changed_role_before: RoleGrant,
    permission_keys_after: frozenset[str],
    actor_holds_role: bool,
    affected_after: tuple[AuthoritySnapshot, ...],
) -> PolicyDecision:
    required = (
        PermissionKey.ROLES_PERMISSIONS_BIND
        if operation == "bind"
        else PermissionKey.ROLES_PERMISSIONS_UNBIND
    )
    basic = _basic_actor_check(actor, required)
    if basic is not None:
        return basic
    if changed_role_before.is_system:
        return deny("system_role_immutable")
    if actor_holds_role:
        return deny("indirect_self_change_forbidden")
    if actor.management_tier <= changed_role_before.management_tier:
        return deny("role_not_strictly_lower")
    if not _role_is_within_delegation(actor, changed_role_before):
        return deny("delegation_ceiling_exceeded")
    if not permission_keys_after <= SUPER_ADMIN_PERMISSION_KEYS:
        return deny("permission_outside_control_plane")
    if not permission_keys_after <= actor.delegable_permissions:
        return deny("delegation_ceiling_exceeded")
    return _affected_subjects_are_manageable(
        actor=actor,
        affected=affected_after,
    )


def decide_role_delegation_change(
    *,
    actor: AuthoritySnapshot,
    changed_role_before: RoleGrant,
    delegable_permission_keys_after: frozenset[str],
    actor_holds_role: bool,
    affected_after: tuple[AuthoritySnapshot, ...],
) -> PolicyDecision:
    basic = _basic_actor_check(actor, PermissionKey.ROLES_DELEGATION_UPDATE)
    if basic is not None:
        return basic
    if not actor.is_owner:
        return deny("super_admin_required")
    if changed_role_before.is_system:
        return deny("system_role_immutable")
    if actor_holds_role:
        return deny("indirect_self_change_forbidden")
    if actor.management_tier <= changed_role_before.management_tier:
        return deny("role_not_strictly_lower")
    if not delegable_permission_keys_after <= changed_role_before.permissions:
        return deny("delegation_requires_role_permission")
    if delegable_permission_keys_after & NON_DELEGABLE_CONTROL_PERMISSIONS:
        return deny("protected_delegation_forbidden")
    if not delegable_permission_keys_after <= actor.delegable_permissions:
        return deny("delegation_ceiling_exceeded")
    return _affected_subjects_are_manageable(
        actor=actor,
        affected=affected_after,
    )


def decide_user_status_change(
    *,
    actor: AuthoritySnapshot,
    target_before: AuthoritySnapshot,
    proposed_is_active: bool,
) -> PolicyDecision:
    del proposed_is_active
    basic = _basic_actor_check(actor, PermissionKey.USERS_STATUS_UPDATE)
    if basic is not None:
        return basic
    if actor.user_id == target_before.user_id:
        return deny("self_management_forbidden")
    if target_before.is_protected:
        return deny("protected_subject")
    if actor.management_tier <= target_before.management_tier:
        return deny("target_not_strictly_lower")
    if not _target_is_within_delegation(actor, target_before):
        return deny("delegation_ceiling_exceeded")
    return allow()


def decide_super_admin_transfer(
    *,
    actor: AuthoritySnapshot,
    target_before: AuthoritySnapshot,
) -> PolicyDecision:
    basic = _basic_actor_check(actor, PermissionKey.SUPER_ADMIN_TRANSFER)
    if basic is not None:
        return basic
    if not actor.is_owner:
        return deny("actor_is_not_super_admin")
    if not target_before.user_is_active:
        return deny("target_inactive")
    if actor.user_id == target_before.user_id:
        return deny("self_transfer_forbidden")
    if target_before.is_protected:
        return deny("protected_target")
    return allow()
