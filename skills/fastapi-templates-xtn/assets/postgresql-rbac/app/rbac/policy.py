from dataclasses import dataclass
from typing import Literal

from app.rbac.domain import (
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


def _target_is_within_actor_authority(
    actor: AuthoritySnapshot,
    target: AuthoritySnapshot,
) -> bool:
    return (
        target.permissions <= SUPER_ADMIN_PERMISSION_KEYS
        and target.permissions <= actor.permissions
    )


def _role_is_within_actor_authority(
    actor: AuthoritySnapshot,
    role: RoleGrant,
) -> bool:
    return (
        role.permissions <= SUPER_ADMIN_PERMISSION_KEYS
        and role.permissions <= actor.permissions
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


def is_administrative_user_visible(
    *,
    actor: AuthoritySnapshot,
    target: AuthoritySnapshot,
) -> bool:
    if actor.is_super_admin:
        return True
    return (
        actor.user_id != target.user_id
        and not target.is_protected
        and target.management_tier < actor.management_tier
    )


def is_administrative_role_visible(
    *,
    actor: AuthoritySnapshot,
    role: RoleGrant,
) -> bool:
    if actor.is_super_admin:
        return True
    return (
        not role.is_protected
        and not role.is_super_admin
        and role.management_tier < actor.management_tier
    )


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
        if not _target_is_within_actor_authority(actor, subject):
            return deny("permission_ceiling_exceeded")
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
            return deny("super_admin_assignment_offline_only")
        if operation == "unbind" and role.key == SystemRoleKey.USER.value:
            return deny("default_user_role_required")
        if role.key == SystemRoleKey.ADMIN.value and not actor.is_super_admin:
            return deny("super_admin_required")
        if not _role_is_within_actor_authority(actor, role):
            return deny("permission_ceiling_exceeded")
        if actor.management_tier <= role.management_tier:
            return deny("role_not_strictly_lower")

    if actor.management_tier <= target_before.management_tier:
        return deny("target_not_strictly_lower")
    if actor.management_tier <= target_after.management_tier:
        return deny("target_not_strictly_lower")
    if not _target_is_within_actor_authority(actor, target_before):
        return deny("permission_ceiling_exceeded")
    if not _target_is_within_actor_authority(actor, target_after):
        return deny("permission_ceiling_exceeded")
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
    if not _role_is_within_actor_authority(actor, changed_role):
        return deny("permission_ceiling_exceeded")
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
    if not _role_is_within_actor_authority(actor, changed_role_before):
        return deny("permission_ceiling_exceeded")
    if not permission_keys_after <= SUPER_ADMIN_PERMISSION_KEYS:
        return deny("permission_outside_control_plane")
    if PermissionKey.REGISTRATION_CONFIGURE.value in permission_keys_after:
        return deny("system_only_permission")
    if not permission_keys_after <= actor.permissions:
        return deny("permission_ceiling_exceeded")
    return _affected_subjects_are_manageable(
        actor=actor,
        affected=affected_after,
    )


def _decide_user_administration(
    *,
    actor: AuthoritySnapshot,
    target_before: AuthoritySnapshot,
    required_permission: PermissionKey,
) -> PolicyDecision:
    basic = _basic_actor_check(actor, required_permission)
    if basic is not None:
        return basic
    if actor.user_id == target_before.user_id:
        return deny("self_management_forbidden")
    if target_before.is_protected:
        return deny("protected_subject")
    if actor.management_tier <= target_before.management_tier:
        return deny("target_not_strictly_lower")
    if not _target_is_within_actor_authority(actor, target_before):
        return deny("permission_ceiling_exceeded")
    return allow()


def decide_user_status_change(
    *,
    actor: AuthoritySnapshot,
    target_before: AuthoritySnapshot,
) -> PolicyDecision:
    return _decide_user_administration(
        actor=actor,
        target_before=target_before,
        required_permission=PermissionKey.USERS_STATUS_UPDATE,
    )


def decide_user_password_reset(
    *,
    actor: AuthoritySnapshot,
    target_before: AuthoritySnapshot,
) -> PolicyDecision:
    """Allow credential reset only for a strictly lower, visible identity."""
    return _decide_user_administration(
        actor=actor,
        target_before=target_before,
        required_permission=PermissionKey.USERS_PASSWORD_RESET,
    )


def decide_user_sessions_revoke(
    *,
    actor: AuthoritySnapshot,
    target_before: AuthoritySnapshot,
) -> PolicyDecision:
    return _decide_user_administration(
        actor=actor,
        target_before=target_before,
        required_permission=PermissionKey.USERS_SESSIONS_REVOKE,
    )
