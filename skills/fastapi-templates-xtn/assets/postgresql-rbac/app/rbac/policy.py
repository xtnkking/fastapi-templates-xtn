from dataclasses import dataclass
from typing import Literal

from app.rbac.domain import (
    NON_DELEGABLE_CONTROL_PERMISSIONS,
    OWNER_PERMISSION_KEYS,
    AuthoritySnapshot,
    PermissionKey,
    RoleGrant,
)


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    allowed: bool
    reason_code: str


def allow() -> PolicyDecision:
    return PolicyDecision(allowed=True, reason_code="allowed")


def deny(reason_code: str) -> PolicyDecision:
    return PolicyDecision(allowed=False, reason_code=reason_code)


def _actor_is_active(actor: AuthoritySnapshot) -> bool:
    return actor.user_is_active


def _target_is_within_delegation(
    actor: AuthoritySnapshot, target: AuthoritySnapshot
) -> bool:
    return (
        target.permissions <= OWNER_PERMISSION_KEYS
        and target.delegable_permissions <= OWNER_PERMISSION_KEYS
        and target.permissions <= actor.delegable_permissions
        and target.delegable_permissions <= actor.delegable_permissions
    )


def _role_is_within_delegation(
    actor: AuthoritySnapshot,
    role: RoleGrant,
) -> bool:
    return (
        role.permissions <= OWNER_PERMISSION_KEYS
        and role.delegable_permissions <= OWNER_PERMISSION_KEYS
        and role.permissions <= actor.delegable_permissions
        and role.delegable_permissions <= actor.delegable_permissions
    )


def decide_role_change(
    *,
    operation: Literal["assign", "revoke"],
    actor: AuthoritySnapshot,
    target_before: AuthoritySnapshot,
    target_after: AuthoritySnapshot,
    changed_role: RoleGrant,
) -> PolicyDecision:
    required = (
        PermissionKey.ROLES_ASSIGN
        if operation == "assign"
        else PermissionKey.ROLES_REVOKE
    )
    if required.value not in actor.permissions:
        return deny("missing_operation_permission")
    if not _actor_is_active(actor):
        return deny("actor_inactive")
    if operation == "assign" and not target_before.user_is_active:
        return deny("target_inactive")
    if actor.user_id == target_before.user_id:
        return deny("self_management_forbidden")
    if target_before.is_protected or changed_role.is_protected:
        return deny("protected_subject")
    if (
        not changed_role.permissions <= OWNER_PERMISSION_KEYS
        or not changed_role.delegable_permissions <= OWNER_PERMISSION_KEYS
    ):
        return deny("permission_outside_rbac_control_plane")

    ceilings = (
        target_before.management_tier,
        target_after.management_tier,
        changed_role.management_tier,
    )
    if any(actor.management_tier <= tier for tier in ceilings):
        return deny("target_not_strictly_lower")

    for target in (target_before, target_after):
        if not _target_is_within_delegation(actor, target):
            return deny("delegation_ceiling_exceeded")
    return allow()


def decide_role_create(
    *,
    actor: AuthoritySnapshot,
    management_tier: int,
    permission_keys: frozenset[str],
) -> PolicyDecision:
    if PermissionKey.ROLES_CREATE.value not in actor.permissions:
        return deny("missing_operation_permission")
    if not _actor_is_active(actor):
        return deny("actor_inactive")
    if not permission_keys <= OWNER_PERMISSION_KEYS:
        return deny("permission_outside_rbac_control_plane")
    if management_tier < 0 or actor.management_tier <= management_tier:
        return deny("role_not_strictly_lower")
    if not permission_keys <= actor.delegable_permissions:
        return deny("delegation_ceiling_exceeded")
    return allow()


def decide_role_permissions_replace(
    *,
    actor: AuthoritySnapshot,
    changed_role_before: RoleGrant,
    permission_keys: frozenset[str],
    actor_holds_role: bool,
    affected_before_after: tuple[tuple[AuthoritySnapshot, AuthoritySnapshot], ...],
) -> PolicyDecision:
    if PermissionKey.ROLES_PERMISSIONS_UPDATE.value not in actor.permissions:
        return deny("missing_operation_permission")
    if not _actor_is_active(actor):
        return deny("actor_inactive")
    if changed_role_before.is_protected:
        return deny("protected_role")
    if not permission_keys <= OWNER_PERMISSION_KEYS:
        return deny("permission_outside_rbac_control_plane")
    if actor_holds_role:
        return deny("indirect_self_change_forbidden")
    if actor.management_tier <= changed_role_before.management_tier:
        return deny("role_not_strictly_lower")
    if not _role_is_within_delegation(actor, changed_role_before):
        return deny("delegation_ceiling_exceeded")
    if not permission_keys <= actor.delegable_permissions:
        return deny("delegation_ceiling_exceeded")

    for before, after in affected_before_after:
        if before.is_protected or actor.user_id == before.user_id:
            return deny("affected_subject_not_manageable")
        if actor.management_tier <= max(before.management_tier, after.management_tier):
            return deny("affected_subject_not_strictly_lower")
        for snapshot in (before, after):
            if not _target_is_within_delegation(actor, snapshot):
                return deny("delegation_ceiling_exceeded")
    return allow()


def decide_role_delegation_replace(
    *,
    actor: AuthoritySnapshot,
    changed_role_before: RoleGrant,
    delegable_permission_keys: frozenset[str],
    actor_holds_role: bool,
    affected_before_after: tuple[tuple[AuthoritySnapshot, AuthoritySnapshot], ...],
) -> PolicyDecision:
    if PermissionKey.ROLES_DELEGATION_UPDATE.value not in actor.permissions:
        return deny("missing_operation_permission")
    if not _actor_is_active(actor):
        return deny("actor_inactive")
    if not actor.is_owner:
        return deny("owner_control_plane_required")
    if changed_role_before.is_protected or changed_role_before.is_owner:
        return deny("protected_role")
    if not changed_role_before.permissions <= OWNER_PERMISSION_KEYS:
        return deny("permission_outside_rbac_control_plane")
    if actor_holds_role:
        return deny("indirect_self_change_forbidden")
    if actor.management_tier <= changed_role_before.management_tier:
        return deny("role_not_strictly_lower")
    if not delegable_permission_keys <= changed_role_before.permissions:
        return deny("delegation_requires_role_permission")
    if delegable_permission_keys & NON_DELEGABLE_CONTROL_PERMISSIONS:
        return deny("protected_delegation_forbidden")
    if not _role_is_within_delegation(actor, changed_role_before):
        return deny("delegation_ceiling_exceeded")
    if not delegable_permission_keys <= actor.delegable_permissions:
        return deny("delegation_ceiling_exceeded")

    for before, after in affected_before_after:
        if before.is_protected or actor.user_id == before.user_id:
            return deny("affected_subject_not_manageable")
        if actor.management_tier <= max(before.management_tier, after.management_tier):
            return deny("affected_subject_not_strictly_lower")
        for snapshot in (before, after):
            if not _target_is_within_delegation(actor, snapshot):
                return deny("delegation_ceiling_exceeded")
    return allow()


def decide_user_status_change(
    *,
    actor: AuthoritySnapshot,
    target_before: AuthoritySnapshot,
    proposed_is_active: bool,
) -> PolicyDecision:
    if PermissionKey.USERS_STATUS_UPDATE.value not in actor.permissions:
        return deny("missing_operation_permission")
    if not _actor_is_active(actor):
        return deny("actor_inactive")
    if actor.user_id == target_before.user_id:
        return deny("self_management_forbidden")
    if target_before.is_protected:
        return deny("protected_subject")
    if actor.management_tier <= target_before.management_tier:
        return deny("target_not_strictly_lower")
    if not _target_is_within_delegation(actor, target_before):
        return deny("delegation_ceiling_exceeded")
    if proposed_is_active == target_before.user_is_active:
        return allow()
    return allow()


def decide_ownership_transfer(
    *,
    actor: AuthoritySnapshot,
    target_before: AuthoritySnapshot,
) -> PolicyDecision:
    if PermissionKey.SYSTEM_OWNER_TRANSFER.value not in actor.permissions:
        return deny("missing_operation_permission")
    if not _actor_is_active(actor) or not actor.is_owner:
        return deny("actor_is_not_current_owner")
    if not target_before.user_is_active:
        return deny("target_inactive")
    if actor.user_id == target_before.user_id:
        return deny("self_transfer_forbidden")
    if target_before.is_protected and not target_before.is_owner:
        return deny("protected_target")
    return allow()
