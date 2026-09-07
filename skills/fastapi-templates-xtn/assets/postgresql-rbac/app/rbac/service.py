import uuid
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Literal, TypeVar

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.database import SessionFactory
from app.rbac.domain import (
    RESERVED_ROLE_KEYS,
    SUPER_ADMIN_PERMISSION_KEYS,
    AuthoritySnapshot,
    AuthorizationContext,
    PermissionKey,
    RoleGrant,
    SystemRoleKey,
)
from app.rbac.errors import (
    RbacError,
    conflict,
    forbidden,
    invalid_request,
    not_found,
    precondition_failed,
    unauthenticated,
)
from app.rbac.models import (
    AuthorizationAuditEvent,
    AuthorizationState,
    Role,
    RolePermission,
    User,
    UserRole,
)
from app.rbac.policy import (
    decide_role_administration,
    decide_role_change,
    decide_role_create,
    decide_role_delegation_change,
    decide_role_permissions_change,
    decide_super_admin_transfer,
    decide_user_status_change,
)
from app.rbac.queries import (
    load_authority_snapshot,
    load_permission_keys,
    load_role_grant,
    lock_authorization_state,
    lock_role_permissions,
    lock_roles,
    lock_users,
    require_current_actor,
)
from app.rbac.schemas import (
    RoleCreateRequest,
    RoleMutationResponse,
    RoleResponse,
    RoleUpdateRequest,
    UserStatusUpdateRequest,
)

T = TypeVar("T")
RoleOperation = Literal["bind", "unbind"]
RoleAdministrationOperation = Literal["update", "enable", "disable", "delete"]


@dataclass(slots=True)
class _MutationOutcome[T]:
    value: T
    reason_code: str
    before_state: dict[str, object] | None = None
    after_state: dict[str, object] | None = None
    audit_target_role_id: uuid.UUID | None = None


@dataclass(slots=True)
class _LockedSharedRole:
    actor: AuthoritySnapshot
    role: Role
    role_before: RoleGrant
    affected_before: tuple[AuthoritySnapshot, ...]
    affected_ids: frozenset[uuid.UUID]
    state: AuthorizationState
    users: dict[uuid.UUID, User]
    permission_rows: dict[str, RolePermission]


def _snapshot_payload(snapshot: AuthoritySnapshot) -> dict[str, object]:
    return {
        "user_id": str(snapshot.user_id),
        "is_active": snapshot.user_is_active,
        "role_ids": [str(role.role_id) for role in snapshot.roles],
        "role_keys": sorted(role.key for role in snapshot.roles),
        "permissions": sorted(snapshot.permissions),
        "delegable_permissions": sorted(snapshot.delegable_permissions),
        "management_tier": snapshot.management_tier,
        "is_protected": snapshot.is_protected,
        "is_owner": snapshot.is_owner,
        "authz_version": snapshot.authz_version,
    }


def _role_response(role: Role, grant: RoleGrant) -> RoleResponse:
    return RoleResponse(
        id=role.id,
        key=role.key,
        name=role.name,
        description=role.description,
        management_tier=role.management_tier,
        is_active=role.is_active,
        is_system=role.is_system,
        is_protected=role.is_protected,
        is_owner=role.is_owner,
        permissions=tuple(sorted(grant.permissions)),
        delegable_permissions=tuple(sorted(grant.delegable_permissions)),
        version=role.version,
        deleted_at=role.deleted_at,
    )


def _role_payload(role: RoleResponse) -> dict[str, object]:
    return {
        "role_id": str(role.id),
        "key": role.key,
        "name": role.name,
        "description": role.description,
        "management_tier": role.management_tier,
        "is_active": role.is_active,
        "is_system": role.is_system,
        "is_deleted": role.deleted_at is not None,
        "permissions": list(role.permissions),
        "delegable_permissions": list(role.delegable_permissions),
        "version": role.version,
    }


class RbacService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def _run_audited(
        self,
        *,
        context: AuthorizationContext,
        action: str,
        target_user_id: uuid.UUID | None,
        target_role_id: uuid.UUID | None,
        operation: Callable[[AsyncSession], Awaitable[_MutationOutcome[T]]],
    ) -> T:
        outcome: _MutationOutcome[T]
        try:
            async with self._session_factory() as session:
                async with session.begin():
                    outcome = await operation(session)
                    session.add(
                        self._audit_event(
                            context=context,
                            action=action,
                            decision="allowed",
                            reason_code=outcome.reason_code,
                            target_user_id=target_user_id,
                            target_role_id=(
                                outcome.audit_target_role_id or target_role_id
                            ),
                            before_state=outcome.before_state,
                            after_state=outcome.after_state,
                        )
                    )
        except RbacError as exc:
            if exc.status_code < 500:
                await self._write_denied_audit(
                    context=context,
                    action=action,
                    reason_code=exc.reason_code,
                    target_user_id=target_user_id,
                    target_role_id=target_role_id,
                )
            raise
        return outcome.value

    async def _write_denied_audit(
        self,
        *,
        context: AuthorizationContext,
        action: str,
        reason_code: str,
        target_user_id: uuid.UUID | None,
        target_role_id: uuid.UUID | None,
    ) -> None:
        async with self._session_factory() as session:
            async with session.begin():
                session.add(
                    self._audit_event(
                        context=context,
                        action=action,
                        decision="denied",
                        reason_code=reason_code,
                        target_user_id=target_user_id,
                        target_role_id=target_role_id,
                    )
                )

    @staticmethod
    def _require_current_locked_actor_row(
        *,
        actor_user: User | None,
        context: AuthorizationContext,
    ) -> User:
        if actor_user is None:
            raise unauthenticated("actor_missing")
        if (
            not actor_user.is_active
            or actor_user.token_version != context.principal.token_version
        ):
            raise unauthenticated("actor_no_longer_active")
        return actor_user

    @staticmethod
    def _require_expected_role_version(role: Role, expected_version: int) -> None:
        if role.version != expected_version:
            raise precondition_failed("stale_role_version")

    @staticmethod
    def _audit_event(
        *,
        context: AuthorizationContext,
        action: str,
        decision: str,
        reason_code: str,
        target_user_id: uuid.UUID | None,
        target_role_id: uuid.UUID | None,
        before_state: dict[str, object] | None = None,
        after_state: dict[str, object] | None = None,
    ) -> AuthorizationAuditEvent:
        return AuthorizationAuditEvent(
            actor_user_id=context.principal.user_id,
            target_user_id=target_user_id,
            target_role_id=target_role_id,
            action=action,
            decision=decision,
            reason_code=reason_code,
            before_state=before_state,
            after_state=after_state,
            request_id=context.request_id,
        )

    async def _lock_actor_and_target_user(
        self,
        session: AsyncSession,
        *,
        context: AuthorizationContext,
        target_user_id: uuid.UUID,
        required_permission: PermissionKey,
        additional_role_ids: set[uuid.UUID] | None = None,
    ) -> tuple[AuthoritySnapshot, AuthoritySnapshot, User, AuthorizationState]:
        state = await lock_authorization_state(session)
        actor_user_id = context.principal.user_id
        users = await lock_users(session, {actor_user_id, target_user_id})
        self._require_current_locked_actor_row(
            actor_user=users.get(actor_user_id),
            context=context,
        )
        actor = await require_current_actor(
            session,
            actor_user_id=actor_user_id,
            token_version=context.principal.token_version,
        )
        if required_permission.value not in actor.permissions:
            raise forbidden("missing_operation_permission")
        if target_user_id not in users:
            raise not_found("target_user_not_found")

        user_ids = {actor_user_id, target_user_id}
        assigned_role_ids = set(
            (
                await session.scalars(
                    select(UserRole.role_id).where(UserRole.user_id.in_(user_ids))
                )
            ).all()
        )
        await lock_roles(
            session,
            role_ids=assigned_role_ids | (additional_role_ids or set()),
        )
        actor = await require_current_actor(
            session,
            actor_user_id=actor_user_id,
            token_version=context.principal.token_version,
        )
        target = await load_authority_snapshot(
            session,
            user_id=target_user_id,
            include_disabled_roles=True,
        )
        return actor, target, users[target_user_id], state

    async def update_user_status(
        self,
        *,
        context: AuthorizationContext,
        target_user_id: uuid.UUID,
        request: UserStatusUpdateRequest,
    ) -> User:
        async def operation(session: AsyncSession) -> _MutationOutcome[User]:
            actor, target_before, target_row, state = (
                await self._lock_actor_and_target_user(
                    session,
                    context=context,
                    target_user_id=target_user_id,
                    required_permission=PermissionKey.USERS_STATUS_UPDATE,
                )
            )
            decision = decide_user_status_change(
                actor=actor,
                target_before=target_before,
                proposed_is_active=request.is_active,
            )
            if not decision.allowed:
                raise forbidden(decision.reason_code)

            changed = target_row.is_active != request.is_active
            target_after = replace(target_before, user_is_active=request.is_active)
            if changed:
                target_row.is_active = request.is_active
                target_row.token_version += 1
                target_row.authz_version += 1
                state.epoch += 1
                target_after = replace(
                    target_after,
                    authz_version=target_row.authz_version,
                )
            return _MutationOutcome(
                value=target_row,
                reason_code=(
                    "user_status_updated" if changed else "user_status_unchanged"
                ),
                before_state=_snapshot_payload(target_before),
                after_state=_snapshot_payload(target_after),
            )

        return await self._run_audited(
            context=context,
            action="user.status.update",
            target_user_id=target_user_id,
            target_role_id=None,
            operation=operation,
        )

    async def change_user_roles(
        self,
        *,
        context: AuthorizationContext,
        target_user_id: uuid.UUID,
        role_ids: Iterable[uuid.UUID],
        operation: RoleOperation,
    ) -> bool:
        requested_role_ids = frozenset(role_ids)
        if not requested_role_ids:
            raise invalid_request("role_ids_required")

        async def mutate(session: AsyncSession) -> _MutationOutcome[bool]:
            required_permission = (
                PermissionKey.ROLES_ASSIGN
                if operation == "bind"
                else PermissionKey.ROLES_REVOKE
            )
            actor, target_before, target_row, state = (
                await self._lock_actor_and_target_user(
                    session,
                    context=context,
                    target_user_id=target_user_id,
                    required_permission=required_permission,
                    additional_role_ids=set(requested_role_ids),
                )
            )
            grants: list[RoleGrant] = []
            for role_id in sorted(requested_role_ids, key=str):
                grants.append(
                    await load_role_grant(
                        session,
                        role_id=role_id,
                        include_disabled=(operation == "unbind"),
                    )
                )

            existing_ids = set(
                (
                    await session.scalars(
                        select(UserRole.role_id).where(
                            UserRole.user_id == target_user_id,
                            UserRole.role_id.in_(requested_role_ids),
                        )
                    )
                ).all()
            )
            target_after = target_before
            if operation == "bind":
                for grant in grants:
                    target_after = target_after.with_role(grant)
                changed_ids = requested_role_ids - existing_ids
            else:
                for grant in grants:
                    target_after = target_after.without_role(grant.role_id)
                changed_ids = requested_role_ids & existing_ids

            decision = decide_role_change(
                operation=operation,
                actor=actor,
                target_before=target_before,
                target_after=target_after,
                changed_roles=tuple(grants),
            )
            if not decision.allowed:
                raise forbidden(decision.reason_code)

            changed = bool(changed_ids)
            if changed:
                if operation == "bind":
                    session.add_all(
                        UserRole(
                            user_id=target_user_id,
                            role_id=role_id,
                            assigned_by_user_id=actor.user_id,
                        )
                        for role_id in sorted(changed_ids, key=str)
                    )
                else:
                    await session.execute(
                        delete(UserRole).where(
                            UserRole.user_id == target_user_id,
                            UserRole.role_id.in_(changed_ids),
                        )
                    )
                target_row.authz_version += 1
                state.epoch += 1
                target_after = replace(
                    target_after,
                    authz_version=target_row.authz_version,
                )
            return _MutationOutcome(
                value=changed,
                reason_code=(
                    (
                        "user_roles_bound"
                        if operation == "bind"
                        else "user_roles_unbound"
                    )
                    if changed
                    else "user_roles_unchanged"
                ),
                before_state=_snapshot_payload(target_before),
                after_state=_snapshot_payload(target_after),
            )

        return await self._run_audited(
            context=context,
            action=f"user.roles.{operation}",
            target_user_id=target_user_id,
            target_role_id=None,
            operation=mutate,
        )

    async def assign_role(
        self,
        *,
        context: AuthorizationContext,
        target_user_id: uuid.UUID,
        role_id: uuid.UUID,
    ) -> None:
        await self.change_user_roles(
            context=context,
            target_user_id=target_user_id,
            role_ids=(role_id,),
            operation="bind",
        )

    async def revoke_role(
        self,
        *,
        context: AuthorizationContext,
        target_user_id: uuid.UUID,
        role_id: uuid.UUID,
    ) -> None:
        await self.change_user_roles(
            context=context,
            target_user_id=target_user_id,
            role_ids=(role_id,),
            operation="unbind",
        )

    async def create_role(
        self,
        *,
        context: AuthorizationContext,
        request: RoleCreateRequest,
    ) -> RoleMutationResponse:
        role_id = uuid.uuid4()

        async def operation(
            session: AsyncSession,
        ) -> _MutationOutcome[RoleMutationResponse]:
            state = await lock_authorization_state(session)
            actor_id = context.principal.user_id
            users = await lock_users(session, {actor_id})
            self._require_current_locked_actor_row(
                actor_user=users.get(actor_id),
                context=context,
            )
            actor_role_ids = set(
                (
                    await session.scalars(
                        select(UserRole.role_id).where(UserRole.user_id == actor_id)
                    )
                ).all()
            )
            await lock_roles(session, role_ids=actor_role_ids)
            actor = await require_current_actor(
                session,
                actor_user_id=actor_id,
                token_version=context.principal.token_version,
            )
            decision = decide_role_create(
                actor=actor,
                management_tier=request.management_tier,
            )
            if not decision.allowed:
                raise forbidden(decision.reason_code)
            if request.key in RESERVED_ROLE_KEYS:
                raise conflict("reserved_role_key")
            if await session.scalar(select(Role.id).where(Role.key == request.key)):
                raise conflict("role_key_exists")

            role = Role(
                id=role_id,
                key=request.key,
                name=request.name,
                description=request.description,
                management_tier=request.management_tier,
                is_active=True,
                is_protected=False,
                is_system=False,
                is_owner=False,
            )
            session.add(role)
            await session.flush()
            state.epoch += 1
            empty_grant = RoleGrant(
                role_id=role.id,
                key=role.key,
                management_tier=role.management_tier,
                permissions=frozenset(),
                delegable_permissions=frozenset(),
                is_system=False,
                is_protected=False,
                is_owner=False,
            )
            role_after = _role_response(role, empty_grant)
            return _MutationOutcome(
                value=RoleMutationResponse(changed=True, role=role_after),
                reason_code="role_created",
                after_state=_role_payload(role_after),
            )

        return await self._run_audited(
            context=context,
            action="role.create",
            target_user_id=None,
            target_role_id=role_id,
            operation=operation,
        )

    async def update_role(
        self,
        *,
        context: AuthorizationContext,
        role_id: uuid.UUID,
        request: RoleUpdateRequest,
        expected_version: int,
    ) -> RoleMutationResponse:
        async def operation(
            session: AsyncSession,
        ) -> _MutationOutcome[RoleMutationResponse]:
            locked = await self._lock_shared_role_change(
                session,
                context=context,
                role_id=role_id,
                required_permission=PermissionKey.ROLES_UPDATE,
                include_inactive=True,
            )
            self._require_expected_role_version(locked.role, expected_version)
            self._require_role_administration(locked, operation="update")
            role_before = _role_response(locked.role, locked.role_before)

            changed = False
            if request.name is not None and request.name != locked.role.name:
                locked.role.name = request.name
                changed = True
            if (
                request.description is not None
                and request.description != locked.role.description
            ):
                locked.role.description = request.description
                changed = True
            if changed:
                locked.role.version += 1
                locked.state.epoch += 1
            role_after = _role_response(locked.role, locked.role_before)
            return _MutationOutcome(
                value=RoleMutationResponse(changed=changed, role=role_after),
                reason_code="role_updated" if changed else "role_unchanged",
                before_state=_role_payload(role_before),
                after_state=_role_payload(role_after),
            )

        return await self._run_audited(
            context=context,
            action="role.update",
            target_user_id=None,
            target_role_id=role_id,
            operation=operation,
        )

    async def set_role_active(
        self,
        *,
        context: AuthorizationContext,
        role_id: uuid.UUID,
        is_active: bool,
        expected_version: int,
    ) -> RoleMutationResponse:
        verb: Literal["enable", "disable"] = "enable" if is_active else "disable"

        async def operation(
            session: AsyncSession,
        ) -> _MutationOutcome[RoleMutationResponse]:
            locked = await self._lock_shared_role_change(
                session,
                context=context,
                role_id=role_id,
                required_permission=PermissionKey.ROLES_STATUS_UPDATE,
                include_inactive=True,
            )
            self._require_expected_role_version(locked.role, expected_version)
            self._require_role_administration(locked, operation=verb)
            role_before = _role_response(locked.role, locked.role_before)
            changed = locked.role.is_active != is_active
            if changed:
                locked.role.is_active = is_active
                self._bump_shared_authority(locked)
            role_after = _role_response(locked.role, locked.role_before)
            return _MutationOutcome(
                value=RoleMutationResponse(changed=changed, role=role_after),
                reason_code=f"role_{verb}d" if changed else "role_status_unchanged",
                before_state=_role_payload(role_before),
                after_state=_role_payload(role_after),
            )

        return await self._run_audited(
            context=context,
            action=f"role.{verb}",
            target_user_id=None,
            target_role_id=role_id,
            operation=operation,
        )

    async def soft_delete_role(
        self,
        *,
        context: AuthorizationContext,
        role_id: uuid.UUID,
        expected_version: int,
    ) -> RoleMutationResponse:
        async def operation(
            session: AsyncSession,
        ) -> _MutationOutcome[RoleMutationResponse]:
            locked = await self._lock_shared_role_change(
                session,
                context=context,
                role_id=role_id,
                required_permission=PermissionKey.ROLES_DELETE,
                include_inactive=True,
            )
            self._require_expected_role_version(locked.role, expected_version)
            self._require_role_administration(locked, operation="delete")
            role_before = _role_response(locked.role, locked.role_before)
            locked.role.is_active = False
            locked.role.deleted_at = datetime.now(UTC)
            locked.role.deleted_by_user_id = locked.actor.user_id
            self._bump_shared_authority(locked)
            role_after = _role_response(locked.role, locked.role_before)
            return _MutationOutcome(
                value=RoleMutationResponse(changed=True, role=role_after),
                reason_code="role_soft_deleted",
                before_state=_role_payload(role_before),
                after_state=_role_payload(role_after),
            )

        return await self._run_audited(
            context=context,
            action="role.delete",
            target_user_id=None,
            target_role_id=role_id,
            operation=operation,
        )

    async def change_role_permissions(
        self,
        *,
        context: AuthorizationContext,
        role_id: uuid.UUID,
        permission_ids: Iterable[uuid.UUID],
        operation: RoleOperation,
        expected_version: int,
    ) -> RoleMutationResponse:
        requested_ids = frozenset(permission_ids)
        if not requested_ids:
            raise invalid_request("permission_ids_required")

        async def mutate(
            session: AsyncSession,
        ) -> _MutationOutcome[RoleMutationResponse]:
            locked = await self._lock_shared_role_change(
                session,
                context=context,
                role_id=role_id,
                required_permission=(
                    PermissionKey.ROLES_PERMISSIONS_BIND
                    if operation == "bind"
                    else PermissionKey.ROLES_PERMISSIONS_UNBIND
                ),
            )
            self._require_expected_role_version(locked.role, expected_version)
            permission_keys_by_id = await load_permission_keys(session, requested_ids)
            if set(permission_keys_by_id) != set(requested_ids):
                raise invalid_request("unknown_permission_id")
            requested_keys = frozenset(permission_keys_by_id.values())
            if not requested_keys <= SUPER_ADMIN_PERMISSION_KEYS:
                raise invalid_request("permission_outside_control_plane")

            if operation == "bind":
                permission_keys_after = locked.role_before.permissions | requested_keys
            else:
                permission_keys_after = locked.role_before.permissions - requested_keys
            retained_delegable = (
                locked.role_before.delegable_permissions & permission_keys_after
            )
            replacement = replace(
                locked.role_before,
                permissions=permission_keys_after,
                delegable_permissions=retained_delegable,
            )
            affected_after = tuple(
                snapshot.with_role(replacement)
                for snapshot in locked.affected_before
            )
            decision = decide_role_permissions_change(
                operation=operation,
                actor=locked.actor,
                changed_role_before=locked.role_before,
                permission_keys_after=permission_keys_after,
                actor_holds_role=locked.actor.user_id in locked.affected_ids,
                affected_after=affected_after,
            )
            if not decision.allowed:
                raise forbidden(decision.reason_code)

            role_before = _role_response(locked.role, locked.role_before)
            changed = locked.role_before.permissions != permission_keys_after
            if changed:
                if operation == "bind":
                    existing = set(locked.permission_rows)
                    session.add_all(
                        RolePermission(
                            role_id=role_id,
                            permission_id=permission_id,
                            can_delegate=False,
                        )
                        for permission_id, key in permission_keys_by_id.items()
                        if key not in existing
                    )
                else:
                    await session.execute(
                        delete(RolePermission).where(
                            RolePermission.role_id == role_id,
                            RolePermission.permission_id.in_(requested_ids),
                        )
                    )
                self._bump_shared_authority(locked)

            role_after = _role_response(locked.role, replacement)
            return _MutationOutcome(
                value=RoleMutationResponse(changed=changed, role=role_after),
                reason_code=(
                    (
                        "role_permissions_bound"
                        if operation == "bind"
                        else "role_permissions_unbound"
                    )
                    if changed
                    else "role_permissions_unchanged"
                ),
                before_state=_role_payload(role_before),
                after_state=_role_payload(role_after),
            )

        return await self._run_audited(
            context=context,
            action=f"role.permissions.{operation}",
            target_user_id=None,
            target_role_id=role_id,
            operation=mutate,
        )

    async def change_role_delegation(
        self,
        *,
        context: AuthorizationContext,
        role_id: uuid.UUID,
        permission_ids: Iterable[uuid.UUID],
        operation: RoleOperation,
        expected_version: int,
    ) -> RoleMutationResponse:
        requested_ids = frozenset(permission_ids)
        if not requested_ids:
            raise invalid_request("permission_ids_required")

        async def mutate(
            session: AsyncSession,
        ) -> _MutationOutcome[RoleMutationResponse]:
            locked = await self._lock_shared_role_change(
                session,
                context=context,
                role_id=role_id,
                required_permission=PermissionKey.ROLES_DELEGATION_UPDATE,
            )
            self._require_expected_role_version(locked.role, expected_version)
            permission_keys_by_id = await load_permission_keys(session, requested_ids)
            if set(permission_keys_by_id) != set(requested_ids):
                raise invalid_request("unknown_permission_id")
            requested_keys = frozenset(permission_keys_by_id.values())
            if operation == "bind":
                delegable_after = (
                    locked.role_before.delegable_permissions | requested_keys
                )
            else:
                delegable_after = (
                    locked.role_before.delegable_permissions - requested_keys
                )
            replacement = replace(
                locked.role_before,
                delegable_permissions=delegable_after,
            )
            affected_after = tuple(
                snapshot.with_role(replacement)
                for snapshot in locked.affected_before
            )
            decision = decide_role_delegation_change(
                actor=locked.actor,
                changed_role_before=locked.role_before,
                delegable_permission_keys_after=delegable_after,
                actor_holds_role=locked.actor.user_id in locked.affected_ids,
                affected_after=affected_after,
            )
            if not decision.allowed:
                if decision.reason_code == "delegation_requires_role_permission":
                    raise invalid_request(decision.reason_code)
                raise forbidden(decision.reason_code)

            role_before = _role_response(locked.role, locked.role_before)
            changed = locked.role_before.delegable_permissions != delegable_after
            if changed:
                for key, row in locked.permission_rows.items():
                    row.can_delegate = key in delegable_after
                self._bump_shared_authority(locked)
            role_after = _role_response(locked.role, replacement)
            return _MutationOutcome(
                value=RoleMutationResponse(changed=changed, role=role_after),
                reason_code=(
                    (
                        "role_delegation_bound"
                        if operation == "bind"
                        else "role_delegation_unbound"
                    )
                    if changed
                    else "role_delegation_unchanged"
                ),
                before_state=_role_payload(role_before),
                after_state=_role_payload(role_after),
            )

        return await self._run_audited(
            context=context,
            action=f"role.delegation.{operation}",
            target_user_id=None,
            target_role_id=role_id,
            operation=mutate,
        )

    async def transfer_ownership(
        self,
        *,
        context: AuthorizationContext,
        target_user_id: uuid.UUID,
    ) -> None:
        async def operation(session: AsyncSession) -> _MutationOutcome[None]:
            state = await lock_authorization_state(session)
            actor_id = context.principal.user_id
            users = await lock_users(session, {actor_id, target_user_id})
            self._require_current_locked_actor_row(
                actor_user=users.get(actor_id),
                context=context,
            )
            actor = await require_current_actor(
                session,
                actor_user_id=actor_id,
                token_version=context.principal.token_version,
            )
            if (
                PermissionKey.SUPER_ADMIN_TRANSFER.value not in actor.permissions
                or not actor.is_owner
            ):
                raise forbidden("actor_is_not_super_admin")
            if target_user_id not in users:
                raise not_found("target_user_not_found")

            owner_role_id = await session.scalar(
                select(Role.id).where(
                    Role.key == SystemRoleKey.SUPER_ADMIN.value,
                    Role.is_owner.is_(True),
                )
            )
            if owner_role_id is None:
                raise conflict("super_admin_role_missing")
            user_ids = {actor_id, target_user_id}
            all_role_ids = set(
                (
                    await session.scalars(
                        select(UserRole.role_id).where(UserRole.user_id.in_(user_ids))
                    )
                ).all()
            )
            locked_roles = await lock_roles(
                session,
                role_ids=all_role_ids | {owner_role_id},
            )
            owner_role = locked_roles.get(owner_role_id)
            if owner_role is None:
                raise conflict("super_admin_role_missing")
            actor = await require_current_actor(
                session,
                actor_user_id=actor_id,
                token_version=context.principal.token_version,
            )
            target_before = await load_authority_snapshot(
                session,
                user_id=target_user_id,
                include_disabled_roles=True,
            )
            decision = decide_super_admin_transfer(
                actor=actor,
                target_before=target_before,
            )
            if not decision.allowed:
                raise forbidden(decision.reason_code)

            owner_grant = await load_role_grant(session, role_id=owner_role.id)
            actor_assignment = await session.scalar(
                select(UserRole).where(
                    UserRole.user_id == actor.user_id,
                    UserRole.role_id == owner_role.id,
                )
            )
            if actor_assignment is None:
                raise forbidden("actor_is_not_super_admin")
            target_assignment = await session.scalar(
                select(UserRole).where(
                    UserRole.user_id == target_user_id,
                    UserRole.role_id == owner_role.id,
                )
            )
            await session.delete(actor_assignment)
            await session.flush()
            if target_assignment is None:
                session.add(
                    UserRole(
                        user_id=target_user_id,
                        role_id=owner_role.id,
                        assigned_by_user_id=actor.user_id,
                    )
                )
            users[actor.user_id].authz_version += 1
            users[target_user_id].authz_version += 1
            state.epoch += 1
            target_after = replace(
                target_before.with_role(owner_grant),
                authz_version=users[target_user_id].authz_version,
            )
            return _MutationOutcome(
                value=None,
                reason_code="super_admin_transferred",
                before_state={
                    "previous_super_admin": _snapshot_payload(actor),
                    "next_super_admin": _snapshot_payload(target_before),
                },
                after_state={
                    "previous_super_admin_user_id": str(actor.user_id),
                    "next_super_admin": _snapshot_payload(target_after),
                },
                audit_target_role_id=owner_role.id,
            )

        await self._run_audited(
            context=context,
            action="super_admin.transfer",
            target_user_id=target_user_id,
            target_role_id=None,
            operation=operation,
        )

    async def _lock_shared_role_change(
        self,
        session: AsyncSession,
        *,
        context: AuthorizationContext,
        role_id: uuid.UUID,
        required_permission: PermissionKey,
        include_inactive: bool = False,
    ) -> _LockedSharedRole:
        state = await lock_authorization_state(session)
        actor_id = context.principal.user_id
        affected_ids = set(
            (
                await session.scalars(
                    select(UserRole.user_id).where(UserRole.role_id == role_id)
                )
            ).all()
        )
        user_ids = affected_ids | {actor_id}
        users = await lock_users(session, user_ids)
        self._require_current_locked_actor_row(
            actor_user=users.get(actor_id),
            context=context,
        )

        all_role_ids = set(
            (
                await session.scalars(
                    select(UserRole.role_id).where(UserRole.user_id.in_(user_ids))
                )
            ).all()
        )
        locked_roles = await lock_roles(
            session,
            role_ids=all_role_ids | {role_id},
        )
        actor = await require_current_actor(
            session,
            actor_user_id=actor_id,
            token_version=context.principal.token_version,
        )
        if required_permission.value not in actor.permissions:
            raise forbidden("missing_operation_permission")

        role = locked_roles.get(role_id)
        if (
            role is None
            or role.deleted_at is not None
            or (not include_inactive and not role.is_active)
        ):
            raise not_found("role_not_found")
        permission_rows = await lock_role_permissions(session, role_id=role_id)
        role_before = await load_role_grant(
            session,
            role_id=role_id,
            include_disabled=True,
        )
        affected_before = tuple(
            [
                await load_authority_snapshot(
                    session,
                    user_id=user_id,
                    include_disabled_roles=True,
                )
                for user_id in sorted(affected_ids, key=str)
            ]
        )
        return _LockedSharedRole(
            actor=actor,
            role=role,
            role_before=role_before,
            affected_before=affected_before,
            affected_ids=frozenset(affected_ids),
            state=state,
            users=users,
            permission_rows=permission_rows,
        )

    @staticmethod
    def _require_role_administration(
        locked: _LockedSharedRole,
        *,
        operation: RoleAdministrationOperation,
    ) -> None:
        decision = decide_role_administration(
            operation=operation,
            actor=locked.actor,
            changed_role=locked.role_before,
            actor_holds_role=locked.actor.user_id in locked.affected_ids,
            affected=locked.affected_before,
        )
        if not decision.allowed:
            raise forbidden(decision.reason_code)

    @staticmethod
    def _bump_shared_authority(locked: _LockedSharedRole) -> None:
        locked.role.version += 1
        for user_id in locked.affected_ids:
            locked.users[user_id].authz_version += 1
        locked.state.epoch += 1


rbac_service = RbacService(SessionFactory)


def get_rbac_service() -> RbacService:
    return rbac_service
