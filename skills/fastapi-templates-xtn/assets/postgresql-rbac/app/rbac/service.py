import logging
import uuid
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal, TypeVar

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.database import SessionFactory
from app.observability import safe_exception_metadata, safe_log
from app.rbac.domain import (
    MAX_ROLES_PER_USER,
    RESERVED_ROLE_KEYS,
    SUPER_ADMIN_PERMISSION_KEYS,
    AuthoritySnapshot,
    AuthorizationContext,
    PermissionKey,
    RoleGrant,
)
from app.rbac.errors import (
    RbacError,
    conflict,
    forbidden,
    invalid_request,
    not_found,
    stale_resource_version,
    unauthenticated,
)
from app.rbac.models import (
    RbacAuditEvent,
    RbacState,
    Role,
    RolePermission,
    User,
    UserRole,
)
from app.rbac.policy import (
    decide_role_administration,
    decide_role_change,
    decide_role_create,
    decide_role_permissions_change,
    decide_user_sessions_revoke,
    decide_user_status_change,
    is_administrative_role_visible,
    is_administrative_user_visible,
)
from app.rbac.queries import (
    UserAccessView,
    count_live_user_roles,
    load_authority_snapshot,
    load_authority_snapshots_for_users,
    load_permission_keys,
    load_role_grant,
    load_role_grants_for_roles,
    load_user_access_views,
    lock_rbac_state,
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
    UserResponse,
    UserRoleMutationResponse,
    UserStatusUpdateRequest,
)

T = TypeVar("T")
RoleOperation = Literal["bind", "unbind"]
RoleAdministrationOperation = Literal["update", "enable", "disable", "delete"]

logger = logging.getLogger(__name__)


class _RoleOperation(StrEnum):
    BIND = "bind"
    UNBIND = "unbind"


def _require_role_operation(operation: RoleOperation) -> RoleOperation:
    try:
        validated = _RoleOperation(operation)
    except ValueError as exc:
        raise ValueError("operation must be 'bind' or 'unbind'") from exc
    return validated.value


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
    state: RbacState
    users: dict[uuid.UUID, User]
    permission_rows: dict[str, RolePermission]


def _snapshot_payload(snapshot: AuthoritySnapshot) -> dict[str, object]:
    return {
        "user_id": str(snapshot.user_id),
        "is_active": snapshot.user_is_active,
        "role_ids": [str(role.role_id) for role in snapshot.roles],
        "role_keys": sorted(role.key for role in snapshot.roles),
        "permissions": sorted(snapshot.permissions),
        "management_tier": snapshot.management_tier,
        "is_protected": snapshot.is_protected,
        "is_super_admin": snapshot.is_super_admin,
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
        permissions=tuple(sorted(grant.permissions)),
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
        "version": role.version,
    }


def _user_response(access: UserAccessView) -> UserResponse:
    authority = access.authority
    return UserResponse(
        id=authority.user_id,
        is_active=authority.user_is_active,
        assigned_role_ids=access.assigned_role_ids,
        effective_role_ids=tuple(role.role_id for role in authority.roles),
        effective_management_tier=authority.management_tier,
        effective_permissions=tuple(sorted(authority.permissions)),
        authz_version=authority.authz_version,
    )


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
                try:
                    await self._write_denied_audit(
                        context=context,
                        action=action,
                        reason_code=exc.reason_code,
                        target_user_id=target_user_id,
                        target_role_id=target_role_id,
                    )
                except Exception as audit_exc:
                    # Denied evidence is best effort and cannot replace the denial.
                    safe_log(
                        logger,
                        logging.ERROR,
                        "audit.write.failed",
                        extra={
                            "audit_action": action,
                            **safe_exception_metadata(audit_exc),
                        },
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
            raise stale_resource_version("stale_role_version")

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
    ) -> RbacAuditEvent:
        return RbacAuditEvent(
            actor_user_id=context.principal.user_id,
            target_user_id=target_user_id,
            target_role_id=target_role_id,
            action=action,
            decision=decision,
            reason_code=reason_code,
            source=context.audit_source.value,
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
    ) -> tuple[
        AuthoritySnapshot,
        AuthoritySnapshot,
        User,
        RbacState,
        dict[uuid.UUID, Role],
    ]:
        state = await lock_rbac_state(session)
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
                    select(UserRole.role_id).where(
                        UserRole.user_id.in_(user_ids),
                        UserRole.deleted_at.is_(None),
                    )
                )
            ).all()
        )
        locked_roles = await lock_roles(
            session,
            role_ids=assigned_role_ids | (additional_role_ids or set()),
        )
        actor = await require_current_actor(
            session,
            actor_user_id=actor_user_id,
            token_version=context.principal.token_version,
        )
        visible_target = await load_authority_snapshot(
            session,
            user_id=target_user_id,
        )
        if not is_administrative_user_visible(actor=actor, target=visible_target):
            raise not_found("target_user_not_found")
        target = await load_authority_snapshot(
            session,
            user_id=target_user_id,
            include_disabled_roles=True,
        )
        return actor, target, users[target_user_id], state, locked_roles

    async def update_user_status(
        self,
        *,
        context: AuthorizationContext,
        target_user_id: uuid.UUID,
        request: UserStatusUpdateRequest,
    ) -> UserResponse:
        async def operation(session: AsyncSession) -> _MutationOutcome[UserResponse]:
            (
                actor,
                target_before,
                target_row,
                state,
                _locked_roles,
            ) = await self._lock_actor_and_target_user(
                session,
                context=context,
                target_user_id=target_user_id,
                required_permission=PermissionKey.USERS_STATUS_UPDATE,
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
            await session.flush()
            access = (
                await load_user_access_views(
                    session,
                    users=(target_row,),
                    actor=actor,
                )
            )[target_user_id]
            return _MutationOutcome(
                value=_user_response(access),
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

    async def revoke_user_sessions(
        self,
        *,
        context: AuthorizationContext,
        target_user_id: uuid.UUID,
    ) -> None:
        async def operation(session: AsyncSession) -> _MutationOutcome[None]:
            (
                actor,
                target_before,
                target_row,
                _state,
                _locked_roles,
            ) = await self._lock_actor_and_target_user(
                session,
                context=context,
                target_user_id=target_user_id,
                required_permission=PermissionKey.USERS_SESSIONS_REVOKE,
            )
            decision = decide_user_sessions_revoke(
                actor=actor,
                target_before=target_before,
            )
            if not decision.allowed:
                raise forbidden(decision.reason_code)
            previous_version = target_row.token_version
            target_row.token_version += 1
            return _MutationOutcome(
                value=None,
                reason_code="user_sessions_revoked",
                before_state={"token_version": previous_version},
                after_state={"token_version": target_row.token_version},
            )

        await self._run_audited(
            context=context,
            action="user.sessions.revoke",
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
    ) -> UserRoleMutationResponse:
        operation = _require_role_operation(operation)
        requested_role_ids = frozenset(role_ids)
        if not requested_role_ids:
            raise invalid_request("role_ids_required")

        async def mutate(
            session: AsyncSession,
        ) -> _MutationOutcome[UserRoleMutationResponse]:
            required_permission = (
                PermissionKey.ROLES_ASSIGN
                if operation == "bind"
                else PermissionKey.ROLES_REVOKE
            )
            (
                actor,
                target_before,
                target_row,
                state,
                locked_roles,
            ) = await self._lock_actor_and_target_user(
                session,
                context=context,
                target_user_id=target_user_id,
                required_permission=required_permission,
                additional_role_ids=set(requested_role_ids),
            )
            existing_ids = set(
                (
                    await session.scalars(
                        select(UserRole.role_id).where(
                            UserRole.user_id == target_user_id,
                            UserRole.role_id.in_(requested_role_ids),
                            UserRole.deleted_at.is_(None),
                        )
                    )
                ).all()
            )
            requested_roles: list[Role] = []
            for role_id in sorted(requested_role_ids, key=str):
                role = locked_roles.get(role_id)
                if role is None or (
                    operation == "bind"
                    and role_id not in existing_ids
                    and not role.is_active
                ):
                    raise not_found("role_not_found")
                requested_roles.append(role)
            grants_by_role_id = await load_role_grants_for_roles(
                session,
                roles=requested_roles,
            )
            grants = [grants_by_role_id[role.id] for role in requested_roles]
            if any(
                not is_administrative_role_visible(actor=actor, role=grant)
                for grant in grants
            ):
                raise not_found("role_not_found")

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
            if operation == "bind" and changed_ids:
                live_role_count = await count_live_user_roles(
                    session,
                    user_id=target_user_id,
                )
                if live_role_count + len(changed_ids) > MAX_ROLES_PER_USER:
                    raise conflict("user_role_limit_exceeded")

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
                    deleted_at = datetime.now(UTC)
                    await session.execute(
                        update(UserRole)
                        .where(
                            UserRole.user_id == target_user_id,
                            UserRole.role_id.in_(changed_ids),
                            UserRole.deleted_at.is_(None),
                        )
                        .values(
                            deleted_at=deleted_at,
                            deleted_by_user_id=actor.user_id,
                        )
                    )
                target_row.authz_version += 1
                state.epoch += 1
                target_after = replace(
                    target_after,
                    authz_version=target_row.authz_version,
                )
            await session.flush()
            access = (
                await load_user_access_views(
                    session,
                    users=(target_row,),
                    actor=actor,
                )
            )[target_user_id]
            return _MutationOutcome(
                value=UserRoleMutationResponse(
                    changed=changed,
                    user=_user_response(access),
                ),
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
            state = await lock_rbac_state(session)
            actor_id = context.principal.user_id
            users = await lock_users(session, {actor_id})
            self._require_current_locked_actor_row(
                actor_user=users.get(actor_id),
                context=context,
            )
            actor_role_ids = set(
                (
                    await session.scalars(
                        select(UserRole.role_id).where(
                            UserRole.user_id == actor_id,
                            UserRole.deleted_at.is_(None),
                        )
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
                is_super_admin=False,
            )
            session.add(role)
            await session.flush()
            state.epoch += 1
            empty_grant = RoleGrant(
                role_id=role.id,
                key=role.key,
                management_tier=role.management_tier,
                permissions=frozenset(),
                is_system=False,
                is_protected=False,
                is_super_admin=False,
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
            self._require_role_administration(locked, operation="update")
            self._require_expected_role_version(locked.role, expected_version)
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
            self._require_role_administration(locked, operation=verb)
            self._require_expected_role_version(locked.role, expected_version)
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
            self._require_role_administration(locked, operation="delete")
            self._require_expected_role_version(locked.role, expected_version)
            role_before = _role_response(locked.role, locked.role_before)
            deleted_at = datetime.now(UTC)
            locked.role.is_active = False
            locked.role.deleted_at = deleted_at
            locked.role.deleted_by_user_id = locked.actor.user_id
            await session.execute(
                update(UserRole)
                .where(
                    UserRole.role_id == role_id,
                    UserRole.deleted_at.is_(None),
                )
                .values(
                    deleted_at=deleted_at,
                    deleted_by_user_id=locked.actor.user_id,
                )
            )
            await session.execute(
                update(RolePermission)
                .where(
                    RolePermission.role_id == role_id,
                    RolePermission.deleted_at.is_(None),
                )
                .values(
                    deleted_at=deleted_at,
                    deleted_by_user_id=locked.actor.user_id,
                )
            )
            self._bump_shared_authority(locked)
            role_after = _role_response(
                locked.role,
                replace(
                    locked.role_before,
                    permissions=frozenset(),
                ),
            )
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
        operation = _require_role_operation(operation)
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
            replacement = replace(
                locked.role_before,
                permissions=permission_keys_after,
            )
            affected_after = tuple(
                snapshot.with_role(replacement) for snapshot in locked.affected_before
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

            self._require_expected_role_version(locked.role, expected_version)
            role_before = _role_response(locked.role, locked.role_before)
            changed = locked.role_before.permissions != permission_keys_after
            if changed:
                if operation == "bind":
                    existing = set(locked.permission_rows)
                    session.add_all(
                        RolePermission(
                            role_id=role_id,
                            permission_id=permission_id,
                            assigned_by_user_id=locked.actor.user_id,
                        )
                        for permission_id, key in permission_keys_by_id.items()
                        if key not in existing
                    )
                else:
                    deleted_at = datetime.now(UTC)
                    await session.execute(
                        update(RolePermission)
                        .where(
                            RolePermission.role_id == role_id,
                            RolePermission.permission_id.in_(requested_ids),
                            RolePermission.deleted_at.is_(None),
                        )
                        .values(
                            deleted_at=deleted_at,
                            deleted_by_user_id=locked.actor.user_id,
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

    async def _lock_shared_role_change(
        self,
        session: AsyncSession,
        *,
        context: AuthorizationContext,
        role_id: uuid.UUID,
        required_permission: PermissionKey,
        include_inactive: bool = False,
    ) -> _LockedSharedRole:
        state = await lock_rbac_state(session)
        actor_id = context.principal.user_id
        affected_ids = set(
            (
                await session.scalars(
                    select(UserRole.user_id)
                    .join(
                        User,
                        (User.id == UserRole.user_id) & User.deleted_at.is_(None),
                    )
                    .where(
                        UserRole.role_id == role_id,
                        UserRole.deleted_at.is_(None),
                    )
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
                    select(UserRole.role_id).where(
                        UserRole.user_id.in_(user_ids),
                        UserRole.deleted_at.is_(None),
                    )
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
        if not is_administrative_role_visible(actor=actor, role=role_before):
            raise not_found("role_not_found")
        affected_users = tuple(
            users[user_id] for user_id in sorted(affected_ids, key=str)
        )
        affected_by_user_id = await load_authority_snapshots_for_users(
            session,
            users=affected_users,
            include_disabled_roles=True,
        )
        affected_before = tuple(affected_by_user_id[user.id] for user in affected_users)
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
