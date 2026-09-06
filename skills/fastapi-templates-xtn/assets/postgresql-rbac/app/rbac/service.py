import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from typing import TypeVar

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.database import SessionFactory
from app.rbac.domain import (
    OWNER_PERMISSION_KEYS,
    AuthoritySnapshot,
    AuthorizationContext,
    RoleGrant,
)
from app.rbac.errors import (
    RbacError,
    conflict,
    forbidden,
    invalid_request,
    not_found,
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
    decide_ownership_transfer,
    decide_role_change,
    decide_role_create,
    decide_role_delegation_replace,
    decide_role_permissions_replace,
    decide_user_status_change,
)
from app.rbac.queries import (
    load_authority_snapshot,
    load_permission_ids,
    load_role_grant,
    lock_authorization_state,
    lock_role_permissions,
    lock_roles,
    lock_users,
    require_current_actor,
)
from app.rbac.schemas import (
    RoleCreateRequest,
    RoleDelegationReplaceRequest,
    RolePermissionsReplaceRequest,
    UserStatusUpdateRequest,
)

T = TypeVar("T")


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
        "permissions": sorted(snapshot.permissions),
        "delegable_permissions": sorted(snapshot.delegable_permissions),
        "management_tier": snapshot.management_tier,
        "is_protected": snapshot.is_protected,
        "is_owner": snapshot.is_owner,
        "authz_version": snapshot.authz_version,
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
    def _require_permission_keys(permission_keys: frozenset[str]) -> None:
        if not permission_keys <= OWNER_PERMISSION_KEYS:
            raise invalid_request("unknown_or_unavailable_permission_key")

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
        additional_role_ids: set[uuid.UUID] | None = None,
    ) -> tuple[AuthoritySnapshot, AuthoritySnapshot, User, AuthorizationState]:
        state = await lock_authorization_state(session)
        actor_user_id = context.principal.user_id
        users = await lock_users(session, {actor_user_id, target_user_id})
        self._require_current_locked_actor_row(
            actor_user=users.get(actor_user_id),
            context=context,
        )
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

    async def _lock_actor_target_and_role(
        self,
        session: AsyncSession,
        *,
        context: AuthorizationContext,
        target_user_id: uuid.UUID,
        requested_role_id: uuid.UUID,
        include_disabled_requested_role: bool = False,
    ) -> tuple[
        AuthoritySnapshot,
        AuthoritySnapshot,
        RoleGrant,
        User,
        AuthorizationState,
    ]:
        actor, target, target_row, state = await self._lock_actor_and_target_user(
            session,
            context=context,
            target_user_id=target_user_id,
            additional_role_ids={requested_role_id},
        )
        role = await load_role_grant(
            session,
            role_id=requested_role_id,
            include_disabled=include_disabled_requested_role,
        )
        return actor, target, role, target_row, state

    async def update_user_status(
        self,
        *,
        context: AuthorizationContext,
        target_user_id: uuid.UUID,
        request: UserStatusUpdateRequest,
    ) -> User:
        async def operation(session: AsyncSession) -> _MutationOutcome[User]:
            (
                actor,
                target_before,
                target_row,
                state,
            ) = await self._lock_actor_and_target_user(
                session,
                context=context,
                target_user_id=target_user_id,
            )
            decision = decide_user_status_change(
                actor=actor,
                target_before=target_before,
                proposed_is_active=request.is_active,
            )
            if not decision.allowed:
                raise forbidden(decision.reason_code)

            changed = target_row.is_active != request.is_active
            target_after = replace(
                target_before,
                user_is_active=request.is_active,
            )
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

    async def assign_role(
        self,
        *,
        context: AuthorizationContext,
        target_user_id: uuid.UUID,
        role_id: uuid.UUID,
    ) -> None:
        async def operation(session: AsyncSession) -> _MutationOutcome[None]:
            (
                actor,
                target_before,
                role,
                target_row,
                state,
            ) = await self._lock_actor_target_and_role(
                session,
                context=context,
                target_user_id=target_user_id,
                requested_role_id=role_id,
            )
            target_after = target_before.with_role(role)
            decision = decide_role_change(
                operation="assign",
                actor=actor,
                target_before=target_before,
                target_after=target_after,
                changed_role=role,
            )
            if not decision.allowed:
                raise forbidden(decision.reason_code)

            existing = await session.scalar(
                select(UserRole).where(
                    UserRole.user_id == target_user_id,
                    UserRole.role_id == role_id,
                )
            )
            changed = existing is None
            if changed:
                session.add(
                    UserRole(
                        user_id=target_user_id,
                        role_id=role_id,
                        assigned_by_user_id=actor.user_id,
                    )
                )
                target_row.authz_version += 1
                state.epoch += 1
                target_after = replace(
                    target_after,
                    authz_version=target_row.authz_version,
                )
            return _MutationOutcome(
                value=None,
                reason_code="role_assigned" if changed else "already_assigned",
                before_state=_snapshot_payload(target_before),
                after_state=_snapshot_payload(target_after),
            )

        await self._run_audited(
            context=context,
            action="role.assign",
            target_user_id=target_user_id,
            target_role_id=role_id,
            operation=operation,
        )

    async def revoke_role(
        self,
        *,
        context: AuthorizationContext,
        target_user_id: uuid.UUID,
        role_id: uuid.UUID,
    ) -> None:
        async def operation(session: AsyncSession) -> _MutationOutcome[None]:
            (
                actor,
                target_before,
                role,
                target_row,
                state,
            ) = await self._lock_actor_target_and_role(
                session,
                context=context,
                target_user_id=target_user_id,
                requested_role_id=role_id,
                include_disabled_requested_role=True,
            )
            target_after = target_before.without_role(role_id)
            decision = decide_role_change(
                operation="revoke",
                actor=actor,
                target_before=target_before,
                target_after=target_after,
                changed_role=role,
            )
            if not decision.allowed:
                raise forbidden(decision.reason_code)

            assignment = await session.scalar(
                select(UserRole).where(
                    UserRole.user_id == target_user_id,
                    UserRole.role_id == role_id,
                )
            )
            changed = assignment is not None
            if assignment is not None:
                await session.delete(assignment)
                target_row.authz_version += 1
                state.epoch += 1
                target_after = replace(
                    target_after,
                    authz_version=target_row.authz_version,
                )
            return _MutationOutcome(
                value=None,
                reason_code="role_revoked" if changed else "already_absent",
                before_state=_snapshot_payload(target_before),
                after_state=_snapshot_payload(target_after),
            )

        await self._run_audited(
            context=context,
            action="role.revoke",
            target_user_id=target_user_id,
            target_role_id=role_id,
            operation=operation,
        )

    async def create_role(
        self,
        *,
        context: AuthorizationContext,
        request: RoleCreateRequest,
    ) -> Role:
        role_id = uuid.uuid4()

        async def operation(session: AsyncSession) -> _MutationOutcome[Role]:
            state = await lock_authorization_state(session)
            actor_user_id = context.principal.user_id
            users = await lock_users(session, {actor_user_id})
            self._require_current_locked_actor_row(
                actor_user=users.get(actor_user_id),
                context=context,
            )
            actor_role_ids = set(
                (
                    await session.scalars(
                        select(UserRole.role_id).where(
                            UserRole.user_id == actor_user_id
                        )
                    )
                ).all()
            )
            await lock_roles(session, role_ids=actor_role_ids)
            actor = await require_current_actor(
                session,
                actor_user_id=actor_user_id,
                token_version=context.principal.token_version,
            )
            permission_keys = frozenset(request.permissions)
            self._require_permission_keys(permission_keys)
            permission_ids = await load_permission_ids(session, permission_keys)
            if set(permission_ids) != set(permission_keys):
                raise invalid_request("unknown_permission_key")
            decision = decide_role_create(
                actor=actor,
                management_tier=request.management_tier,
                permission_keys=permission_keys,
            )
            if not decision.allowed:
                raise forbidden(decision.reason_code)
            if await session.scalar(select(Role.id).where(Role.key == request.key)):
                raise conflict("role_key_exists")

            role = Role(
                id=role_id,
                key=request.key,
                name=request.name,
                management_tier=request.management_tier,
                is_active=True,
                is_protected=False,
                is_system=False,
                is_owner=False,
            )
            session.add(role)
            await session.flush()
            session.add_all(
                RolePermission(
                    role_id=role.id,
                    permission_id=permission_id,
                    can_delegate=False,
                )
                for permission_id in permission_ids.values()
            )
            state.epoch += 1
            return _MutationOutcome(
                value=role,
                reason_code="role_created",
                after_state={
                    "role_id": str(role.id),
                    "key": role.key,
                    "management_tier": role.management_tier,
                    "permissions": sorted(permission_keys),
                    "delegable_permissions": [],
                },
            )

        return await self._run_audited(
            context=context,
            action="role.create",
            target_user_id=None,
            target_role_id=role_id,
            operation=operation,
        )

    async def replace_role_permissions(
        self,
        *,
        context: AuthorizationContext,
        role_id: uuid.UUID,
        request: RolePermissionsReplaceRequest,
    ) -> Role:
        return await self._run_audited(
            context=context,
            action="role.permissions.replace",
            target_user_id=None,
            target_role_id=role_id,
            operation=lambda session: self._replace_role_permissions(
                session,
                context=context,
                role_id=role_id,
                request=request,
            ),
        )

    async def replace_role_delegation(
        self,
        *,
        context: AuthorizationContext,
        role_id: uuid.UUID,
        request: RoleDelegationReplaceRequest,
    ) -> Role:
        return await self._run_audited(
            context=context,
            action="role.delegation.replace",
            target_user_id=None,
            target_role_id=role_id,
            operation=lambda session: self._replace_role_delegation(
                session,
                context=context,
                role_id=role_id,
                request=request,
            ),
        )

    async def transfer_ownership(
        self,
        *,
        context: AuthorizationContext,
        target_user_id: uuid.UUID,
    ) -> None:
        async def operation(session: AsyncSession) -> _MutationOutcome[None]:
            state = await lock_authorization_state(session)
            actor_user_id = context.principal.user_id
            users = await lock_users(session, {actor_user_id, target_user_id})
            self._require_current_locked_actor_row(
                actor_user=users.get(actor_user_id),
                context=context,
            )
            if target_user_id not in users:
                raise not_found("target_user_not_found")

            owner_role_id = await session.scalar(
                select(Role.id).where(Role.is_owner.is_(True))
            )
            if owner_role_id is None:
                raise conflict("owner_role_missing")
            user_ids = {actor_user_id, target_user_id}
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
                raise conflict("owner_role_missing")
            actor = await require_current_actor(
                session,
                actor_user_id=actor_user_id,
                token_version=context.principal.token_version,
            )
            target_before = await load_authority_snapshot(
                session,
                user_id=target_user_id,
                include_disabled_roles=True,
            )
            decision = decide_ownership_transfer(
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
                raise forbidden("actor_is_not_current_owner")
            target_assignment = await session.scalar(
                select(UserRole).where(
                    UserRole.user_id == target_user_id,
                    UserRole.role_id == owner_role.id,
                )
            )
            if target_assignment is None:
                session.add(
                    UserRole(
                        user_id=target_user_id,
                        role_id=owner_role.id,
                        assigned_by_user_id=actor.user_id,
                    )
                )
            await session.delete(actor_assignment)
            users[actor.user_id].authz_version += 1
            users[target_user_id].authz_version += 1
            state.epoch += 1
            target_after = replace(
                target_before.with_role(owner_grant),
                authz_version=users[target_user_id].authz_version,
            )
            return _MutationOutcome(
                value=None,
                reason_code="ownership_transferred",
                before_state={
                    "old_owner": _snapshot_payload(actor),
                    "new_owner": _snapshot_payload(target_before),
                },
                after_state={
                    "old_owner_user_id": str(actor.user_id),
                    "new_owner": _snapshot_payload(target_after),
                },
                audit_target_role_id=owner_role.id,
            )

        await self._run_audited(
            context=context,
            action="system_owner.transfer",
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
        role = locked_roles.get(role_id)
        if role is None or not role.is_active:
            raise not_found("role_not_found")
        permission_rows = await lock_role_permissions(session, role_id=role_id)

        actor = await require_current_actor(
            session,
            actor_user_id=actor_id,
            token_version=context.principal.token_version,
        )
        role_before = await load_role_grant(session, role_id=role_id)
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

    async def _replace_role_permissions(
        self,
        session: AsyncSession,
        *,
        context: AuthorizationContext,
        role_id: uuid.UUID,
        request: RolePermissionsReplaceRequest,
    ) -> _MutationOutcome[Role]:
        locked = await self._lock_shared_role_change(
            session,
            context=context,
            role_id=role_id,
        )
        permission_keys = frozenset(request.permissions)
        self._require_permission_keys(permission_keys)
        permission_ids = await load_permission_ids(session, permission_keys)
        if set(permission_ids) != set(permission_keys):
            raise invalid_request("unknown_permission_key")

        retained_delegable = locked.role_before.delegable_permissions & permission_keys
        replacement = RoleGrant(
            role_id=locked.role_before.role_id,
            management_tier=locked.role_before.management_tier,
            permissions=permission_keys,
            delegable_permissions=retained_delegable,
            is_protected=locked.role_before.is_protected,
            is_owner=locked.role_before.is_owner,
        )
        before_after = tuple(
            (before, before.with_role(replacement)) for before in locked.affected_before
        )
        decision = decide_role_permissions_replace(
            actor=locked.actor,
            changed_role_before=locked.role_before,
            permission_keys=permission_keys,
            actor_holds_role=locked.actor.user_id in locked.affected_ids,
            affected_before_after=before_after,
        )
        if not decision.allowed:
            raise forbidden(decision.reason_code)

        changed = locked.role_before.permissions != permission_keys
        if changed:
            await session.execute(
                delete(RolePermission).where(RolePermission.role_id == role_id)
            )
            session.add_all(
                RolePermission(
                    role_id=role_id,
                    permission_id=permission_id,
                    can_delegate=permission_key in retained_delegable,
                )
                for permission_key, permission_id in permission_ids.items()
            )
            locked.role.version += 1
            for user_id in locked.affected_ids:
                locked.users[user_id].authz_version += 1
            locked.state.epoch += 1
        return _MutationOutcome(
            value=locked.role,
            reason_code=(
                "role_permissions_replaced" if changed else "role_permissions_unchanged"
            ),
            before_state={
                "role_id": str(role_id),
                "permissions": sorted(locked.role_before.permissions),
                "delegable_permissions": sorted(
                    locked.role_before.delegable_permissions
                ),
                "affected_user_ids": sorted(map(str, locked.affected_ids)),
            },
            after_state={
                "role_id": str(role_id),
                "permissions": sorted(permission_keys),
                "delegable_permissions": sorted(retained_delegable),
                "affected_user_ids": sorted(map(str, locked.affected_ids)),
            },
        )

    async def _replace_role_delegation(
        self,
        session: AsyncSession,
        *,
        context: AuthorizationContext,
        role_id: uuid.UUID,
        request: RoleDelegationReplaceRequest,
    ) -> _MutationOutcome[Role]:
        locked = await self._lock_shared_role_change(
            session,
            context=context,
            role_id=role_id,
        )
        delegable_permission_keys = frozenset(request.delegable_permissions)
        self._require_permission_keys(delegable_permission_keys)
        replacement = RoleGrant(
            role_id=locked.role_before.role_id,
            management_tier=locked.role_before.management_tier,
            permissions=locked.role_before.permissions,
            delegable_permissions=delegable_permission_keys,
            is_protected=locked.role_before.is_protected,
            is_owner=locked.role_before.is_owner,
        )
        before_after = tuple(
            (before, before.with_role(replacement)) for before in locked.affected_before
        )
        decision = decide_role_delegation_replace(
            actor=locked.actor,
            changed_role_before=locked.role_before,
            delegable_permission_keys=delegable_permission_keys,
            actor_holds_role=locked.actor.user_id in locked.affected_ids,
            affected_before_after=before_after,
        )
        if not decision.allowed:
            if decision.reason_code == "delegation_requires_role_permission":
                raise invalid_request(decision.reason_code)
            raise forbidden(decision.reason_code)

        changed = locked.role_before.delegable_permissions != delegable_permission_keys
        if changed:
            for permission_key, permission_row in locked.permission_rows.items():
                permission_row.can_delegate = (
                    permission_key in delegable_permission_keys
                )
            locked.role.version += 1
            for user_id in locked.affected_ids:
                locked.users[user_id].authz_version += 1
            locked.state.epoch += 1

        return _MutationOutcome(
            value=locked.role,
            reason_code=(
                "role_delegation_replaced" if changed else "role_delegation_unchanged"
            ),
            before_state={
                "role_id": str(role_id),
                "delegable_permissions": sorted(
                    locked.role_before.delegable_permissions
                ),
                "affected_user_ids": sorted(map(str, locked.affected_ids)),
            },
            after_state={
                "role_id": str(role_id),
                "delegable_permissions": sorted(delegable_permission_keys),
                "affected_user_ids": sorted(map(str, locked.affected_ids)),
            },
        )


rbac_service = RbacService(SessionFactory)


def get_rbac_service() -> RbacService:
    return rbac_service
