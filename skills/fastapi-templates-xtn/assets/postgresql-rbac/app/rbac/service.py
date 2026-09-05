import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from typing import TypeVar

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.database import SessionFactory
from app.rbac.domain import (
    TENANT_OWNER_PERMISSION_KEYS,
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
    unauthenticated,
)
from app.rbac.models import (
    AuthorizationAuditEvent,
    Membership,
    MembershipRole,
    Role,
    RolePermission,
    TenantAuthorizationState,
)
from app.rbac.policy import (
    decide_membership_create,
    decide_membership_status_change,
    decide_ownership_transfer,
    decide_role_change,
    decide_role_create,
    decide_role_delegation_replace,
    decide_role_permissions_replace,
)
from app.rbac.queries import (
    load_authority_snapshot,
    load_permission_ids,
    load_role_grant,
    lock_memberships,
    lock_role_permissions,
    lock_roles,
    lock_tenant_authorization_state,
    lock_users,
    require_current_actor,
)
from app.rbac.schemas import (
    MembershipCreateRequest,
    MembershipStatusUpdateRequest,
    RoleCreateRequest,
    RoleDelegationReplaceRequest,
    RolePermissionsReplaceRequest,
)

T = TypeVar("T")


class _RetryAffectedSet(Exception):
    pass


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
    tenant_state: TenantAuthorizationState
    permission_rows: dict[str, RolePermission]


def _snapshot_payload(snapshot: AuthoritySnapshot) -> dict[str, object]:
    return {
        "membership_id": str(snapshot.membership_id),
        "user_id": str(snapshot.user_id),
        "status": snapshot.membership_status,
        "user_is_active": snapshot.user_is_active,
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
        target_membership_id: uuid.UUID | None,
        target_role_id: uuid.UUID | None,
        operation: Callable[[AsyncSession], Awaitable[_MutationOutcome[T]]],
    ) -> T:
        outcome: _MutationOutcome[T]
        try:
            async with self._session_factory() as session:
                async with session.begin():
                    if context.principal.token_tenant_id != context.tenant_id:
                        raise not_found("tenant_not_visible")
                    outcome = await operation(session)
                    session.add(
                        self._audit_event(
                            context=context,
                            action=action,
                            decision="allowed",
                            reason_code=outcome.reason_code,
                            target_membership_id=target_membership_id,
                            target_role_id=(
                                outcome.audit_target_role_id or target_role_id
                            ),
                            before_state=outcome.before_state,
                            after_state=outcome.after_state,
                        )
                    )
        except RbacError as exc:
            await self._write_denied_audit(
                context=context,
                action=action,
                reason_code=exc.reason_code,
                target_membership_id=target_membership_id,
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
        target_membership_id: uuid.UUID | None,
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
                        target_membership_id=target_membership_id,
                        target_role_id=target_role_id,
                    )
                )

    @staticmethod
    def _require_context_permission(
        context: AuthorizationContext, permission: PermissionKey
    ) -> None:
        if permission.value not in context.permissions:
            raise forbidden("missing_operation_permission")

    @staticmethod
    def _require_tenant_permission_keys(permission_keys: frozenset[str]) -> None:
        if not permission_keys <= TENANT_OWNER_PERMISSION_KEYS:
            raise invalid_request("unknown_or_unavailable_permission_key")

    @staticmethod
    def _audit_event(
        *,
        context: AuthorizationContext,
        action: str,
        decision: str,
        reason_code: str,
        target_membership_id: uuid.UUID | None,
        target_role_id: uuid.UUID | None,
        before_state: dict[str, object] | None = None,
        after_state: dict[str, object] | None = None,
    ) -> AuthorizationAuditEvent:
        return AuthorizationAuditEvent(
            tenant_id=context.tenant_id,
            actor_user_id=context.principal.user_id,
            actor_membership_id=context.authority.membership_id,
            target_membership_id=target_membership_id,
            target_role_id=target_role_id,
            action=action,
            decision=decision,
            reason_code=reason_code,
            before_state=before_state,
            after_state=after_state,
            request_id=context.request_id,
        )

    async def _lock_actor_target_and_roles(
        self,
        session: AsyncSession,
        *,
        context: AuthorizationContext,
        target_membership_id: uuid.UUID,
        requested_role_id: uuid.UUID,
        include_disabled_requested_role: bool = False,
    ) -> tuple[
        AuthoritySnapshot,
        AuthoritySnapshot,
        RoleGrant,
        Membership,
        TenantAuthorizationState,
    ]:
        (
            actor,
            target,
            target_row,
            tenant_state,
        ) = await self._lock_actor_and_target_membership(
            session,
            context=context,
            target_membership_id=target_membership_id,
            additional_role_ids={requested_role_id},
        )
        role = await load_role_grant(
            session,
            tenant_id=context.tenant_id,
            role_id=requested_role_id,
            include_disabled=include_disabled_requested_role,
        )
        return actor, target, role, target_row, tenant_state

    async def _lock_actor_and_target_membership(
        self,
        session: AsyncSession,
        *,
        context: AuthorizationContext,
        target_membership_id: uuid.UUID,
        additional_role_ids: set[uuid.UUID] | None = None,
    ) -> tuple[
        AuthoritySnapshot,
        AuthoritySnapshot,
        Membership,
        TenantAuthorizationState,
    ]:
        membership_ids = {
            context.authority.membership_id,
            target_membership_id,
        }
        preliminary_rows = (
            await session.execute(
                select(Membership.id, Membership.user_id).where(
                    Membership.tenant_id == context.tenant_id,
                    Membership.id.in_(membership_ids),
                )
            )
        ).all()
        preliminary = {row.id: row.user_id for row in preliminary_rows}
        if context.authority.membership_id not in preliminary:
            raise unauthenticated("actor_membership_missing")
        if target_membership_id not in preliminary:
            raise not_found("target_membership_not_found")

        users = await lock_users(session, set(preliminary.values()))
        if context.principal.user_id not in users:
            raise unauthenticated("actor_missing")
        tenant, tenant_state = await lock_tenant_authorization_state(
            session, context.tenant_id
        )
        if not tenant.is_active:
            raise not_found("tenant_not_visible")
        memberships = await lock_memberships(
            session,
            tenant_id=context.tenant_id,
            membership_ids=membership_ids,
        )
        if target_membership_id not in memberships:
            raise not_found("target_membership_not_found")

        assigned_role_ids = set(
            (
                await session.scalars(
                    select(MembershipRole.role_id).where(
                        MembershipRole.tenant_id == context.tenant_id,
                        MembershipRole.membership_id.in_(membership_ids),
                    )
                )
            ).all()
        )
        await lock_roles(
            session,
            tenant_id=context.tenant_id,
            role_ids=assigned_role_ids | (additional_role_ids or set()),
        )
        actor = await require_current_actor(
            session,
            tenant_id=context.tenant_id,
            actor_membership_id=context.authority.membership_id,
            actor_user_id=context.principal.user_id,
            token_version=context.principal.token_version,
        )
        target = await load_authority_snapshot(
            session,
            tenant_id=context.tenant_id,
            membership_id=target_membership_id,
            include_disabled_roles=True,
        )
        return actor, target, memberships[target_membership_id], tenant_state

    async def create_membership(
        self,
        *,
        context: AuthorizationContext,
        request: MembershipCreateRequest,
    ) -> Membership:
        membership_id = uuid.uuid4()

        async def operation(session: AsyncSession) -> _MutationOutcome[Membership]:
            self._require_context_permission(context, PermissionKey.MEMBERSHIPS_CREATE)
            actor_user_id = await session.scalar(
                select(Membership.user_id).where(
                    Membership.tenant_id == context.tenant_id,
                    Membership.id == context.authority.membership_id,
                )
            )
            if actor_user_id is None:
                raise unauthenticated("actor_membership_missing")

            users = await lock_users(session, {actor_user_id, request.user_id})
            target_user = users.get(request.user_id)
            if target_user is None:
                raise not_found("target_user_not_found")
            tenant, tenant_state = await lock_tenant_authorization_state(
                session, context.tenant_id
            )
            if not tenant.is_active:
                raise not_found("tenant_not_visible")
            await lock_memberships(
                session,
                tenant_id=context.tenant_id,
                membership_ids={context.authority.membership_id},
            )
            actor_role_ids = set(
                (
                    await session.scalars(
                        select(MembershipRole.role_id).where(
                            MembershipRole.tenant_id == context.tenant_id,
                            MembershipRole.membership_id
                            == context.authority.membership_id,
                        )
                    )
                ).all()
            )
            await lock_roles(
                session,
                tenant_id=context.tenant_id,
                role_ids=actor_role_ids,
            )
            actor = await require_current_actor(
                session,
                tenant_id=context.tenant_id,
                actor_membership_id=context.authority.membership_id,
                actor_user_id=context.principal.user_id,
                token_version=context.principal.token_version,
            )
            decision = decide_membership_create(
                actor=actor,
                target_user_id=target_user.id,
                target_user_is_active=target_user.is_active,
                target_user_is_protected=target_user.is_protected,
            )
            if not decision.allowed:
                raise forbidden(decision.reason_code)

            existing_id = await session.scalar(
                select(Membership.id).where(
                    Membership.tenant_id == context.tenant_id,
                    Membership.user_id == request.user_id,
                )
            )
            if existing_id is not None:
                raise conflict("membership_already_exists")

            membership = Membership(
                id=membership_id,
                tenant_id=context.tenant_id,
                user_id=request.user_id,
                status="active",
                is_protected=False,
                authz_version=1,
            )
            session.add(membership)
            await session.flush()
            tenant_state.epoch += 1
            return _MutationOutcome(
                value=membership,
                reason_code="membership_created",
                after_state={
                    "membership_id": str(membership.id),
                    "user_id": str(membership.user_id),
                    "status": membership.status,
                    "role_ids": [],
                    "permissions": [],
                    "delegable_permissions": [],
                    "management_tier": 0,
                    "authz_version": membership.authz_version,
                },
            )

        return await self._run_audited(
            context=context,
            action="membership.create",
            target_membership_id=membership_id,
            target_role_id=None,
            operation=operation,
        )

    async def update_membership_status(
        self,
        *,
        context: AuthorizationContext,
        target_membership_id: uuid.UUID,
        request: MembershipStatusUpdateRequest,
    ) -> Membership:
        async def operation(session: AsyncSession) -> _MutationOutcome[Membership]:
            self._require_context_permission(
                context, PermissionKey.MEMBERSHIPS_STATUS_UPDATE
            )
            (
                actor,
                target_before,
                target_row,
                tenant_state,
            ) = await self._lock_actor_and_target_membership(
                session,
                context=context,
                target_membership_id=target_membership_id,
            )
            decision = decide_membership_status_change(
                actor=actor,
                target_before=target_before,
                proposed_status=request.status,
            )
            if not decision.allowed:
                raise forbidden(decision.reason_code)

            changed = target_row.status != request.status
            target_after = replace(target_before, membership_status=request.status)
            if changed:
                target_row.status = request.status
                target_row.authz_version += 1
                tenant_state.epoch += 1
                target_after = replace(
                    target_after,
                    authz_version=target_row.authz_version,
                )
            return _MutationOutcome(
                value=target_row,
                reason_code=(
                    "membership_status_updated"
                    if changed
                    else "membership_status_unchanged"
                ),
                before_state=_snapshot_payload(target_before),
                after_state=_snapshot_payload(target_after),
            )

        return await self._run_audited(
            context=context,
            action="membership.status.update",
            target_membership_id=target_membership_id,
            target_role_id=None,
            operation=operation,
        )

    async def assign_role(
        self,
        *,
        context: AuthorizationContext,
        target_membership_id: uuid.UUID,
        role_id: uuid.UUID,
    ) -> None:
        async def operation(session: AsyncSession) -> _MutationOutcome[None]:
            self._require_context_permission(context, PermissionKey.ROLES_ASSIGN)
            (
                actor,
                target_before,
                role,
                target_row,
                tenant_state,
            ) = await self._lock_actor_target_and_roles(
                session,
                context=context,
                target_membership_id=target_membership_id,
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
                select(MembershipRole).where(
                    MembershipRole.tenant_id == context.tenant_id,
                    MembershipRole.membership_id == target_membership_id,
                    MembershipRole.role_id == role_id,
                )
            )
            changed = existing is None
            if changed:
                session.add(
                    MembershipRole(
                        tenant_id=context.tenant_id,
                        membership_id=target_membership_id,
                        role_id=role_id,
                        assigned_by_membership_id=actor.membership_id,
                    )
                )
                target_row.authz_version += 1
                tenant_state.epoch += 1
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
            target_membership_id=target_membership_id,
            target_role_id=role_id,
            operation=operation,
        )

    async def revoke_role(
        self,
        *,
        context: AuthorizationContext,
        target_membership_id: uuid.UUID,
        role_id: uuid.UUID,
    ) -> None:
        async def operation(session: AsyncSession) -> _MutationOutcome[None]:
            self._require_context_permission(context, PermissionKey.ROLES_REVOKE)
            (
                actor,
                target_before,
                role,
                target_row,
                tenant_state,
            ) = await self._lock_actor_target_and_roles(
                session,
                context=context,
                target_membership_id=target_membership_id,
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
                select(MembershipRole).where(
                    MembershipRole.tenant_id == context.tenant_id,
                    MembershipRole.membership_id == target_membership_id,
                    MembershipRole.role_id == role_id,
                )
            )
            changed = assignment is not None
            if assignment is not None:
                await session.delete(assignment)
                target_row.authz_version += 1
                tenant_state.epoch += 1
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
            target_membership_id=target_membership_id,
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
            self._require_context_permission(context, PermissionKey.ROLES_CREATE)
            actor_user_id = await session.scalar(
                select(Membership.user_id).where(
                    Membership.tenant_id == context.tenant_id,
                    Membership.id == context.authority.membership_id,
                )
            )
            if actor_user_id is None:
                raise unauthenticated("actor_membership_missing")
            await lock_users(session, {actor_user_id})
            tenant, tenant_state = await lock_tenant_authorization_state(
                session, context.tenant_id
            )
            if not tenant.is_active:
                raise not_found("tenant_not_visible")
            await lock_memberships(
                session,
                tenant_id=context.tenant_id,
                membership_ids={context.authority.membership_id},
            )
            actor_role_ids = set(
                (
                    await session.scalars(
                        select(MembershipRole.role_id).where(
                            MembershipRole.tenant_id == context.tenant_id,
                            MembershipRole.membership_id
                            == context.authority.membership_id,
                        )
                    )
                ).all()
            )
            await lock_roles(
                session,
                tenant_id=context.tenant_id,
                role_ids=actor_role_ids,
            )
            actor = await require_current_actor(
                session,
                tenant_id=context.tenant_id,
                actor_membership_id=context.authority.membership_id,
                actor_user_id=context.principal.user_id,
                token_version=context.principal.token_version,
            )
            permission_keys = frozenset(request.permissions)
            self._require_tenant_permission_keys(permission_keys)
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
            if await session.scalar(
                select(Role.id).where(
                    Role.tenant_id == context.tenant_id,
                    Role.key == request.key,
                )
            ):
                raise conflict("role_key_exists")

            role = Role(
                id=role_id,
                tenant_id=context.tenant_id,
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
                    tenant_id=context.tenant_id,
                    role_id=role.id,
                    permission_id=permission_id,
                    can_delegate=False,
                )
                for permission_id in permission_ids.values()
            )
            tenant_state.epoch += 1
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
            target_membership_id=None,
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
        for _attempt in range(4):
            try:
                return await self._run_audited(
                    context=context,
                    action="role.permissions.replace",
                    target_membership_id=None,
                    target_role_id=role_id,
                    operation=lambda session: self._replace_role_permissions_once(
                        session,
                        context=context,
                        role_id=role_id,
                        request=request,
                    ),
                )
            except _RetryAffectedSet:
                continue
        rejection = conflict("affected_memberships_changed_repeatedly")
        await self._write_denied_audit(
            context=context,
            action="role.permissions.replace",
            reason_code=rejection.reason_code,
            target_membership_id=None,
            target_role_id=role_id,
        )
        raise rejection

    async def transfer_ownership(
        self,
        *,
        context: AuthorizationContext,
        target_membership_id: uuid.UUID,
    ) -> None:
        async def operation(session: AsyncSession) -> _MutationOutcome[None]:
            self._require_context_permission(
                context, PermissionKey.TENANT_OWNERSHIP_TRANSFER
            )
            membership_ids = {
                context.authority.membership_id,
                target_membership_id,
            }
            preliminary_rows = (
                await session.execute(
                    select(Membership.id, Membership.user_id).where(
                        Membership.tenant_id == context.tenant_id,
                        Membership.id.in_(membership_ids),
                    )
                )
            ).all()
            preliminary = {row.id: row.user_id for row in preliminary_rows}
            if context.authority.membership_id not in preliminary:
                raise unauthenticated("actor_membership_missing")
            if target_membership_id not in preliminary:
                raise not_found("target_membership_not_found")

            await lock_users(session, set(preliminary.values()))
            tenant, tenant_state = await lock_tenant_authorization_state(
                session, context.tenant_id
            )
            if not tenant.is_active:
                raise not_found("tenant_not_visible")
            memberships = await lock_memberships(
                session,
                tenant_id=context.tenant_id,
                membership_ids=membership_ids,
            )
            owner_role = await session.scalar(
                select(Role).where(
                    Role.tenant_id == context.tenant_id,
                    Role.is_owner.is_(True),
                )
            )
            if owner_role is None:
                raise conflict("owner_role_missing")
            all_role_ids = set(
                (
                    await session.scalars(
                        select(MembershipRole.role_id).where(
                            MembershipRole.tenant_id == context.tenant_id,
                            MembershipRole.membership_id.in_(membership_ids),
                        )
                    )
                ).all()
            )
            await lock_roles(
                session,
                tenant_id=context.tenant_id,
                role_ids=all_role_ids | {owner_role.id},
            )
            actor = await require_current_actor(
                session,
                tenant_id=context.tenant_id,
                actor_membership_id=context.authority.membership_id,
                actor_user_id=context.principal.user_id,
                token_version=context.principal.token_version,
            )
            target_before = await load_authority_snapshot(
                session,
                tenant_id=context.tenant_id,
                membership_id=target_membership_id,
                include_disabled_roles=True,
            )
            decision = decide_ownership_transfer(
                actor=actor,
                target_before=target_before,
            )
            if not decision.allowed:
                raise forbidden(decision.reason_code)

            owner_grant = await load_role_grant(
                session,
                tenant_id=context.tenant_id,
                role_id=owner_role.id,
            )
            actor_assignment = await session.scalar(
                select(MembershipRole).where(
                    MembershipRole.tenant_id == context.tenant_id,
                    MembershipRole.membership_id == actor.membership_id,
                    MembershipRole.role_id == owner_role.id,
                )
            )
            if actor_assignment is None:
                raise forbidden("actor_is_not_current_owner")
            target_assignment = await session.scalar(
                select(MembershipRole).where(
                    MembershipRole.tenant_id == context.tenant_id,
                    MembershipRole.membership_id == target_membership_id,
                    MembershipRole.role_id == owner_role.id,
                )
            )
            if target_assignment is None:
                session.add(
                    MembershipRole(
                        tenant_id=context.tenant_id,
                        membership_id=target_membership_id,
                        role_id=owner_role.id,
                        assigned_by_membership_id=actor.membership_id,
                    )
                )
            await session.delete(actor_assignment)
            memberships[actor.membership_id].authz_version += 1
            memberships[target_membership_id].authz_version += 1
            tenant_state.epoch += 1
            target_after = replace(
                target_before.with_role(owner_grant),
                authz_version=memberships[target_membership_id].authz_version,
            )
            return _MutationOutcome(
                value=None,
                reason_code="ownership_transferred",
                before_state={
                    "old_owner": _snapshot_payload(actor),
                    "new_owner": _snapshot_payload(target_before),
                },
                after_state={
                    "old_owner_membership_id": str(actor.membership_id),
                    "new_owner": _snapshot_payload(target_after),
                },
                audit_target_role_id=owner_role.id,
            )

        await self._run_audited(
            context=context,
            action="tenant.ownership.transfer",
            target_membership_id=target_membership_id,
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
    ) -> _LockedSharedRole:
        self._require_context_permission(context, required_permission)
        actor_id = context.authority.membership_id
        candidate_rows = (
            await session.execute(
                select(Membership.id, Membership.user_id)
                .join(
                    MembershipRole,
                    (MembershipRole.tenant_id == Membership.tenant_id)
                    & (MembershipRole.membership_id == Membership.id),
                    isouter=True,
                )
                .where(
                    Membership.tenant_id == context.tenant_id,
                    (Membership.id == actor_id) | (MembershipRole.role_id == role_id),
                )
            )
        ).all()
        candidate_memberships = {row.id: row.user_id for row in candidate_rows}
        if actor_id not in candidate_memberships:
            raise unauthenticated("actor_membership_missing")

        await lock_users(session, set(candidate_memberships.values()))
        tenant, tenant_state = await lock_tenant_authorization_state(
            session, context.tenant_id
        )
        if not tenant.is_active:
            raise not_found("tenant_not_visible")
        affected_ids = set(
            (
                await session.scalars(
                    select(MembershipRole.membership_id).where(
                        MembershipRole.tenant_id == context.tenant_id,
                        MembershipRole.role_id == role_id,
                    )
                )
            ).all()
        )
        if not affected_ids <= set(candidate_memberships):
            raise _RetryAffectedSet

        membership_ids = affected_ids | {actor_id}
        await lock_memberships(
            session,
            tenant_id=context.tenant_id,
            membership_ids=membership_ids,
        )
        all_role_ids = set(
            (
                await session.scalars(
                    select(MembershipRole.role_id).where(
                        MembershipRole.tenant_id == context.tenant_id,
                        MembershipRole.membership_id.in_(membership_ids),
                    )
                )
            ).all()
        )
        locked_roles = await lock_roles(
            session,
            tenant_id=context.tenant_id,
            role_ids=all_role_ids | {role_id},
        )
        role = locked_roles.get(role_id)
        if role is None or not role.is_active:
            raise not_found("role_not_found")
        permission_rows = await lock_role_permissions(
            session,
            tenant_id=context.tenant_id,
            role_id=role_id,
        )

        actor = await require_current_actor(
            session,
            tenant_id=context.tenant_id,
            actor_membership_id=actor_id,
            actor_user_id=context.principal.user_id,
            token_version=context.principal.token_version,
        )
        role_before = await load_role_grant(
            session,
            tenant_id=context.tenant_id,
            role_id=role_id,
        )
        affected_before = tuple(
            [
                await load_authority_snapshot(
                    session,
                    tenant_id=context.tenant_id,
                    membership_id=membership_id,
                    include_disabled_roles=True,
                )
                for membership_id in sorted(affected_ids, key=str)
            ]
        )
        return _LockedSharedRole(
            actor=actor,
            role=role,
            role_before=role_before,
            affected_before=affected_before,
            affected_ids=frozenset(affected_ids),
            tenant_state=tenant_state,
            permission_rows=permission_rows,
        )

    async def _replace_role_permissions_once(
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
            required_permission=PermissionKey.ROLES_PERMISSIONS_UPDATE,
        )
        permission_keys = frozenset(request.permissions)
        self._require_tenant_permission_keys(permission_keys)
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
            actor_holds_role=locked.actor.membership_id in locked.affected_ids,
            affected_before_after=before_after,
        )
        if not decision.allowed:
            raise forbidden(decision.reason_code)

        changed = locked.role_before.permissions != permission_keys
        if changed:
            await session.execute(
                delete(RolePermission).where(
                    RolePermission.tenant_id == context.tenant_id,
                    RolePermission.role_id == role_id,
                )
            )
            session.add_all(
                RolePermission(
                    tenant_id=context.tenant_id,
                    role_id=role_id,
                    permission_id=permission_id,
                    can_delegate=permission_key in retained_delegable,
                )
                for permission_key, permission_id in permission_ids.items()
            )
            locked.role.version += 1
            locked.tenant_state.epoch += 1
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
                "affected_membership_ids": sorted(map(str, locked.affected_ids)),
            },
            after_state={
                "role_id": str(role_id),
                "permissions": sorted(permission_keys),
                "delegable_permissions": sorted(retained_delegable),
                "affected_membership_ids": sorted(map(str, locked.affected_ids)),
            },
        )

    async def replace_role_delegation(
        self,
        *,
        context: AuthorizationContext,
        role_id: uuid.UUID,
        request: RoleDelegationReplaceRequest,
    ) -> Role:
        for _attempt in range(4):
            try:
                return await self._run_audited(
                    context=context,
                    action="role.delegation.replace",
                    target_membership_id=None,
                    target_role_id=role_id,
                    operation=lambda session: self._replace_role_delegation_once(
                        session,
                        context=context,
                        role_id=role_id,
                        request=request,
                    ),
                )
            except _RetryAffectedSet:
                continue
        rejection = conflict("affected_memberships_changed_repeatedly")
        await self._write_denied_audit(
            context=context,
            action="role.delegation.replace",
            reason_code=rejection.reason_code,
            target_membership_id=None,
            target_role_id=role_id,
        )
        raise rejection

    async def _replace_role_delegation_once(
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
            required_permission=PermissionKey.ROLES_DELEGATION_UPDATE,
        )
        delegable_permission_keys = frozenset(request.delegable_permissions)
        self._require_tenant_permission_keys(delegable_permission_keys)
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
            actor_holds_role=locked.actor.membership_id in locked.affected_ids,
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
            locked.tenant_state.epoch += 1

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
                "affected_membership_ids": sorted(map(str, locked.affected_ids)),
            },
            after_state={
                "role_id": str(role_id),
                "delegable_permissions": sorted(delegable_permission_keys),
                "affected_membership_ids": sorted(map(str, locked.affected_ids)),
            },
        )


rbac_service = RbacService(SessionFactory)


def get_rbac_service() -> RbacService:
    return rbac_service
