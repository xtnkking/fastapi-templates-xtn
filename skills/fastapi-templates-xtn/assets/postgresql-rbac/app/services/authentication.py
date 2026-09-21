from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, cast

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.api_contract import BusinessCode
from app.core.audit import AuditSource
from app.core.errors import (
    RbacError,
    conflict,
    forbidden,
    invalid_request,
    not_found,
    unavailable,
)
from app.core.i18n import MessageKey
from app.core.observability import safe_exception_metadata, safe_log
from app.core.security.domain import AuthorizationContext, PermissionKey
from app.core.security.passwords import (
    PasswordHashError,
    PasswordManager,
    PasswordPolicyError,
    PasswordVerification,
    password_manager,
    validate_new_password,
)
from app.core.security.policy import (
    decide_user_password_reset,
    is_administrative_user_visible,
)
from app.db.postgres import SessionFactory
from app.models.access import RbacState, User
from app.models.account_security import (
    AccountSecurityActorType,
    AccountSecurityAuditEvent,
    AccountSecurityAuditOutcome,
)
from app.repositories.access import (
    load_authority_snapshot,
    load_live_super_admin_holder_ids,
    lock_rbac_state,
    lock_users,
    require_current_actor,
)
from app.services.abuse_flow import IdentityAbuseFlow, InvalidLoginCredentialsError
from app.services.provisioning import create_user_with_default_role

logger = logging.getLogger(__name__)


def _password_policy_response(exc: PasswordPolicyError) -> RbacError:
    message_keys = {
        "password_same_as_user_name": MessageKey.ERROR_PASSWORD_SAME_AS_USER_NAME,
        "password_common_or_weak": MessageKey.ERROR_PASSWORD_COMMON_OR_WEAK,
    }
    message_key = message_keys.get(exc.reason_code)
    if message_key is None:
        return invalid_request(exc.reason_code)
    return RbacError(
        status_code=400,
        business_code=BusinessCode.BAD_REQUEST,
        message_key=message_key,
        reason_code=exc.reason_code,
    )


def _username_exists() -> RbacError:
    return RbacError(
        status_code=409,
        business_code=BusinessCode.CONFLICT,
        message_key=MessageKey.ERROR_USER_NAME_TAKEN,
        reason_code="user_identity_exists",
    )


@dataclass(frozen=True, slots=True)
class AuthenticatedPasswordUser:
    user_id: uuid.UUID
    token_version: int
    must_change_password: bool


@dataclass(frozen=True, slots=True)
class _PasswordSnapshot:
    user_id: uuid.UUID
    user_name: str | None
    is_active: bool
    is_deleted: bool
    token_version: int
    password_hash: str | None
    password_changed_at: datetime | None
    must_change_password: bool

    @property
    def identity_values(self) -> tuple[str, ...]:
        return (self.user_name,) if self.user_name is not None else ()


class LocalAuthenticationService:
    """Own local-password state while keeping Argon2 outside database locks."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        manager: PasswordManager,
    ) -> None:
        self._session_factory = session_factory
        self._password_manager = manager

    async def registration_enabled(self) -> bool:
        async with self._session_factory() as session:
            enabled = await session.scalar(
                select(RbacState.public_registration_enabled).where(
                    RbacState.scope == "global"
                )
            )
        if enabled is None:
            raise unavailable("registration_setting_unavailable")
        return bool(enabled)

    async def set_registration_enabled(
        self, *, context: AuthorizationContext, enabled: bool
    ) -> bool:
        async with self._session_factory() as session:
            async with session.begin():
                state = await lock_rbac_state(session)
                await lock_users(session, {context.principal.user_id})
                actor = await require_current_actor(
                    session,
                    actor_user_id=context.principal.user_id,
                    token_version=context.principal.token_version,
                )
                if not actor.is_super_admin or (
                    PermissionKey.REGISTRATION_CONFIGURE.value not in actor.permissions
                ):
                    raise forbidden("registration_setting_requires_super_admin")
                if state.public_registration_enabled != enabled:
                    state.public_registration_enabled = enabled
                    session.add(
                        self._account_event(
                            action="account_security.registration.setting_updated",
                            outcome=AccountSecurityAuditOutcome.SUCCEEDED,
                            reason_code="registration_setting_updated",
                            actor_type=AccountSecurityActorType.USER,
                            actor_user_id=context.principal.user_id,
                            target_user_id=None,
                            source=context.audit_source,
                            request_id=context.request_id,
                        )
                    )
        return enabled

    async def register(
        self,
        *,
        abuse_flow: IdentityAbuseFlow | None,
        client_ip: str,
        user_name: str,
        password: str,
        request_id: str,
    ) -> uuid.UUID:
        async def registration_action() -> uuid.UUID:
            try:
                password_hash = await self._password_manager.hash_new_password(
                    password,
                    identity_values=(user_name,),
                )
            except PasswordPolicyError as exc:
                raise _password_policy_response(exc) from exc

            try:
                async with self._session_factory() as session:
                    async with session.begin():
                        state = await lock_rbac_state(session)
                        if not state.public_registration_enabled:
                            raise RbacError(
                                status_code=403,
                                business_code=BusinessCode.ACCESS_FORBIDDEN,
                                message_key=MessageKey.ERROR_REGISTRATION_CLOSED,
                                reason_code="public_registration_closed",
                            )
                        user = await create_user_with_default_role(
                            session,
                            user_name=user_name,
                            request_id=request_id,
                        )
                        await self._rotate_password(
                            session,
                            user=user,
                            password_hash=password_hash,
                            must_change_password=False,
                        )
                        session.add(
                            self._account_event(
                                action="account_security.registration.completed",
                                outcome=AccountSecurityAuditOutcome.SUCCEEDED,
                                reason_code="registration_completed",
                                actor_type=AccountSecurityActorType.ANONYMOUS,
                                actor_user_id=None,
                                target_user_id=user.id,
                                source=AuditSource.HTTP,
                                request_id=request_id,
                            )
                        )
                return user.id
            except IntegrityError as exc:
                if self._is_identity_conflict(exc):
                    raise _username_exists() from exc
                raise
            except RbacError as exc:
                if exc.reason_code == "user_identity_exists":
                    raise _username_exists() from exc
                raise

        if abuse_flow is None:
            return await registration_action()
        return await abuse_flow.register(
            client_ip=client_ip,
            registration_action=registration_action,
        )

    async def create_user_by_administrator(
        self,
        *,
        context: AuthorizationContext,
        user_name: str,
        temporary_password: str,
    ) -> uuid.UUID:
        try:
            password_hash = await self._password_manager.hash_new_password(
                temporary_password, identity_values=(user_name,)
            )
        except PasswordPolicyError as exc:
            raise _password_policy_response(exc) from exc
        try:
            async with self._session_factory() as session:
                async with session.begin():
                    await lock_rbac_state(session)
                    await lock_users(session, {context.principal.user_id})
                    actor = await require_current_actor(
                        session,
                        actor_user_id=context.principal.user_id,
                        token_version=context.principal.token_version,
                    )
                    if PermissionKey.USERS_CREATE.value not in actor.permissions:
                        raise forbidden("missing_operation_permission")
                    user = await create_user_with_default_role(
                        session,
                        user_name=user_name,
                        assigned_by_user_id=context.principal.user_id,
                        request_id=context.request_id,
                    )
                    await self._rotate_password(
                        session,
                        user=user,
                        password_hash=password_hash,
                        must_change_password=True,
                    )
                    session.add(
                        self._account_event(
                            action="account_security.registration.admin_created",
                            outcome=AccountSecurityAuditOutcome.SUCCEEDED,
                            reason_code="temporary_password_set",
                            actor_type=AccountSecurityActorType.USER,
                            actor_user_id=context.principal.user_id,
                            target_user_id=user.id,
                            source=context.audit_source,
                            request_id=context.request_id,
                        )
                    )
            return user.id
        except IntegrityError as exc:
            if self._is_identity_conflict(exc):
                raise _username_exists() from exc
            raise
        except RbacError as exc:
            if exc.reason_code == "user_identity_exists":
                raise _username_exists() from exc
            raise

    async def authenticate(
        self,
        *,
        abuse_flow: IdentityAbuseFlow | None,
        client_ip: str,
        user_name: str,
        password: str,
    ) -> AuthenticatedPasswordUser:
        async def verify_credentials() -> AuthenticatedPasswordUser | None:
            return await self._verify_login_snapshot(
                user_name=user_name,
                password=password,
                require_temporary=False,
            )

        if abuse_flow is None:
            result = await verify_credentials()
            if result is None:
                raise InvalidLoginCredentialsError()
            return result
        return await abuse_flow.authenticate(
            client_ip=client_ip,
            verify_real_or_dummy_credentials=verify_credentials,
        )

    async def change_password(
        self,
        *,
        context: AuthorizationContext,
        current_password: str,
        new_password: str,
    ) -> bool:
        if current_password == new_password:
            raise invalid_request("new_password_must_differ")
        actor_snapshot = await self._reauthenticate_actor(
            context=context,
            current_password=current_password,
            action="account_security.password.changed",
            target_user_id=context.principal.user_id,
        )
        try:
            new_hash = await self._password_manager.hash_new_password(
                new_password,
                identity_values=actor_snapshot.identity_values,
            )
        except PasswordPolicyError as exc:
            raise _password_policy_response(exc) from exc

        async with self._session_factory() as session:
            async with session.begin():
                await lock_rbac_state(session)
                users = await lock_users(session, {context.principal.user_id})
                user = users.get(context.principal.user_id)
                if (
                    user is None
                    or not user.is_active
                    or user.token_version != context.principal.token_version
                    or not self._same_identity(user, actor_snapshot)
                ):
                    raise forbidden("current_credential_changed")
                if not self._same_password_state(user, actor_snapshot):
                    raise forbidden("current_credential_changed")

                await self._rotate_password(
                    session,
                    user=user,
                    password_hash=new_hash,
                    must_change_password=False,
                )
                user.token_version += 1
                session.add(
                    self._account_event(
                        action="account_security.password.changed",
                        outcome=AccountSecurityAuditOutcome.SUCCEEDED,
                        reason_code="password_changed",
                        actor_type=AccountSecurityActorType.USER,
                        actor_user_id=user.id,
                        target_user_id=user.id,
                        source=context.audit_source,
                        request_id=context.request_id,
                    )
                )
        return True

    async def reset_user_password(
        self,
        *,
        context: AuthorizationContext,
        target_user_id: uuid.UUID,
        new_password: str,
        reset_mode: Literal["direct", "temporary"],
    ) -> bool:
        require_password_change = reset_mode == "temporary"
        try:
            async with self._session_factory() as session:
                async with session.begin():
                    target_user = await self._lock_authorized_reset_target(
                        session,
                        context=context,
                        target_user_id=target_user_id,
                    )
                    target_identity_values = tuple(
                        value for value in (target_user.user_name,) if value
                    )
        except RbacError as exc:
            await self._write_client_denial(
                error=exc,
                action="account_security.password.admin_reset",
                actor_user_id=context.principal.user_id,
                target_user_id=target_user_id,
                source=context.audit_source,
                request_id=context.request_id,
            )
            raise

        try:
            new_password_hash = await self._password_manager.hash_new_password(
                new_password,
                identity_values=target_identity_values,
            )
        except PasswordPolicyError as exc:
            raise _password_policy_response(exc) from exc

        try:
            async with self._session_factory() as session:
                async with session.begin():
                    target_user = await self._lock_authorized_reset_target(
                        session,
                        context=context,
                        target_user_id=target_user_id,
                    )
                    try:
                        validate_new_password(
                            new_password,
                            identity_values=tuple(
                                value for value in (target_user.user_name,) if value
                            ),
                        )
                    except PasswordPolicyError as exc:
                        raise _password_policy_response(exc) from exc

                    await self._rotate_password(
                        session,
                        user=target_user,
                        password_hash=new_password_hash,
                        must_change_password=require_password_change,
                    )
                    target_user.token_version += 1
                    session.add(
                        self._account_event(
                            action="account_security.password.admin_reset",
                            outcome=AccountSecurityAuditOutcome.SUCCEEDED,
                            reason_code=(
                                "temporary_password_set"
                                if require_password_change
                                else "permanent_password_set"
                            ),
                            actor_type=AccountSecurityActorType.USER,
                            actor_user_id=context.principal.user_id,
                            target_user_id=target_user.id,
                            source=context.audit_source,
                            request_id=context.request_id,
                        )
                    )
        except RbacError as exc:
            await self._write_client_denial(
                error=exc,
                action="account_security.password.admin_reset",
                actor_user_id=context.principal.user_id,
                target_user_id=target_user_id,
                source=context.audit_source,
                request_id=context.request_id,
            )
            raise
        return True

    async def complete_password_reset(
        self,
        *,
        abuse_flow: IdentityAbuseFlow | None,
        client_ip: str,
        user_name: str,
        temporary_password: str,
        new_password: str,
        request_id: str,
    ) -> bool:
        if temporary_password == new_password:
            raise invalid_request("new_password_must_differ")

        async def verify_temporary() -> _PasswordSnapshot | None:
            return await self._verify_temporary_snapshot(
                user_name=user_name,
                password=temporary_password,
            )

        if abuse_flow is None:
            snapshot = await verify_temporary()
            if snapshot is None:
                raise InvalidLoginCredentialsError()
        else:
            snapshot = await abuse_flow.complete_temporary_password_reset(
                client_ip=client_ip,
                verify_real_or_dummy_credentials=verify_temporary,
            )

        try:
            new_hash = await self._password_manager.hash_new_password(
                new_password,
                identity_values=snapshot.identity_values,
            )
        except PasswordPolicyError as exc:
            raise _password_policy_response(exc) from exc

        async with self._session_factory() as session:
            async with session.begin():
                await lock_rbac_state(session)
                users = await lock_users(session, {snapshot.user_id})
                user = users.get(snapshot.user_id)
                if (
                    user is None
                    or not user.is_active
                    or not self._same_identity(user, snapshot)
                ):
                    raise InvalidLoginCredentialsError()
                if not self._same_login_user_state(
                    user, snapshot
                ) or not self._same_password_state(user, snapshot):
                    raise InvalidLoginCredentialsError()
                if not user.must_change_password:
                    raise InvalidLoginCredentialsError()

                await self._rotate_password(
                    session,
                    user=user,
                    password_hash=new_hash,
                    must_change_password=False,
                )
                user.token_version += 1
                session.add(
                    self._account_event(
                        action="account_security.password.reset_completed",
                        outcome=AccountSecurityAuditOutcome.SUCCEEDED,
                        reason_code="temporary_password_completed",
                        actor_type=AccountSecurityActorType.USER,
                        actor_user_id=user.id,
                        target_user_id=user.id,
                        source=AuditSource.HTTP,
                        request_id=request_id,
                    )
                )
        return True

    async def operator_reset_super_admin_password(
        self,
        *,
        user_id: uuid.UUID,
        temporary_password: str,
        request_id: str,
    ) -> bool:
        try:
            temporary_hash = await self._password_manager.hash_new_password(
                temporary_password
            )
        except PasswordPolicyError as exc:
            raise _password_policy_response(exc) from exc

        async with self._session_factory() as session:
            async with session.begin():
                await lock_rbac_state(session)
                users = await lock_users(session, {user_id})
                user = users.get(user_id)
                if user is None or not user.is_active:
                    raise not_found("user_not_found")
                holder_ids = await load_live_super_admin_holder_ids(session)
                if holder_ids != frozenset({user_id}):
                    raise conflict("operator_reset_requires_sole_super_admin")
                authority = await load_authority_snapshot(
                    session,
                    user_id=user_id,
                    include_disabled_roles=True,
                )
                if not authority.is_super_admin:
                    raise forbidden("operator_reset_requires_super_admin")
                try:
                    validate_new_password(
                        temporary_password,
                        identity_values=tuple(
                            value for value in (user.user_name,) if value
                        ),
                    )
                except PasswordPolicyError as exc:
                    raise _password_policy_response(exc) from exc
                await self._rotate_password(
                    session,
                    user=user,
                    password_hash=temporary_hash,
                    must_change_password=True,
                )
                user.token_version += 1
                session.add(
                    self._account_event(
                        action="account_security.password.operator_reset",
                        outcome=AccountSecurityAuditOutcome.SUCCEEDED,
                        reason_code="operator_temporary_password_set",
                        actor_type=AccountSecurityActorType.OPERATOR,
                        actor_user_id=None,
                        target_user_id=user.id,
                        source=AuditSource.OPERATOR,
                        request_id=request_id,
                    )
                )
        return True

    async def _reauthenticate_actor(
        self,
        *,
        context: AuthorizationContext,
        current_password: str,
        action: str,
        target_user_id: uuid.UUID,
    ) -> _PasswordSnapshot:
        async def verify_current_password() -> _PasswordSnapshot | None:
            snapshot = await self._load_snapshot_by_user_id(context.principal.user_id)
            verification = await self._verify_password(
                current_password,
                snapshot.password_hash if snapshot is not None else None,
            )
            if (
                snapshot is None
                or not verification
                or snapshot.password_hash is None
                or snapshot.is_deleted
                or not snapshot.is_active
                or snapshot.must_change_password
                or snapshot.token_version != context.principal.token_version
            ):
                return None
            return snapshot

        try:
            verified_snapshot = await verify_current_password()
            if verified_snapshot is None:
                raise InvalidLoginCredentialsError()
        except InvalidLoginCredentialsError as exc:
            await self._write_denied_event(
                action=action,
                reason_code="current_password_invalid",
                actor_user_id=context.principal.user_id,
                target_user_id=target_user_id,
                source=context.audit_source,
                request_id=context.request_id,
            )
            raise forbidden("current_password_invalid") from exc
        return verified_snapshot

    async def _lock_authorized_reset_target(
        self,
        session: AsyncSession,
        *,
        context: AuthorizationContext,
        target_user_id: uuid.UUID,
    ) -> User:
        await lock_rbac_state(session)
        users = await lock_users(
            session,
            {context.principal.user_id, target_user_id},
        )
        actor = await require_current_actor(
            session,
            actor_user_id=context.principal.user_id,
            token_version=context.principal.token_version,
        )
        if PermissionKey.USERS_PASSWORD_RESET.value not in actor.permissions:
            raise forbidden("missing_operation_permission")
        target_user = users.get(target_user_id)
        if target_user is None:
            raise not_found("user_not_found")
        target = await load_authority_snapshot(
            session,
            user_id=target_user_id,
            include_disabled_roles=True,
        )
        if not is_administrative_user_visible(actor=actor, target=target):
            raise not_found("user_not_found")
        decision = decide_user_password_reset(
            actor=actor,
            target_before=target,
        )
        if not decision.allowed:
            raise forbidden(decision.reason_code)
        return target_user

    async def _verify_login_snapshot(
        self,
        *,
        user_name: str,
        password: str,
        require_temporary: bool,
    ) -> AuthenticatedPasswordUser | None:
        snapshot = await self._load_snapshot_by_user_name(user_name)
        verification = await self._verify_password_details(
            password,
            snapshot.password_hash if snapshot is not None else None,
        )
        if (
            snapshot is None
            or not verification.verified
            or verification.used_dummy
            or snapshot.password_hash is None
            or snapshot.is_deleted
            or not snapshot.is_active
            or (require_temporary and not snapshot.must_change_password)
        ):
            return None

        replacement_hash: str | None = None
        if verification.needs_rehash:
            replacement_hash = await self._password_manager.hash_verified_password(
                password
            )

        concurrent_rehash_snapshot: _PasswordSnapshot | None = None
        async with self._session_factory() as session:
            async with session.begin():
                users = await lock_users(session, {snapshot.user_id})
                user = users.get(snapshot.user_id)
                if (
                    user is None
                    or not self._same_login_user_state(user, snapshot)
                    or user.must_change_password != snapshot.must_change_password
                ):
                    return None
                if require_temporary and not user.must_change_password:
                    return None
                if user.password_hash == snapshot.password_hash:
                    if replacement_hash is not None:
                        # A hash-parameter upgrade is not a password change.
                        user.password_hash = replacement_hash
                    return AuthenticatedPasswordUser(
                        user_id=user.id,
                        token_version=user.token_version,
                        must_change_password=user.must_change_password,
                    )

                if replacement_hash is None or user.password_hash is None:
                    return None
                concurrent_rehash_snapshot = self._snapshot_from_user(user)

        assert concurrent_rehash_snapshot is not None
        concurrent_verification = await self._verify_password_details(
            password,
            concurrent_rehash_snapshot.password_hash,
        )
        if (
            not concurrent_verification.verified
            or concurrent_verification.needs_rehash
            or concurrent_verification.used_dummy
        ):
            return None

        async with self._session_factory() as session:
            async with session.begin():
                users = await lock_users(session, {snapshot.user_id})
                user = users.get(snapshot.user_id)
                if (
                    user is None
                    or not self._same_login_user_state(
                        user,
                        concurrent_rehash_snapshot,
                    )
                    or not self._same_password_state(user, concurrent_rehash_snapshot)
                ):
                    return None
                if require_temporary and not user.must_change_password:
                    return None
                return AuthenticatedPasswordUser(
                    user_id=user.id,
                    token_version=user.token_version,
                    must_change_password=user.must_change_password,
                )

    async def _verify_temporary_snapshot(
        self,
        *,
        user_name: str,
        password: str,
    ) -> _PasswordSnapshot | None:
        snapshot = await self._load_snapshot_by_user_name(user_name)
        verified = await self._verify_password(
            password,
            snapshot.password_hash if snapshot is not None else None,
        )
        if (
            snapshot is None
            or not verified
            or snapshot.password_hash is None
            or snapshot.is_deleted
            or not snapshot.is_active
            or not snapshot.must_change_password
        ):
            return None
        return snapshot

    async def _verify_password(self, password: str, password_hash: str | None) -> bool:
        verification = await self._verify_password_details(password, password_hash)
        return verification.verified

    async def _verify_password_details(
        self,
        password: str,
        password_hash: str | None,
    ) -> PasswordVerification:
        try:
            return await self._password_manager.verify_or_dummy(password, password_hash)
        except PasswordPolicyError as exc:
            raise InvalidLoginCredentialsError() from exc
        except PasswordHashError as exc:
            safe_log(
                logger,
                logging.ERROR,
                "authentication.password_store.invalid",
                extra=safe_exception_metadata(exc),
            )
            raise unavailable("password_credential_unavailable") from exc

    async def _load_snapshot_by_user_name(
        self,
        user_name: str,
    ) -> _PasswordSnapshot | None:
        async with self._session_factory() as session:
            user = await session.scalar(select(User).where(User.user_name == user_name))
            return self._snapshot_from_user(user) if user is not None else None

    async def _load_snapshot_by_user_id(
        self,
        user_id: uuid.UUID,
    ) -> _PasswordSnapshot | None:
        async with self._session_factory() as session:
            user = await session.get(User, user_id)
            return self._snapshot_from_user(user) if user is not None else None

    @staticmethod
    def _snapshot_from_user(user: User) -> _PasswordSnapshot:
        return _PasswordSnapshot(
            user_id=user.id,
            user_name=user.user_name,
            is_active=user.is_active,
            is_deleted=user.deleted_at is not None,
            token_version=user.token_version,
            password_hash=user.password_hash,
            password_changed_at=user.password_changed_at,
            must_change_password=user.must_change_password,
        )

    @staticmethod
    def _same_identity(user: User, snapshot: _PasswordSnapshot) -> bool:
        return (
            user.id == snapshot.user_id
            and user.user_name == snapshot.user_name
            and user.deleted_at is None
        )

    @staticmethod
    def _same_login_user_state(user: User, snapshot: _PasswordSnapshot) -> bool:
        return (
            LocalAuthenticationService._same_identity(user, snapshot)
            and user.is_active == snapshot.is_active
            and user.token_version == snapshot.token_version
            and user.password_changed_at == snapshot.password_changed_at
        )

    @staticmethod
    def _same_password_state(user: User, snapshot: _PasswordSnapshot) -> bool:
        return (
            user.password_hash is not None
            and user.password_hash == snapshot.password_hash
            and user.must_change_password == snapshot.must_change_password
        )

    @staticmethod
    async def _rotate_password(
        session: AsyncSession,
        *,
        user: User,
        password_hash: str,
        must_change_password: bool,
    ) -> None:
        changed_at = cast(
            datetime, await session.scalar(select(func.statement_timestamp()))
        )
        user.password_hash = password_hash
        user.must_change_password = must_change_password
        user.password_changed_at = changed_at

    @staticmethod
    def _is_identity_conflict(exc: IntegrityError) -> bool:
        candidates = (exc.orig, getattr(exc.orig, "__cause__", None))
        constraint_name = next(
            (
                value
                for candidate in candidates
                if isinstance(
                    value := getattr(candidate, "constraint_name", None),
                    str,
                )
            ),
            None,
        )
        return constraint_name == "uq_users_user_name"

    @staticmethod
    def _account_event(
        *,
        action: str,
        outcome: AccountSecurityAuditOutcome,
        reason_code: str,
        actor_type: AccountSecurityActorType,
        actor_user_id: uuid.UUID | None,
        target_user_id: uuid.UUID | None,
        source: AuditSource,
        request_id: str,
    ) -> AccountSecurityAuditEvent:
        return AccountSecurityAuditEvent(
            id=uuid.uuid4(),
            action=action,
            outcome=outcome,
            reason_code=reason_code,
            actor_type=actor_type,
            actor_user_id=actor_user_id,
            target_user_id=target_user_id,
            source=source,
            schema_version=1,
            request_id=request_id,
        )

    async def _write_denied_event(
        self,
        *,
        action: str,
        reason_code: str,
        actor_user_id: uuid.UUID,
        target_user_id: uuid.UUID,
        source: AuditSource,
        request_id: str,
    ) -> None:
        try:
            async with self._session_factory() as session:
                async with session.begin():
                    session.add(
                        self._account_event(
                            action=action,
                            outcome=AccountSecurityAuditOutcome.DENIED,
                            reason_code=reason_code,
                            actor_type=AccountSecurityActorType.USER,
                            actor_user_id=actor_user_id,
                            target_user_id=target_user_id,
                            source=source,
                            request_id=request_id,
                        )
                    )
        except Exception as exc:
            safe_log(
                logger,
                logging.ERROR,
                "audit.write.failed",
                extra={
                    "audit_domain": "account_security",
                    "audit_action": action,
                    **safe_exception_metadata(exc),
                },
            )

    async def _write_client_denial(
        self,
        *,
        error: RbacError,
        action: str,
        actor_user_id: uuid.UUID,
        target_user_id: uuid.UUID,
        source: AuditSource,
        request_id: str,
    ) -> None:
        if error.status_code >= 500:
            return
        await self._write_denied_event(
            action=action,
            reason_code=error.reason_code,
            actor_user_id=actor_user_id,
            target_user_id=target_user_id,
            source=source,
            request_id=request_id,
        )


local_authentication_service = LocalAuthenticationService(
    SessionFactory,
    password_manager,
)


def get_local_authentication_service() -> LocalAuthenticationService:
    return local_authentication_service
