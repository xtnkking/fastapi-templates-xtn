from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import cast

from sqlalchemy import and_, func, select
from sqlalchemy.engine import Row
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.sql import Select

from app.abuse_flow import IdentityAbuseFlow, InvalidLoginCredentialsError
from app.audit import AuditSource
from app.database import SessionFactory
from app.observability import safe_exception_metadata, safe_log
from app.password_models import (
    AccountSecurityActorType,
    AccountSecurityAuditEvent,
    AccountSecurityAuditOutcome,
    PasswordCredential,
)
from app.passwords import (
    PasswordHashError,
    PasswordManager,
    PasswordPolicyError,
    PasswordVerification,
    password_manager,
    validate_new_password,
)
from app.rbac.domain import AuthorizationContext, PermissionKey
from app.rbac.errors import (
    RbacError,
    conflict,
    forbidden,
    invalid_request,
    not_found,
    unavailable,
)
from app.rbac.models import User
from app.rbac.policy import (
    decide_user_password_reset,
    is_administrative_user_visible,
)
from app.rbac.provisioning import create_user_with_default_role
from app.rbac.queries import (
    load_authority_snapshot,
    load_live_super_admin_holder_ids,
    lock_rbac_state,
    lock_users,
    require_current_actor,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class AuthenticatedPasswordUser:
    user_id: uuid.UUID
    token_version: int
    must_change_password: bool


@dataclass(frozen=True, slots=True)
class _PasswordSnapshot:
    user_id: uuid.UUID
    user_name: str | None
    email: str | None
    is_active: bool
    is_deleted: bool
    token_version: int
    credential_id: uuid.UUID | None
    password_hash: str | None
    credential_version: int | None
    must_change_password: bool

    @property
    def identity_values(self) -> tuple[str, ...]:
        return tuple(value for value in (self.user_name, self.email) if value)


class LocalAuthenticationService:
    """Own local-password state while keeping Argon2 outside database locks."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        manager: PasswordManager,
    ) -> None:
        self._session_factory = session_factory
        self._password_manager = manager

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
                raise invalid_request(exc.reason_code) from exc

            try:
                async with self._session_factory() as session:
                    async with session.begin():
                        user = await create_user_with_default_role(
                            session,
                            user_name=user_name,
                            request_id=request_id,
                        )
                        session.add(
                            PasswordCredential(
                                user_id=user.id,
                                password_hash=password_hash,
                                version=1,
                                must_change_password=False,
                                created_by_user_id=None,
                            )
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
                    raise conflict("user_identity_exists") from exc
                raise

        if abuse_flow is None:
            return await registration_action()
        return await abuse_flow.register(
            client_ip=client_ip,
            normalized_identifier=user_name,
            registration_action=registration_action,
        )

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
            normalized_identifier=user_name,
            verify_real_or_dummy_credentials=verify_credentials,
        )

    async def change_password(
        self,
        *,
        abuse_flow: IdentityAbuseFlow | None,
        client_ip: str,
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
            abuse_flow=abuse_flow,
            client_ip=client_ip,
        )
        try:
            new_hash = await self._password_manager.hash_new_password(
                new_password,
                identity_values=actor_snapshot.identity_values,
            )
        except PasswordPolicyError as exc:
            raise invalid_request(exc.reason_code) from exc

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
                credential = await self._lock_live_credential(session, user.id)
                if not self._same_credential(credential, actor_snapshot):
                    raise forbidden("current_credential_changed")

                await self._rotate_password(
                    session,
                    user=user,
                    password_hash=new_hash,
                    must_change_password=False,
                    created_by_user_id=user.id,
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
        abuse_flow: IdentityAbuseFlow | None,
        client_ip: str,
        context: AuthorizationContext,
        target_user_id: uuid.UUID,
        current_password: str,
        temporary_password: str,
    ) -> bool:
        actor_snapshot = await self._reauthenticate_actor(
            context=context,
            current_password=current_password,
            action="account_security.password.admin_reset",
            target_user_id=target_user_id,
            abuse_flow=abuse_flow,
            client_ip=client_ip,
        )

        try:
            async with self._session_factory() as session:
                async with session.begin():
                    target_user = await self._lock_authorized_reset_target(
                        session,
                        context=context,
                        actor_snapshot=actor_snapshot,
                        target_user_id=target_user_id,
                    )
                    target_identity_values = tuple(
                        value
                        for value in (target_user.user_name, target_user.email)
                        if value
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
            temporary_hash = await self._password_manager.hash_new_password(
                temporary_password,
                identity_values=target_identity_values,
            )
        except PasswordPolicyError as exc:
            raise invalid_request(exc.reason_code) from exc

        try:
            async with self._session_factory() as session:
                async with session.begin():
                    target_user = await self._lock_authorized_reset_target(
                        session,
                        context=context,
                        actor_snapshot=actor_snapshot,
                        target_user_id=target_user_id,
                    )
                    try:
                        validate_new_password(
                            temporary_password,
                            identity_values=tuple(
                                value
                                for value in (target_user.user_name, target_user.email)
                                if value
                            ),
                        )
                    except PasswordPolicyError as exc:
                        raise invalid_request(exc.reason_code) from exc

                    await self._rotate_password(
                        session,
                        user=target_user,
                        password_hash=temporary_hash,
                        must_change_password=True,
                        created_by_user_id=context.principal.user_id,
                    )
                    target_user.token_version += 1
                    session.add(
                        self._account_event(
                            action="account_security.password.admin_reset",
                            outcome=AccountSecurityAuditOutcome.SUCCEEDED,
                            reason_code="temporary_password_set",
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
            snapshot = await abuse_flow.authenticate(
                client_ip=client_ip,
                normalized_identifier=user_name,
                verify_real_or_dummy_credentials=verify_temporary,
            )

        try:
            new_hash = await self._password_manager.hash_new_password(
                new_password,
                identity_values=snapshot.identity_values,
            )
        except PasswordPolicyError as exc:
            raise invalid_request(exc.reason_code) from exc

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
                credential = await self._lock_live_credential(session, user.id)
                if credential is None or not self._same_credential(
                    credential, snapshot
                ):
                    raise InvalidLoginCredentialsError()
                if not credential.must_change_password:
                    raise InvalidLoginCredentialsError()

                await self._rotate_password(
                    session,
                    user=user,
                    password_hash=new_hash,
                    must_change_password=False,
                    created_by_user_id=user.id,
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
            raise invalid_request(exc.reason_code) from exc

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
                            value for value in (user.user_name, user.email) if value
                        ),
                    )
                except PasswordPolicyError as exc:
                    raise invalid_request(exc.reason_code) from exc
                await self._rotate_password(
                    session,
                    user=user,
                    password_hash=temporary_hash,
                    must_change_password=True,
                    created_by_user_id=None,
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
        abuse_flow: IdentityAbuseFlow | None,
        client_ip: str,
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
                or snapshot.is_deleted
                or not snapshot.is_active
                or snapshot.must_change_password
                or snapshot.token_version != context.principal.token_version
            ):
                return None
            return snapshot

        try:
            if abuse_flow is None:
                verified_snapshot = await verify_current_password()
                if verified_snapshot is None:
                    raise InvalidLoginCredentialsError()
            else:
                verified_snapshot = await abuse_flow.authenticate(
                    client_ip=client_ip,
                    normalized_identifier=str(context.principal.user_id),
                    verify_real_or_dummy_credentials=verify_current_password,
                )
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
        actor_snapshot: _PasswordSnapshot,
        target_user_id: uuid.UUID,
    ) -> User:
        await lock_rbac_state(session)
        users = await lock_users(
            session,
            {context.principal.user_id, target_user_id},
        )
        actor_user = users.get(context.principal.user_id)
        if (
            actor_user is None
            or not actor_user.is_active
            or actor_user.token_version != context.principal.token_version
            or not self._same_identity(actor_user, actor_snapshot)
        ):
            raise forbidden("current_credential_changed")
        actor_credential = await self._lock_live_credential(session, actor_user.id)
        if not self._same_credential(actor_credential, actor_snapshot):
            raise forbidden("current_credential_changed")

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
                credential = await self._lock_live_credential(session, snapshot.user_id)
                if (
                    user is None
                    or not self._same_login_user_state(user, snapshot)
                    or not self._same_credential_episode(credential, snapshot)
                ):
                    return None
                assert credential is not None
                if require_temporary and not credential.must_change_password:
                    return None
                if credential.password_hash == snapshot.password_hash:
                    if replacement_hash is not None:
                        # The password is unchanged. Upgrade only its encoding after
                        # rechecking the exact credential under the row lock.
                        credential.password_hash = replacement_hash
                    return AuthenticatedPasswordUser(
                        user_id=user.id,
                        token_version=user.token_version,
                        must_change_password=credential.must_change_password,
                    )

                if replacement_hash is None or credential.password_hash is None:
                    return None
                concurrent_rehash_snapshot = self._snapshot_from_models(
                    user,
                    credential,
                )

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
                credential = await self._lock_live_credential(session, snapshot.user_id)
                if (
                    user is None
                    or not self._same_login_user_state(
                        user,
                        concurrent_rehash_snapshot,
                    )
                    or not self._same_credential(
                        credential,
                        concurrent_rehash_snapshot,
                    )
                ):
                    return None
                assert credential is not None
                if require_temporary and not credential.must_change_password:
                    return None
                return AuthenticatedPasswordUser(
                    user_id=user.id,
                    token_version=user.token_version,
                    must_change_password=credential.must_change_password,
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
            row = (
                await session.execute(
                    self._snapshot_statement().where(User.user_name == user_name)
                )
            ).one_or_none()
            return self._snapshot_from_row(row)

    async def _load_snapshot_by_user_id(
        self,
        user_id: uuid.UUID,
    ) -> _PasswordSnapshot | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    self._snapshot_statement().where(User.id == user_id)
                )
            ).one_or_none()
            return self._snapshot_from_row(row)

    @staticmethod
    def _snapshot_statement() -> Select[tuple[User, PasswordCredential]]:
        return select(User, PasswordCredential).outerjoin(
            PasswordCredential,
            and_(
                PasswordCredential.user_id == User.id,
                PasswordCredential.deleted_at.is_(None),
            ),
        )

    @staticmethod
    def _snapshot_from_row(
        row: Row[tuple[User, PasswordCredential]] | None,
    ) -> _PasswordSnapshot | None:
        if row is None:
            return None
        user = row[0]
        credential = cast(PasswordCredential | None, row[1])
        return LocalAuthenticationService._snapshot_from_models(user, credential)

    @staticmethod
    def _snapshot_from_models(
        user: User,
        credential: PasswordCredential | None,
    ) -> _PasswordSnapshot:
        return _PasswordSnapshot(
            user_id=user.id,
            user_name=user.user_name,
            email=user.email,
            is_active=user.is_active,
            is_deleted=user.deleted_at is not None,
            token_version=user.token_version,
            credential_id=credential.id if credential is not None else None,
            password_hash=(
                credential.password_hash if credential is not None else None
            ),
            credential_version=(credential.version if credential is not None else None),
            must_change_password=(
                credential.must_change_password if credential is not None else False
            ),
        )

    @staticmethod
    async def _lock_live_credential(
        session: AsyncSession,
        user_id: uuid.UUID,
    ) -> PasswordCredential | None:
        return cast(
            PasswordCredential | None,
            await session.scalar(
                select(PasswordCredential)
                .where(
                    PasswordCredential.user_id == user_id,
                    PasswordCredential.deleted_at.is_(None),
                )
                .with_for_update()
                .execution_options(populate_existing=True)
            ),
        )

    @staticmethod
    def _same_identity(user: User, snapshot: _PasswordSnapshot) -> bool:
        return (
            user.id == snapshot.user_id
            and user.user_name == snapshot.user_name
            and user.email == snapshot.email
            and user.deleted_at is None
        )

    @staticmethod
    def _same_login_user_state(user: User, snapshot: _PasswordSnapshot) -> bool:
        return (
            LocalAuthenticationService._same_identity(user, snapshot)
            and user.is_active == snapshot.is_active
            and user.token_version == snapshot.token_version
        )

    @staticmethod
    def _same_credential_episode(
        credential: PasswordCredential | None,
        snapshot: _PasswordSnapshot,
    ) -> bool:
        return (
            credential is not None
            and credential.id == snapshot.credential_id
            and credential.version == snapshot.credential_version
            and credential.must_change_password == snapshot.must_change_password
        )

    @staticmethod
    def _same_credential(
        credential: PasswordCredential | None,
        snapshot: _PasswordSnapshot,
    ) -> bool:
        return (
            LocalAuthenticationService._same_credential_episode(credential, snapshot)
            and credential is not None
            and credential.password_hash == snapshot.password_hash
        )

    @staticmethod
    async def _rotate_password(
        session: AsyncSession,
        *,
        user: User,
        password_hash: str,
        must_change_password: bool,
        created_by_user_id: uuid.UUID | None,
    ) -> PasswordCredential:
        old_credential = await LocalAuthenticationService._lock_live_credential(
            session,
            user.id,
        )
        latest_version = cast(
            int | None,
            await session.scalar(
                select(func.max(PasswordCredential.version)).where(
                    PasswordCredential.user_id == user.id
                )
            ),
        )
        changed_at = cast(
            datetime, await session.scalar(select(func.statement_timestamp()))
        )
        next_version = (latest_version or 0) + 1
        if old_credential is not None:
            old_credential.password_hash = None
            old_credential.must_change_password = False
            old_credential.deleted_at = changed_at
            old_credential.deleted_by_user_id = created_by_user_id
            # Release the partial unique index before adding the next episode.
            await session.flush()

        credential = PasswordCredential(
            user_id=user.id,
            password_hash=password_hash,
            version=next_version,
            must_change_password=must_change_password,
            created_by_user_id=created_by_user_id,
            password_changed_at=changed_at,
        )
        session.add(credential)
        return credential

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
        return constraint_name in {"uq_users_email", "uq_users_user_name"}

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
