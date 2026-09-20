import logging
from collections.abc import Awaitable, Callable
from typing import Annotated, Literal

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api_contract import request_id_for
from app.audit import AuditSource
from app.database import SessionFactory, get_session
from app.observability import (
    dependency_error_category,
    safe_exception_metadata,
    safe_log,
)
from app.rate_limit_dependencies import (
    enforce_principal_rate_limit,
    precheck_principal_rate_limit,
)
from app.rbac.domain import AuthorizationContext, PermissionKey, Principal
from app.rbac.errors import RbacError, forbidden, unauthenticated, unavailable
from app.rbac.models import RbacAuditEvent, RbacState
from app.rbac.queries import load_authority_snapshot
from app.rbac.security import (
    MAX_BEARER_TOKEN_BYTES,
    AccessTokenClaims,
    decode_access_token,
    require_active_jti,
    revoke_active_jti,
)
from app.redis_client import get_redis
from app.settings import Settings, get_settings

bearer = HTTPBearer(auto_error=False)
logger = logging.getLogger(__name__)
SessionDependency = Annotated[AsyncSession, Depends(get_session)]
SettingsDependency = Annotated[Settings, Depends(get_settings)]


async def _write_permission_denial_audit(
    *,
    context: AuthorizationContext,
    action: str,
) -> None:
    async with SessionFactory() as audit_session:
        async with audit_session.begin():
            audit_session.add(
                RbacAuditEvent(
                    actor_user_id=context.principal.user_id,
                    target_user_id=None,
                    target_role_id=None,
                    action=action,
                    decision="denied",
                    reason_code="missing_required_permission",
                    source=context.audit_source.value,
                    before_state=None,
                    after_state=None,
                    request_id=context.request_id,
                )
            )


async def _best_effort_revoke_invalid_principal(
    *,
    request: Request,
    principal: Principal,
    settings: Settings,
) -> None:
    """Make a database-rejected JTI cheap to reject on its next request."""
    try:
        await revoke_active_jti(
            get_redis(request),
            claims=AccessTokenClaims(
                user_id=principal.user_id,
                token_id=principal.token_id,
                issued_at=principal.issued_at,
                expires_at=principal.expires_at,
            ),
            user_token_version=principal.token_version,
            settings=settings,
        )
    except RbacError:
        # revoke_active_jti already logs Redis failures. A compare miss means a
        # concurrent request has already removed the exact JTI.
        return
    except Exception as exc:
        safe_log(
            logger,
            logging.ERROR,
            "security.inactive_token_cleanup.failed",
            extra=safe_exception_metadata(exc),
        )


async def get_current_principal(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    settings: SettingsDependency,
) -> Principal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise unauthenticated("missing_bearer_token")
    token = credentials.credentials
    if len(token.encode("utf-8")) > MAX_BEARER_TOKEN_BYTES:
        raise unauthenticated("bearer_token_too_large")
    claims = decode_access_token(token, settings)
    redis = get_redis(request)
    token_version = await require_active_jti(
        redis,
        claims=claims,
        settings=settings,
    )
    principal = Principal(
        user_id=claims.user_id,
        token_version=token_version,
        token_id=claims.token_id,
        issued_at=claims.issued_at,
        expires_at=claims.expires_at,
    )
    return principal


PrincipalDependency = Annotated[Principal, Depends(get_current_principal)]


async def get_authorization_context(
    request: Request,
    principal: PrincipalDependency,
    session: SessionDependency,
    settings: SettingsDependency,
) -> AuthorizationContext:
    await precheck_principal_rate_limit(request, principal, settings)
    try:
        state = await session.scalar(
            select(RbacState).where(RbacState.scope == "global")
        )
        if state is None:
            raise unavailable("rbac_state_missing")
        authority = await load_authority_snapshot(session, user_id=principal.user_id)
    except RbacError as exc:
        if exc.reason_code == "user_not_found":
            await _best_effort_revoke_invalid_principal(
                request=request,
                principal=principal,
                settings=settings,
            )
            raise unauthenticated("identity_inactive_or_revoked") from exc
        raise
    except SQLAlchemyError as exc:
        safe_log(
            logger,
            logging.ERROR,
            "dependency.database.unavailable",
            extra={
                "dependency": "postgresql",
                "dependency_operation": "load_authorization_context",
                "error_category": dependency_error_category(exc),
                **safe_exception_metadata(exc),
            },
        )
        raise unavailable("authorization_store_unavailable") from exc
    if (
        not authority.user_is_active
        or authority.token_version != principal.token_version
    ):
        await _best_effort_revoke_invalid_principal(
            request=request,
            principal=principal,
            settings=settings,
        )
        raise unauthenticated("identity_inactive_or_revoked")
    request.state.actor_user_id = str(principal.user_id)
    await enforce_principal_rate_limit(request, principal, settings)
    context = AuthorizationContext(
        principal=principal,
        authorization_epoch=state.epoch,
        authority=authority,
        request_id=request_id_for(request),
        audit_source=AuditSource.HTTP,
    )
    return context


def require_permissions(
    *required: PermissionKey,
    mode: Literal["all", "any"] = "all",
) -> Callable[..., Awaitable[AuthorizationContext]]:
    if not required:
        raise ValueError("at least one permission is required")
    if mode not in ("all", "any"):
        raise ValueError("mode must be 'all' or 'any'")
    required_keys = frozenset(item.value for item in required)

    async def dependency(
        context: Annotated[
            AuthorizationContext,
            Depends(get_authorization_context),
        ],
        request: Request,
    ) -> AuthorizationContext:
        allowed = (
            required_keys <= context.permissions
            if mode == "all"
            else bool(required_keys & context.permissions)
        )
        if not allowed:
            if request.method == "POST":
                route = request.scope.get("route")
                operation_id = getattr(route, "operation_id", None)
                action = (
                    f"api.{operation_id}"
                    if isinstance(operation_id, str) and operation_id
                    else "api.protected_write"
                )
                try:
                    await _write_permission_denial_audit(
                        context=context,
                        action=action,
                    )
                except Exception as exc:
                    safe_log(
                        logger,
                        logging.ERROR,
                        "audit.write.failed",
                        extra={
                            "audit_action": action,
                            **safe_exception_metadata(exc),
                        },
                    )
            raise forbidden("missing_required_permission")
        return context

    return dependency
