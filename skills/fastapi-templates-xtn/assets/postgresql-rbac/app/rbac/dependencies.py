import logging
import uuid
from collections.abc import Awaitable, Callable
from typing import Annotated, Literal

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import SessionFactory, get_session
from app.rbac.domain import AuthorizationContext, PermissionKey, Principal
from app.rbac.errors import RbacError, forbidden, unauthenticated, unavailable
from app.rbac.models import AuthorizationAuditEvent, AuthorizationState, User
from app.rbac.queries import load_authority_snapshot
from app.rbac.security import decode_access_token
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
                AuthorizationAuditEvent(
                    actor_user_id=context.principal.user_id,
                    target_user_id=None,
                    target_role_id=None,
                    action=action,
                    decision="denied",
                    reason_code="missing_required_permission",
                    before_state=None,
                    after_state=None,
                    request_id=context.request_id,
                )
            )


async def get_current_principal(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    session: SessionDependency,
    settings: SettingsDependency,
) -> Principal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise unauthenticated("missing_bearer_token")
    principal = decode_access_token(credentials.credentials, settings)
    user = await session.scalar(select(User).where(User.id == principal.user_id))
    if (
        user is None
        or not user.is_active
        or user.token_version != principal.token_version
    ):
        raise unauthenticated("identity_inactive_or_revoked")
    return principal


PrincipalDependency = Annotated[Principal, Depends(get_current_principal)]


async def get_authorization_context(
    request: Request,
    principal: PrincipalDependency,
    session: SessionDependency,
) -> AuthorizationContext:
    state = await session.scalar(
        select(AuthorizationState).where(AuthorizationState.scope == "global")
    )
    if state is None:
        raise unavailable("authorization_state_missing")

    try:
        authority = await load_authority_snapshot(session, user_id=principal.user_id)
    except RbacError as exc:
        if exc.reason_code == "user_not_found":
            raise unauthenticated("identity_inactive_or_revoked") from exc
        raise
    if not authority.user_is_active:
        raise unauthenticated("identity_inactive_or_revoked")
    request_id = request.headers.get("X-Request-ID", "").strip()
    if not request_id or len(request_id) > 128:
        request_id = str(uuid.uuid4())
    return AuthorizationContext(
        principal=principal,
        authorization_epoch=state.epoch,
        authority=authority,
        request_id=request_id,
    )


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
                except Exception:
                    logger.exception(
                        "failed to persist denied access-control audit",
                        extra={"audit_action": action},
                    )
            raise forbidden("missing_required_permission")
        return context

    return dependency
