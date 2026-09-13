import logging
from dataclasses import dataclass

from fastapi import Request

from app.observability import safe_exception_metadata, safe_log
from app.rate_limit import RateLimitPolicy, RateLimitResult, RateLimitUnavailable
from app.rate_limit import check_rate_limit as check_bucket
from app.rbac.domain import Principal
from app.rbac.errors import unavailable
from app.redis_client import get_rate_limit_redis
from app.security_policies import SecurityPolicies
from app.settings import Settings

logger = logging.getLogger(__name__)

_MANAGEMENT_READ_OPERATIONS = frozenset(
    {
        "list_permissions",
        "get_permission",
        "list_roles",
        "get_role",
        "list_users",
        "get_user",
    }
)
_AUTHORIZATION_WRITE_OPERATIONS = frozenset(
    {
        "create_role",
        "update_role",
        "disable_role",
        "enable_role",
        "delete_role",
        "bind_role_permissions",
        "unbind_role_permissions",
        "bind_role_delegable_permissions",
        "unbind_role_delegable_permissions",
        "bind_user_roles",
        "unbind_user_roles",
        "disable_user",
        "enable_user",
        "reset_user_password",
    }
)


@dataclass(frozen=True, slots=True)
class RateLimitExceeded(Exception):
    policy_name: str
    result: RateLimitResult


def _operation_id(request: Request) -> str:
    route = request.scope.get("route")
    value = getattr(route, "operation_id", None)
    return value if isinstance(value, str) else ""


def actor_policy_for(request: Request, settings: Settings) -> RateLimitPolicy | None:
    policies = SecurityPolicies.from_settings(settings)
    operation_id = _operation_id(request)
    if operation_id == "logout_current_access_token":
        return None
    if operation_id == "logout_all_access_tokens":
        return policies.logout_all
    if operation_id == "transfer_super_admin":
        return policies.super_admin_transfer
    if request.method == "GET":
        if operation_id in _MANAGEMENT_READ_OPERATIONS:
            return policies.management_read
        return policies.authenticated_read
    if request.method == "POST" and operation_id in _AUTHORIZATION_WRITE_OPERATIONS:
        return policies.authorization_write
    return policies.ordinary_write


async def enforce_principal_rate_limit(
    request: Request,
    principal: Principal,
    settings: Settings,
) -> None:
    if not settings.rate_limit_enabled:
        return
    policy = actor_policy_for(request, settings)
    if policy is None:
        return
    try:
        result = await check_bucket(
            get_rate_limit_redis(request),
            namespace=settings.rate_limit_namespace,
            policy=policy,
            subject_type="actor",
            subject=str(principal.user_id),
            key_secret=settings.rate_limit_hmac_key.get_secret_value().encode("utf-8"),
        )
    except RateLimitUnavailable as exc:
        safe_log(
            logger,
            logging.ERROR,
            "dependency.rate_limit.unavailable",
            extra={
                "dependency": "rate_limit_redis",
                "dependency_operation": "authenticated_admission",
                "rate_limit_policy": policy.name,
                **safe_exception_metadata(exc),
            },
        )
        raise unavailable("rate_limit_registry_unavailable") from exc
    if result.allowed:
        request.state.actor_rate_limit_result = result
        return
    raise RateLimitExceeded(policy_name=policy.name, result=result)
