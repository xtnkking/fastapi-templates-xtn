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
        "bind_user_roles",
        "unbind_user_roles",
        "disable_user",
        "enable_user",
        "reset_user_password",
        "create_user",
        "force_logout_user",
        "update_registration_policy",
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


def actor_policy_for(request: Request, settings: Settings) -> RateLimitPolicy:
    policies = SecurityPolicies.from_settings(settings)
    operation_id = _operation_id(request)
    if not operation_id:
        raise RateLimitUnavailable("protected operation needs a stable identifier")
    if request.method == "GET":
        if operation_id in _MANAGEMENT_READ_OPERATIONS:
            quota = policies.management_read
        else:
            quota = policies.authenticated_read
    elif request.method == "POST" and operation_id in _AUTHORIZATION_WRITE_OPERATIONS:
        quota = policies.authorization_write
    else:
        quota = policies.ordinary_write
    try:
        return RateLimitPolicy(
            name=operation_id,
            limit=quota.limit,
            window_seconds=quota.window_seconds,
        )
    except ValueError as exc:
        raise RateLimitUnavailable(
            "protected operation has invalid identifier"
        ) from exc


async def enforce_principal_rate_limit(
    request: Request,
    principal: Principal,
    settings: Settings,
) -> None:
    if not settings.rate_limit_enabled:
        return
    # Each CAPTCHA scene has its own 10/5-minute quota in check_captcha_create.
    # A generic bucket here would combine unrelated private scenes.
    if _operation_id(request) == "create_authenticated_captcha":
        return
    try:
        policy = actor_policy_for(request, settings)
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
                **safe_exception_metadata(exc),
            },
        )
        raise unavailable("rate_limit_registry_unavailable") from exc
    if result.allowed:
        request.state.actor_rate_limit_result = result
        return
    raise RateLimitExceeded(policy_name=policy.name, result=result)
