import logging
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal

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

type ActorQuotaName = Literal[
    "authenticated_read",
    "management_read",
    "ordinary_write",
    "authorization_write",
]

AUTHENTICATED_RATE_LIMIT_RULES: Mapping[
    str, tuple[Literal["GET", "POST"], ActorQuotaName]
] = MappingProxyType(
    {
        "logout_current_access_token": ("POST", "ordinary_write"),
        "get_my_access": ("GET", "authenticated_read"),
        "my_active_sessions": ("GET", "authenticated_read"),
        "list_permissions": ("GET", "management_read"),
        "get_permission": ("GET", "management_read"),
        "list_roles": ("GET", "management_read"),
        "get_role": ("GET", "management_read"),
        "list_users": ("GET", "management_read"),
        "get_user": ("GET", "management_read"),
        "change_my_password": ("POST", "ordinary_write"),
        "create_role": ("POST", "authorization_write"),
        "update_role": ("POST", "authorization_write"),
        "disable_role": ("POST", "authorization_write"),
        "enable_role": ("POST", "authorization_write"),
        "delete_role": ("POST", "authorization_write"),
        "bind_role_permissions": ("POST", "authorization_write"),
        "unbind_role_permissions": ("POST", "authorization_write"),
        "bind_user_roles": ("POST", "authorization_write"),
        "unbind_user_roles": ("POST", "authorization_write"),
        "disable_user": ("POST", "authorization_write"),
        "enable_user": ("POST", "authorization_write"),
        "reset_user_password": ("POST", "authorization_write"),
        "create_user": ("POST", "authorization_write"),
        "revoke_user_sessions": ("POST", "authorization_write"),
        "update_registration_policy": ("POST", "authorization_write"),
    }
)
AUTHENTICATED_RATE_LIMIT_EXEMPT_OPERATIONS: Mapping[str, Literal["POST"]] = (
    MappingProxyType(
        {
            # This route applies a separate quota for each authenticated CAPTCHA scene.
            "create_authenticated_captcha": "POST",
        }
    )
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
    rule = AUTHENTICATED_RATE_LIMIT_RULES.get(operation_id)
    if rule is None:
        raise RateLimitUnavailable("protected operation needs a stable identifier")
    expected_method, quota_name = rule
    if request.method != expected_method:
        raise RateLimitUnavailable("protected operation method does not match policy")
    quotas: dict[ActorQuotaName, RateLimitPolicy] = {
        "authenticated_read": policies.authenticated_read,
        "management_read": policies.management_read,
        "ordinary_write": policies.ordinary_write,
        "authorization_write": policies.authorization_write,
    }
    quota = quotas[quota_name]
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
    operation_id = _operation_id(request)
    exempt_method = AUTHENTICATED_RATE_LIMIT_EXEMPT_OPERATIONS.get(operation_id)
    if exempt_method is not None:
        if request.method != exempt_method:
            raise unavailable("rate_limit_policy_unavailable")
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
