from dataclasses import dataclass

from app.core.config import Settings
from app.core.security.rate_limit import RateLimitPolicy


@dataclass(frozen=True, slots=True)
class SecurityPolicies:
    """Quota values live in Settings; each operation gets its own Redis key."""

    captcha_create: RateLimitPolicy
    login: RateLimitPolicy
    registration: RateLimitPolicy
    temporary_complete: RateLimitPolicy
    authenticated_read: RateLimitPolicy
    management_read: RateLimitPolicy
    ordinary_write: RateLimitPolicy
    authorization_write: RateLimitPolicy

    @classmethod
    def from_settings(cls, settings: Settings) -> "SecurityPolicies":
        return cls(
            captcha_create=RateLimitPolicy(
                "captcha_create",
                settings.rate_limit_captcha_create_per_five_minutes,
                300,
            ),
            login=RateLimitPolicy(
                "login", settings.rate_limit_login_ip_per_five_minutes, 300
            ),
            registration=RateLimitPolicy(
                "register", settings.rate_limit_registration_ip_per_hour, 3600
            ),
            temporary_complete=RateLimitPolicy(
                "temporary_complete",
                settings.rate_limit_temporary_complete_ip_per_five_minutes,
                300,
            ),
            authenticated_read=RateLimitPolicy(
                "authenticated_read",
                settings.rate_limit_authenticated_read_per_minute,
                60,
            ),
            management_read=RateLimitPolicy(
                "management_read", settings.rate_limit_management_read_per_minute, 60
            ),
            ordinary_write=RateLimitPolicy(
                "ordinary_write", settings.rate_limit_ordinary_write_per_minute, 60
            ),
            authorization_write=RateLimitPolicy(
                "authorization_write",
                settings.rate_limit_authorization_write_per_minute,
                60,
            ),
        )
