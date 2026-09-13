from dataclasses import dataclass

from app.rate_limit import RateLimitPolicy
from app.settings import Settings


def _token_bucket(name: str, limit: int, seconds: int) -> RateLimitPolicy:
    return RateLimitPolicy(
        name=name,
        burst_capacity=limit,
        refill_tokens=limit,
        refill_period_seconds=seconds,
    )


@dataclass(frozen=True, slots=True)
class SecurityPolicies:
    """Central policy names and configurable starting limits."""

    api_global: RateLimitPolicy
    api_ip: RateLimitPolicy
    anonymous_read: RateLimitPolicy
    authenticated_read: RateLimitPolicy
    management_read: RateLimitPolicy
    ordinary_write: RateLimitPolicy
    authorization_write: RateLimitPolicy
    super_admin_transfer: RateLimitPolicy
    logout_all: RateLimitPolicy
    login_ip: RateLimitPolicy
    login_pair: RateLimitPolicy
    login_global: RateLimitPolicy
    registration_ip: RateLimitPolicy
    registration_target: RateLimitPolicy
    registration_pair: RateLimitPolicy
    registration_global: RateLimitPolicy
    verification_target_cooldown: RateLimitPolicy
    verification_target_average: RateLimitPolicy
    verification_ip: RateLimitPolicy
    verification_pair: RateLimitPolicy
    verification_global: RateLimitPolicy
    verification_channel: RateLimitPolicy
    verification_submit_ip: RateLimitPolicy
    verification_submit_target: RateLimitPolicy
    verification_submit_pair: RateLimitPolicy
    verification_submit_global: RateLimitPolicy

    @classmethod
    def from_settings(cls, settings: Settings) -> "SecurityPolicies":
        return cls(
            api_global=RateLimitPolicy(
                name="api_global",
                burst_capacity=settings.rate_limit_global_burst,
                refill_tokens=settings.rate_limit_global_per_minute,
                refill_period_seconds=60,
            ),
            api_ip=RateLimitPolicy(
                name="api_ip",
                burst_capacity=settings.rate_limit_api_ip_burst,
                refill_tokens=settings.rate_limit_api_ip_per_minute,
                refill_period_seconds=60,
            ),
            anonymous_read=_token_bucket(
                "anonymous_read",
                settings.rate_limit_anonymous_read_per_minute,
                60,
            ),
            authenticated_read=_token_bucket(
                "authenticated_read",
                settings.rate_limit_authenticated_read_per_minute,
                60,
            ),
            management_read=_token_bucket(
                "management_read",
                settings.rate_limit_management_read_per_minute,
                60,
            ),
            ordinary_write=_token_bucket(
                "ordinary_write",
                settings.rate_limit_ordinary_write_per_minute,
                60,
            ),
            authorization_write=_token_bucket(
                "authorization_write",
                settings.rate_limit_authorization_write_per_minute,
                60,
            ),
            super_admin_transfer=_token_bucket(
                "super_admin_transfer",
                settings.rate_limit_super_admin_transfer_per_hour,
                3600,
            ),
            logout_all=_token_bucket(
                "logout_all",
                settings.rate_limit_logout_all_per_ten_minutes,
                600,
            ),
            login_ip=_token_bucket(
                "login_ip",
                settings.rate_limit_login_ip_per_five_minutes,
                300,
            ),
            login_pair=_token_bucket(
                "login_pair",
                settings.rate_limit_login_pair_per_fifteen_minutes,
                900,
            ),
            login_global=RateLimitPolicy(
                name="login_global",
                burst_capacity=settings.rate_limit_login_global_burst,
                refill_tokens=settings.rate_limit_login_global_per_five_minutes,
                refill_period_seconds=300,
            ),
            registration_ip=_token_bucket(
                "registration_ip",
                settings.rate_limit_registration_ip_per_hour,
                3600,
            ),
            registration_target=_token_bucket(
                "registration_target",
                settings.rate_limit_registration_target_per_hour,
                3600,
            ),
            registration_pair=_token_bucket(
                "registration_pair",
                settings.rate_limit_registration_pair_per_hour,
                3600,
            ),
            registration_global=RateLimitPolicy(
                name="registration_global",
                burst_capacity=settings.rate_limit_registration_global_burst,
                refill_tokens=settings.rate_limit_registration_global_per_hour,
                refill_period_seconds=3600,
            ),
            verification_target_cooldown=_token_bucket(
                "verification_target_cooldown",
                1,
                settings.verification_send_cooldown_seconds,
            ),
            verification_target_average=_token_bucket(
                "verification_target_average",
                settings.rate_limit_verification_target_average_per_day,
                86400,
            ),
            verification_ip=_token_bucket(
                "verification_ip",
                settings.rate_limit_verification_ip_per_hour,
                3600,
            ),
            verification_pair=_token_bucket(
                "verification_pair",
                settings.rate_limit_verification_pair_per_hour,
                3600,
            ),
            verification_global=RateLimitPolicy(
                name="verification_global",
                burst_capacity=settings.rate_limit_verification_global_burst,
                refill_tokens=settings.rate_limit_verification_global_per_minute,
                refill_period_seconds=60,
            ),
            verification_channel=RateLimitPolicy(
                name="verification_channel",
                burst_capacity=settings.rate_limit_verification_channel_burst,
                refill_tokens=settings.rate_limit_verification_channel_per_minute,
                refill_period_seconds=60,
            ),
            verification_submit_ip=_token_bucket(
                "verification_submit_ip",
                settings.rate_limit_verification_submit_ip_per_hour,
                3600,
            ),
            verification_submit_target=_token_bucket(
                "verification_submit_target",
                settings.rate_limit_verification_submit_target_per_hour,
                3600,
            ),
            verification_submit_pair=_token_bucket(
                "verification_submit_pair",
                settings.rate_limit_verification_submit_pair_per_hour,
                3600,
            ),
            verification_submit_global=RateLimitPolicy(
                name="verification_submit_global",
                burst_capacity=settings.rate_limit_verification_submit_global_burst,
                refill_tokens=(
                    settings.rate_limit_verification_submit_global_per_minute
                ),
                refill_period_seconds=60,
            ),
        )
