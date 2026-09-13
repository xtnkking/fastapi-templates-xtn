import asyncio
import unicodedata
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Final, TypeVar

from argon2 import PasswordHasher, extract_parameters
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from argon2.low_level import Type

ARGON2_MEMORY_COST_KIB: Final = 65_536
ARGON2_TIME_COST: Final = 3
ARGON2_PARALLELISM: Final = 4
ARGON2_HASH_LENGTH: Final = 32
ARGON2_SALT_LENGTH: Final = 16
MIN_PASSWORD_CHARACTERS: Final = 15
MAX_PASSWORD_CHARACTERS: Final = 128
MAX_PASSWORD_UTF8_BYTES: Final = 1_024
DEFAULT_MAX_CONCURRENT_OPERATIONS: Final = 2
LOCAL_PASSWORD_DENYLIST_VERSION: Final = "xtn-minimal-v1"

# This is a real Argon2id hash with the production parameters. Unknown accounts use
# it so a login attempt still performs password verification work. The plaintext is
# deliberately not retained because no request should ever authenticate against it.
DUMMY_PASSWORD_HASH: Final = (
    "$argon2id$v=19$m=65536,t=3,p=4$LXt4vIgFZ6WkGw0A38ssxg$"
    "FHhivkBqhiWg1sDCem36CG0Ob137XKSwAlPuAVbeAp8"
)

# This intentionally small, versioned set is a runnable fallback, not a complete
# compromised-password corpus. Replace it with a maintained offline dataset for
# the target product and update LOCAL_PASSWORD_DENYLIST_VERSION with the data.
_LOCAL_PASSWORD_DENYLIST: Final = frozenset(
    {
        "123456789012345",
        "adminadminadmin",
        "changemechangeme",
        "iloveyouiloveyou",
        "letmeinletmeinletmein",
        "password123456789",
        "passwordpassword",
        "qwertyuiopasdfgh",
        "welcome123456789",
    }
)

_T = TypeVar("_T")


class PasswordPolicyError(ValueError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class PasswordHashError(RuntimeError):
    """Raised when a stored credential is not a usable Argon2 hash."""


@dataclass(frozen=True, slots=True)
class PasswordVerification:
    verified: bool
    needs_rehash: bool
    used_dummy: bool


def _encoded_length(value: str) -> int:
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError:
        raise PasswordPolicyError("password_invalid_unicode") from None


def _has_control_character(value: str) -> bool:
    return any(unicodedata.category(character) == "Cc" for character in value)


def _comparison_form(value: str) -> str:
    return unicodedata.normalize("NFKC", value).casefold()


def validate_login_password_input(password: str) -> str:
    """Apply only transport bounds so older valid passwords remain usable."""

    if not isinstance(password, str):
        raise PasswordPolicyError("password_invalid_type")
    if not password:
        raise PasswordPolicyError("password_empty")
    if len(password) > MAX_PASSWORD_CHARACTERS:
        raise PasswordPolicyError("password_too_long")
    if _encoded_length(password) > MAX_PASSWORD_UTF8_BYTES:
        raise PasswordPolicyError("password_too_large")
    return password


def _identity_fragments(identity_values: Iterable[str]) -> frozenset[str]:
    fragments: set[str] = set()
    for value in identity_values:
        if not isinstance(value, str):
            raise TypeError("identity values must be strings")
        folded = _comparison_form(value)
        if len(folded) >= 3:
            fragments.add(folded)
        local_part, separator, _domain = folded.partition("@")
        if separator and len(local_part) >= 3:
            fragments.add(local_part)
    return frozenset(fragments)


def validate_new_password(
    password: str,
    *,
    identity_values: Iterable[str] = (),
) -> str:
    """Validate without trimming or normalizing the value that will be hashed."""

    validate_login_password_input(password)
    if len(password) < MIN_PASSWORD_CHARACTERS:
        raise PasswordPolicyError("password_too_short")
    if _has_control_character(password):
        raise PasswordPolicyError("password_contains_control_character")

    folded = _comparison_form(password)
    if folded in _LOCAL_PASSWORD_DENYLIST or len(set(folded)) == 1:
        raise PasswordPolicyError("password_common_or_weak")
    if any(fragment in folded for fragment in _identity_fragments(identity_values)):
        raise PasswordPolicyError("password_contains_identity")
    return password


class PasswordManager:
    def __init__(
        self,
        *,
        max_concurrent_operations: int = DEFAULT_MAX_CONCURRENT_OPERATIONS,
    ) -> None:
        if (
            isinstance(max_concurrent_operations, bool)
            or not isinstance(max_concurrent_operations, int)
            or not 1 <= max_concurrent_operations <= 32
        ):
            raise ValueError("max_concurrent_operations must be between 1 and 32")
        self._hasher = PasswordHasher(
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST_KIB,
            parallelism=ARGON2_PARALLELISM,
            hash_len=ARGON2_HASH_LENGTH,
            salt_len=ARGON2_SALT_LENGTH,
            type=Type.ID,
        )
        self._semaphore = asyncio.Semaphore(max_concurrent_operations)

    async def _run_bounded(self, operation: Callable[[], _T]) -> _T:
        async with self._semaphore:
            worker = asyncio.create_task(asyncio.to_thread(operation))
            try:
                return await asyncio.shield(worker)
            except asyncio.CancelledError:
                # Keep the slot until the native worker really stops; releasing it
                # early could exceed the configured memory/CPU concurrency bound.
                try:
                    await worker
                except Exception:
                    pass
                raise

    async def hash_new_password(
        self,
        password: str,
        *,
        identity_values: Iterable[str] = (),
    ) -> str:
        validated = validate_new_password(
            password,
            identity_values=identity_values,
        )
        return await self._run_bounded(lambda: self._hasher.hash(validated))

    async def hash_verified_password(self, password: str) -> str:
        """Rehash a verified legacy password without applying today's new policy."""

        validated = validate_login_password_input(password)
        return await self._run_bounded(lambda: self._hasher.hash(validated))

    async def verify_or_dummy(
        self,
        password: str,
        password_hash: str | None,
    ) -> PasswordVerification:
        validated = validate_login_password_input(password)
        used_dummy = password_hash is None
        encoded_hash = DUMMY_PASSWORD_HASH if password_hash is None else password_hash

        try:
            parameters = extract_parameters(encoded_hash)
        except InvalidHashError as exc:
            raise PasswordHashError("stored password hash is invalid") from exc
        if (
            parameters.type is not Type.ID
            or parameters.version != 19
            or parameters.memory_cost > ARGON2_MEMORY_COST_KIB
            or parameters.time_cost > ARGON2_TIME_COST
            or parameters.parallelism > ARGON2_PARALLELISM
            or parameters.salt_len > 64
            or parameters.hash_len > 64
        ):
            raise PasswordHashError("stored password hash parameters are unsafe")

        def verify() -> tuple[bool, bool]:
            try:
                verified = self._hasher.verify(encoded_hash, validated)
            except VerifyMismatchError:
                return False, False
            except (InvalidHashError, VerificationError) as exc:
                raise PasswordHashError("stored password hash is invalid") from exc
            return bool(verified), self._hasher.check_needs_rehash(encoded_hash)

        verified, needs_rehash = await self._run_bounded(verify)
        return PasswordVerification(
            verified=verified and not used_dummy,
            needs_rehash=needs_rehash and not used_dummy,
            used_dummy=used_dummy,
        )


password_manager = PasswordManager()
