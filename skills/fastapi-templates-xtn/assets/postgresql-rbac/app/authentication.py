import logging

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.database import SessionFactory
from app.observability import safe_log
from app.rbac.domain import AuthorizationContext
from app.rbac.errors import unauthenticated
from app.rbac.queries import lock_rbac_state, lock_users

logger = logging.getLogger(__name__)


class AccessTokenRevocationService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def revoke_all_for_current_user(
        self,
        *,
        context: AuthorizationContext,
    ) -> None:
        user_id = context.principal.user_id
        async with self._session_factory() as session:
            async with session.begin():
                await lock_rbac_state(session)
                user = (await lock_users(session, {user_id})).get(user_id)
                if (
                    user is None
                    or not user.is_active
                    or user.token_version != context.principal.token_version
                ):
                    raise unauthenticated("identity_inactive_or_revoked")
                user.token_version += 1

        safe_log(
            logger,
            logging.INFO,
            "authentication.access_tokens.revoked_all",
            extra={"revocation_scope": "account"},
        )


access_token_revocation_service = AccessTokenRevocationService(SessionFactory)


def get_access_token_revocation_service() -> AccessTokenRevocationService:
    return access_token_revocation_service
