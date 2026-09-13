from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.settings import get_settings

settings = get_settings()
engine = create_async_engine(
    settings.database_url,
    echo=settings.sql_echo,
    hide_parameters=True,
    pool_pre_ping=True,
    isolation_level="READ COMMITTED",
)
SessionFactory = async_sessionmaker(engine, expire_on_commit=False)


async def get_session() -> AsyncIterator[AsyncSession]:
    async with SessionFactory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
