"""Loopback-only subprocess harness for disposable multi-instance tests.

Never use this launcher for deployment: CAPTCHA answers are deterministic and
the additional drain route exists only to exercise real Uvicorn shutdown.
"""

import asyncio
import os
import sys
from unittest.mock import patch

import uvicorn
from sqlalchemy import text

from tests.integration.safety import confirmed_database_name, confirmed_redis_targets


async def serve(port: int) -> None:
    confirmed_database_name()
    redis_targets = confirmed_redis_targets()
    if (
        os.environ.get("APP_ENVIRONMENT") != "test"
        or os.environ.get("DATABASE_URL") != os.environ.get("TEST_DATABASE_URL")
        or (
            os.environ.get("REDIS_URL"),
            os.environ.get("RATE_LIMIT_REDIS_URL"),
        )
        != redis_targets
    ):
        raise RuntimeError("This server requires the guarded disposable test profile")

    from app.db.postgres import SessionFactory
    from app.main import app

    entered = asyncio.Event()

    @app.get("/__test__/drain", include_in_schema=False)
    async def drain_probe() -> dict[str, bool]:
        entered.set()
        async with SessionFactory() as session:
            await session.execute(text("SELECT pg_sleep(0.2)"))
        return {"completed": True}

    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            access_log=False,
            log_config=None,
            timeout_graceful_shutdown=5,
        )
    )

    async def control() -> None:
        command = await asyncio.to_thread(sys.stdin.readline)
        if command.strip() == "drain":
            await asyncio.wait_for(entered.wait(), timeout=5)
        server.should_exit = True

    controller = asyncio.create_task(control())
    try:
        with patch("app.core.security.captcha.secrets.choice", return_value="A"):
            await server.serve()
    finally:
        controller.cancel()
        await asyncio.gather(controller, return_exceptions=True)


if __name__ == "__main__":
    asyncio.run(serve(int(sys.argv[1])))
