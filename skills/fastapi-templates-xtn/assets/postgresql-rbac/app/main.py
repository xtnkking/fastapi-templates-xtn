from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.database import engine
from app.rbac.api import router as rbac_router
from app.rbac.errors import RbacError


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    yield
    await engine.dispose()


app = FastAPI(title="PostgreSQL RBAC Example", lifespan=lifespan)
app.include_router(rbac_router)


@app.exception_handler(RbacError)
async def handle_rbac_error(_request: Request, exc: RbacError) -> JSONResponse:
    headers = {"WWW-Authenticate": "Bearer"} if exc.status_code == 401 else None
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": {"code": exc.public_code}},
        headers=headers,
    )


@app.get("/health/live", include_in_schema=False)
async def liveness() -> dict[str, str]:
    return {"status": "ok"}
