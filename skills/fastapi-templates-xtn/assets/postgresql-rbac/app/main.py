from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.database import engine
from app.rbac.api import router as access_router
from app.rbac.errors import RbacError


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    yield
    await engine.dispose()


app = FastAPI(title="PostgreSQL Access Control Example", lifespan=lifespan)
app.include_router(access_router)


@app.exception_handler(RequestValidationError)
async def handle_request_validation_error(
    request: Request,
    exc: RequestValidationError,
) -> Response:
    missing_if_match = any(
        error.get("type") == "missing"
        and len(location := error.get("loc", ())) >= 2
        and location[0] == "header"
        and str(location[-1]).casefold() == "if-match"
        for error in exc.errors()
    )
    if missing_if_match:
        return JSONResponse(
            status_code=428,
            content={"detail": {"code": "precondition_required"}},
        )
    return await request_validation_exception_handler(request, exc)


@app.exception_handler(RbacError)
async def handle_access_error(_request: Request, exc: RbacError) -> JSONResponse:
    headers = {"WWW-Authenticate": "Bearer"} if exc.status_code == 401 else None
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": {"code": exc.public_code}},
        headers=headers,
    )


@app.get("/health/live", include_in_schema=False)
async def liveness() -> dict[str, str]:
    return {"status": "ok"}
