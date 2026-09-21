"""Two real application processes sharing the guarded PostgreSQL/Redis targets."""

import asyncio
import os
import socket
import subprocess
import sys
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest

from scripts.load_test import run_load

pytestmark = pytest.mark.postgresql
ASSET_ROOT = Path(__file__).resolve().parents[2]
PASSWORD = "isolated river lantern password 72"


@asynccontextmanager
async def instance(
    environment: dict[str, str],
) -> AsyncIterator[tuple[httpx.AsyncClient, subprocess.Popen[str]]]:
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    process = await asyncio.to_thread(
        subprocess.Popen,
        [sys.executable, "-B", "-m", "tests.integration.instance_server", str(port)],
        cwd=ASSET_ROOT,
        env=environment,
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        creationflags=creationflags,
    )
    try:
        async with httpx.AsyncClient(
            base_url=f"http://127.0.0.1:{port}", timeout=10, trust_env=False
        ) as client:
            deadline = time.monotonic() + 15
            while True:
                assert process.poll() is None, "isolated application exited at startup"
                try:
                    response = await client.get("/health/ready", timeout=1)
                    if response.status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                if time.monotonic() >= deadline:
                    pytest.fail("isolated application readiness deadline exceeded")
                await asyncio.sleep(0.05)
            yield client, process
    finally:
        if process.poll() is None:
            assert process.stdin is not None
            try:
                process.stdin.write("stop\n")
                process.stdin.flush()
                await asyncio.to_thread(process.wait, 10)
            except (OSError, subprocess.TimeoutExpired):
                process.kill()
                await asyncio.to_thread(process.wait, 5)
        if process.stdin is not None:
            process.stdin.close()


def instance_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        PYTHONDONTWRITEBYTECODE="1",
        APP_ENVIRONMENT="test",
        SERVICE_NAME=f"multi-instance-{uuid.uuid4().hex}",
        RATE_LIMIT_NAMESPACE=f"multi_instance_{uuid.uuid4().hex}",
        RATE_LIMIT_ENABLED="true",
        MAX_ACTIVE_SESSIONS_PER_USER="2",
        DATABASE_POOL_SIZE="1",
        DATABASE_MAX_OVERFLOW="0",
        RATE_LIMIT_AUTHENTICATED_READ_PER_MINUTE="3",
    )
    return environment


async def challenge(client: httpx.AsyncClient, scene: str) -> dict[str, str]:
    response = await client.post("/api/v1/auth/captcha", json={"scene": scene})
    assert response.status_code == 200
    return {
        "captcha_id": response.json()["data"]["captcha_id"],
        "captcha_answer": "AAAAA",
    }


async def login(
    issuer: httpx.AsyncClient, verifier: httpx.AsyncClient, username: str
) -> str:
    response = await verifier.post(
        "/api/v1/auth/login",
        json={
            "user_name": username,
            "password": PASSWORD,
            **await challenge(issuer, "login"),
        },
    )
    assert response.status_code == 200
    return str(response.json()["data"]["access_token"])


async def test_shared_captcha_login_sessions_logout_and_quotas() -> None:
    environment = instance_environment()
    async with instance(environment) as (first, first_process):
        async with instance(environment) as (second, second_process):
            assert first_process.pid != second_process.pid
            username = "member_" + uuid.uuid4().hex[:12]
            registration = await second.post(
                "/api/v1/auth/register",
                json={
                    "user_name": username,
                    "password": PASSWORD,
                    **await challenge(first, "register"),
                },
            )
            assert registration.status_code == 201

            # The same challenge may be consumed by only one of two processes.
            captcha = await challenge(first, "login")
            body = {"user_name": username, "password": PASSWORD, **captcha}
            results = await asyncio.gather(
                first.post("/api/v1/auth/login", json=body),
                second.post("/api/v1/auth/login", json=body),
            )
            assert sorted(response.status_code for response in results) == [200, 400]
            first_token = next(
                response.json()["data"]["access_token"]
                for response in results
                if response.status_code == 200
            )
            second_token = await login(first, second, username)
            third_token = await login(second, first, username)
            oldest = await second.get(
                "/api/v1/me/access", headers={"Authorization": f"Bearer {first_token}"}
            )
            assert oldest.status_code == 401

            # Both instances spend the same per-business, per-user window.
            responses = await asyncio.gather(
                *(
                    client.get(
                        "/api/v1/me/access",
                        headers={"Authorization": f"Bearer {third_token}"},
                    )
                    for client in (first, second, first, second)
                )
            )
            assert sorted(response.status_code for response in responses) == [
                200,
                200,
                200,
                429,
            ]
            logout = await first.post(
                "/api/v1/auth/logout",
                headers={"Authorization": f"Bearer {third_token}"},
            )
            assert logout.status_code == 200
            rejected = await second.get(
                "/api/v1/me/access", headers={"Authorization": f"Bearer {third_token}"}
            )
            assert rejected.status_code == 401
            # Logout of one token leaves the other active session intact.
            remaining = await second.post(
                "/api/v1/auth/logout",
                headers={"Authorization": f"Bearer {second_token}"},
            )
            assert remaining.status_code == 200


async def test_real_server_drains_inflight_request_before_lifespan_shutdown() -> None:
    async with instance(instance_environment()) as (client, process):
        request = asyncio.create_task(client.get("/__test__/drain"))
        assert process.stdin is not None
        process.stdin.write("drain\n")
        process.stdin.flush()
        response = await asyncio.wait_for(request, timeout=5)
        assert response.status_code == 200
        assert response.json() == {"completed": True}
        assert await asyncio.to_thread(process.wait, 10) == 0


@pytest.mark.parametrize("duration_seconds", [None, 2.0])
async def test_authenticated_read_load_across_two_small_pool_instances(
    duration_seconds: float | None,
) -> None:
    environment = instance_environment()
    # Test-only quota: measure the protected read path rather than repeated 429s.
    environment["RATE_LIMIT_AUTHENTICATED_READ_PER_MINUTE"] = "10000"
    async with instance(environment) as (first, _first_process):
        async with instance(environment) as (second, _second_process):
            username = "probe_" + uuid.uuid4().hex[:12]
            registered = await first.post(
                "/api/v1/auth/register",
                json={
                    "user_name": username,
                    "password": PASSWORD,
                    **await challenge(second, "register"),
                },
            )
            assert registered.status_code == 201
            token = await login(first, second, username)
            report = await run_load(
                urls=[
                    str(first.base_url.join("/api/v1/me/access")),
                    str(second.base_url.join("/api/v1/me/access")),
                ],
                requests=100 if duration_seconds is None else None,
                duration_seconds=duration_seconds,
                concurrency=10,
                timeout_seconds=10,
                token=token,
            )
            assert report["successful"] == report["requests"]
            if duration_seconds is None:
                assert report["requests"] == 100
            else:
                assert report["mode"] == "duration"
                assert report["successful"] != 0
            assert report["failed"] == 0
            # Visible with pytest -s; the report contains no URL, token or body.
            print(report)
