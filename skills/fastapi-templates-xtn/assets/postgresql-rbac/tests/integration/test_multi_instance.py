#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    使用明确配置的隔离 PostgreSQL、Redis 目标验证两个应用进程共享业务状态。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/29    XTN       V1.000        用现有账号接口的匿名拒绝响应等待应用启动，不依赖健康入口
# 2026/09/29    XTN       V1.001        多实例注册测试密码改为可见 ASCII 字符
# 2026/10/09    XTN       V1.002        多实例注册响应变量统一使用 register 命名
# 2026/10/13    XTN       V1.003        每轮多实例测试共享随机限流密钥以隔离其他测试计数
# 2026/10/14    XTN       V1.004        多实例共享独立日志密码指纹密钥
# 2026/10/22    XTN       V1.005        测试环境使用简短本人查询限流配置名称
# --------------------------------------------------------------------------------------------------

"""Two real application processes sharing the guarded PostgreSQL/Redis targets."""

import asyncio
import os
import secrets
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
PASSWORD = "isolated-river-lantern-password-72"


@asynccontextmanager
async def instance(environment: dict[str, str]) -> AsyncIterator[tuple[httpx.AsyncClient, subprocess.Popen[str]]]:
    """
        启动隔离应用进程，等待已有账号接口可响应后交给业务测试。
        匿名请求应返回 401，不消耗已登录用户的业务配额；退出时关闭该进程。

    :param environment: 已准备好的隔离测试配置和子进程环境变量。
    :yield: 对应应用的 HTTP 客户端和子进程，由上下文退出时统一关闭。
    """
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    if sys.platform == "win32":
        creationflags = subprocess.CREATE_NO_WINDOW
    else:
        creationflags = 0
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
                    response = await client.get("/api/v1/me/user_info", timeout=1)
                    if response.status_code == 401 and response.json().get("code") == 40110:
                        break
                except httpx.HTTPError:
                    pass
                if time.monotonic() >= deadline:
                    pytest.fail("isolated application startup deadline exceeded")
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
    """
        生成同一轮多实例共享的配置，用独立 HMAC 密钥隔离其他轮次的匿名限流计数。

    :return: 两个应用进程复用的环境变量；同轮仍共享相同业务和主体的限流窗口。
    """
    environment = os.environ.copy()
    # 每轮只生成一次强密钥，两个实例复用该配置，继续验证跨进程共享计数。
    environment.update(
        PYTHONDONTWRITEBYTECODE="1",
        APP_ENVIRONMENT="test",
        SERVICE_NAME=f"multi-instance-{uuid.uuid4().hex}",
        RATE_LIMIT_HMAC_KEY=secrets.token_urlsafe(32),
        LOG_HMAC_KEY=secrets.token_urlsafe(32),
        MAX_ACTIVE_SESSIONS_PER_USER="2",
        DATABASE_POOL_SIZE="1",
        DATABASE_MAX_OVERFLOW="0",
        RATE_LIMIT_USER_READ="3",
    )
    return environment


async def challenge(client: httpx.AsyncClient, scene: str) -> dict[str, str]:
    response = await client.post("/api/v1/auth/captcha", json={"scene": scene})
    assert response.status_code == 200
    return {
        "captcha_id": response.json()["data"]["captcha_id"],
        "captcha_answer": "AAAAA",
    }


async def login(issuer: httpx.AsyncClient, verifier: httpx.AsyncClient, username: str) -> str:
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
            register_response = await second.post(
                "/api/v1/auth/register",
                json={
                    "user_name": username,
                    "password": PASSWORD,
                    **await challenge(first, "register"),
                },
            )
            assert register_response.status_code == 201

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
                "/api/v1/me/user_info", headers={"Authorization": f"Bearer {first_token}"}
            )
            assert oldest.status_code == 401

            # Both instances spend the same per-business, per-user window.
            responses = await asyncio.gather(
                *(
                    client.get(
                        "/api/v1/me/user_info",
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
                "/api/v1/me/user_info", headers={"Authorization": f"Bearer {third_token}"}
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
async def test_authenticated_read_load_across_two_small_pool_instances(duration_seconds: float | None) -> None:
    environment = instance_environment()
    # Test-only quota: measure the protected read path rather than repeated 429s.
    environment["RATE_LIMIT_USER_READ"] = "10000"
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
                    str(first.base_url.join("/api/v1/me/user_info")),
                    str(second.base_url.join("/api/v1/me/user_info")),
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
