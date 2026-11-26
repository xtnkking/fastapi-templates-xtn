#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    按请求数或时长发送有上限的 GET 探测，汇总状态码、错误和耗时，不发送写入类 HTTP 方法。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/13    XTN       V1.000        完善负载探测函数的通俗说明与步骤注释
# --------------------------------------------------------------------------------------------------

"""Bounded GET-only load probe; install the asset's test extra for httpx."""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import random
import time
from collections import Counter
from collections.abc import Sequence
from itertools import count
from urllib.parse import urlsplit

import httpx

# 单次响应最多读取 2 MiB；耗时最多保留一万份样本，持续模式最长运行一小时。
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_LATENCY_SAMPLES = 10_000
MAX_DURATION_SECONDS = 3_600


def validate_url(value: str) -> str:
    """
        检查探测地址是否为不带凭据、查询参数或片段的 HTTP(S) 地址。
        这里只解析地址，不向目标发送请求。

    :param value: 命令行或调用方提供的完整探测地址。
    :return: 校验通过后的原始地址，不重新拼接或改写。
    :raises argparse.ArgumentTypeError: 地址无法解析或包含不允许的组成部分。
    """
    # 先解析地址及端口，再检查协议和敏感组成部分，拒绝结果统一使用固定提示。
    message = "Use an HTTP(S) endpoint without credentials, query, or fragment"
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise argparse.ArgumentTypeError(message) from None
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.query
        or port == 0
    ):
        raise argparse.ArgumentTypeError(message)
    return value


async def run_load(*, urls: Sequence[str], requests: int | None = None, duration_seconds: float | None = None,
                   concurrency: int, timeout_seconds: float, token: str | None = None,
                   transport: httpx.AsyncBaseTransport | None = None) -> dict[str, object]:
    """
        用限定并发发送 GET 请求，并统计成功数量、错误类别和毫秒耗时。
        请求数和运行时长只能选一种；到时不再接纳新请求，已发出的请求按各自超时收尾。
        不跟随重定向、不读取环境代理，报告不包含 Token 或目标地址。

    :param urls: 轮流访问的完整 HTTP(S) 地址列表，至少提供一个。
    :param requests: 请求总数，范围 1 到 100000；None 表示使用持续时长模式。
    :param duration_seconds: 接纳新请求的秒数，范围大于 0 且不超过 3600；None 表示按请求数运行。
    :param concurrency: 同时工作的协程数，范围 1 到 200；请求总数更少时相应减少。
    :param timeout_seconds: 单次完整请求的超时秒数，范围大于 0 且不超过 300。
    :param token: 可选 Bearer Token；None 不发送认证头，非空值不能含空白字符。
    :param transport: 可选 HTTPX 请求传输实现；None 使用正常网络传输。
    :return: 请求模式、数量、状态码、错误计数、吞吐量和耗时百分位的汇总字典。
    :raises ValueError: 数量、时长、并发、超时或 Token 不符合探测边界。
    :raises argparse.ArgumentTypeError: 某个目标地址不符合允许的格式。
    """
    # 发请求前检查全部边界，避免无上限探测或带着错误参数进入网络阶段。
    if not urls or type(concurrency) is not int or not 1 <= concurrency <= 200:
        raise ValueError("Require endpoints and 1..200 workers")
    if (requests is None) == (duration_seconds is None):
        raise ValueError("Choose exactly one request count or duration")
    if requests is not None and (
        type(requests) is not int or not 1 <= requests <= 100_000
    ):
        raise ValueError("Request count must be an integer within 1..100000")
    if duration_seconds is not None and (
        isinstance(duration_seconds, bool)
        or not math.isfinite(duration_seconds)
        or not 0 < duration_seconds <= MAX_DURATION_SECONDS
    ):
        raise ValueError("Duration must be finite and within (0, 3600] seconds")
    if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 300:
        raise ValueError("Timeout must be finite and within (0, 300] seconds")
    for url in urls:
        validate_url(url)
    if token is not None and (not token or any(c.isspace() for c in token)):
        raise ValueError("The bearer token must be nonempty without whitespace")

    # 所有 worker 共用计数器和递增请求编号；只保留有上限的耗时样本。
    statuses: Counter[str] = Counter()
    errors: Counter[str] = Counter()
    latencies: list[float] = []
    completed = 0
    sampler = random.Random()
    next_request = count()
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    # 复用一个受并发连接数限制的客户端，退出上下文后自动关闭网络资源。
    async with httpx.AsyncClient(
        headers=headers,
        timeout=timeout_seconds,
        limits=httpx.Limits(max_connections=concurrency),
        follow_redirects=False,
        trust_env=False,
        transport=transport,
    ) as client:
        started = time.perf_counter()
        deadline = started + duration_seconds if duration_seconds is not None else None

        async def worker() -> None:
            """
                从共享编号领取请求，逐个发送 GET 并将状态和耗时记入外层统计。
                只有下方 gather 调用后才开始请求；单次超时和传输错误只计数，不中止其他 worker。

            :return: 无返回值；达到请求数或截止时间后结束，已经领取的请求已计入统计。
            """
            nonlocal completed
            while True:
                # 到截止时间或达到总数后停止领取；已发出的请求仍受单次超时限制。
                if deadline is not None and time.perf_counter() >= deadline:
                    return
                index = next(next_request)
                if requests is not None and index >= requests:
                    return
                request_started = time.perf_counter()
                try:
                    # HTTPX 自带超时分别约束读写阶段，外层再限制整次请求的总时间。
                    async with asyncio.timeout(timeout_seconds):
                        async with client.stream(
                            "GET", urls[index % len(urls)]
                        ) as resp:
                            # 分块读取并限制累计字节；超大响应计为错误，不再统计它的状态码。
                            received = 0
                            async for chunk in resp.aiter_bytes():
                                received += len(chunk)
                                if received > MAX_RESPONSE_BYTES:
                                    errors["response_too_large"] += 1
                                    break
                            else:
                                statuses[str(resp.status_code)] += 1
                except (TimeoutError, httpx.TimeoutException):
                    errors["timeout"] += 1
                except httpx.HTTPError:
                    errors["transport_error"] += 1
                finally:
                    # 无论成功还是错误都计为已完成，并把整次请求耗时换算成毫秒。
                    latency = (time.perf_counter() - request_started) * 1000
                    completed += 1
                    if len(latencies) < MAX_LATENCY_SAMPLES:
                        latencies.append(latency)
                    else:
                        # 样本已满时随机替换，让每次完成的请求都有相同保留机会，内存不随总数增长。
                        replacement = sampler.randrange(completed)
                        if replacement < MAX_LATENCY_SAMPLES:
                            latencies[replacement] = latency

        # 此处真正启动 worker 并等待全部结束，再统一计算耗时和吞吐量。
        worker_count = (
            min(concurrency, requests) if requests is not None else concurrency
        )
        await asyncio.gather(*(worker() for _ in range(worker_count)))
    # 对保留的毫秒样本排序得到百分位；请求多于样本上限时，百分位只是抽样估计。
    elapsed = time.perf_counter() - started
    latencies.sort()
    successful = sum(n for status, n in statuses.items() if 200 <= int(status) < 300)
    return {
        "mode": "duration" if duration_seconds is not None else "requests",
        "duration_seconds": duration_seconds,
        "requests": completed,
        "concurrency": concurrency,
        "endpoint_count": len(urls),
        "elapsed_seconds": round(elapsed, 3),
        "requests_per_second": round(completed / elapsed, 3),
        "successful_requests_per_second": round(successful / elapsed, 3),
        "successful": successful,
        "failed": completed - successful,
        "http_status_counts": dict(sorted(statuses.items())),
        "transport_errors": dict(sorted(errors.items())),
        "latency_samples": len(latencies),
        "latency_sample_limit": MAX_LATENCY_SAMPLES,
        "latency_percentiles_estimated": len(latencies) < completed,
        "latency_ms": {
            f"p{percentile}": (
                round(latencies[math.ceil(len(latencies) * percentile / 100) - 1], 3)
                if latencies
                else None
            )
            for percentile in (50, 95, 99)
        },
    }


def main() -> int:
    """
        读取命令行探测配置和环境变量里的 Token，运行探测并打印 JSON 汇总。

    :return: 没有失败且至少完成一次请求时返回 0，否则返回 1；手动中断返回 130。
    :raises SystemExit: 命令行格式错误或探测参数无效时以状态码 2 退出。
    """
    # 命令帮助继续使用模块说明；请求数和持续时长互斥，未指定时默认探测 100 次。
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", action="append", required=True, type=validate_url)
    workload = parser.add_mutually_exclusive_group()
    workload.add_argument("--requests", type=int, help="1..100000 calls; default: 100")
    workload.add_argument(
        "--duration",
        type=float,
        help="Send calls for this many seconds (0 < seconds <= 3600), then drain",
    )
    parser.add_argument("--concurrency", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--token-env", default="LOAD_TEST_BEARER_TOKEN")
    args = parser.parse_args()
    # 从指定环境变量读取认证值，避免要求使用者把 Token 直接写进命令行参数。
    try:
        result = asyncio.run(
            run_load(
                urls=args.url,
                requests=(
                    args.requests
                    if args.requests is not None
                    else (100 if args.duration is None else None)
                ),
                duration_seconds=args.duration,
                concurrency=args.concurrency,
                timeout_seconds=args.timeout,
                token=os.environ.get(args.token_env),
            )
        )
    except (ValueError, argparse.ArgumentTypeError):
        parser.exit(2, "Invalid probe parameters; no secrets or endpoints are shown.\n")
    except KeyboardInterrupt:
        return 130
    # 输出不含地址或认证值的统计结果，再用退出码表达整次探测是否全部成功。
    print(json.dumps(result, indent=2))
    return 0 if result["failed"] == 0 and result["requests"] != 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
