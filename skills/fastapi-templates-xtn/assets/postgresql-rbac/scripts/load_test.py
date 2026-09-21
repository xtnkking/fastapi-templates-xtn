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

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_LATENCY_SAMPLES = 10_000
MAX_DURATION_SECONDS = 3_600


def validate_url(value: str) -> str:
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


async def run_load(
    *,
    urls: Sequence[str],
    requests: int | None = None,
    duration_seconds: float | None = None,
    concurrency: int,
    timeout_seconds: float,
    token: str | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, object]:
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

    statuses: Counter[str] = Counter()
    errors: Counter[str] = Counter()
    latencies: list[float] = []
    completed = 0
    sampler = random.Random()
    next_request = count()
    headers = {"Authorization": f"Bearer {token}"} if token else {}
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
            nonlocal completed
            while True:
                # Stop admitting work at the deadline, then let in-flight calls
                # finish within their existing per-request timeout.
                if deadline is not None and time.perf_counter() >= deadline:
                    return
                index = next(next_request)
                if requests is not None and index >= requests:
                    return
                request_started = time.perf_counter()
                try:
                    # HTTPX timeouts apply per I/O phase; this bounds the whole call.
                    async with asyncio.timeout(timeout_seconds):
                        async with client.stream(
                            "GET", urls[index % len(urls)]
                        ) as resp:
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
                    latency = (time.perf_counter() - request_started) * 1000
                    completed += 1
                    if len(latencies) < MAX_LATENCY_SAMPLES:
                        latencies.append(latency)
                    else:
                        # Algorithm R: each completed call has equal probability
                        # of being retained; memory stays bounded during long runs.
                        replacement = sampler.randrange(completed)
                        if replacement < MAX_LATENCY_SAMPLES:
                            latencies[replacement] = latency

        worker_count = (
            min(concurrency, requests) if requests is not None else concurrency
        )
        await asyncio.gather(*(worker() for _ in range(worker_count)))
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
    print(json.dumps(result, indent=2))
    return 0 if result["failed"] == 0 and result["requests"] != 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
