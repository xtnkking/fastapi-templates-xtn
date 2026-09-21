import argparse
import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

import scripts.load_test as load_module
from scripts.load_test import (
    MAX_DURATION_SECONDS,
    MAX_RESPONSE_BYTES,
    run_load,
    validate_url,
)


async def test_probe_bounds_concurrency_rotates_endpoints_and_keeps_errors() -> None:
    active = peak = calls = 0
    reached_capacity = asyncio.Event()
    hosts: list[str] = []

    async def respond(request: httpx.Request) -> httpx.Response:
        nonlocal active, peak, calls
        active += 1
        peak = max(peak, active)
        calls += 1
        ordinal = calls
        hosts.append(request.url.host)
        assert request.method == "GET"
        assert request.headers["Authorization"] == "Bearer private-test-token"
        if active == 3:
            reached_capacity.set()
        await asyncio.wait_for(reached_capacity.wait(), timeout=2)
        await asyncio.sleep(0)
        active -= 1
        if ordinal == 1:
            raise httpx.ConnectError("secret-error-detail")
        return httpx.Response(429 if ordinal == 2 else 200, text="secret-body")

    result = await run_load(
        urls=["http://instance-a/me", "http://instance-b/me"],
        requests=12,
        concurrency=3,
        timeout_seconds=2,
        token="private-test-token",
        transport=httpx.MockTransport(respond),
    )
    assert calls == 12 and peak == 3
    assert hosts.count("instance-a") == hosts.count("instance-b") == 6
    assert result["successful"] == 10
    assert result["failed"] == 2
    assert result["http_status_counts"] == {"200": 10, "429": 1}
    assert result["mode"] == "requests"
    assert result["requests"] == result["latency_samples"] == 12
    assert result["latency_percentiles_estimated"] is False
    assert float(str(result["successful_requests_per_second"])) < float(
        str(result["requests_per_second"])
    )
    rendered = json.dumps(result)
    assert not any(secret in rendered for secret in ("secret", "instance", "private"))


async def test_probe_bounds_whole_call_and_does_not_retry() -> None:
    async def slow(_request: httpx.Request) -> httpx.Response:
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    result = await run_load(
        urls=["http://example.test/me"],
        requests=2,
        concurrency=1,
        timeout_seconds=0.01,
        transport=httpx.MockTransport(slow),
    )
    assert result["failed"] == 2
    assert result["transport_errors"] == {"timeout": 2}


async def test_probe_rejects_oversized_responses_and_does_not_follow_redirects() -> (
    None
):
    async def respond(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/large":
            return httpx.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1))
        return httpx.Response(302, headers={"Location": "https://elsewhere.test/"})

    result = await run_load(
        urls=["http://example.test/large", "http://example.test/redirect"],
        requests=2,
        concurrency=1,
        timeout_seconds=1,
        transport=httpx.MockTransport(respond),
    )
    assert result["failed"] == 2
    assert result["transport_errors"] == {"response_too_large": 1}
    assert result["http_status_counts"] == {"302": 1}


@pytest.mark.parametrize("seconds", [0, -1, float("nan"), float("inf")])
async def test_probe_rejects_invalid_timeout(seconds: float) -> None:
    with pytest.raises(ValueError):
        await run_load(
            urls=["http://example.test/me"],
            requests=1,
            concurrency=1,
            timeout_seconds=seconds,
        )


@pytest.mark.parametrize(
    "url",
    [
        "https://person:marker@example.test/me",
        "https://example.test/me?token=marker",
        "https://example.test/me#marker",
        "https://[marker",
        "https://example.test:marker/me",
        "https://example.test:0/me",
    ],
)
def test_invalid_endpoint_does_not_echo_secrets(url: str) -> None:
    with pytest.raises(argparse.ArgumentTypeError) as error:
        validate_url(url)
    assert "marker" not in str(error.value)


async def test_duration_stops_new_calls_and_drains_bounded_workers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = 0.0
    active = peak = calls = 0
    admitted_at: list[float] = []
    reached_capacity = asyncio.Event()
    monkeypatch.setattr(
        load_module, "time", SimpleNamespace(perf_counter=lambda: clock)
    )

    async def respond(_request: httpx.Request) -> httpx.Response:
        nonlocal clock, active, peak, calls
        admitted_at.append(clock)
        calls += 1
        ordinal = calls
        active += 1
        peak = max(peak, active)
        if active == 3:
            reached_capacity.set()
        await asyncio.wait_for(reached_capacity.wait(), timeout=2)
        await asyncio.sleep(0)
        clock += 0.1
        active -= 1
        return httpx.Response(503 if ordinal == 1 else 200)

    result = await run_load(
        urls=["http://example.test/me"],
        duration_seconds=0.25,
        concurrency=3,
        timeout_seconds=2,
        transport=httpx.MockTransport(respond),
    )

    assert result["mode"] == "duration"
    assert result["duration_seconds"] == 0.25
    assert all(start < 0.25 for start in admitted_at)
    assert peak == 3 and active == 0
    assert calls >= 3
    assert result["requests"] == calls
    assert result["successful"] == calls - 1
    assert result["failed"] == 1
    assert result["elapsed_seconds"] == round(clock, 3)
    assert result["requests_per_second"] == round(calls / clock, 3)
    assert result["successful_requests_per_second"] == round((calls - 1) / clock, 3)


async def test_latency_reservoir_is_bounded_and_can_include_later_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = 0.0
    calls = 0
    observed_counts: list[int] = []
    monkeypatch.setattr(load_module, "MAX_LATENCY_SAMPLES", 3)
    monkeypatch.setattr(
        load_module, "time", SimpleNamespace(perf_counter=lambda: clock)
    )

    def choose_slot(completed: int) -> int:
        observed_counts.append(completed)
        return 0

    monkeypatch.setattr(
        load_module,
        "random",
        SimpleNamespace(Random=lambda: SimpleNamespace(randrange=choose_slot)),
    )

    async def respond(_request: httpx.Request) -> httpx.Response:
        nonlocal calls, clock
        calls += 1
        clock += calls / 1000
        return httpx.Response(200)

    result = await run_load(
        urls=["http://example.test/me"],
        requests=30,
        concurrency=1,
        timeout_seconds=1,
        transport=httpx.MockTransport(respond),
    )

    assert result["requests"] == 30
    assert result["latency_samples"] == result["latency_sample_limit"] == 3
    assert result["latency_percentiles_estimated"] is True
    assert observed_counts == list(range(4, 31))
    assert result["latency_ms"] == {"p50": 3.0, "p95": 30.0, "p99": 30.0}


async def test_a_duration_that_expires_before_admission_reports_no_percentiles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ticks = iter([0.0, 1.0, 1.0])
    monkeypatch.setattr(
        load_module, "time", SimpleNamespace(perf_counter=lambda: next(ticks))
    )
    respond = AsyncMock(return_value=httpx.Response(200))

    result = await run_load(
        urls=["http://example.test/me"],
        duration_seconds=0.1,
        concurrency=1,
        timeout_seconds=1,
        transport=httpx.MockTransport(respond),
    )

    respond.assert_not_awaited()
    assert result["requests"] == result["latency_samples"] == 0
    assert result["requests_per_second"] == 0
    assert result["successful_requests_per_second"] == 0
    assert result["latency_ms"] == {"p50": None, "p95": None, "p99": None}


@pytest.mark.parametrize(
    "seconds", [0, -1, float("nan"), float("inf"), MAX_DURATION_SECONDS + 1, True]
)
async def test_probe_rejects_invalid_duration(seconds: float) -> None:
    with pytest.raises(ValueError, match="Duration"):
        await run_load(
            urls=["http://example.test/me"],
            duration_seconds=seconds,
            concurrency=1,
            timeout_seconds=1,
        )


async def test_probe_requires_exactly_one_workload_limit() -> None:
    for requests, duration in ((None, None), (1, 1.0)):
        with pytest.raises(ValueError, match="exactly one"):
            await run_load(
                urls=["http://example.test/me"],
                requests=requests,
                duration_seconds=duration,
                concurrency=1,
                timeout_seconds=1,
            )


@pytest.mark.parametrize(
    ("arguments", "requests", "duration"),
    [
        ([], 100, None),
        (["--requests", "7"], 7, None),
        (["--duration", "1.5"], None, 1.5),
    ],
)
def test_cli_workload_selection_preserves_default_and_uses_token_environment(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    arguments: list[str],
    requests: int | None,
    duration: float | None,
) -> None:
    monkeypatch.setattr(
        "sys.argv", ["load_test.py", "--url", "http://example.test/me", *arguments]
    )
    monkeypatch.setenv("LOAD_TEST_BEARER_TOKEN", "private-test-token")
    run = AsyncMock(return_value={"requests": 7, "failed": 0})
    monkeypatch.setattr(load_module, "run_load", run)

    assert load_module.main() == 0

    assert run.await_args is not None
    assert run.await_args.kwargs["requests"] == requests
    assert run.await_args.kwargs["duration_seconds"] == duration
    assert run.await_args.kwargs["token"] == "private-test-token"
    output = capsys.readouterr().out
    assert "private-test-token" not in output
    assert "example.test" not in output


def test_cli_rejects_combined_count_and_duration_before_starting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "sys.argv",
        [
            "load_test.py",
            "--url",
            "http://example.test/me",
            "--requests",
            "7",
            "--duration",
            "1",
        ],
    )
    run = AsyncMock()
    monkeypatch.setattr(load_module, "run_load", run)

    with pytest.raises(SystemExit) as caught:
        load_module.main()

    assert caught.value.code == 2
    run.assert_not_called()
