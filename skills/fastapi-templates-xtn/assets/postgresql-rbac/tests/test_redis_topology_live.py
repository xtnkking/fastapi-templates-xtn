"""Opt-in real topology tests; only spawn fresh Redis processes on loopback."""

import asyncio
import os
import secrets
import uuid
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from redis.crc import key_slot
from redis.exceptions import RedisError

from app.core.config import Settings, get_settings
from app.core.errors import RbacError
from app.core.security.captcha import CaptchaService
from app.core.security.rate_limit import (
    RATE_LIMIT_KEY_PREFIX,
    RateLimitPolicy,
    build_rate_limit_key,
    check_rate_limit,
)
from app.core.security.tokens import (
    decode_access_token,
    issue_access_token,
    list_active_sessions,
    require_active_jti,
    revoke_active_jti,
)
from app.db.redis import (
    close_redis_client,
    create_rate_limit_redis_client,
    create_redis_client,
)
from app.main import _probe_redis
from tests.redis_topology import RedisTopology, disposable_topology, redis_command


@pytest.fixture(params=["standalone", "sentinel", "cluster"])
async def topology(
    request: pytest.FixtureRequest, tmp_path: Path
) -> AsyncIterator[RedisTopology]:
    executable = os.environ.get("TEST_REDIS_SERVER")
    if not executable:
        pytest.skip(
            "set TEST_REDIS_SERVER to a Redis 7 executable for private topologies"
        )
    async with disposable_topology(
        Path(executable), tmp_path, request.param
    ) as running:
        yield running


def topology_settings(topology: RedisTopology) -> Settings:
    values = get_settings().model_dump()
    values.update(
        redis_url=None,
        redis_connection=topology.endpoint(),
        rate_limit_redis_url=None,
        rate_limit_redis_connection=None,
        service_name=f"topology-{uuid.uuid4().hex}",
        redis_connect_timeout_seconds=0.5,
        redis_socket_timeout_seconds=0.5,
        max_active_sessions_per_user=2,
    )
    return Settings(**values)


async def test_real_topology_preserves_sessions_captcha_and_atomic_quota(
    topology: RedisTopology, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = topology_settings(topology)
    client = create_redis_client(settings)
    peer = create_redis_client(settings)
    limiter = create_rate_limit_redis_client(settings)
    try:
        assert await client.ping() is True
        await _probe_redis(client, key_namespace="active-jti")
        await _probe_redis(limiter, key_namespace="rate-limit")
        # Keys spanning slots must reach every primary using just one seed node.
        keys = [f"routing:{uuid.uuid4().hex}" for _ in range(60)]
        for key in keys:
            assert await client.set(key, "routed", ex=60)
            assert await peer.get(key) == "routed"
        if topology.mode == "cluster":
            for node in topology.data_nodes:
                direct = node.client()
                try:
                    assert await direct.dbsize() > 0
                finally:
                    await direct.aclose()

        user_id = uuid.uuid4()
        claims = []
        for _ in range(3):
            token = await issue_access_token(
                client, user_id=user_id, user_token_version=0, settings=settings
            )
            claims.append(decode_access_token(token, settings))
        with pytest.raises(RbacError) as evicted:
            await require_active_jti(peer, claims=claims[0], settings=settings)
        assert evicted.value.status_code == 401
        assert await require_active_jti(peer, claims=claims[1], settings=settings) == 0
        assert await require_active_jti(peer, claims=claims[2], settings=settings) == 0
        assert (
            len(
                await list_active_sessions(
                    peer, user_id=user_id, token_version=0, settings=settings
                )
            )
            == 2
        )
        await revoke_active_jti(
            peer, claims=claims[1], user_token_version=0, settings=settings
        )
        with pytest.raises(RbacError):
            await require_active_jti(client, claims=claims[1], settings=settings)
        assert (
            len(
                await list_active_sessions(
                    client, user_id=user_id, token_version=0, settings=settings
                )
            )
            == 1
        )

        # Concurrent issuers share one user's bound across independent clients.
        issued = await asyncio.gather(
            *(
                issue_access_token(
                    client if index % 2 else peer,
                    user_id=user_id,
                    user_token_version=1,
                    settings=settings,
                )
                for index in range(8)
            )
        )
        admissions = await asyncio.gather(
            *(
                require_active_jti(
                    peer, claims=decode_access_token(token, settings), settings=settings
                )
                for token in issued
            ),
            return_exceptions=True,
        )
        assert sum(value == 1 for value in admissions) == 2
        assert sum(isinstance(value, RbacError) for value in admissions) == 6
        with pytest.raises(RbacError):
            await issue_access_token(
                client, user_id=user_id, user_token_version=0, settings=settings
            )

        monkeypatch.setattr(secrets, "choice", lambda _alphabet: "A")
        first = CaptchaService(client, settings)
        second = CaptchaService(peer, settings)
        for scene, owner in (("login", None), ("admin_reset", user_id)):
            captcha_id, _image = await first.issue(scene=scene, owner_id=owner)
            refreshed, _image = await second.issue(
                scene=scene, owner_id=owner, previous_captcha_id=captcha_id
            )
            with pytest.raises(RbacError):
                await first.consume(
                    captcha_id=captcha_id, answer="AAAAA", scene=scene, owner_id=owner
                )
            attempts = await asyncio.gather(
                *(
                    service.consume(
                        captcha_id=refreshed,
                        answer="AAAAA",
                        scene=scene,
                        owner_id=owner,
                    )
                    for service in (first, second)
                ),
                return_exceptions=True,
            )
            assert sum(value is None for value in attempts) == 1
            assert sum(isinstance(value, RbacError) for value in attempts) == 1
            wrong_id, _image = await first.issue(scene=scene, owner_id=owner)
            for answer in ("BBBBB", "AAAAA"):
                with pytest.raises(RbacError):
                    await second.consume(
                        captcha_id=wrong_id, answer=answer, scene=scene, owner_id=owner
                    )

        decisions = await asyncio.gather(
            *(
                check_rate_limit(
                    limiter if index % 2 else peer,
                    namespace="topology_test",
                    policy=RateLimitPolicy("test-login", limit=10, window_seconds=300),
                    subject_type="ip",
                    subject="203.0.113.10",
                    key_secret=b"isolated-topology-test-key-32-bytes",
                )
                for index in range(20)
            )
        )
        assert sum(decision.allowed for decision in decisions) == 10
        assert all(0 < decision.reset_after_ms <= 300000 for decision in decisions)

        policy = RateLimitPolicy("test-login", limit=10, window_seconds=300)
        slots = set()
        for subject_number in range(32):
            subject = f"quota-subject-{subject_number}"
            key = build_rate_limit_key(
                namespace="topology_route",
                policy=policy,
                subject_type="user",
                subject=subject,
                key_secret=b"isolated-topology-test-key-32-bytes",
            )
            slots.add(key_slot(key.encode()))
            result = await check_rate_limit(
                limiter,
                namespace="topology_route",
                policy=policy,
                subject_type="user",
                subject=subject,
                key_secret=b"isolated-topology-test-key-32-bytes",
            )
            assert result.allowed and result.remaining == 9
        assert len(slots) > 1
        if topology.mode == "cluster":
            for node in topology.data_nodes:
                direct = node.client()
                try:
                    count = 0
                    async for key in direct.scan_iter(
                        match=f"{RATE_LIMIT_KEY_PREFIX}:topology_route:*"
                    ):
                        assert await direct.get(key) == "1"
                        count += 1
                    assert count > 0
                finally:
                    await direct.aclose()
    finally:
        await asyncio.gather(
            close_redis_client(client),
            close_redis_client(peer),
            close_redis_client(limiter),
        )


async def test_sentinel_client_rediscovers_after_controlled_primary_switch(
    tmp_path: Path,
) -> None:
    executable = os.environ.get("TEST_REDIS_SERVER")
    if not executable:
        pytest.skip(
            "set TEST_REDIS_SERVER to a Redis 7 executable for private topologies"
        )
    async with disposable_topology(Path(executable), tmp_path, "sentinel") as topology:
        assert topology.sentinel is not None
        control = topology.sentinel.client()
        primary = topology.data_nodes[0].client()
        client = create_redis_client(topology_settings(topology))
        try:
            key = f"switch:{uuid.uuid4().hex}"
            assert await client.set(key, "before", ex=60)
            # WAIT is a test barrier, not a production durability claim.
            for _ in range(100):
                replicas = await redis_command(
                    control, "SENTINEL", "REPLICAS", topology.master_name
                )
                if replicas and await redis_command(primary, "WAIT", 1, 200) == 1:
                    break
                await asyncio.sleep(0.1)
            else:
                raise AssertionError("Disposable replica was not discovered and synced")
            await redis_command(control, "SENTINEL", "FAILOVER", topology.master_name)
            for _ in range(200):
                address = await redis_command(
                    control, "SENTINEL", "GET-MASTER-ADDR-BY-NAME", topology.master_name
                )
                old_role = await redis_command(primary, "ROLE")
                if (
                    int(address[1]) == topology.data_nodes[1].port
                    and old_role[0] == "slave"
                ):
                    try:
                        assert await client.set(key, "after", ex=60)
                        assert await client.get(key) == "after"
                    except RedisError:
                        pass
                    else:
                        break
                await asyncio.sleep(0.1)
            else:
                raise AssertionError(
                    "Existing client did not find the promoted primary"
                )
            new_primary = topology.data_nodes[1].client()
            try:
                assert await new_primary.get(key) == "after"
            finally:
                await new_primary.aclose()
        finally:
            await close_redis_client(client)
            await primary.aclose()
            await control.aclose()


async def test_captcha_pointer_compare_and_set_and_consume_races(
    topology: RedisTopology, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = topology_settings(topology)
    client = create_redis_client(settings)
    peer = create_redis_client(settings)
    first = CaptchaService(client, settings)
    second = CaptchaService(peer, settings)
    owner = uuid.uuid4()
    monkeypatch.setattr(secrets, "choice", lambda _alphabet: "A")
    try:
        original_get = client.get
        competing_id: uuid.UUID | None = None
        index = first._index("self_change", owner)

        async def replace_pointer_after_read(key: str) -> object:
            nonlocal competing_id
            raw = await original_get(key)
            if key == index and competing_id is None:
                competing_id, _image = await second.issue(
                    scene="self_change", owner_id=owner
                )
            return raw

        with monkeypatch.context() as patch:
            patch.setattr(client, "get", replace_pointer_after_read)
            newest, _image = await first.issue(scene="self_change", owner_id=owner)
        assert competing_id is not None
        assert await peer.get(index) == str(newest)
        assert await peer.get(first._key(competing_id)) is None
        await first.consume(
            captcha_id=newest, answer="AAAAA", scene="self_change", owner_id=owner
        )

        old, _image = await first.issue(scene="admin_reset", owner_id=owner)
        replacement_id: uuid.UUID | None = None

        async def replace_challenge_after_read(key: str) -> object:
            nonlocal replacement_id
            raw = await original_get(key)
            if key == first._key(old) and replacement_id is None:
                replacement_id, _image = await second.issue(
                    scene="admin_reset", owner_id=owner
                )
            return raw

        with monkeypatch.context() as patch:
            patch.setattr(client, "get", replace_challenge_after_read)
            with pytest.raises(RbacError) as lost:
                await first.consume(
                    captcha_id=old, answer="AAAAA", scene="admin_reset", owner_id=owner
                )
        assert lost.value.status_code == 400
        assert replacement_id is not None
        assert await peer.get(first._index("admin_reset", owner)) == str(replacement_id)
        await first.consume(
            captcha_id=replacement_id,
            answer="AAAAA",
            scene="admin_reset",
            owner_id=owner,
        )

        # A wrong binding consumes the real challenge and only its own pointer.
        for wrong_scene, wrong_owner in (
            ("admin_reset", uuid.uuid4()),
            ("self_change", owner),
        ):
            actual, _image = await first.issue(scene="admin_reset", owner_id=owner)
            unrelated, _image = await second.issue(
                scene=wrong_scene, owner_id=wrong_owner
            )
            with pytest.raises(RbacError) as rejected:
                await first.consume(
                    captcha_id=actual,
                    answer="AAAAA",
                    scene=wrong_scene,
                    owner_id=wrong_owner,
                )
            assert rejected.value.status_code == 400
            assert await peer.get(first._key(actual)) is None
            assert await peer.get(first._index("admin_reset", owner)) is None
            await second.consume(
                captcha_id=unrelated,
                answer="AAAAA",
                scene=wrong_scene,
                owner_id=wrong_owner,
            )
    finally:
        await asyncio.gather(close_redis_client(client), close_redis_client(peer))
