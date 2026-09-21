"""Disposable loopback Redis processes, never a supplied server or database.

Set TEST_REDIS_SERVER to a Redis 7 server binary to enable these tests. This is
test infrastructure, not a production cluster installer. Every process has a
fresh private directory and is stopped through its own process handle.
"""

from __future__ import annotations

import asyncio
import secrets
import socket
import subprocess
import sys
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Literal, cast

from redis.asyncio import Redis
from redis.exceptions import RedisError

Mode = Literal["standalone", "sentinel", "cluster"]


async def redis_command(client: Redis, *arguments: str | int) -> Any:
    """Adapt redis-py 5's untyped raw-command API for test control-plane calls."""
    execute = cast(Callable[..., Awaitable[Any]], client.execute_command)
    return await execute(*arguments)


@dataclass
class RedisNode:
    port: int
    process: subprocess.Popen[bytes]
    output: BinaryIO
    username: str
    password: str

    def client(self) -> Redis:
        return Redis(
            host="127.0.0.1",
            port=self.port,
            username=self.username,
            password=self.password,
            decode_responses=True,
            socket_timeout=0.5,
            socket_connect_timeout=0.5,
        )


class RedisTopology:
    def __init__(self, executable: Path, directory: Path, mode: Mode) -> None:
        self.executable = executable
        self.directory = directory
        self.mode = mode
        self.nodes: list[RedisNode] = []
        self.data_nodes: list[RedisNode] = []
        self.sentinel: RedisNode | None = None
        self.username = "topology-data"
        self.password = secrets.token_hex(24)
        self.master_name = "test-primary"

    def endpoint(self) -> dict[str, object]:
        if self.mode == "standalone":
            port = self.data_nodes[0].port
            return {
                "mode": "standalone",
                "url": f"redis://{self.username}:{self.password}@127.0.0.1:{port}/0",
            }
        if self.mode == "sentinel":
            assert self.sentinel is not None
            nodes = [self.sentinel]
        else:
            # A single seed proves discovery and routing to the other primaries.
            nodes = self.data_nodes[:1]
        result: dict[str, object] = {
            "mode": self.mode,
            "nodes": [{"host": "127.0.0.1", "port": node.port} for node in nodes],
            "username": self.username,
            "password": self.password,
        }
        if self.sentinel is not None:
            result.update(
                sentinel_master=self.master_name,
                sentinel_username=self.sentinel.username,
                sentinel_password=self.sentinel.password,
            )
        return result

    def _spawn_node(self, *, extra: list[str], sentinel: bool) -> RedisNode:
        node_directory = self.directory / f"node-{len(self.nodes)}"
        node_directory.mkdir()
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
            username = "topology-sentinel" if sentinel else self.username
            password = secrets.token_hex(24) if sentinel else self.password
            config = [
                "bind 127.0.0.1",
                "protected-mode yes",
                f"port {port}",
                'dir "."',
                'save ""',
                "appendonly no",
                "daemonize no",
                "user default off",
                f"user {username} on >{password} ~* &* +@all",
                *extra,
            ]
            (node_directory / "redis.conf").write_text(
                "\n".join(config) + "\n", encoding="utf-8"
            )
        output = (node_directory / "process.log").open("wb")
        # Debian/Ubuntu redis-server can link to the redis-check-rdb binary.
        # Redis selects its mode from argv[0], so preserve the executable name.
        command = [str(self.executable.absolute()), "redis.conf"]
        if sentinel:
            command.append("--sentinel")
        if sys.platform == "win32":
            creationflags = subprocess.CREATE_NO_WINDOW
        else:
            creationflags = 0
        try:
            process = subprocess.Popen(
                command,
                cwd=node_directory,
                stdout=output,
                stderr=subprocess.STDOUT,
                creationflags=creationflags,
            )
        except BaseException:
            output.close()
            raise
        node = RedisNode(port, process, output, username, password)
        self.nodes.append(node)
        return node

    async def _start_node(
        self, *, extra: list[str], sentinel: bool = False
    ) -> RedisNode:
        # Register ownership synchronously, before cancellation can interrupt.
        node = self._spawn_node(extra=extra, sentinel=sentinel)
        client = node.client()
        try:
            for _ in range(100):
                if node.process.poll() is not None:
                    raise RuntimeError(
                        f"Disposable Redis exited; inspect {node.output.name}"
                    )
                try:
                    if await client.ping():
                        return node
                except RedisError:
                    pass
                await asyncio.sleep(0.05)
            raise RuntimeError("Disposable Redis startup deadline exceeded")
        finally:
            await client.aclose()

    async def start(self) -> None:
        if self.mode == "cluster":
            bus_ports: list[int] = []
            for _ in range(3):
                with socket.socket() as reservation:
                    reservation.bind(("127.0.0.1", 0))
                    bus_port = reservation.getsockname()[1]
                bus_ports.append(bus_port)
                node = await self._start_node(
                    extra=[
                        "cluster-enabled yes",
                        "cluster-config-file nodes.conf",
                        "cluster-node-timeout 1000",
                        f"cluster-port {bus_port}",
                        "cluster-announce-ip 127.0.0.1",
                    ]
                )
                self.data_nodes.append(node)
            clients = [node.client() for node in self.data_nodes]
            try:
                for index, client in enumerate(clients):
                    start = index * 16384 // 3
                    end = (index + 1) * 16384 // 3 - 1
                    await redis_command(client, "CLUSTER", "ADDSLOTSRANGE", start, end)
                    for peer, bus_port in zip(self.data_nodes, bus_ports, strict=True):
                        if peer.port != self.data_nodes[index].port:
                            await redis_command(
                                client,
                                "CLUSTER",
                                "MEET",
                                "127.0.0.1",
                                peer.port,
                                bus_port,
                            )
                for _ in range(200):
                    states = await asyncio.gather(
                        *(
                            redis_command(client, "CLUSTER", "INFO")
                            for client in clients
                        )
                    )
                    if all("cluster_state:ok" in state for state in states):
                        return
                    await asyncio.sleep(0.05)
                raise RuntimeError(
                    "Disposable Redis Cluster formation deadline exceeded"
                )
            finally:
                await asyncio.gather(*(client.aclose() for client in clients))
        else:
            primary = await self._start_node(extra=[])
            self.data_nodes.append(primary)
            if self.mode == "sentinel":
                replica = await self._start_node(
                    extra=[
                        f"replicaof 127.0.0.1 {primary.port}",
                        f"masteruser {self.username}",
                        f"masterauth {self.password}",
                        "repl-diskless-sync-delay 0",
                    ]
                )
                self.data_nodes.append(replica)
                self.sentinel = await self._start_node(
                    extra=[
                        f"sentinel monitor {self.master_name} "
                        f"127.0.0.1 {primary.port} 1",
                        f"sentinel auth-user {self.master_name} {self.username}",
                        f"sentinel auth-pass {self.master_name} {self.password}",
                        f"sentinel down-after-milliseconds {self.master_name} 1000",
                        f"sentinel failover-timeout {self.master_name} 5000",
                    ],
                    sentinel=True,
                )

    async def stop(self) -> None:
        for node in reversed(self.nodes):
            if node.process.poll() is None:
                node.process.terminate()
        for node in reversed(self.nodes):
            try:
                await asyncio.to_thread(node.process.wait, timeout=5)
            except subprocess.TimeoutExpired:
                node.process.kill()
                await asyncio.to_thread(node.process.wait, timeout=5)
            finally:
                node.output.close()


@asynccontextmanager
async def disposable_topology(
    executable: Path, directory: Path, mode: Mode
) -> AsyncIterator[RedisTopology]:
    topology = RedisTopology(executable, directory, mode)
    try:
        await topology.start()
        yield topology
    finally:
        await topology.stop()
