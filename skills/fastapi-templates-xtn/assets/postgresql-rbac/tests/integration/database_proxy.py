"""Loopback TCP fault injection for the confirmed disposable PostgreSQL target.

The proxy never interprets PostgreSQL messages, so separate CancelRequest
connections receive the same fault policy as ordinary database connections.
"""

import asyncio
import math
import os
from contextlib import suppress
from typing import Literal

from sqlalchemy.engine import make_url

from tests.integration.safety import UnsafeTestTarget, confirmed_database_name

_FaultMode = Literal["normal", "server_to_client", "both"]
_CONNECT_TIMEOUT_SECONDS = 2.0
_CLOSE_TIMEOUT_SECONDS = 2.0


class DatabaseFaultProxy:
    """Relay a test database connection with switchable, silent packet loss."""

    def __init__(self) -> None:
        confirmed_database_name()
        try:
            self._target_url = make_url(os.environ["TEST_DATABASE_URL"])
            if (
                not self._target_url.host
                or self._target_url.port == 0
                or "host" in self._target_url.query
                or "port" in self._target_url.query
            ):
                raise ValueError
        except (KeyError, ValueError):
            raise UnsafeTestTarget("invalid disposable PostgreSQL TCP target") from None

        self._target_host = self._target_url.host
        self._target_port = self._target_url.port or 5432
        self._server: asyncio.AbstractServer | None = None
        self._url: str | None = None
        self._mode: _FaultMode = "normal"
        self._closed = False
        self._connection_tasks: set[asyncio.Task[None]] = set()
        self._writers: set[asyncio.StreamWriter] = set()
        self._data_condition = asyncio.Condition()
        self.client_data_count = 0
        self.client_bytes_received = 0
        self.dropped_client_bytes = 0
        self.dropped_server_bytes = 0
        self.accepted_connections = 0

    @property
    def url(self) -> str:
        """URL with only host/port changed; keep its value out of test output."""
        if self._url is None or self._closed:
            raise RuntimeError("database proxy is not listening")
        return self._url

    async def __aenter__(self) -> "DatabaseFaultProxy":
        if self._server is not None or self._closed:
            raise RuntimeError("database proxy cannot be started twice")
        self._server = await asyncio.start_server(self._accept, "127.0.0.1", 0)
        socket = self._server.sockets[0]
        port = socket.getsockname()[1]
        self._url = self._target_url.set(host="127.0.0.1", port=port).render_as_string(
            hide_password=False
        )
        return self

    async def __aexit__(
        self, _type: object, _value: object, _traceback: object
    ) -> None:
        await self.close()

    def drop_server_to_client(self) -> None:
        """Forward requests, but silently discard every database response."""
        self._set_mode("server_to_client")

    def drop_both(self) -> None:
        """Silently discard traffic in both directions, including new sockets."""
        self._set_mode("both")

    def restore(self) -> None:
        """Allow traffic again; callers should open a fresh database connection."""
        self._set_mode("normal")

    def _set_mode(self, mode: _FaultMode) -> None:
        if self._server is None or self._closed:
            raise RuntimeError("database proxy is not listening")
        self._mode = mode

    async def wait_for_client_data(
        self, *, after: int, timeout_seconds: float = 3.0
    ) -> int:
        """Wait for a client data chunk beyond a previously sampled counter."""
        if (
            type(after) is not int
            or after < 0
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ValueError("invalid client-data barrier")
        async with self._data_condition:
            await asyncio.wait_for(
                self._data_condition.wait_for(
                    lambda: self.client_data_count > after or self._closed
                ),
                timeout_seconds,
            )
            if self.client_data_count <= after:
                raise RuntimeError("database proxy closed before client data arrived")
            return self.client_data_count

    async def _accept(
        self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.current_task()
        assert task is not None
        self._connection_tasks.add(task)
        self._writers.add(client_writer)
        self.accepted_connections += 1
        server_writer: asyncio.StreamWriter | None = None
        relay_tasks: tuple[asyncio.Task[None], ...] = ()
        try:
            try:
                server_reader, connected_writer = await asyncio.wait_for(
                    asyncio.open_connection(self._target_host, self._target_port),
                    timeout=_CONNECT_TIMEOUT_SECONDS,
                )
            except (OSError, TimeoutError):
                return
            server_writer = connected_writer
            self._writers.add(server_writer)
            relay_tasks = (
                asyncio.create_task(
                    self._relay(client_reader, connected_writer, from_client=True)
                ),
                asyncio.create_task(
                    self._relay(server_reader, client_writer, from_client=False)
                ),
            )
            await asyncio.wait(relay_tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for relay in relay_tasks:
                relay.cancel()
            writers = (
                (client_writer,)
                if server_writer is None
                else (
                    client_writer,
                    server_writer,
                )
            )
            for writer in writers:
                with suppress(OSError, RuntimeError):
                    writer.close()
                self._writers.discard(writer)
            try:
                if relay_tasks:
                    await asyncio.gather(*relay_tasks, return_exceptions=True)
                with suppress(TimeoutError):
                    await asyncio.wait_for(
                        asyncio.gather(
                            *(writer.wait_closed() for writer in writers),
                            return_exceptions=True,
                        ),
                        _CLOSE_TIMEOUT_SECONDS,
                    )
            finally:
                self._connection_tasks.discard(task)

    async def _relay(
        self,
        source: asyncio.StreamReader,
        destination: asyncio.StreamWriter,
        *,
        from_client: bool,
    ) -> None:
        try:
            while data := await source.read(16_384):
                if from_client:
                    async with self._data_condition:
                        self.client_data_count += 1
                        self.client_bytes_received += len(data)
                        self._data_condition.notify_all()
                if self._mode == "both":
                    if from_client:
                        self.dropped_client_bytes += len(data)
                    else:
                        self.dropped_server_bytes += len(data)
                    continue
                if self._mode == "server_to_client" and not from_client:
                    self.dropped_server_bytes += len(data)
                    continue
                destination.write(data)
                await destination.drain()
        except (ConnectionError, OSError):
            return

    async def close(self) -> None:
        if self._server is None or self._closed:
            return
        self._closed = True
        async with self._data_condition:
            self._data_condition.notify_all()
        self._server.close()
        writers = tuple(self._writers)
        for writer in writers:
            with suppress(OSError, RuntimeError):
                writer.close()
        for task in tuple(self._connection_tasks):
            task.cancel()
        with suppress(TimeoutError):
            await asyncio.wait_for(self._server.wait_closed(), _CLOSE_TIMEOUT_SECONDS)
        tasks = tuple(self._connection_tasks)
        if tasks:
            with suppress(TimeoutError):
                await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    _CLOSE_TIMEOUT_SECONDS,
                )
        if writers:
            with suppress(TimeoutError):
                await asyncio.wait_for(
                    asyncio.gather(
                        *(writer.wait_closed() for writer in writers),
                        return_exceptions=True,
                    ),
                    _CLOSE_TIMEOUT_SECONDS,
                )
