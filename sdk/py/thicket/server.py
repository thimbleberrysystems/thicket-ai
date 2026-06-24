"""Serving primitive: accept connections, handshake (responder), and dispatch
each inbound request to a handler.

``handler(conn, request_payload)`` is an async callable that replies via
``conn.respond`` / ``conn.respond_error`` / ``conn.stream_chunk``.
"""

from __future__ import annotations

import asyncio

from .conn import Conn


async def serve(host: str, port: int, local, handler) -> asyncio.AbstractServer:
    """Start a server. Returns the asyncio server (read the bound port via
    ``server.sockets[0].getsockname()``; run with ``serve_forever``)."""

    async def on_client(reader, writer):
        try:
            conn = await Conn.accept(reader, writer, local)
        except Exception:
            try:
                writer.close()
            except Exception:
                pass
            return
        try:
            while True:
                env = await conn.recv()
                if env is None:
                    break
                if env["payload"].get("typ") == "Request":
                    await handler(conn, env["payload"])
        except Exception:
            pass
        finally:
            await conn.close()

    return await asyncio.start_server(on_client, host, port)
