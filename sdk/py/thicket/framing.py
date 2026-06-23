"""Length-delimited framing over asyncio streams: 4-byte big-endian length
prefix + body (matches the Rust core's framing)."""

from __future__ import annotations

import asyncio

MAX_FRAME = 16 * 1024 * 1024


async def write_frame(writer: asyncio.StreamWriter, payload: bytes) -> None:
    if len(payload) > MAX_FRAME:
        raise ValueError("frame too large")
    writer.write(len(payload).to_bytes(4, "big") + payload)
    await writer.drain()


async def read_frame(reader: asyncio.StreamReader):
    try:
        header = await reader.readexactly(4)
    except asyncio.IncompleteReadError:
        return None
    n = int.from_bytes(header, "big")
    if n > MAX_FRAME:
        raise ValueError("frame too large")
    return await reader.readexactly(n)
