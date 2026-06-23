"""Minimal canonical CBOR codec for the Thicket wire subset.

Mirrors the Rust core's encoding exactly (see ``spec/thicket-wire.md`` §1):
structs are CBOR maps in declaration order, byte fields are CBOR *byte strings*,
integers are unsigned shortest-form, booleans are 0xf4/0xf5. The caller controls
map ordering by building dicts in the right order (field order for structs,
sorted keys for ``String→String`` maps). No floats, no negatives, no null.
"""

from __future__ import annotations


def _enc_head(major: int, n: int, out: bytearray) -> None:
    m = major << 5
    if n < 24:
        out.append(m | n)
    elif n < 0x100:
        out.append(m | 24)
        out.append(n)
    elif n < 0x10000:
        out.append(m | 25)
        out += n.to_bytes(2, "big")
    elif n < 0x100000000:
        out.append(m | 26)
        out += n.to_bytes(4, "big")
    else:
        out.append(m | 27)
        out += n.to_bytes(8, "big")


def _enc(obj, out: bytearray) -> None:
    if obj is None:
        out.append(0xF6)  # CBOR null (for un-skipped Option::None)
    # bool first — it is a subclass of int in Python.
    elif isinstance(obj, bool):
        out.append(0xF5 if obj else 0xF4)
    elif isinstance(obj, int):
        if obj < 0:
            raise ValueError("negative ints are not part of the wire subset")
        _enc_head(0, obj, out)
    elif isinstance(obj, (bytes, bytearray)):
        _enc_head(2, len(obj), out)
        out += obj
    elif isinstance(obj, str):
        b = obj.encode("utf-8")
        _enc_head(3, len(b), out)
        out += b
    elif isinstance(obj, (list, tuple)):
        _enc_head(4, len(obj), out)
        for item in obj:
            _enc(item, out)
    elif isinstance(obj, dict):
        _enc_head(5, len(obj), out)
        for k, v in obj.items():
            _enc(k, out)
            _enc(v, out)
    else:
        raise TypeError(f"cannot CBOR-encode {type(obj).__name__}")


def encode(obj) -> bytes:
    """Canonically encode a value (dict order is preserved as the map order)."""
    out = bytearray()
    _enc(obj, out)
    return bytes(out)


def _dec(data: bytes, i: int):
    b = data[i]
    i += 1
    major = b >> 5
    info = b & 0x1F
    if major == 7:
        if info == 20:
            return False, i
        if info == 21:
            return True, i
        if info == 22:
            return None, i  # CBOR null
        raise ValueError(f"unsupported simple value {info}")
    # length / value
    if info < 24:
        n = info
    elif info == 24:
        n = data[i]
        i += 1
    elif info == 25:
        n = int.from_bytes(data[i : i + 2], "big")
        i += 2
    elif info == 26:
        n = int.from_bytes(data[i : i + 4], "big")
        i += 4
    elif info == 27:
        n = int.from_bytes(data[i : i + 8], "big")
        i += 8
    else:
        raise ValueError(f"bad additional info {info}")

    if major == 0:
        return n, i
    if major == 2:
        return bytes(data[i : i + n]), i + n
    if major == 3:
        return data[i : i + n].decode("utf-8"), i + n
    if major == 4:
        arr = []
        for _ in range(n):
            v, i = _dec(data, i)
            arr.append(v)
        return arr, i
    if major == 5:
        d = {}
        for _ in range(n):
            k, i = _dec(data, i)
            v, i = _dec(data, i)
            d[k] = v
        return d, i
    raise ValueError(f"unsupported major type {major}")


def decode(data: bytes):
    """Decode a single CBOR value (must consume the whole buffer)."""
    obj, i = _dec(data, 0)
    if i != len(data):
        raise ValueError("trailing bytes after CBOR value")
    return obj
