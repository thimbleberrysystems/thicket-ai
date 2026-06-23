"""Envelopes: build + sign + verify. Field order matches the spec (optional
fields omitted; `stream_end` always present)."""

from __future__ import annotations

from . import crypto


def build_envelope_payload(
    *,
    from_id: bytes,
    to_id: bytes,
    typ: str,
    correlation: bytes,
    capability=None,
    content_type=None,
    context=None,
    auth=None,
    stream_seq=None,
    stream_end=False,
    error=None,
    body=b"",
    ext=None,
) -> dict:
    p = {"v": 1, "from": from_id, "to": to_id, "typ": typ}
    if capability is not None:
        p["capability"] = capability
    p["correlation"] = correlation
    if content_type is not None:
        p["content_type"] = content_type
    if context:
        p["context"] = context
    if auth is not None:
        p["auth"] = auth
    if stream_seq is not None:
        p["stream_seq"] = stream_seq
    p["stream_end"] = stream_end
    if error is not None:
        p["error"] = error
    p["body"] = body
    p["ext"] = dict(sorted((ext or {}).items()))
    return p


def sign_envelope(payload: dict, working: crypto.WorkingKey) -> dict:
    sig = working.sign(crypto.signing_input("thicket-envelope-v1", payload))
    return {"payload": payload, "signer_pub": working.public(), "signature": sig}


def verify_envelope_with_key(signed: dict, working_pub: bytes) -> bool:
    """Fast per-message check against an already-authenticated peer key."""
    if signed["signer_pub"] != working_pub:
        return False
    return crypto.verify_sig(
        signed["signer_pub"],
        crypto.signing_input("thicket-envelope-v1", signed["payload"]),
        signed["signature"],
    )
