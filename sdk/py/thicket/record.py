"""Fiber records: build, sign, and verify — field order matches the spec."""

from __future__ import annotations

from . import crypto


def _sorted_map(m: dict) -> dict:
    # String→String maps are emitted with keys in ascending order.
    return dict(sorted(m.items()))


def capability(kind, description, *, io=None, tags=None, modalities=None, envelope=None):
    c = {"kind": kind, "description": description}
    if io is not None:
        c["io"] = io
    c["tags"] = list(tags or [])
    c["modalities"] = list(modalities or [])
    c["envelope"] = _sorted_map(envelope or {})
    return c


def locator(protocol, endpoint):
    return {"protocol": protocol, "endpoint": endpoint}


def lease(ttl, issued_at, expires_at):
    return {"ttl": ttl, "issued_at": issued_at, "expires_at": expires_at}


def build_record_payload(
    *,
    schema,
    root: crypto.RootKey,
    endorsement: dict,
    kind,
    locators=None,
    capabilities=None,
    profile=None,
    supports=None,
    visibility="Public",
    lease=None,
    version,
    ext=None,
) -> dict:
    """Build a RecordPayload as an ordered dict (declaration order, lease omitted
    when absent)."""
    payload = {
        "schema": schema,
        "id": root.id(),
        "root_public_key": root.public(),
        "keys": [endorsement],
        "kind": kind,
        "locators": list(locators or []),
        "capabilities": list(capabilities or []),
        "profile": _sorted_map(profile or {}),
        "supports": _sorted_map(supports or {}),
        "visibility": visibility,
    }
    if lease is not None:
        payload["lease"] = lease
    payload["version"] = version
    payload["ext"] = _sorted_map(ext or {})
    return payload


def sign_record(payload: dict, working: crypto.WorkingKey) -> dict:
    sig = working.sign(crypto.signing_input("thicket-record-v1", payload))
    return {"payload": payload, "signer_pub": working.public(), "signature": sig}


def verify_record(signed: dict, now: int) -> bool:
    payload = signed["payload"]
    # 1. id binds to the root public key
    if payload["id"] != crypto.sha256(payload["root_public_key"]):
        return False
    # 2. signer is a root-endorsed working key, valid at `now`
    signer = signed["signer_pub"]
    endo = next((e for e in payload["keys"] if e["working_pub"] == signer), None)
    if endo is None:
        return False
    view = {
        "working_pub": endo["working_pub"],
        "not_before": endo["not_before"],
        "not_after": endo["not_after"],
    }
    if not crypto.verify_sig(
        payload["root_public_key"],
        crypto.signing_input("thicket-endorsement-v1", view),
        endo["root_sig"],
    ):
        return False
    if now < endo["not_before"] or now > endo["not_after"]:
        return False
    # 3. signature over the canonical payload
    return crypto.verify_sig(
        signer, crypto.signing_input("thicket-record-v1", payload), signed["signature"]
    )
