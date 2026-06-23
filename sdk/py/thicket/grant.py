"""Capability grants: issue + attenuate + verify. Field order matches the spec;
attenuation only narrows."""

from __future__ import annotations

from . import crypto


def caveats(capabilities, not_after: int, constraints=None) -> dict:
    return {
        # BTreeSet → sorted array
        "capabilities": sorted(set(capabilities)),
        "not_after": not_after,
        "constraints": dict(sorted((constraints or {}).items())),
    }


def _link_sig(target: bytes, issuer: crypto.WorkingKey, audience_pub: bytes, cav: dict, prev: bytes) -> bytes:
    view = {
        "target": target,
        "issuer_pub": issuer.public(),
        "audience_pub": audience_pub,
        "caveats": cav,
        "prev": prev,
    }
    return issuer.sign(crypto.signing_input("thicket-grant-v1", view))


def issue(target: bytes, target_key: crypto.WorkingKey, audience_pub: bytes, cav: dict) -> dict:
    """Issue a root grant from the target resource to `audience_pub`."""
    sig = _link_sig(target, target_key, audience_pub, cav, b"")
    link = {
        "issuer_pub": target_key.public(),
        "audience_pub": audience_pub,
        "caveats": cav,
        "sig": sig,
    }
    return {"target": target, "links": [link]}


def attenuate(grant: dict, holder_key: crypto.WorkingKey, new_audience_pub: bytes, cav: dict) -> dict:
    """Append a strictly-narrower link delegating to a new audience."""
    last = grant["links"][-1]
    if holder_key.public() != last["audience_pub"]:
        raise ValueError("not the current grant holder")
    _ensure_narrows(cav, last["caveats"])
    sig = _link_sig(grant["target"], holder_key, new_audience_pub, cav, last["sig"])
    link = {
        "issuer_pub": holder_key.public(),
        "audience_pub": new_audience_pub,
        "caveats": cav,
        "sig": sig,
    }
    return {"target": grant["target"], "links": grant["links"] + [link]}


def _ensure_narrows(child: dict, parent: dict) -> None:
    pc = set(parent["capabilities"])
    if "*" not in pc:
        for c in child["capabilities"]:
            if c == "*" or c not in pc:
                raise ValueError("attenuation widened capabilities")
    if child["not_after"] > parent["not_after"]:
        raise ValueError("attenuation extended expiry")
