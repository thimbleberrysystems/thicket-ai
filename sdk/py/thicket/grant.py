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
    if not _narrows(child, parent):
        raise ValueError("attenuation widened authority")


def _narrows(child: dict, parent: dict) -> bool:
    pc = set(parent["capabilities"])
    if "*" not in pc:
        for c in child["capabilities"]:
            if c == "*" or c not in pc:
                return False
    if child["not_after"] > parent["not_after"]:
        return False
    for k, v in (parent.get("constraints") or {}).items():
        if (child.get("constraints") or {}).get(k) != v:
            return False
    return True


def satisfies(grant: dict, attributes: dict) -> bool:
    """Resource-side constraint check: True if every constraint in the grant's
    effective (last-link, tightest) caveats is matched by ``attributes`` (exact
    string match). A grant with no constraints is satisfied by anything. The
    resource decides which request attributes to supply (e.g. ``{"path": ...}``).
    """
    links = grant.get("links") if grant else None
    if not links:
        return True
    constraints = links[-1]["caveats"].get("constraints") or {}
    return all(str(attributes.get(k)) == v for k, v in constraints.items())


def _endorsed(root_pub: bytes, target_id: bytes, endorsements, working_pub: bytes, now: int) -> bool:
    if target_id != crypto.sha256(root_pub):
        return False
    endo = next((e for e in endorsements if e["working_pub"] == working_pub), None)
    if endo is None:
        return False
    view = {
        "working_pub": endo["working_pub"],
        "not_before": endo["not_before"],
        "not_after": endo["not_after"],
    }
    if not crypto.verify_sig(
        root_pub, crypto.signing_input("thicket-endorsement-v1", view), endo["root_sig"]
    ):
        return False
    return endo["not_before"] <= now <= endo["not_after"]


def verify(
    grant: dict,
    target_root_pub: bytes,
    target_endorsements,
    caller_pub: bytes,
    capability: str,
    now: int,
    revocations=None,
) -> bool:
    """Verify, from the target's view, that `grant` authorizes `caller_pub` to
    invoke `capability` at `now` (chain links, narrowing, expiry, audience).

    `revocations` is the resource's set of revoked working-key public keys; the
    grant is rejected if **any** key in the chain (issuer or audience) is revoked
    — so a resource can kill both its own issuing key and a delegated sub-grant.
    """
    revoked = revocations or ()
    links = grant.get("links") or []
    if not links:
        return False
    if grant["target"] != crypto.sha256(target_root_pub):
        return False
    prev = b""
    parent = None
    for idx, link in enumerate(links):
        if link["issuer_pub"] in revoked or link["audience_pub"] in revoked:
            return False  # a revoked key appears in the chain
        if idx == 0:
            if not _endorsed(target_root_pub, grant["target"], target_endorsements, link["issuer_pub"], now):
                return False
        elif link["issuer_pub"] != links[idx - 1]["audience_pub"]:
            return False
        if parent is not None and not _narrows(link["caveats"], parent):
            return False
        view = {
            "target": grant["target"],
            "issuer_pub": link["issuer_pub"],
            "audience_pub": link["audience_pub"],
            "caveats": link["caveats"],
            "prev": prev,
        }
        if not crypto.verify_sig(link["issuer_pub"], crypto.signing_input("thicket-grant-v1", view), link["sig"]):
            return False
        caps = link["caveats"]["capabilities"]
        if "*" not in caps and capability not in caps:
            return False
        if now > link["caveats"]["not_after"]:
            return False
        prev = link["sig"]
        parent = link["caveats"]
    return links[-1]["audience_pub"] == caller_pub
