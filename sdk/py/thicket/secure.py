"""Encrypted, mutually-authenticated channel: Noise XX + Ed25519 identity
binding, matching the Rust core (``spec/thicket-wire.md`` §5).

Noise via the `noiseprotocol` library (as Rust uses `snow`); the identity
binding (signing the Noise static with the working key) is ours.
"""

from __future__ import annotations

import os

from noise.connection import Keypair, NoiseConnection

from . import cbor, crypto
from .framing import read_frame, write_frame

NOISE_PARAMS = b"Noise_XX_25519_ChaChaPoly_SHA256"
STATIC_BINDING_DOMAIN = "thicket-noise-static-v1"
NOISE_MAX_PAYLOAD = 65535 - 16


def make_proof(local, noise_static_pub: bytes) -> bytes:
    static_sig = local.working.sign(
        crypto.signing_input(STATIC_BINDING_DOMAIN, noise_static_pub)
    )
    proof = {
        "id": local.id,
        "root_public_key": local.root_public_key,
        "endorsements": local.endorsements,
        "working_pub": local.working.public(),
        "static_sig": static_sig,
    }
    return cbor.encode(proof)


def verify_proof(proof: dict, remote_static: bytes, now: int) -> dict:
    root_pub = proof["root_public_key"]
    if proof["id"] != crypto.sha256(root_pub):
        raise ValueError("id does not match root key")
    working_pub = proof["working_pub"]
    endo = next((e for e in proof["endorsements"] if e["working_pub"] == working_pub), None)
    if endo is None:
        raise ValueError("no endorsement for signer")
    view = {
        "working_pub": endo["working_pub"],
        "not_before": endo["not_before"],
        "not_after": endo["not_after"],
    }
    if not crypto.verify_sig(
        root_pub, crypto.signing_input("thicket-endorsement-v1", view), endo["root_sig"]
    ):
        raise ValueError("bad endorsement")
    if now < endo["not_before"] or now > endo["not_after"]:
        raise ValueError("endorsement expired")
    if not crypto.verify_sig(
        working_pub,
        crypto.signing_input(STATIC_BINDING_DOMAIN, remote_static),
        proof["static_sig"],
    ):
        raise ValueError("static-key binding invalid")
    return {"id": proof["id"], "working_pub": working_pub}


async def handshake(reader, writer, local, initiator: bool, now: int):
    """Run the Noise XX handshake with identity binding. Returns
    ``(noise_connection, verified_peer)``."""
    noise = NoiseConnection.from_name(NOISE_PARAMS)
    (noise.set_as_initiator if initiator else noise.set_as_responder)()
    noise.set_keypair_from_private_bytes(Keypair.STATIC, os.urandom(32))
    noise.start_handshake()
    # Hold the handshake-state reference: it stays populated even after the final
    # message clears `noise_protocol.handshake_state` (needed for the responder,
    # whose peer static arrives in the last message).
    hs = noise.noise_protocol.handshake_state
    local_static_pub = bytes(noise.noise_protocol.keypairs["s"].public_bytes)
    proof_bytes = make_proof(local, local_static_pub)

    if initiator:
        await write_frame(writer, noise.write_message(b""))  # -> e
        m2 = await read_frame(reader)  # <- e, ee, s, es
        peer_proof = cbor.decode(bytes(noise.read_message(m2)))
        remote_static = bytes(hs.rs.public_bytes)
        await write_frame(writer, noise.write_message(proof_bytes))  # -> s, se
    else:
        m1 = await read_frame(reader)  # <- e
        noise.read_message(m1)
        await write_frame(writer, noise.write_message(proof_bytes))  # -> e, ee, s, es
        m3 = await read_frame(reader)  # <- s, se
        peer_proof = cbor.decode(bytes(noise.read_message(m3)))
        remote_static = bytes(hs.rs.public_bytes)

    peer = verify_proof(peer_proof, remote_static, now)
    return noise, peer


def encrypt_frame(noise, plaintext: bytes) -> bytes:
    chunks = (
        [plaintext[i : i + NOISE_MAX_PAYLOAD] for i in range(0, len(plaintext), NOISE_MAX_PAYLOAD)]
        if plaintext
        else []
    )
    out = bytearray(len(chunks).to_bytes(4, "big"))
    for ch in chunks:
        ct = noise.encrypt(ch)
        out += len(ct).to_bytes(2, "big")
        out += ct
    return bytes(out)


def decrypt_frame(noise, frame: bytes) -> bytes:
    count = int.from_bytes(frame[0:4], "big")
    pos = 4
    out = bytearray()
    for _ in range(count):
        n = int.from_bytes(frame[pos : pos + 2], "big")
        pos += 2
        out += noise.decrypt(frame[pos : pos + n])
        pos += n
    return bytes(out)
