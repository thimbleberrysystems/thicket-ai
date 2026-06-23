"""Identity, signing, and the canonical signing-input rule.

`id = sha256(root_public_key)`; the root key endorses working keys; working keys
sign records/envelopes/grants. Signing input is ``domain ‖ 0x00 ‖ CBOR(payload)``
(see ``spec/thicket-wire.md`` §2).
"""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from . import cbor


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def signing_input(domain: str, payload) -> bytes:
    """The exact bytes that get signed: domain ‖ 0x00 ‖ canonical CBOR."""
    return domain.encode("utf-8") + b"\x00" + cbor.encode(payload)


def verify_sig(public_key: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(sig, msg)
        return True
    except Exception:
        return False


class WorkingKey:
    """A short-lived signing key (32-byte Ed25519)."""

    def __init__(self, sk: Ed25519PrivateKey) -> None:
        self._sk = sk

    @classmethod
    def from_seed(cls, seed: bytes) -> "WorkingKey":
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    @classmethod
    def generate(cls) -> "WorkingKey":
        return cls(Ed25519PrivateKey.generate())

    def public(self) -> bytes:
        return self._sk.public_key().public_bytes_raw()

    def sign(self, msg: bytes) -> bytes:
        return self._sk.sign(msg)


class RootKey:
    """The long-lived identity key. `id = sha256(public)`."""

    def __init__(self, sk: Ed25519PrivateKey) -> None:
        self._sk = sk

    @classmethod
    def from_seed(cls, seed: bytes) -> "RootKey":
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    @classmethod
    def generate(cls) -> "RootKey":
        return cls(Ed25519PrivateKey.generate())

    def public(self) -> bytes:
        return self._sk.public_key().public_bytes_raw()

    def id(self) -> bytes:
        return sha256(self.public())

    def sign(self, msg: bytes) -> bytes:
        return self._sk.sign(msg)

    def endorse(self, working_pub: bytes, not_before: int, not_after: int) -> dict:
        """Produce a KeyEndorsement (root-signed authorization of a working key)."""
        view = {
            "working_pub": working_pub,
            "not_before": not_before,
            "not_after": not_after,
        }
        sig = self.sign(signing_input("thicket-endorsement-v1", view))
        return {
            "working_pub": working_pub,
            "not_before": not_before,
            "not_after": not_after,
            "root_sig": sig,
        }
