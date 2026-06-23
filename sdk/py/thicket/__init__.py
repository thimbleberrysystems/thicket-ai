"""Thicket Python SDK — an independent implementation of the wire protocol.

Shares no code with the Rust core; conformance is proven against
``spec/vectors/``.
"""

from . import cbor, crypto, directory, envelope, grant, identity, record, secure
from .conn import Conn
from .directory import DirectoryClient
from .crypto import RootKey, WorkingKey, sha256, signing_input, verify_sig
from .identity import LocalIdentity, unix_now
from .record import (
    build_record_payload,
    capability,
    lease,
    locator,
    sign_record,
    verify_record,
)

__all__ = [
    "cbor",
    "crypto",
    "envelope",
    "grant",
    "identity",
    "record",
    "secure",
    "directory",
    "Conn",
    "DirectoryClient",
    "LocalIdentity",
    "unix_now",
    "RootKey",
    "WorkingKey",
    "sha256",
    "signing_input",
    "verify_sig",
    "build_record_payload",
    "capability",
    "lease",
    "locator",
    "sign_record",
    "verify_record",
]
