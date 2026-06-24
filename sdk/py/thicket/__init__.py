"""Thicket Python SDK — an independent implementation of the wire protocol.

Shares no code with the Rust core; conformance is proven against
``spec/vectors/``.
"""

from . import cbor, crypto, directory, envelope, federation, grant, identity, record, secure, server, tracing
from .conn import Conn
from .directory import DirectoryClient
from .federation import FederatedDirectory
from .crypto import RootKey, WorkingKey, sha256, signing_input, verify_sig
from .identity import LocalIdentity, unix_now
from .server import serve
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
    "server",
    "directory",
    "federation",
    "tracing",
    "Conn",
    "DirectoryClient",
    "FederatedDirectory",
    "LocalIdentity",
    "serve",
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
