"""Conformance: the Python SDK must reproduce the Rust-generated vectors
byte-for-byte, and verify Rust-produced records.

Run: ``cd sdk/py && python3 -m unittest discover -s tests``
"""

import os
import unittest

from thicket import cbor, crypto, envelope, grant, record

VEC = os.path.join(os.path.dirname(__file__), "..", "..", "..", "spec", "vectors")
NOW = 1_000_000


def _vector_record():
    """Build the exact record committed as the Rust vector (same seeds/fields)."""
    root = crypto.RootKey.from_seed(bytes([1]) * 32)
    working = crypto.WorkingKey.from_seed(bytes([101]) * 32)
    endorsement = root.endorse(working.public(), 0, 2_000_000)
    payload = record.build_record_payload(
        schema="thicket/record/1",
        root=root,
        endorsement=endorsement,
        kind="model",
        locators=[record.locator("tcp", "10.0.0.1:7000")],
        capabilities=[record.capability("model", "text generation", tags=["chat"])],
        profile={"cost_per_1k": "0.5"},
        visibility="Public",
        lease=record.lease(3600, NOW, NOW + 3600),
        version=1,
    )
    return record.sign_record(payload, working), payload


def _read(name):
    with open(os.path.join(VEC, name), "rb") as f:
        return f.read()


class RecordConformance(unittest.TestCase):
    def test_signing_input_matches_vector(self):
        _, payload = _vector_record()
        signin = crypto.signing_input("thicket-record-v1", payload)
        self.assertEqual(signin, _read("record.signin"))

    def test_signed_record_cbor_matches_vector(self):
        signed, _ = _vector_record()
        self.assertEqual(cbor.encode(signed), _read("record.cbor"))

    def test_verifies_rust_record_vector(self):
        signed = cbor.decode(_read("record.cbor"))
        self.assertTrue(record.verify_record(signed, NOW))

    def test_rejects_tampered_record(self):
        signed = cbor.decode(_read("record.cbor"))
        signed["payload"]["kind"] = "memory"  # mutate signed content
        self.assertFalse(record.verify_record(signed, NOW))

    def test_cbor_roundtrip(self):
        signed, _ = _vector_record()
        encoded = cbor.encode(signed)
        self.assertEqual(cbor.encode(cbor.decode(encoded)), encoded)


def _vector_envelope():
    root = crypto.RootKey.from_seed(bytes([1]) * 32)
    working = crypto.WorkingKey.from_seed(bytes([101]) * 32)
    to_root = crypto.RootKey.from_seed(bytes([3]) * 32)
    payload = envelope.build_envelope_payload(
        from_id=root.id(),
        to_id=to_root.id(),
        typ="Request",
        correlation=bytes([0xAB]) * 16,
        capability="generate",
        body=b"hello",
    )
    return envelope.sign_envelope(payload, working), payload


def _vector_grant():
    root = crypto.RootKey.from_seed(bytes([1]) * 32)
    working = crypto.WorkingKey.from_seed(bytes([101]) * 32)
    audience = crypto.WorkingKey.from_seed(bytes([104]) * 32)
    return grant.issue(root.id(), working, audience.public(), grant.caveats(["generate"], 2_000_000))


class EnvelopeConformance(unittest.TestCase):
    def test_signing_input_matches_vector(self):
        _, payload = _vector_envelope()
        self.assertEqual(
            crypto.signing_input("thicket-envelope-v1", payload), _read("envelope.signin")
        )

    def test_envelope_cbor_matches_vector(self):
        signed, _ = _vector_envelope()
        self.assertEqual(cbor.encode(signed), _read("envelope.cbor"))


class GrantConformance(unittest.TestCase):
    def test_grant_cbor_matches_vector(self):
        # Ed25519 is deterministic, so the re-signed grant must be byte-identical.
        self.assertEqual(cbor.encode(_vector_grant()), _read("grant.cbor"))

    def test_verifies_rust_minted_grant(self):
        # Cross-language *verification* (not just encoding): a grant minted by the
        # Rust core is decoded and verified by the Python SDK, which must accept it
        # and reject the obvious over-reaches identically.
        g = cbor.decode(_read("grant.cbor"))
        root = crypto.RootKey.from_seed(bytes([1]) * 32)
        working = crypto.WorkingKey.from_seed(bytes([101]) * 32)
        audience = crypto.WorkingKey.from_seed(bytes([104]) * 32)
        endo = root.endorse(working.public(), 0, 2_000_000)  # matches the vector's window
        now = 1_000_000

        self.assertTrue(grant.verify(g, root.public(), [endo], audience.public(), "generate", now))
        self.assertFalse(grant.verify(g, root.public(), [endo], audience.public(), "delete", now))
        self.assertFalse(grant.verify(g, root.public(), [endo], crypto.WorkingKey.generate().public(), "generate", now))
        self.assertFalse(grant.verify(g, root.public(), [endo], audience.public(), "generate", 2_000_001))

    def test_constraint_satisfaction_matches_vector(self):
        # The constrained-grant vector: Python reproduces it byte-for-byte and its
        # satisfies() agrees with Rust's on the same grant bytes.
        root = crypto.RootKey.from_seed(bytes([1]) * 32)
        working = crypto.WorkingKey.from_seed(bytes([101]) * 32)
        audience = crypto.WorkingKey.from_seed(bytes([104]) * 32)
        cav = grant.caveats(["read"], 2_000_000, {"region": "eu"})
        g = grant.issue(root.id(), working, audience.public(), cav)
        self.assertEqual(cbor.encode(g), _read("grant_constrained.cbor"))

        loaded = cbor.decode(_read("grant_constrained.cbor"))
        self.assertTrue(grant.satisfies(loaded, {"region": "eu"}))
        self.assertFalse(grant.satisfies(loaded, {"region": "us"}))
        self.assertFalse(grant.satisfies(loaded, {}))

    def test_attenuation_narrows(self):
        g = _vector_grant()
        holder = crypto.WorkingKey.from_seed(bytes([104]) * 32)
        delegate = crypto.WorkingKey.from_seed(bytes([5]) * 32)
        sub = grant.attenuate(g, holder, delegate.public(), grant.caveats(["generate"], 1_500_000))
        self.assertEqual(len(sub["links"]), 2)
        with self.assertRaises(ValueError):
            grant.attenuate(g, holder, delegate.public(), grant.caveats(["delete"], 2_000_000))


class RevocationConformance(unittest.TestCase):
    def test_reproduces_and_verifies_revocation_vector(self):
        root = crypto.RootKey.from_seed(bytes([1]) * 32)
        revoked = crypto.WorkingKey.from_seed(bytes([105]) * 32)
        rev = root.revoke(revoked.public(), 1_500_000)
        # byte-exact with the Rust-minted vector
        self.assertEqual(cbor.encode(rev), _read("revocation.cbor"))
        # Python verifies the Rust-minted revocation's signature
        loaded = cbor.decode(_read("revocation.cbor"))
        self.assertTrue(crypto.verify_revocation(root.public(), loaded))
        self.assertFalse(crypto.verify_revocation(crypto.RootKey.generate().public(), loaded))


if __name__ == "__main__":
    unittest.main()
