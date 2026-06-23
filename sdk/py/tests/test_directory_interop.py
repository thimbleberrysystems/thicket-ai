"""Directory interop: a Python fiber registers with / resolves from / searches a
**Rust** directory over real TCP (the "find each other" proof).

Skipped if the Rust directory_server example isn't built
(``cargo build -p thicket-directory --example directory_server``).
"""

import asyncio
import os
import subprocess
import unittest

from thicket import crypto, identity, record
from thicket.directory import DirectoryClient
from thicket.identity import unix_now

REPO = os.path.join(os.path.dirname(__file__), "..", "..", "..")
DIR_BIN = os.path.join(REPO, "target", "debug", "examples", "directory_server")


def _build_own_record(local) -> dict:
    now = unix_now()
    payload = record.build_record_payload(
        schema="thicket/record/1",
        root=local.root,
        endorsement=local.endorsements[0],
        kind="model",
        locators=[record.locator("tcp", "127.0.0.1:9")],
        capabilities=[record.capability("model", "summarize text", tags=["chat"])],
        visibility="Public",
        lease=record.lease(3600, now, now + 3600),
        version=1,
    )
    return record.sign_record(payload, local.working)


@unittest.skipUnless(os.path.exists(DIR_BIN), "rust directory_server example not built")
class DirectoryInterop(unittest.TestCase):
    def test_register_resolve_search_against_rust_directory(self):
        proc = subprocess.Popen(
            [DIR_BIN], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
        try:
            id_hex, addr = proc.stdout.readline().strip().split()
            host, port = addr.split(":")
            dir_id = bytes.fromhex(id_hex)
            local = identity.LocalIdentity.from_root(crypto.RootKey.generate())
            signed = _build_own_record(local)

            async def run():
                dc = await DirectoryClient.connect(host, int(port), local, dir_id)
                await dc.register(signed)
                got = await dc.resolve(local.id)
                results = await dc.search("summarize", top_k=5)
                await dc.close()
                return got, results

            got, results = asyncio.run(asyncio.wait_for(run(), timeout=15))
            self.assertIsNotNone(got)
            self.assertEqual(got["payload"]["id"], local.id)
            self.assertTrue(any(r["payload"]["id"] == local.id for r in results))
        finally:
            proc.kill()
            proc.wait()
            if proc.stdout:
                proc.stdout.close()


if __name__ == "__main__":
    unittest.main()
