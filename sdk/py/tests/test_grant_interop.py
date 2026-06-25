"""Cross-language grant verification (gap 1, issue #2).

A grant **minted in Python** is presented to a **Rust** resource that verifies it
with the core's `Grant::verify`, over real TCP+Noise. Together with the reverse
direction in test_conformance (Python verifies a Rust-minted grant), this proves
the authorization model — not just the encoding — is language-symmetric.

Skipped if the Rust `grant_gated_server` example isn't built.
"""

import asyncio
import os
import subprocess
import unittest

HERE = os.path.dirname(__file__)
REPO = os.path.join(HERE, "..", "..", "..")
GATED_BIN = os.path.join(REPO, "target", "debug", "examples", "grant_gated_server")

from thicket import Conn, LocalIdentity, RootKey, WorkingKey, crypto, grant, unix_now  # noqa: E402


@unittest.skipUnless(os.path.exists(GATED_BIN), "rust grant_gated_server example not built")
class PythonGrantOnRustResource(unittest.TestCase):
    def test_python_minted_grant_verified_by_rust(self):
        proc = subprocess.Popen([GATED_BIN], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        try:

            async def scenario():
                id_hex, addr = proc.stdout.readline().strip().split()
                server_id = bytes.fromhex(id_hex)
                host, port = addr.split(":")

                # reconstruct the server's keys from its known seeds and mint grants
                server_root = RootKey.from_seed(bytes([12]) * 32)
                server_working = WorkingKey.from_seed(bytes([112]) * 32)
                self.assertEqual(server_root.id(), server_id)  # from_seed is cross-language identical

                client = LocalIdentity.generate()
                far = unix_now() + 1_000_000
                g_ok = grant.issue(server_root.id(), server_working, client.working.public(),
                                   grant.caveats(["secret"], far))
                g_wrong = grant.issue(server_root.id(), server_working, client.working.public(),
                                      grant.caveats(["other"], far))

                conn = await Conn.connect(host, int(port), client, expected_id=server_id)
                ok = (await conn.call("secret", b"hi", auth=g_ok))["payload"]
                wrong = (await conn.call("secret", b"hi", auth=g_wrong))["payload"]
                missing = (await conn.call("secret", b"hi"))["payload"]
                await conn.close()
                return ok, wrong, missing

            ok, wrong, missing = asyncio.run(asyncio.wait_for(scenario(), 30))
            self.assertEqual(ok.get("typ"), "Response")  # Rust accepted the Python-minted grant
            self.assertEqual(ok.get("body"), b"hi")
            self.assertEqual(wrong.get("typ"), "Error")  # wrong capability -> rejected
            self.assertEqual(wrong["error"]["code"], "Unauthorized")
            self.assertEqual(missing.get("typ"), "Error")  # no grant -> rejected
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()


if __name__ == "__main__":
    unittest.main()
