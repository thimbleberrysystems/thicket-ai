"""Cross-language interop: a Python client does a Noise handshake with and
invokes a **Rust** echo server over real TCP. The headline Phase 2 test.

Skipped if the Rust echo_server example binary isn't built
(``cargo build -p thicket-net --example echo_server``).
"""

import asyncio
import os
import subprocess
import unittest

from thicket import crypto, identity
from thicket.conn import Conn

REPO = os.path.join(os.path.dirname(__file__), "..", "..", "..")
ECHO_BIN = os.path.join(REPO, "target", "debug", "examples", "echo_server")


@unittest.skipUnless(os.path.exists(ECHO_BIN), "rust echo_server example not built")
class Interop(unittest.TestCase):
    def test_python_client_invokes_rust_echo_server(self):
        proc = subprocess.Popen(
            [ECHO_BIN], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
        try:
            line = proc.stdout.readline().strip()
            id_hex, addr = line.split()
            host, port = addr.split(":")
            server_id = bytes.fromhex(id_hex)
            local = identity.LocalIdentity.from_root(crypto.RootKey.generate())

            async def run():
                conn = await Conn.connect(host, int(port), local, expected_id=server_id)
                resp = await conn.call("echo", b"hello from python")
                ok = conn.verify_response(resp)
                await conn.close()
                return resp, ok

            resp, verified = asyncio.run(asyncio.wait_for(run(), timeout=15))
            # round-tripped through the encrypted channel and echoed back
            self.assertEqual(resp["payload"]["body"], b"hello from python")
            self.assertEqual(resp["payload"]["from"], server_id)
            self.assertTrue(verified, "response signature did not verify under peer key")
        finally:
            proc.kill()
            proc.wait()
            if proc.stdout:
                proc.stdout.close()


if __name__ == "__main__":
    unittest.main()
