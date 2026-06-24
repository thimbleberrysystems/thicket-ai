"""Cross-impl interop, the other direction: a **Rust** caller invokes a **Python**
fiber over real TCP+Noise. Together with ``test_interop`` (Python→Rust) this
proves the wire contract is language-symmetric.

Skipped if the Rust ``rust_caller`` example binary isn't built
(``cargo build -p thicket-net --example rust_caller``).
"""

import asyncio
import os
import subprocess
import unittest

HERE = os.path.dirname(__file__)
REPO = os.path.join(HERE, "..", "..", "..")
CALLER_BIN = os.path.join(REPO, "target", "debug", "examples", "rust_caller")

from thicket import LocalIdentity, RootKey, serve  # noqa: E402


@unittest.skipUnless(os.path.exists(CALLER_BIN), "rust rust_caller example not built")
class RustToPython(unittest.TestCase):
    def test_rust_caller_invokes_python_fiber(self):
        async def scenario():
            local = LocalIdentity.from_root(RootKey.generate())

            async def handler(conn, payload):
                if payload.get("capability") == "echo":
                    await conn.respond(payload, payload.get("body", b""))
                else:
                    await conn.respond_error(payload, "NotFound", "unknown capability")

            server = await serve("127.0.0.1", 0, local, handler)
            port = server.sockets[0].getsockname()[1]
            proc = await asyncio.create_subprocess_exec(
                CALLER_BIN, local.id.hex(), f"127.0.0.1:{port}", "echo", "hello-from-rust",
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            out, err = await asyncio.wait_for(proc.communicate(), 30)
            server.close()
            await server.wait_closed()
            return proc.returncode, out.decode(), err.decode()

        rc, out, err = asyncio.run(asyncio.wait_for(scenario(), 40))
        self.assertEqual(rc, 0, f"rust_caller failed: {err}")
        self.assertIn("OK", out)
        self.assertIn("hello-from-rust", out)


if __name__ == "__main__":
    unittest.main()
