"""A grant-gated filesystem tool fiber: read / write / delete, each requiring a
valid capability grant. Used to demonstrate capability-scoped delegation — an
agent can be handed read-only access that it cannot exceed.

(An in-memory store stands in for a real filesystem; the point is the authority
model, not the storage.)
"""

from thicket import Fiber

fs = Fiber(kind="tool")


@fs.handles("fs.read", "read a file", tags=["fs"], require_grant=True)
async def read(req, ctx):
    return {"content": ctx.config.setdefault("files", {}).get(req["path"], "")}


@fs.handles("fs.write", "write a file", tags=["fs"], require_grant=True)
async def write(req, ctx):
    ctx.config.setdefault("files", {})[req["path"]] = req["content"]
    return {"ok": True}


@fs.handles("fs.delete", "delete a file", tags=["fs"], require_grant=True)
async def delete(req, ctx):
    ctx.config.setdefault("files", {}).pop(req["path"], None)
    return {"ok": True}


run = fs.run

if __name__ == "__main__":
    fs.main()
