"""A grant-gated filesystem tool fiber: read / write / delete, each requiring a
valid capability grant. Used to demonstrate capability-scoped delegation — an
agent can be handed read-only access that it cannot exceed.

(An in-memory store stands in for a real filesystem; the point is the authority
model, not the storage.)
"""

from thicket import Fiber, ThicketError, grant

fs = Fiber(kind="tool")


def _enforce_path(ctx, path):
    # a grant may carry a {"path": ...} constraint; the resource enforces it
    if not grant.satisfies(ctx.grant, {"path": path}):
        raise ThicketError("Unauthorized", "path not permitted by grant")


@fs.handles("fs.read", "read a file", tags=["fs"], require_grant=True)
async def read(req, ctx):
    _enforce_path(ctx, req["path"])
    return {"content": ctx.config.setdefault("files", {}).get(req["path"], "")}


@fs.handles("fs.write", "write a file", tags=["fs"], require_grant=True)
async def write(req, ctx):
    _enforce_path(ctx, req["path"])
    ctx.config.setdefault("files", {})[req["path"]] = req["content"]
    return {"ok": True}


@fs.handles("fs.delete", "delete a file", tags=["fs"], require_grant=True)
async def delete(req, ctx):
    _enforce_path(ctx, req["path"])
    ctx.config.setdefault("files", {}).pop(req["path"], None)
    return {"ok": True}


run = fs.run

if __name__ == "__main__":
    fs.main()
