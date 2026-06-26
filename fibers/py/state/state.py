"""State fiber: a generic durable key→value store (`kind: state`).

The network-native backend for durable execution — a fiber's checkpoints live
*here*, not in the fiber's own process, so a run is portable across machines: a
weave can crash on one host and resume on another by reading its checkpoint from
this fiber. Pass ``run(persist="<path>")`` to make the store survive the state
fiber's own restart too.
"""

from thicket import Fiber
from thicket.store import FileStore

state = Fiber(kind="state")


def _store(ctx) -> FileStore:
    s = ctx.config.get("_store")
    if s is None:
        s = FileStore(ctx.config.get("persist"))  # None -> in-memory
        ctx.config["_store"] = s
    return s


@state.handles("state.set", "store a value by key", tags=["state"])
async def set_value(req, ctx):
    s = _store(ctx)
    s.data[req["key"]] = req["value"]
    s.save()
    return {"ok": True}


@state.handles("state.get", "fetch a value by key (or null)")
async def get_value(req, ctx):
    return {"value": _store(ctx).data.get(req["key"])}


run = state.run

if __name__ == "__main__":
    state.main()
