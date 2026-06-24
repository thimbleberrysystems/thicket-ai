"""A Weave: compose a tool fiber and a model fiber to accomplish a goal.

`ctx.call` / `ctx.gather` hide discovery, the connection, child-context
propagation (trace / deadline / budget / sink), and grant attenuation — so the
weave is just the recipe. It is itself a fiber (`kind: weave`) and nests.
"""

from thicket import Fiber

weave = Fiber(kind="weave")


@weave.handles("describe_sum", "describe the sum of two numbers", tags=["compose"])
async def describe_sum(req, ctx):
    total = await ctx.call("tool", "calc.add", {"a": req["a"], "b": req["b"]})
    text = await ctx.gather("model", "generate", f"The sum is {total['result']}")
    return {"sum": total["result"], "description": text}


run = weave.run

if __name__ == "__main__":
    weave.main()
