"""Tool fiber: integer addition. Grant-gating, deadlines, budgets, spans, and
error handling are all the SDK's job — this is the whole fiber."""

from thicket import Fiber

calc = Fiber(kind="tool")


@calc.handles("calc.add", "integer addition", tags=["calc"])
async def add(req):
    return {"result": req["a"] + req["b"]}


run = calc.run  # so `python calc.py <dir...>` and the test harness can launch it

if __name__ == "__main__":
    calc.main()
