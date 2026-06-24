"""LLM fiber: streams a text completion. Thicket defines no model backend — you
wrap whatever you like. The example ships a deterministic stub and a keyless
Ollama client; choose one with ``run(model=...)``. Streaming is just ``yield``."""

import asyncio

from thicket import Fiber

model = Fiber(kind="model")


def stub_model(prompt: str):
    """Deterministic 'tokens' — no real model needed for tests."""
    return ["echo: ", prompt, " [done]"]


def ollama_model(prompt, *, model="qwen2.5:0.5b", host="http://127.0.0.1:11434", timeout=120):
    """Real inference via a local Ollama model (keyless). Swapping in OpenAI /
    vLLM / a hosted endpoint is a change here only — the wire never knows."""
    import json
    import urllib.request

    data = json.dumps({"model": model, "prompt": prompt, "stream": False}).encode("utf-8")
    req = urllib.request.Request(
        f"{host}/api/generate", data=data, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return [json.loads(r.read().decode("utf-8"))["response"]]


@model.handles("generate", "text generation", tags=["chat"])
async def generate(prompt, ctx):
    backend = ctx.config.get("model", stub_model)
    for token in await asyncio.to_thread(backend, prompt):  # the call may block (HTTP)
        yield token


run = model.run

if __name__ == "__main__":
    model.main()
