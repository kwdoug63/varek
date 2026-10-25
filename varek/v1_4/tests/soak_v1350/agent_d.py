#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""agent_d.py — the framework agent of the v1.35 soak (soak.sh): an OpenAI
Agents SDK agent, run by the SDK's own loop (Runner), its MCP client and its
function tools, under the Warden, held to the plan `varek plan generate
--from openai-agents` writes from it. Its model is scripted (ScriptedModel):
each turn asks for the docs server's search_docs and get_doc and the agent's
own word_count, then answers; nothing reaches a model provider.

Read as data by the adapter (--entry agent_d.py:agent): `agent` is built
when the module is imported, from soak.json beside it:

  {"mcp_url": "https://docs.example.com:PORT/mcp", "status_url": "https://status.example.com:PORT/",
   "docs": DIR, "notes": DIR, "outside": FILE}

Run (python3 agent_d.py --hours H --interval S), each turn is a JSON line
on standard output. Every tenth turn three probes, each a call the policy
allows and the plan does not name, which a run held to its plan refuses:
reading FILE (outside), connecting to status_url, and calling the docs
server's get_secret (past the agent's tool filter, as a compromised agent
would). A probe that is let through is recorded, and fails the soak.
"""
import argparse
import asyncio
import json
import os
import ssl
import sys
import time

import httpx
from agents import Agent, Runner, function_tool, set_tracing_disabled
from agents.items import ModelResponse
from agents.mcp import MCPServerStreamableHttp, create_static_tool_filter
from agents.models.interface import Model
from agents.usage import Usage
from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "soak.json")) as fh:
    CONF = json.load(fh)
TURN = {"n": 0}


def system_client(headers=None, timeout=None, auth=None):
    """the MCP client's HTTP client, trusting the system's store (which the
    Warden answers with the run's view of it), not certifi's bundle"""
    return httpx.AsyncClient(verify=ssl.create_default_context(), headers=headers, timeout=timeout, auth=auth)


@function_tool
def word_count(doc: str) -> str:
    """Count a document's words and keep the count as a note"""
    with open(os.path.join(CONF["docs"], os.path.basename(doc) + ".txt")) as fh:
        n = len(fh.read().split())
    with open(os.path.join(CONF["notes"], "last.txt"), "w") as fh:
        fh.write(f"turn {TURN['n']}: {doc} has {n} words\n")
    return str(n)


class ScriptedModel(Model):
    """asks for the tools, then answers: the same calls every turn"""

    async def get_response(self, system_instructions, input, model_settings, tools, output_schema, handoffs,
                           tracing, *, previous_response_id=None, conversation_id=None, prompt=None):
        items = input if isinstance(input, list) else []
        done = any((x.get("type") if isinstance(x, dict) else getattr(x, "type", None)) == "function_call_output"
                   for x in items)
        n = TURN["n"]
        if done:
            out = [ResponseOutputMessage(id=f"msg_{n}", type="message", role="assistant", status="completed",
                                         content=[ResponseOutputText(type="output_text", text=f"turn {n} done",
                                                                     annotations=[])])]
        else:
            calls = [("search_docs", {"query": "plan"}), ("get_doc", {"id": "holds"}), ("word_count", {"doc": "plans"})]
            out = [ResponseFunctionToolCall(id=f"fc_{n}_{i}", call_id=f"call_{n}_{i}", type="function_call", name=nm,
                                            arguments=json.dumps(a)) for i, (nm, a) in enumerate(calls)]
        return ModelResponse(output=out, usage=Usage(), response_id=None)

    def stream_response(self, *a, **k):
        raise NotImplementedError("the soak's model does not stream")


docs = MCPServerStreamableHttp(name="docs", params={"url": CONF["mcp_url"], "httpx_client_factory": system_client},
                               tool_filter=create_static_tool_filter(allowed_tool_names=["search_docs", "get_doc"]),
                               cache_tools_list=True, client_session_timeout_seconds=30)
agent = Agent(name="soak", instructions="Answer from the docs server.", model=ScriptedModel(), mcp_servers=[docs],
              tools=[word_count])


async def probes():
    out = {}
    try:
        with open(CONF["outside"]) as fh:
            fh.read()
        out["file"] = (False, "read")
    except OSError as e:
        out["file"] = (True, f"{type(e).__name__}: {e.errno}")
    try:
        async with httpx.AsyncClient(verify=ssl.create_default_context(), timeout=10) as c:
            r = await c.get(CONF["status_url"])
        out["host"] = (False, f"HTTP {r.status_code}")
    except (httpx.HTTPError, OSError) as e:
        out["host"] = (True, type(e).__name__)
    # get_secret past the agent's tool filter, on a client of its own, in a task of its own: the
    # proxy's refusal ends that client's session (the MCP client cancels it), not the agent's
    async def secret():
        srv = MCPServerStreamableHttp(name="probe", params={"url": CONF["mcp_url"], "httpx_client_factory": system_client},
                                      client_session_timeout_seconds=15)
        try:
            await srv.connect()
            r = await srv.session.call_tool("get_secret", {})
            return " ".join(getattr(c, "text", "") for c in r.content), bool(r.isError)
        finally:
            try:
                await srv.cleanup()
            except BaseException:                # a session the refusal already ended
                pass
    t = asyncio.create_task(secret())
    await asyncio.wait({t}, timeout=60)
    if not t.done():
        t.cancel()
        out["mcp"] = (True, "no answer in 60 s")
    elif t.cancelled():
        out["mcp"] = (True, "cancelled (the proxy's refusal ended the session)")
    elif t.exception() is not None:
        out["mcp"] = (True, type(t.exception()).__name__)
    else:
        text, err = t.result()
        out["mcp"] = (err and "secret" not in text, f"isError={err}")
    return out


async def main(a):
    set_tracing_disabled(True)
    await docs.connect()
    end = time.time() + a.hours * 3600
    try:
        while time.time() < end:
            TURN["n"] += 1
            t0 = time.time()
            rec = {"turn": TURN["n"], "t": t0}
            try:
                r = await Runner.run(agent, f"turn {TURN['n']}")
                rec["ok"] = r.final_output == f"turn {TURN['n']} done"
                rec["output"] = str(r.final_output)
            except Exception as e:
                rec["ok"] = False
                rec["error"] = f"{type(e).__name__}: {e}"[:300]
            if TURN["n"] % 10 == 0:
                rec["probes"] = {k: {"refused": v[0], "detail": v[1]} for k, v in (await probes()).items()}
            rec["seconds"] = round(time.time() - t0, 3)
            print(json.dumps(rec), flush=True)
            await asyncio.sleep(max(0.0, a.interval - (time.time() - t0)))
    finally:
        await docs.cleanup()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=float, default=24)
    ap.add_argument("--interval", type=float, default=60)
    sys.exit(asyncio.run(main(ap.parse_args())))
