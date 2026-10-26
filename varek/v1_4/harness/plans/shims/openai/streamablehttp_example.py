# SPDX-License-Identifier: MIT
# A shim for the v1.35 plan corpus (harness/plans/README.md): the example's own
# server and agent, as its main() builds them, at module level, so the
# adapter (--entry varek_shim.py:agent) can read them, with the arguments that
# make the plan as the example gives them (instructions may be shortened).
# Note: the example picks a free port at run time; the shim names 8000.
from agents import Agent, ModelSettings
from agents.mcp import MCPServerStreamableHttp

mcp_server = MCPServerStreamableHttp(name="Streamable HTTP Python Server", params={"url": "http://127.0.0.1:8000/mcp"})
agent = Agent(name="Assistant", instructions="Use the tools to answer the questions.", mcp_servers=[mcp_server],
              model_settings=ModelSettings(tool_choice="required"))
