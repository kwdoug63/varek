# SPDX-License-Identifier: MIT
# A shim for the v1.35 plan corpus (harness/plans/README.md): the example's own
# server and agent, as its main() builds them, at module level, so the
# adapter (--entry varek_shim.py:agent) can read them, with the arguments that
# make the plan as the example gives them (instructions may be shortened).
from agents import Agent
from agents.mcp import MCPServerStreamableHttp

server = MCPServerStreamableHttp(name="DeepWiki MCP Streamable HTTP Server",
                                 params={"url": "https://mcp.deepwiki.com/mcp", "timeout": 15, "sse_read_timeout": 300},
                                 max_retry_attempts=2)
agent = Agent(name="DeepWiki Assistant", instructions="Use the tools to respond to user requests.", mcp_servers=[server])
