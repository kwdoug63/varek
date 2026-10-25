# SPDX-License-Identifier: MIT
# A shim for the v1.35 plan corpus (harness/plans/README.md): the example's own
# server and agent, as its main() builds them, at module level, so the
# adapter (--entry varek_shim.py:agent) can read them, with the arguments that
# make the plan as the example gives them (instructions may be shortened).
from agents import Agent
from agents.mcp import MCPServerStdio

mcp_server = MCPServerStdio(cache_tools_list=True, params={"command": "uvx", "args": ["mcp-server-git"]})
agent = Agent(name="Assistant", instructions="Answer questions about the git repository, use that for repo_path",
              mcp_servers=[mcp_server])
