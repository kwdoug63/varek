# SPDX-License-Identifier: MIT
# A shim for the v1.35 plan corpus (harness/plans/README.md): the example's own
# server and agent, as its main() builds them, at module level, so the
# adapter (--entry varek_shim.py:agent) can read them, with the arguments that
# make the plan as the example gives them (instructions may be shortened).
# Note: the example takes its sample directory beside it.
import os
from agents import Agent
from agents.mcp import MCPServerStdio

samples_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_files")
mcp_server = MCPServerStdio(name="Filesystem Server, via npx",
                            params={"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", samples_dir]})
agent = Agent(name="Assistant", instructions="Use the tools to read the filesystem and answer questions based on those files.",
              mcp_servers=[mcp_server])
