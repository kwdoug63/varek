# SPDX-License-Identifier: MIT
# A shim for the v1.35 plan corpus (harness/plans/README.md): the example's own
# server and agent, as its main() builds them, at module level, so the
# adapter (--entry varek_shim.py:agent) can read them, with the arguments that
# make the plan as the example gives them (instructions may be shortened).
import os
from agents import Agent
from agents.mcp import MCPServerStdio, create_static_tool_filter

samples_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_files")
server = MCPServerStdio(name="Filesystem Server with filter",
                        params={"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", samples_dir],
                                "cwd": samples_dir},
                        require_approval="always",
                        tool_filter=create_static_tool_filter(allowed_tool_names=["read_file", "list_directory"],
                                                              blocked_tool_names=["write_file"]))
agent = Agent(name="MCP Assistant", instructions="Use only the available filesystem tools.", mcp_servers=[server])
