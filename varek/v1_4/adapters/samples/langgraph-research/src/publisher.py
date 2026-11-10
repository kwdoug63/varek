# The sample's publisher (VAREK v1.35): a graph built per run by a factory, on
# OpenAI, with a file-writing MCP server it launches over stdio.
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

files = MultiServerMCPClient({"files": {"transport": "stdio", "command": "/usr/bin/python3",
                                        "args": ["-m", "files_server", "/srv/site"]}})


def make_graph(config):
    return create_react_agent(ChatOpenAI(model="gpt-4o-mini"), [])
