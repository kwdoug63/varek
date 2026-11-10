# The sample's researcher (VAREK v1.35): a ReAct agent on Claude, with a tool of
# its own and the team's documentation server over MCP.
from langchain_anthropic import ChatAnthropic
from langchain_core.tools import tool
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent

docs = MultiServerMCPClient({"docs": {"transport": "streamable_http", "url": "https://docs.example.com/mcp"}})


@tool
def word_count(text: str) -> int:
    """How many words a text has"""
    return len(text.split())


model = ChatAnthropic(model="claude-sonnet-4-5")
graph = create_react_agent(model, [word_count])
print("researcher built")      # printed as it is imported: not part of the plan
