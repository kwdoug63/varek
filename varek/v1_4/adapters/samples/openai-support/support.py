# The sample's agents (VAREK v1.35): a triage agent that searches the help
# center over MCP and hands billing questions off; and an ops agent with an
# MCP server and no tool filter.
from agents import Agent, function_tool
from agents.mcp import MCPServerStreamableHttp, create_static_tool_filter


@function_tool
def invoice_total(invoice_id: str) -> str:
    """The total of an invoice"""
    return "42.00"


help_center = MCPServerStreamableHttp(
    name="help_center", params={"url": "https://help.example.com/mcp"},
    tool_filter=create_static_tool_filter(allowed_tool_names=["search_articles", "get_article"]))

billing = Agent(name="billing", instructions="Answer billing questions.", tools=[invoice_total], model="gpt-4.1-mini")
triage = Agent(name="triage", instructions="Answer from the help center; hand billing questions to billing.",
               mcp_servers=[help_center], handoffs=[billing], model="gpt-4.1")

ops_tools = MCPServerStreamableHttp(name="ops", params={"url": "https://ops.example.com/mcp"})
ops = Agent(name="ops", instructions="Run the operations runbooks.", mcp_servers=[ops_tools], model="gpt-4.1")
