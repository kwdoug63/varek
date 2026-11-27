# SPDX-License-Identifier: MIT
"""claude_agent_sdk.py: a Claude Agent SDK agent using a Palantir Ontology MCP server through
VAREK's gateway (v1.43 step 5, integrations/palantir/README.md).

Run it under VAREK, for example:
  sudo varek run --policy omcp.policy -- python3 claude_agent_sdk.py "Which to-do tasks are overdue?"

The MCP server's URL is the gateway's, http://HOST/PATH (port 80): VAREK decides
each call against https://HOST/PATH and speaks verified TLS to the server. The
bearer token is $VAREK_CRED_OMCP, which holds only the credential's placeholder;
the proxy releases the real token into the calls the policy allows. A call the
policy holds waits for an approver (`varek pending`, `varek approve`).

Needs `pip install claude-agent-sdk`. VAREK is not affiliated with Palantir.
"""
import asyncio
import os
import sys

from claude_agent_sdk import ClaudeAgentOptions, query

GATEWAY_URL = os.environ.get("OMCP_GATEWAY_URL", "http://omcp.example.com/mcp/app1")


async def main(prompt):
    options = ClaudeAgentOptions(
        mcp_servers={
            "palantir": {
                "type": "http",
                "url": GATEWAY_URL,
                "headers": {"Authorization": f"Bearer {os.environ.get('VAREK_CRED_OMCP', '')}"},
            }
        },
        # The agent may try any of the server's tools; VAREK decides each call.
        allowed_tools=["mcp__palantir"],
    )
    async for message in query(prompt=prompt, options=options):
        print(message)


if __name__ == "__main__":
    asyncio.run(main(" ".join(sys.argv[1:]) or "List the to-do tasks."))
