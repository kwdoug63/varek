# v1.35 step 8: the plan corpus, v1.11's condition

131 agents, 5 frameworks (agentcore, claude, langgraph, openai-agents, watsonx); 130 plans generated.

| framework | agents | plans | authorized | refused | refused only for unlisted tools | refused only for collection steps | v1.11 could let start (0 by construction) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| agentcore | 5 | 5 | 5 | 0 | 0/5 (0.0%) | 0/5 (0.0%) | 0/5 (0.0%) |
| claude | 7 | 7 | 7 | 0 | 0/7 (0.0%) | 0/7 (0.0%) | 0/7 (0.0%) |
| langgraph | 6 | 6 | 6 | 0 | 0/6 (0.0%) | 0/6 (0.0%) | 0/6 (0.0%) |
| openai-agents | 44 | 43 | 37 | 6 | 1/43 (2.3%) | 0/43 (0.0%) | 0/43 (0.0%) |
| watsonx | 69 | 69 | 68 | 1 | 1/69 (1.4%) | 0/69 (0.0%) | 0/69 (0.0%) |
| **all** | 131 | 130 | 123 | 7 | 2/130 (1.5%) | 0/130 (0.0%) | 0/130 (0.0%) |
| plans naming a tool server | 10 | 10 | 3 | 7 | 2/10 (20.0%) | 0/10 (0.0%) | 0/10 (0.0%) |

Steps not SATISFIED, by stratum: launch 3, string-host 6, unlisted-tools 4.

Per framework (each framework's share, averaged): 0.8% refused only for unlisted tools.

No step of plan 1.35 is on the collection stratum, so the collection column and v1.11's are 0 by construction: with plan 1.35 the plan gate cannot meet v1.11's condition. The agents are the frameworks' published examples, not deployed agents.

No plan for 1: openai-agents/voice/static/main/agent (openai-agents: importing /var/tmp/corpus-src/openai-agents-python/examples/voice/static/main.py failed: ModuleNotFoundError: No module named 'sounddevice').
