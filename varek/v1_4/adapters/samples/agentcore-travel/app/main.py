# The sample's agent (a stand-in: VAREK's adapter reads agentcore.json, not this code)
from bedrock_agentcore.runtime import BedrockAgentCoreApp
app = BedrockAgentCoreApp()

@app.entrypoint
def invoke(payload):
    return {"answer": "booked"}

if __name__ == "__main__":
    app.run()
