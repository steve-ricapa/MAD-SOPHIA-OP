from agents.insightvm_agent import InsightVMAgent

class DummyClient:
    def get(self, endpoint, params=None):
        if endpoint == "/assets":
            return {"data": ["a1", "a2"]}
        if endpoint == "/vulnerabilities":
            return {"data": ["v1"]}
        return {}

def test_insightvm(monkeypatch):
    agent = InsightVMAgent()
    monkeypatch.setattr(agent, "client", DummyClient())

    data = agent.run()

    assert "assets" in data
