from agents.unified_agent import UnifiedAgent

class DummyA:
    def run(self):
        return {"x":1}

class DummyB:
    def run(self):
        return {"y":2}

def test_unified(monkeypatch):
    agent = UnifiedAgent()

    monkeypatch.setattr(agent, "insightvm", DummyA())

    data = agent.run()

    assert "insightvm" in data
