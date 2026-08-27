from agents.insightvm_agent import InsightVMAgent


class DummyClient:
    def __init__(self):
        self.assets = [
            {"id": 1, "ip": "10.0.0.1"},
            {"id": 2, "ip": "10.0.0.2"},
        ]
        self.asset_vulns = {
            1: [{"id": "v1"}],
            2: [{"id": "v2"}],
        }
        self.catalog = [
            {"id": "v1", "title": "Vuln One", "severity": "Critical"},
            {"id": "v2", "title": "Vuln Two", "severity": "High"},
            {"id": "v3", "title": "Vuln Three", "severity": "Low"},
        ]

    def get_paged(self, endpoint, size=200, params=None, items_key="resources", max_pages=None):
        if endpoint == "/assets":
            for a in self.assets:
                yield a
        elif endpoint.startswith("/assets/") and endpoint.endswith("/vulnerabilities"):
            asset_id = int(endpoint.split("/")[2])
            for v in self.asset_vulns.get(asset_id, []):
                yield v
        elif endpoint == "/vulnerabilities":
            for v in self.catalog:
                yield v
        else:
            return


def test_insightvm_full_snapshot(monkeypatch):
    agent = InsightVMAgent()
    monkeypatch.setattr(agent, "client", DummyClient())

    data = agent.run()

    assert "assets" in data
    assert isinstance(data["assets"], dict)
    assert isinstance(data["assets"]["resources"], list)
    assert len(data["assets"]["resources"]) == 2

    # tabla puente: cada asset con sus vulnerability_ids
    ids_by_asset = {a["id"]: a.get("vulnerabilities_ids", []) for a in data["assets"]["resources"]}
    assert ids_by_asset[1] == ["v1"]
    assert ids_by_asset[2] == ["v2"]

    # catálogo solo con las definiciones usadas, sin v3 (no referenciado)
    vuln_ids = [v["id"] for v in data["vulnerabilities"]["resources"]]
    assert "v1" in vuln_ids
    assert "v2" in vuln_ids
    assert "v3" not in vuln_ids


def test_insightvm_assets_failure_does_not_crash(monkeypatch):
    class FailingClient(DummyClient):
        def get_paged(self, endpoint, size=200, params=None, items_key="resources", max_pages=None):
            raise Exception("HTTP 401 -> unauthorized")

    agent = InsightVMAgent()
    monkeypatch.setattr(agent, "client", FailingClient())

    data = agent.run()

    assert isinstance(data["assets"], dict)
    assert "error" in data["assets"]
    # No debe crashear con KeyError 'resources'
    assert data["vulnerabilities"] == {"resources": []}


def test_insightvm_vuln_fetch_failure(monkeypatch):
    class VulnFailClient(DummyClient):
        def get_paged(self, endpoint, size=200, params=None, items_key="resources", max_pages=None):
            if endpoint == "/vulnerabilities":
                raise Exception("HTTP 500 -> server error")
            return super().get_paged(endpoint, size=size, params=params, items_key=items_key, max_pages=max_pages)

    agent = InsightVMAgent()
    monkeypatch.setattr(agent, "client", VulnFailClient())

    data = agent.run()

    assert isinstance(data["assets"]["resources"], list)
    assert data["vulnerabilities"] == {"resources": []}
