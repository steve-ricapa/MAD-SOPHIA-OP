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
        self.catalog = {
            "v1": {"id": "v1", "title": "Vuln One", "severity": "Critical"},
            "v2": {"id": "v2", "title": "Vuln Two", "severity": "High"},
            "v3": {"id": "v3", "title": "Vuln Three", "severity": "Low"},
        }

    def get_paged(self, endpoint, size=200, params=None, items_key="resources", max_pages=None):
        if endpoint == "/assets":
            for a in self.assets:
                yield a
        elif endpoint.startswith("/assets/") and endpoint.endswith("/vulnerabilities"):
            asset_id = int(endpoint.split("/")[2])
            for v in self.asset_vulns.get(asset_id, []):
                yield v
        elif endpoint == "/vulnerabilities":
            # Respaldo: catálogo paginado completo.
            for v in self.catalog.values():
                yield v
        else:
            return

    def get(self, endpoint, params=None):
        prefix = "/vulnerabilities/"
        if endpoint.startswith(prefix):
            vid = endpoint[len(prefix):]
            if vid in self.catalog:
                return self.catalog[vid]
            raise Exception("HTTP 404 -> not found")
        raise Exception(f"Unhandled get: {endpoint}")


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

    # solo las definiciones usadas, sin v3 (no referenciado)
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


def test_insightvm_missing_def_tolerated(monkeypatch):
    # Una definición puntual que no existe NO debe crashear el run: se omite y el resto se resuelve.
    class MissingDefClient(DummyClient):
        def get(self, endpoint, params=None):
            if endpoint == "/vulnerabilities/v2":
                raise Exception("HTTP 404 -> not found")
            return super().get(endpoint, params=params)

    agent = InsightVMAgent()
    monkeypatch.setattr(agent, "client", MissingDefClient())

    data = agent.run()

    vuln_ids = [v["id"] for v in data["vulnerabilities"]["resources"]]
    assert "v1" in vuln_ids
    assert "v2" not in vuln_ids


def test_insightvm_fallback_catalog_when_many_ids(monkeypatch):
    # Si used_ids excede el tamaño de página, cae al catálogo paginado como respaldo.
    class ManyIdsClient(DummyClient):
        def __init__(self):
            super().__init__()
            self.assets = [{"id": i, "ip": f"10.0.0.{i}"} for i in range(1, 3)]
            self.asset_vulns = {
                i: [{"id": f"v{i}"} for i in range(1, 300)] for i in (1, 2)
            }
            self.catalog = {
                f"v{i}": {"id": f"v{i}", "title": f"Vuln {i}", "severity": "Low"}
                for i in range(1, 300)
            }

    agent = InsightVMAgent()
    monkeypatch.setattr(agent, "client", ManyIdsClient())

    data = agent.run(page_size=200)

    vuln_ids = [v["id"] for v in data["vulnerabilities"]["resources"]]
    assert len(vuln_ids) == 299  # v1..v299 (v300 no existe en esta simulación)
