import pytest
from clients.insightvm_client import InsightVMClient

def test_http_error(monkeypatch):

    class R:
        status_code = 500
        text = "error"
        def json(self): return {}

    class S:
        def get(self, *a, **k): return R()

    c = InsightVMClient()
    c.session = S()

    with pytest.raises(Exception):
        c.get("/assets")
