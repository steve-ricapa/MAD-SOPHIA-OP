import logging
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import main


def _failed_collection(monkeypatch, raw):
    monkeypatch.setattr(main, "UnifiedAgent", lambda **kwargs: SimpleNamespace(run=lambda **kwargs: raw))
    monkeypatch.setattr(main, "save_json", lambda *args: None)
    monkeypatch.setattr(main, "normalize_unified", lambda raw: {"insightvm": {"assets": [], "findings": []}})
    backend = Mock(side_effect=AssertionError("Collection failure must not reach delivery"))
    monkeypatch.setattr(main, "BackendClient", backend)
    return backend


@pytest.mark.parametrize("source", [
    {"error": "HTTP 401 unauthorized"},
    {"assets": {"error": "HTTP 401 unauthorized"}},
    {"error": "HTTP 401 unauthorized", "assets": {}},
])
def test_collection_failure_raises_without_delivery(monkeypatch, source):
    backend = _failed_collection(monkeypatch, {"insightvm": source})
    args = main.build_parser().parse_args([])

    with pytest.raises(RuntimeError, match="InsightVM collection failed: HTTP 401 unauthorized"):
        main.execute_run(args, logging.getLogger("test"), SimpleNamespace(),
                         SimpleNamespace(url="https://backend.example"), SimpleNamespace(state={}))

    backend.assert_not_called()


def test_single_run_collection_failure_does_not_exit_successfully(monkeypatch):
    backend = _failed_collection(monkeypatch, {"insightvm": {"assets": {"error": "No route to host"}}})
    monkeypatch.setattr(main, "setup_logging", lambda *args: None)
    monkeypatch.setattr(main, "load_dotenv", lambda **kwargs: None)
    monkeypatch.setattr(main, "load_general_settings", lambda: SimpleNamespace(state_file="unused", interval=60))
    monkeypatch.setattr(main, "load_backend_settings", lambda: SimpleNamespace(url="https://backend.example"))
    monkeypatch.setattr(main, "StateManager", lambda **kwargs: SimpleNamespace(state={}))
    monkeypatch.setattr(sys, "argv", ["main.py", "--once"])

    with pytest.raises(RuntimeError, match="No route to host"):
        main.main()

    backend.assert_not_called()
