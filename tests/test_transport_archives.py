"""Transport diagnostic flags use bounded local bundles, without HTTP calls."""
import importlib.util
import json
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
TRANSPORTS = [
    ("nessus", "NESSUS", "nessus_integration/deliver.py"),
    ("uptimekuma", "UPTIME", "uptimekuma_integration/deliver.py"),
    ("zabbix", "ZABBIX", "zabix_integration/deliver.py"),
    ("insightvm", "INSIGHTVM", "insightVM_integration/clients/backend_client.py"),
]


@pytest.fixture(params=TRANSPORTS, ids=[row[0] for row in TRANSPORTS])
def transport(request, monkeypatch, tmp_path):
    name, prefix, relative = request.param
    spec = importlib.util.spec_from_file_location("archive_test_transport_" + name, REPO / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    root = tmp_path / "payload_debug" / name
    monkeypatch.setenv(prefix + "_PAYLOAD_DEBUG_DIR", str(root))
    monkeypatch.setenv("MAD_ARCHIVE_ENABLED", "false")
    monkeypatch.setenv("MAD_ARCHIVE_MAX_ENTRIES", "2")
    return name, prefix, module, root


def test_disabled_transport_flag_does_not_create_diagnostics(transport, monkeypatch):
    _, prefix, module, root = transport
    monkeypatch.setenv(prefix + "_PAYLOAD_DEBUG", "false")
    # Ordinary snapshot archival does not enable transport diagnostics.
    monkeypatch.setenv("MAD_ARCHIVE_ENABLED", "true")
    module._save_payload_debug({"scan_id": "disabled"}, 200, "ok")
    assert not root.exists()


def test_unset_transport_flag_defaults_to_disabled(transport, monkeypatch):
    _, prefix, module, root = transport
    monkeypatch.delenv(prefix + "_PAYLOAD_DEBUG", raising=False)
    module._save_payload_debug({"scan_id": "disabled"}, 200, "ok")
    assert not root.exists()


def test_explicit_transport_debug_is_bounded_even_when_global_off(transport, monkeypatch):
    name, prefix, module, root = transport
    monkeypatch.setenv(prefix + "_PAYLOAD_DEBUG", "true")
    for index in range(5):
        monkeypatch.setattr("mad_common.artifacts.time.time", lambda value=index: 1000 + value)
        module._save_payload_debug({"scan_id": str(index), "findings": [{"description": "x" * 300}]},
                                   200, "response", "")
    bundles = list((root / ".mad-archive-v1" / name).glob("entry-*"))
    assert len(bundles) == 2
    assert {json.loads((entry / "payload.json").read_text())["scan_id"] for entry in bundles} == {"3", "4"}
    for entry in bundles:
        assert {p.name for p in entry.iterdir()} == {"payload.json", "metadata.json", ".entry.json"}
        metadata = json.loads((entry / "metadata.json").read_text())
        assert metadata["status_code"] == 200
        assert metadata["strings_over_255"]
    assert not list(root.glob("*.json"))
