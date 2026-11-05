import json

import pytest

from openVAS_integration.tests.test_delivery_policy import delivery_agent  # noqa: F401 - shared offline fixture


@pytest.mark.parametrize("first_result,expected_code", [(False, 1), (RuntimeError("first report failed"), 1), (True, 0)])
def test_one_failed_report_cannot_be_hidden_by_later_success(delivery_agent, first_result, expected_code):
    agent = delivery_agent
    agent.outcomes = [first_result, True]
    assert agent.run() == expected_code
    assert [payload["scan_id"] for payload in agent.attempts] == ["report-1", "report-2"]
    # A successful final receipt cannot hide an earlier failed GMP/HTTP delivery.
    meta = json.loads((agent.root / "reports" / "last_delivery_meta.json").read_text(encoding="utf-8"))
    assert meta["delivery_success"] is True
    assert meta["collector"] == "gmp"
    assert meta["output_mode"] == "http"
