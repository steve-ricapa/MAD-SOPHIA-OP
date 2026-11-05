import pytest

from mad_common.delivery import DeliveryJournal, DeliveryPolicy, resolve_delivery_policy


@pytest.mark.parametrize("integration", ["nessus", "openvas", "insightvm", "wazuh", "uptimekuma", "zabbix"])
def test_sixth_successful_unchanged_cycle_after_restart(integration, tmp_path):
    policy = resolve_delivery_policy({}, integration)
    directory = tmp_path / integration
    with DeliveryJournal(directory, integration, policy) as j:
        first = j.enqueue("A", {"value": 1})
        j.drain(lambda *_: True)
    for count in range(1, 6):
        with DeliveryJournal(directory, integration, policy) as j:
            assert j.decision("A")["unchanged_cycles"] == count
            assert j.enqueue("A", {}) is None
            assert j.state["unchanged_cycles"] == count
    with DeliveryJournal(directory, integration, policy) as j:
        assert j.decision("A")["reason"] == "backup_cycle"
        event = j.enqueue("A", {"value": 1})
        assert event["key"] != first["key"]
        assert j.state["unchanged_cycles"] == 6
        assert j.drain(lambda *_: False) == 0
        assert j.state["unchanged_cycles"] == 6
    with DeliveryJournal(directory, integration, policy) as j:
        assert j.enqueue("A", {}) is None
        assert len(j.state["pending"]) == 1
        assert j.state["unchanged_cycles"] == 6
        assert j.state["pending"][0] == event
        j.drain(lambda *_: True)
        assert j.state["unchanged_cycles"] == 0
        # Retrying successfully and checking the source in one cycle is not two cycles.
        j.enqueue("A", {})
        assert j.state["unchanged_cycles"] == 0


def test_changes_send_immediately_but_reset_counter_only_on_ack(tmp_path):
    with DeliveryJournal(tmp_path, "nessus", DeliveryPolicy()) as j:
        j.enqueue("A", {})
        j.drain(lambda *_: True)
    for _ in range(3):
        with DeliveryJournal(tmp_path, "nessus", DeliveryPolicy()) as j:
            j.enqueue("A", {})
    with DeliveryJournal(tmp_path, "nessus", DeliveryPolicy()) as j:
        assert j.decision("B")["reason"] == "snapshot_changed"
        j.enqueue("B", {})
        assert j.state["unchanged_cycles"] == 3
        j.drain(lambda *_: False)
        assert j.state["unchanged_cycles"] == 3
        j.drain(lambda *_: True)
        assert j.state["unchanged_cycles"] == 0


def test_failed_source_and_pure_decisions_do_not_count(tmp_path):
    with DeliveryJournal(tmp_path, "nessus", DeliveryPolicy(), baseline_signature="A") as j:
        for _ in range(20):
            j.decision("A")
        # Source failure exits before committing an observation.
        assert j.state["unchanged_cycles"] == 0
    with DeliveryJournal(tmp_path, "nessus", DeliveryPolicy()) as j:
        assert j.decision("A")["unchanged_cycles"] == 1


@pytest.mark.parametrize("value", ["0", "-1", "1.5", "true", "nan"])
def test_invalid_backup_cycle_configuration(value):
    with pytest.raises(ValueError):
        resolve_delivery_policy({"MAD_DELIVERY_BACKUP_CYCLES": value}, "nessus")


def test_backup_configuration_precedence():
    policy = resolve_delivery_policy({"MAD_DELIVERY_BACKUP_CYCLES": "6", "UPTIME_DELIVERY_BACKUP_CYCLES": "8"}, "uptimekuma")
    assert policy.backup_cycles == 8
