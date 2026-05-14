import sys
from pathlib import Path


for _module_name in ("snapshot",):
    sys.modules.pop(_module_name, None)

OPENVAS_DIR = Path(__file__).resolve().parents[1]
if str(OPENVAS_DIR) not in sys.path:
    sys.path.insert(0, str(OPENVAS_DIR))

from snapshot import build_snapshot_signature, decide_snapshot_send


def test_snapshot_signature_stable_on_reordered_tasks():
    tasks_a = [
        {"task_id": "2", "task_name": "B", "report_id": "r2", "status": "Done", "modification_time": "t2"},
        {"task_id": "1", "task_name": "A", "report_id": "r1", "status": "Done", "modification_time": "t1"},
    ]
    tasks_b = [
        {"task_id": "1", "task_name": "A", "report_id": "r1", "status": "Done", "modification_time": "t1"},
        {"task_id": "2", "task_name": "B", "report_id": "r2", "status": "Done", "modification_time": "t2"},
    ]
    assert build_snapshot_signature(tasks_a) == build_snapshot_signature(tasks_b)


def test_decide_snapshot_send_first_snapshot():
    decision = decide_snapshot_send(
        current_signature="sig1",
        previous_signature="",
        unchanged_cycles=0,
        has_sent_once=False,
        force_send_every_cycles=6,
        snapshot_always_send=False,
    )
    assert decision["should_send"] is True
    assert decision["reason"] == "first_snapshot"


def test_decide_snapshot_send_force_cycle_when_unchanged_threshold_reached():
    decision = decide_snapshot_send(
        current_signature="sig1",
        previous_signature="sig1",
        unchanged_cycles=5,
        has_sent_once=True,
        force_send_every_cycles=6,
        snapshot_always_send=False,
    )
    assert decision["should_send"] is True
    assert decision["reason"] == "force_send_cycle"


def test_decide_snapshot_send_skip_when_no_change_below_threshold():
    decision = decide_snapshot_send(
        current_signature="sig1",
        previous_signature="sig1",
        unchanged_cycles=2,
        has_sent_once=True,
        force_send_every_cycles=6,
        snapshot_always_send=False,
    )
    assert decision["should_send"] is False
    assert decision["reason"] == "no_change"


def test_decide_snapshot_send_always_mode():
    decision = decide_snapshot_send(
        current_signature="sig1",
        previous_signature="sig1",
        unchanged_cycles=10,
        has_sent_once=True,
        force_send_every_cycles=6,
        snapshot_always_send=True,
    )
    assert decision["should_send"] is True
    assert decision["reason"] == "always_snapshot"
