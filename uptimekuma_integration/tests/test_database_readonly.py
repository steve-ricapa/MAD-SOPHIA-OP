import hashlib
import importlib.util
import sqlite3
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


UPTIME_DIR = Path(__file__).resolve().parents[1]
if str(UPTIME_DIR) not in sys.path:
    sys.path.insert(0, str(UPTIME_DIR))

# Keep this module isolated from collectors imported by other integrations.
spec = importlib.util.spec_from_file_location("uptime_database_collector", UPTIME_DIR / "collector.py")
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


@pytest.fixture
def kuma_db(tmp_path):
    path = tmp_path / "kuma data#test.db"
    with sqlite3.connect(path) as con:
        con.executescript("""
            CREATE TABLE monitor (
                id INTEGER, active, interval, maxretries, retry_interval, timeout, method,
                keyword, upside_down, ignore_tls, parent, description, created_date
            );
            INSERT INTO monitor (id, active, description) VALUES (1, 1, 'test monitor');
            CREATE TABLE heartbeat (
                id INTEGER, monitor_id, status, msg, ping, time, duration, retries, response
            );
            CREATE TABLE monitor_tag (monitor_id, tag_id, value);
            CREATE TABLE tag (id, name, color);
            CREATE TABLE monitor_tls_info (id INTEGER, monitor_id, info_json);
            CREATE TABLE stat_hourly (monitor_id, up, down, ping, ping_min, ping_max, timestamp);
            CREATE TABLE stat_daily (monitor_id, up, down, ping, timestamp);
        """)
    return path


def test_enrichment_opens_real_database_read_only_with_uri_escaping(kuma_db, monkeypatch):
    original_connect = sqlite3.connect
    original_hash = hashlib.sha256(kuma_db.read_bytes()).hexdigest()
    calls = []

    def checked_connect(database, **kwargs):
        calls.append((database, kwargs))
        con = original_connect(database, **kwargs)
        try:
            with pytest.raises(sqlite3.OperationalError, match="readonly"):
                con.execute("CREATE TABLE unintended_write (id INTEGER)")
        except BaseException:
            con.close()
            raise
        return con

    monkeypatch.setattr(collector.sqlite3, "connect", checked_connect)
    monitors = {"1": {"name": "test monitor", "status": 1}}

    result = collector.enrich_with_db(monitors, kuma_db)

    assert result["1"]["db"]["monitor_config"]["description"] == "test monitor"
    assert calls == [(kuma_db.resolve().as_uri() + "?mode=ro", {"uri": True})]
    assert "%23" in calls[0][0] and "%20" in calls[0][0]
    assert hashlib.sha256(kuma_db.read_bytes()).hexdigest() == original_hash


def test_missing_configured_database_fails_without_creation(tmp_path, monkeypatch):
    missing = tmp_path / "missing.db"

    def unexpected_connect(*args, **kwargs):
        pytest.fail("Missing database must not be created or opened")

    monkeypatch.setattr(collector.sqlite3, "connect", unexpected_connect)

    with pytest.raises(FileNotFoundError, match="Uptime Kuma"):
        collector.enrich_with_db({"1": {"status": 1}}, missing)

    assert not missing.exists()


def test_collect_does_not_return_metrics_when_configured_database_is_missing(tmp_path, monkeypatch):
    missing = tmp_path / "missing.db"
    instance = collector.UptimeKumaCollector(SimpleNamespace(kuma_db_path=missing))
    monkeypatch.setattr(instance, "fetch_metrics_text", lambda: 'monitor_status{monitor_id="1",monitor_name="test"} 1\n')

    with pytest.raises(FileNotFoundError, match="Uptime Kuma"):
        instance.collect()

    assert not missing.exists()


def test_collect_metrics_without_database_only_when_database_is_not_configured(monkeypatch):
    instance = collector.UptimeKumaCollector(SimpleNamespace(kuma_db_path=None))
    monkeypatch.setattr(instance, "fetch_metrics_text", lambda: 'monitor_status{monitor_id="1",monitor_name="test"} 1\n')

    result = instance.collect()

    assert result["1"]["status"] == 1
    assert result["1"]["db"] == {}


def test_database_permission_failure_propagates_without_partial_enrichment(kuma_db, monkeypatch):
    error = PermissionError("database read denied")

    def denied(*args, **kwargs):
        raise error

    monkeypatch.setattr(collector.sqlite3, "connect", denied)
    monitors = {"1": {"status": 1}}

    with pytest.raises(PermissionError) as caught:
        collector.enrich_with_db(monitors, kuma_db)

    assert caught.value is error
    assert monitors == {"1": {"status": 1}}
