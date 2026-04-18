import sqlite3
from pathlib import Path
from loguru import logger


class StateStore:
    def __init__(self, db_path="state/agent_state.db"):
        self.db_path = db_path
        db_parent = Path(db_path).parent
        db_parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS checkpoints (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS processed_alerts (
                    alert_id TEXT PRIMARY KEY,
                    seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

    def get_checkpoint(self, key, default="now-30m"):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT value FROM checkpoints WHERE key = ?", (key,))
                row = cursor.fetchone()
                return row[0] if row else default
        except Exception as e:
            logger.error(f"Error reading checkpoint {key}: {e}")
            return default

    def update_checkpoint(self, key, value):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO checkpoints (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
                    (key, value)
                )
                conn.commit()
        except Exception as e:
            logger.error(f"Error updating checkpoint {key}: {e}")

    def is_alert_processed(self, alert_id):
        if not alert_id:
            return False
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT 1 FROM processed_alerts WHERE alert_id = ? LIMIT 1",
                    (alert_id,),
                )
                return cursor.fetchone() is not None
        except Exception as e:
            logger.error(f"Error checking processed alert {alert_id}: {e}")
            return False

    def mark_alerts_processed(self, alert_ids):
        if not alert_ids:
            return
        try:
            unique_ids = {(alert_id,) for alert_id in alert_ids if alert_id}
            if not unique_ids:
                return
            with sqlite3.connect(self.db_path) as conn:
                conn.executemany(
                    "INSERT OR IGNORE INTO processed_alerts (alert_id) VALUES (?)",
                    list(unique_ids),
                )
                conn.commit()
        except Exception as e:
            logger.error(f"Error marking processed alerts: {e}")

    def purge_processed_alerts(self, older_than_days=7):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "DELETE FROM processed_alerts WHERE seen_at < datetime('now', ?)",
                    (f"-{int(older_than_days)} days",),
                )
                conn.commit()
        except Exception as e:
            logger.error(f"Error purging processed alerts: {e}")
