#!/usr/bin/env bash

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "== MAD schedule diagnosis =="
echo "repo: $REPO_DIR"
echo

echo "-- systemd units --"
systemctl cat mad-6x.timer 2>/dev/null || echo "mad-6x.timer: not found"
echo
systemctl cat mad-6x.service 2>/dev/null || echo "mad-6x.service: not found"
echo

echo "-- timer state --"
systemctl list-timers --all --no-pager 2>/dev/null | grep -E "mad-6x|NEXT|UNIT" || echo "mad-6x.timer: not listed"
echo

echo "-- timer/service status --"
systemctl status mad-6x.timer --no-pager 2>/dev/null || echo "mad-6x.timer: status unavailable"
echo
systemctl status mad-6x.service --no-pager 2>/dev/null || echo "mad-6x.service: status unavailable"
echo

echo "-- current user crontab --"
if crontab -l 2>/dev/null; then
  :
else
  echo "(no crontab or crontab unavailable)"
fi
echo

echo "-- cron files with MAD matches --"
found=0
for path in /etc/crontab /etc/cron.d /var/spool/cron; do
  if [ -e "$path" ]; then
    if grep -RniE "run_hourly|mad-6x|nessus_integration/agent.py|uptimekuma_integration/agent.py|zabix_integration/agent.py|openVAS_integration/main.py|wazuh_integration/main.py|insightVM_integration/main.py" "$path" 2>/dev/null; then
      found=1
    fi
  fi
done
if [ "$found" -eq 0 ]; then
  echo "(no cron matches found)"
fi
echo

echo "-- quick verdict --"
echo "If cron output shows a MAD command, there is a remnant cron."
echo "If only mad-6x.timer appears, scheduling is systemd-only."
