#!/usr/bin/env bash

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

PATTERNS='run_hourly|mad-6x|insightVM_integration/main.py|openVAS_integration/main.py|wazuh_integration/main.py|zabix_integration/agent.py|uptimekuma_integration/agent.py|nessus_integration/agent.py'

hr() {
  printf '%s\n' "============================================================"
}

section() {
  hr
  printf '%s\n' "$1"
  hr
}

run_cmd() {
  printf '$ %s\n' "$1"
  shift
  "$@" 2>/dev/null || true
  printf '\n'
}

grep_ro() {
  local title="$1"
  shift
  section "$title"
  local hit=0
  for path in "$@"; do
    if [ -e "$path" ]; then
      if grep -RniE "$PATTERNS" "$path" 2>/dev/null; then
        hit=1
      fi
    fi
  done
  if [ "$hit" -eq 0 ]; then
    printf '%s\n' '(no matches)'
  fi
  printf '\n'
}

printf 'MAD schedule deep diagnosis\n'
printf 'repo: %s\n' "$REPO_DIR"
printf 'host: '; hostname 2>/dev/null || true
printf 'user: '; id 2>/dev/null || true
printf 'date: '; date 2>/dev/null || true
printf '\n'

section "SYSTEMD: active timers"
run_cmd "systemctl list-timers --all --no-pager | grep -Ei 'mad-6x|NEXT|UNIT|run_hourly'" \
  bash -lc "systemctl list-timers --all --no-pager 2>/dev/null | grep -Ei 'mad-6x|NEXT|UNIT|run_hourly' || true"

section "SYSTEMD: timer/service units"
run_cmd "systemctl cat mad-6x.timer" bash -lc "systemctl cat mad-6x.timer 2>/dev/null || true"
run_cmd "systemctl cat mad-6x.service" bash -lc "systemctl cat mad-6x.service 2>/dev/null || true"
printf '\n'

section "SYSTEMD: all timer unit files"
run_cmd "systemctl list-unit-files --type=timer --no-pager | grep -Ei 'mad|hour|week|run'" \
  bash -lc "systemctl list-unit-files --type=timer --no-pager 2>/dev/null | grep -Ei 'mad|hour|week|run' || true"

section "SYSTEMD: weekly/sunday timers"
run_cmd "systemctl list-timers --all --no-pager | grep -Ei 'Sun|weekly|monthly|mad|run_hourly'" \
  bash -lc "systemctl list-timers --all --no-pager 2>/dev/null | grep -Ei 'Sun|weekly|monthly|mad|run_hourly' || true"

grep_ro "SYSTEMD: grep in /etc/systemd/system and /usr/lib/systemd/system" \
  /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system

section "CRON: user crontab"
run_cmd "crontab -l" bash -lc "crontab -l 2>/dev/null || echo '(no user crontab)'"

section "CRON: system crontab"
run_cmd "cat /etc/crontab" bash -lc "[ -f /etc/crontab ] && cat /etc/crontab || echo '(missing /etc/crontab)'"

section "CRON: cron.d files"
run_cmd "grep -RniE PATTERNS /etc/cron.d" bash -lc "grep -RniE '$PATTERNS' /etc/cron.d 2>/dev/null || true"

section "CRON: periodic dirs"
for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
  if [ -d "$d" ]; then
    printf '%s\n' "-- $d --"
    ls -la "$d" 2>/dev/null || true
    grep -RniE "$PATTERNS" "$d" 2>/dev/null || true
    printf '\n'
  fi
done

section "ANACRON"
run_cmd "cat /etc/anacrontab" bash -lc "[ -f /etc/anacrontab ] && cat /etc/anacrontab || echo '(missing /etc/anacrontab)'"
run_cmd "grep -RniE PATTERNS /etc/anacrontab /etc/cron.d /etc/cron.* /var/spool/anacron" \
  bash -lc "grep -RniE '$PATTERNS' /etc/anacrontab /etc/cron.d /etc/cron.* /var/spool/anacron 2>/dev/null || true"

section "AT JOBS"
run_cmd "atq" bash -lc "atq 2>/dev/null || echo '(no at jobs or at unavailable)'"
run_cmd "grep -RniE PATTERNS /var/spool/at /var/spool/cron /var/at /etc/at*" \
  bash -lc "grep -RniE '$PATTERNS' /var/spool/at /var/spool/cron /var/at /etc/at* 2>/dev/null || true"

section "SYSTEMD override/drop-ins"
run_cmd "systemctl cat mad-6x.timer mad-6x.service" bash -lc "systemctl cat mad-6x.timer mad-6x.service 2>/dev/null || true"
run_cmd "systemctl show mad-6x.timer -p OnCalendar -p Unit -p Persistent -p NextElapseUSecRealtime" \
  bash -lc "systemctl show mad-6x.timer -p OnCalendar -p Unit -p Persistent -p NextElapseUSecRealtime 2>/dev/null || true"

section "MAYBE REMANENT FILES"
for p in \
  /etc/cron.d \
  /etc/cron.weekly \
  /etc/cron.daily \
  /etc/cron.hourly \
  /var/spool/cron \
  /var/spool/anacron \
  /etc/systemd/system \
  /usr/lib/systemd/system \
  /lib/systemd/system; do
  [ -e "$p" ] || continue
  printf '%s\n' "-- search in $p --"
  grep -RniE "$PATTERNS|OnCalendar=.*Sun|OnCalendar=.*weekly|OnCalendar=.*daily|OnCalendar=.*hourly" "$p" 2>/dev/null || true
  printf '\n'
done

section "VERDICT"
echo "- If a cron/anacron match appears, there is a remnant scheduler outside systemd."
echo "- If only mad-6x.timer appears with OnCalendar hourly, systemd is the scheduler."
echo "- If a weekly/Sun timer appears, that is the likely source of Sunday runs."
