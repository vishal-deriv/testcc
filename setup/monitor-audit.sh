#!/usr/bin/env bash
# Monitor SafeSkill audit log — prints evaluate events as they arrive.
# Usage: sudo bash setup/monitor-audit.sh

AUDIT="/var/log/safeskill/audit-$(date +%Y-%m-%d).jsonl"
sudo tail -f "$AUDIT" 2>/dev/null | python3 -c '
import sys, json
for line in sys.stdin:
    try:
        d = json.loads(line)
        if d.get("event_action") == "evaluate":
            ts = d.get("event_timestamp", "")[:19]
            out = d.get("event_outcome", "").upper()
            cmd = d.get("system_command", "")
            print(f"{ts} [{out:7}] {cmd}")
    except Exception:
        pass
'
