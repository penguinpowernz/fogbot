# fogbot: Alert Structure & Status Reports

## Alert Structure (SALUTE Format)

### RED — immediate, single event
```
🔴 [CONTACT] File Integrity
━━━━━━━━━━━━━━━━━━━━━
S: 1 process
A: WRITE to /etc/passwd
L: inode 12345 (/etc/passwd)
U: uid=1337 (unknown) → bash → sshd
T: 2024-01-15 03:42:17 UTC
E: auditd rule: watch-passwd
━━━━━━━━━━━━━━━━━━━━━
Host: prod-web-01
```

### YELLOW — rate-limited digest
```
🟡 [MOVEMENT] Auth: SSH Brute Force
━━━━━━━━━━━━━━━━━━━━━
47 failed attempts from 1.2.3.4
Targeting: root (32), admin (15)
Window: 60s
Last seen: 03:44:01 UTC
━━━━━━━━━━━━━━━━━━━━━
Host: prod-web-01
```

### GREEN — lifecycle
```
🟢 [NOMINAL] fogbot online
8 sensors active | baseline: approved
Host: prod-web-01 | 2024-01-15 03:40:00 UTC
```

Severity levels: 🔴 CONTACT / 🟡 MOVEMENT / 🟢 NOMINAL

---

## Intel Buttons (Interactive Recon)

Alerts can include an **Intel** button for operator-triggered active reconnaissance. When tapped, fogbot gathers additional context using appropriate Intel modules:

```
🔴 [CONTACT] #715 net-discover
━━━━━━━━━━━━━━━━━━━━━
S: 1 new host
A: First contact on network
L: 192.168.1.47
U: MAC: aa:bb:cc:dd:ee:ff
T: 2024-01-15 03:42:17 UTC
E: baseline established 2024-01-10
━━━━━━━━━━━━━━━━━━━━━
Host: prod-web-01
[🔍 Intel]
```

Tapping `[🔍 Intel]` triggers the `net-scan` module:
- nmap service scan on common ports
- arp-scan for MAC vendor lookup
- Reverse DNS lookup
- TCP banner grab on open ports

Results delivered as follow-up message with structured findings.

**Intel Modules:**
- `net-scan` — Network hosts (nmap, arp-scan, DNS)
- `proc-detail` — Suspicious processes (tree, open files, memory maps)
- `file-analysis` — Suspicious files (hash, strings, permissions)
- `port-intel` — Port tripwires (service ID, banner grab)
- `user-context` — Auth anomalies (login history, sudo log)

Each alert type automatically includes the appropriate Intel button.

---

## Status Reports (Tier 1 & 2)

Acts as both an operational summary and a **heartbeat** — if the report doesn't arrive, something is wrong even if no alerts fired.

Two-tier design: a brief pushed summary you can read at a glance, with interactive drill-down into any section that has non-zero counts.

### Tier 1 — Summary (pushed on schedule)

Numbers only, fits on a phone screen without scrolling.

```
🟢 [STATUS] Daily — prod-web-01
━━━━━━━━━━━━━━━━━━━━━
2024-01-15 09:00 UTC  |  uptime 24h

ALERTS      2 🔴  1 🟡  0 suppressed
AUTH        SSH logins 3 ✓  |  failures 47 ✗  |  sudo 12
NETWORK     Outbound conns 1,204  |  tripwires hit 0
FILES       Watched files touched 2  |  SUID changes 0
PROCESSES   Suspicious exec 0  |  /tmp executables 0
SYSTEM      Modules loaded 0  |  cron changes 0
━━━━━━━━━━━━━━━━━━━━━
[🔍 Drill down ▾]
```

Drill-down button only appears for sections with non-zero counts — no point offering a modules drill-down if nothing loaded.

### Tier 2 — Drill down (on button tap)

Tapping `[🔍 Drill down ▾]` reveals an inline keyboard with one button per non-zero section. Tapping a section sends the detail view. Example for AUTH:

```
🔍 AUTH detail — last 24h
━━━━━━━━━━━━━━━━━━━━━
SSH logins (3):
  ✓ 03:12 UTC  192.168.1.5  →  alice
  ✓ 09:44 UTC  10.0.0.2     →  bob
  ✓ 11:30 UTC  10.0.0.2     →  bob

SSH failures (47):
  ✗ 1.2.3.4  —  47 attempts  targeting: root
    first: 03:40  last: 03:41 UTC  [brute force]

Sudo usage (12):
  alice  →  12x  all succeeded
  root direct login: 0
━━━━━━━━━━━━━━━━━━━━━
[◀ Back]
```

`[◀ Back]` returns to the summary inline keyboard. All navigation via buttons — no free text.

### Tracked Metrics per Section

| Section | Metrics |
|---------|---------|
| **Alerts** | RED count, YELLOW count, dedup-suppressed count, top offending IP |
| **Auth** | SSH logins (success/fail/IPs/users), sudo usage, su attempts, new accounts created, root direct logins |
| **Network** | Outbound connections by process, tripwire port hits, unique external IPs seen |
| **Files** | Watched file touches (who/when), permission changes, new SUID binaries |
| **Processes** | Suspicious parent→child execs, interpreter `-c` invocations, executions from `/tmp` `/dev/shm` |
| **System** | Kernel modules loaded, cron/systemd timer changes, `/proc/sys` changes |

### Schedule Config
```yaml
status_report:
  enabled: true
  schedule: daily        # daily | weekly
  time: "09:00"          # 24h
  day: monday            # weekly only — mon/tue/wed/thu/fri/sat/sun
  timezone: "Europe/London"  # IANA tz string
```

### Implementation
- Uses a ticker that wakes at the next scheduled time, then every interval — no cron dependency
- Metrics accumulated in an in-memory ring buffer per period, flushed on report
- If fogbot was down during a scheduled report time, sends catch-up on next startup: `"Note: fogbot was offline. Last report was 36h ago. Metrics incomplete for that period."`
- Timezone-aware via Go's `time.LoadLocation`
- Drill-down state tracked per Telegram message ID so multiple reports can be open simultaneously without confusion

---

## Presence System (Phase 3)

Continuous presence indication without notification spam.

### Format

Two-line message at the bottom of the chat:
```
2026-03-11
14:23
```

### Behavior

- Updates every 30 seconds via Telegram message edit (editMessageText API)
- Message ID stored in `/var/lib/fogbot/state.json` as `presence_message_id`
- On daemon startup:
  - If old presence message ID exists, delete it (deleteMessage API)
  - Create new presence message, store new ID
- On normal alert send:
  - Delete presence message
  - Send alert
  - Recreate presence message (keeps it at bottom)
- Acts as continuous heartbeat — operator can see fogbot is alive without notification spam

### State Persistence

```json
{
  "authorized_chat_id": 123456789,
  "presence_message_id": 987654321,
  "last_presence_update": "2026-03-11T14:23:00Z"
}
```

### Error Handling

- If edit fails (message deleted by user), create new presence message
- If delete fails (message already gone), ignore error and create new one
- Log all presence operations for debugging
