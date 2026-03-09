# Alerts & Notifications

## SALUTE Alert Format

All alerts follow SALUTE military reporting format:

- **S**ize - How many (1 process, 47 attempts, 3 files)
- **A**ctivity - What happened (WRITE to /etc/passwd, SSH brute force, SUID bit set)
- **L**ocation - Where (inode, IP address, filepath, port)
- **U**nit - Who/what entity (uid, process chain, username)
- **T**ime - When (timestamp)
- **E**quipment - Sensor/context (auditd rule, skill name, authentication method)

## Severity Levels

### 🔴 CONTACT (Red)
Immediate, single event requiring attention:
- File integrity violation
- New SUID binary appeared
- Kernel module loaded
- Shell spawned from web server
- Root login detected

**Behavior:** Sent immediately, always fires regardless of quiet hours

### 🟡 MOVEMENT (Yellow)
Rate-limited digest of multiple related events:
- SSH brute force attempts (N failures in T seconds)
- Port scan summary
- Resource anomaly sustained over time

**Behavior:** Deduplicated and rate-limited by dedup engine

### 🟢 NOMINAL (Green)
Lifecycle and operational events:
- fogbot startup
- fogbot shutdown
- Baseline approval prompts
- Configuration changes
- Skill enabled/disabled

**Behavior:** Always sent, used as heartbeat

## Alert Examples

### RED Alert Example

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

### YELLOW Alert Example

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

### GREEN Alert Example

```
🟢 [NOMINAL] fogbot online
8 sensors active | baseline: approved
Host: prod-web-01 | 2024-01-15 03:40:00 UTC
```

## Telegram Authentication (TOFU)

Trust On First Use authentication proves operator has shell access.

### Flow

1. Daemon starts with no auth
2. User sends `/start` to bot via Telegram
3. Bot generates `FOG-XXXX-XXXX` code, logs it to stdout/journald
4. User copies code from logs (proves shell access)
5. User sends code to bot via Telegram
6. Bot authorizes that chat_id, saves to `state.json`
7. On restart, if `state.json` has authorized chat_id, auth is automatic

### Commands (Post-Auth)

- `/help` - Show available commands
- `/status` - System status summary
- `/reset` - Deauthorize this chat
- `hi` / `hello` - Ping test
- `/approve` - Approve pending baselines (future)

### Security Features

- **No expiry** - Code valid until used, operator can take their time
- **First to auth wins** - Subsequent auth attempts silently dropped
- **One authorized chat only** - No ambiguity about who the operator is
- **Persistent state** - Survives restarts via `state.json`

## Deduplication Engine

Prevents alert storms by rate-limiting similar alerts.

### Configuration

```yaml
dedup:
  window: 300s      # Suppress duplicate alerts for 5 minutes
  max_burst: 10     # Max alerts per sensor per window
```

### Behavior

1. First alert of its type → sent immediately
2. Similar alerts within window → suppressed
3. After `max_burst` alerts → digest sent instead
4. After window expires → next alert sent normally

### Digest Format

Digested alerts include count:
```
🟡 [MOVEMENT] SSH Brute Force (digest: 47 events)
```

## Quiet Hours (Future)

```yaml
quiet_hours:
  enabled: false
  start: "23:00"
  end: "06:00"
```

- **RED alerts** - Always fire regardless of quiet hours
- **YELLOW alerts** - Suppressed during quiet hours
- **GREEN alerts** - Suppressed during quiet hours
